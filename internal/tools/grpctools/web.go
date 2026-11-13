package grpctools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/connectrpc"
	"github.com/HamedFathi/NetKitMCP/internal/grpcweb"
	"github.com/HamedFathi/NetKitMCP/internal/grpcx"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// WebOptions are the inputs shared by grpcweb_request and connect_request.
type WebOptions struct {
	URL      string            `json:"url" jsonschema:"base URL of the endpoint, e.g. https://api.example.com/prefix (the /package.Service/Method path is appended)"`
	Method   string            `json:"method" jsonschema:"package.Service/Method (or package.Service.Method)"`
	Request  any               `json:"request,omitempty" jsonschema:"request message as protojson (object); bytes fields take base64 or {\"$file\": \"path\"}"`
	Metadata map[string]string `json:"metadata,omitempty" jsonschema:"request headers / metadata"`
	types.StreamLimits
	DescriptorOptions
	JSONOptions
	types.HTTPOptions
	Auth *auth.Config `json:"auth,omitempty"`
}

type grpcwebIn struct {
	WebOptions
	Format string `json:"format,omitempty" jsonschema:"binary (application/grpc-web+proto, default) or text (application/grpc-web-text, base64 body)"`
}

type connectIn struct {
	WebOptions
	Encoding        string `json:"encoding,omitempty" jsonschema:"json (default) or proto"`
	ServerStreaming *bool  `json:"server_streaming,omitempty" jsonschema:"force server-streaming mode (only needed for JSON calls without descriptors)"`
}

type webOut struct {
	*types.StreamResult
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Protocol    string            `json:"protocol"`
	Kind        string            `json:"kind"`
	HTTPStatus  int               `json:"http_status"`
	Status      grpcx.StatusInfo  `json:"status"`
	ConnectCode string            `json:"connect_code,omitempty"`
	Response    json.RawMessage   `json:"response,omitempty"`
	Headers     map[string]string `json:"headers"`
	Trailers    map[string]string `json:"trailers"`
	TimingMS    struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	TLS              *types.TLSInfo `json:"tls,omitempty"`
	DescriptorSource string         `json:"descriptor_source,omitempty"`
	Warnings         []string       `json:"warnings,omitempty"`
}

func webHeaders(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

func joinURL(base, path string) string {
	return strings.TrimRight(base, "/") + path
}

// loadWebMethod resolves the method from descriptor files (reflection is
// not available over gRPC-Web / Connect).
func loadWebMethod(ctx context.Context, d *tools.Deps, w *WebOptions) (grpcx.Source, protoreflect.MethodDescriptor, error) {
	src, err := source(ctx, d, w.DescriptorOptions, nil)
	if err != nil {
		return nil, nil, err
	}
	md, err := grpcx.FindMethod(ctx, src, w.Method)
	if err != nil {
		return nil, nil, err
	}
	if md.IsStreamingClient() {
		return nil, nil, fmt.Errorf("%s is %s; only unary and server-streaming methods work over this protocol", md.FullName(), grpcx.MethodKind(md))
	}
	return src, md, nil
}

// transportErr makes HTTP transport failures actionable.
func transportErr(err error) error {
	if errors.Is(err, netguard.ErrBlocked) || strings.Contains(err.Error(), netguard.ErrBlocked.Error()) {
		return err
	}
	return fmt.Errorf("request failed: %w", err)
}

// stoppedStatus reports a stream the client abandoned after a limit fired.
var stoppedStatus = grpcx.StatusInfo{Code: 1, Name: "CANCELLED", Message: "stopped by the client after a limit was reached"}

// collectRun runs call in the background, feeding messages to a collector
// until the call ends or a limit fires (the call is then cancelled). It
// returns the call's error and whether a limit (max_messages,
// max_duration, idle) ended collection before the call ended on its own;
// when limited, callErr is usually the resulting cancellation.
func collectRun(ctx context.Context, col *types.Collector, call func(ctx context.Context, add func(types.StreamMessage) bool) error) (callErr error, limited bool) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := call(cctx, col.Add)
		if err != nil {
			col.Finish(types.EndedError, err)
		} else {
			col.Finish(types.EndedComplete, nil)
		}
		callErr = err
	}()
	col.Wait(ctx)
	cancel()
	<-done
	// The first Finish wins: anything other than complete/error means a
	// limit fired first.
	switch col.Result().EndedBy {
	case types.EndedComplete, types.EndedError:
		return callErr, false
	}
	return callErr, true
}

// streamStatus decides the status of a bounded web stream. override is
// false when the stream completed (use the protocol status); st is then
// zero. err is non-nil for a failure that should be a tool error (no
// response at all, e.g. blocked by the SSRF guard or connection refused).
func streamStatus(callErr error, limited, gotResult, stopped bool) (st grpcx.StatusInfo, override bool, err error) {
	completed := callErr == nil && gotResult && !stopped
	switch {
	case completed:
		return st, false, nil
	case limited || stopped:
		return stoppedStatus, true, nil
	case callErr != nil && !gotResult:
		return st, false, transportErr(callErr)
	case callErr != nil:
		return grpcx.StatusInfo{Code: 2, Name: "UNKNOWN", Message: "stream failed: " + callErr.Error()}, true, nil
	}
	return st, false, nil
}

func registerGRPCWeb(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "grpcweb_request", "gRPC-Web call",
		"Call a unary or server-streaming method over gRPC-Web (binary application/grpc-web+proto, or format=text for application/grpc-web-text) through the shared HTTP client (SSRF guard, TLS, proxy, auth apply). "+
			"Needs proto_files or descriptor_sets (reflection is not available over gRPC-Web). Returns status (with decoded details), response JSON or streamed messages, headers and trailers.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in grpcwebIn) (any, error) {
			if !in.DescriptorOptions.any() {
				return nil, fmt.Errorf("grpcweb_request needs proto_files or descriptor_sets: server reflection is not available over gRPC-Web")
			}
			text := false
			switch strings.ToLower(in.Format) {
			case "", "binary", "proto":
			case "text", "grpc-web-text":
				text = true
			default:
				return nil, fmt.Errorf("format must be binary or text")
			}
			hc, err := d.NewHTTPClient(in.HTTPOptions, in.Auth)
			if err != nil {
				return nil, err
			}
			defer hc.Close()
			maxMsgs, maxDur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
			ctx, cancel := context.WithTimeout(ctx, hc.Timeout+maxDur)
			defer cancel()
			src, md, err := loadWebMethod(ctx, d, &in.WebOptions)
			if err != nil {
				return nil, err
			}
			codec := newCodec(d, src, in.JSONOptions)
			msg, err := codec.NewMessage(md.Input(), in.Request)
			if err != nil {
				return nil, err
			}
			body, err := proto.Marshal(msg)
			if err != nil {
				return nil, err
			}
			wreq := grpcweb.Request{
				URL: joinURL(in.URL, grpcx.FullMethod(md)), Text: text, Message: body,
				Header: webHeaders(in.Metadata), Timeout: hc.Timeout,
				MaxMessageSize: int(hc.MaxResponseBytes), UserAgent: d.Cfg.UserAgent,
			}
			out := webOut{URL: wreq.URL, Method: grpcx.FullMethod(md), Protocol: "grpc-web", Kind: grpcx.MethodKind(md), DescriptorSource: src.Kind()}
			if text {
				out.Protocol = "grpc-web-text"
			}
			if hc.Insecure {
				out.Warnings = append(out.Warnings, "insecure_skip_verify is set: the server certificate was not verified")
			}
			start := time.Now()
			var res *grpcweb.Result
			var overrideStatus *grpcx.StatusInfo
			if !md.IsStreamingServer() {
				uctx, ucancel := context.WithTimeout(ctx, hc.Timeout)
				defer ucancel()
				var respData []byte
				res, err = grpcweb.Call(uctx, hc.Client, wreq, func(b []byte) bool { respData = b; return true })
				if err != nil {
					return nil, transportErr(err)
				}
				if respData != nil {
					js, err := codec.Unmarshal(md.Output(), respData)
					if err != nil {
						return nil, err
					}
					out.Response = js
				}
			} else {
				col := types.NewCollector(maxMsgs, maxDur, idle, d.Cfg.ResponseBytes(0))
				var mu sync.Mutex
				callErr, limited := collectRun(ctx, col, func(cctx context.Context, add func(types.StreamMessage) bool) error {
					r, err := grpcweb.Call(cctx, hc.Client, wreq, func(b []byte) bool {
						js, jerr := codec.Unmarshal(md.Output(), b)
						if jerr != nil {
							return add(types.StreamMessage{Dir: "in", Type: "error", Data: jerr.Error(), Encoding: "text"})
						}
						return add(types.StreamMessage{Dir: "in", Type: "json", Data: string(js), Encoding: "text"})
					})
					mu.Lock()
					res = r
					mu.Unlock()
					return err
				})
				st, override, terr := streamStatus(callErr, limited, res != nil, res != nil && res.Stopped)
				if terr != nil {
					return nil, terr
				}
				out.StreamResult = col.Result()
				if override {
					overrideStatus = &st
				}
			}
			out.TimingMS.Total = types.MS(time.Since(start))
			if res != nil {
				out.HTTPStatus = res.HTTPStatus
				out.Headers = grpcx.HeaderToMap(res.Header)
				out.Trailers = grpcx.HeaderToMap(res.Trailer)
				out.TLS = tlsx.Info(res.TLS, hc.Insecure)
				if res.Status != nil {
					out.Status = grpcx.StatusFromParts(res.Status.Code, res.Status.Message, res.Status.DetailsBin, codec.Resolver)
				}
			}
			if overrideStatus != nil {
				out.Status = *overrideStatus
			}
			return out, nil
		})
}

func registerConnect(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "connect_request", "Connect RPC call",
		"Call a unary or server-streaming method with the Connect protocol (encoding json or proto) through the shared HTTP client (SSRF guard, TLS, proxy, auth apply). "+
			"JSON calls work without descriptors (request passed through; set server_streaming for streams); proto encoding needs proto_files or descriptor_sets. "+
			"Returns the Connect/gRPC status with decoded error details, the response JSON or streamed messages, headers and trailers.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in connectIn) (any, error) {
			enc := strings.ToLower(in.Encoding)
			if enc == "" {
				enc = connectrpc.CodecJSON
			}
			if enc != connectrpc.CodecJSON && enc != connectrpc.CodecProto {
				return nil, fmt.Errorf("encoding must be json or proto")
			}
			if enc == connectrpc.CodecProto && !in.DescriptorOptions.any() {
				return nil, fmt.Errorf("encoding=proto needs proto_files or descriptor_sets")
			}
			hc, err := d.NewHTTPClient(in.HTTPOptions, in.Auth)
			if err != nil {
				return nil, err
			}
			defer hc.Close()
			maxMsgs, maxDur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
			ctx, cancel := context.WithTimeout(ctx, hc.Timeout+maxDur)
			defer cancel()

			var (
				md       protoreflect.MethodDescriptor
				codec    *grpcx.Codec
				srcKind  string
				path     string
				body     []byte
				resolver grpcx.TypeResolver
			)
			if in.DescriptorOptions.any() {
				src, m, err := loadWebMethod(ctx, d, &in.WebOptions)
				if err != nil {
					return nil, err
				}
				md, srcKind, path = m, src.Kind(), grpcx.FullMethod(m)
				codec = newCodec(d, src, in.JSONOptions)
				resolver = codec.Resolver
				msg, err := codec.NewMessage(md.Input(), in.Request)
				if err != nil {
					return nil, err
				}
				if enc == connectrpc.CodecProto {
					body, err = proto.Marshal(msg)
				} else {
					body, err = codec.ToJSON(msg)
				}
				if err != nil {
					return nil, err
				}
			} else {
				svc, m, err := grpcx.ParseMethodName(in.Method)
				if err != nil {
					return nil, err
				}
				path = "/" + svc + "/" + m
				resolver = grpcx.NewResolver(nil)
				switch v := in.Request.(type) {
				case nil:
					body = []byte("{}")
				case string:
					body = []byte(v)
				default:
					if body, err = json.Marshal(v); err != nil {
						return nil, err
					}
				}
			}
			streaming := md != nil && md.IsStreamingServer()
			if in.ServerStreaming != nil {
				streaming = *in.ServerStreaming
			}
			kind := "unary"
			if streaming {
				kind = "server_streaming"
			}
			decode := func(b []byte) (json.RawMessage, error) {
				switch {
				case md != nil && enc == connectrpc.CodecProto:
					return codec.Unmarshal(md.Output(), b)
				case md != nil:
					return codec.NormalizeJSON(md.Output(), b)
				default:
					var buf bytes.Buffer
					if err := json.Compact(&buf, b); err != nil {
						return nil, fmt.Errorf("response is not JSON: %w", err)
					}
					return buf.Bytes(), nil
				}
			}
			creq := connectrpc.Request{
				URL: joinURL(in.URL, path), Codec: enc, Message: body, Header: webHeaders(in.Metadata),
				Timeout: hc.Timeout, Streaming: streaming, MaxMessageSize: int(hc.MaxResponseBytes), UserAgent: d.Cfg.UserAgent,
			}
			out := webOut{URL: creq.URL, Method: path, Protocol: "connect+" + enc, Kind: kind, DescriptorSource: srcKind}
			if hc.Insecure {
				out.Warnings = append(out.Warnings, "insecure_skip_verify is set: the server certificate was not verified")
			}
			start := time.Now()
			var res *connectrpc.Result
			var overrideStatus *grpcx.StatusInfo
			if !streaming {
				uctx, ucancel := context.WithTimeout(ctx, hc.Timeout)
				defer ucancel()
				var respData []byte
				res, err = connectrpc.Call(uctx, hc.Client, creq, func(b []byte) bool { respData = b; return true })
				if err != nil {
					return nil, transportErr(err)
				}
				if res.Error == nil && respData != nil {
					js, err := decode(respData)
					if err != nil {
						return nil, err
					}
					out.Response = js
				}
			} else {
				col := types.NewCollector(maxMsgs, maxDur, idle, d.Cfg.ResponseBytes(0))
				var mu sync.Mutex
				callErr, limited := collectRun(ctx, col, func(cctx context.Context, add func(types.StreamMessage) bool) error {
					r, err := connectrpc.Call(cctx, hc.Client, creq, func(b []byte) bool {
						js, jerr := decode(b)
						if jerr != nil {
							return add(types.StreamMessage{Dir: "in", Type: "error", Data: jerr.Error(), Encoding: "text"})
						}
						return add(types.StreamMessage{Dir: "in", Type: "json", Data: string(js), Encoding: "text"})
					})
					mu.Lock()
					res = r
					mu.Unlock()
					return err
				})
				st, override, terr := streamStatus(callErr, limited, res != nil, res != nil && res.Stopped)
				if terr != nil {
					return nil, terr
				}
				out.StreamResult = col.Result()
				if override {
					overrideStatus = &st
				}
			}
			out.TimingMS.Total = types.MS(time.Since(start))
			if overrideStatus != nil {
				out.Status = *overrideStatus
				out.ConnectCode = connectrpc.CodeName(overrideStatus.Code)
			}
			if res != nil {
				out.HTTPStatus = res.HTTPStatus
				out.Headers = grpcx.HeaderToMap(res.Header)
				out.Trailers = grpcx.HeaderToMap(res.Trailer)
				out.TLS = tlsx.Info(res.TLS, hc.Insecure)
				switch {
				case overrideStatus != nil:
				case res.Error != nil:
					code := connectrpc.CodeNumber(res.Error.Code)
					out.ConnectCode = res.Error.Code
					out.Status = grpcx.StatusInfo{Code: code, Name: grpcx.CodeName(code), Message: res.Error.Message}
					for _, det := range res.Error.Details {
						out.Status.Details = append(out.Status.Details, connectDetail(det, resolver))
					}
				default:
					out.Status = grpcx.StatusInfo{Code: 0, Name: "OK"}
					out.ConnectCode = "ok"
				}
			}
			return out, nil
		})
}

func connectDetail(det connectrpc.ErrorDetail, res grpcx.TypeResolver) any {
	if b, err := types.DecodeBase64(det.Value); err == nil {
		if v, ok := grpcx.DecodeTyped(det.Type, b, res); ok {
			return v
		}
	}
	m := map[string]any{"type": det.Type, "value": det.Value}
	if len(det.Debug) > 0 {
		var dbg any
		if json.Unmarshal(det.Debug, &dbg) == nil {
			m["debug"] = dbg
		}
	}
	return m
}
