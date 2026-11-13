package grpctools

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/HamedFathi/NetKitMCP/internal/grpcx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/session"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

const sessionKind = "grpc_stream"

// ---- grpc_stream_request ----

type streamIn struct {
	Target   string `json:"target" jsonschema:"gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS)"`
	Method   string `json:"method" jsonschema:"package.Service/Method of a streaming (or unary) method"`
	Messages []any  `json:"messages,omitempty" jsonschema:"request messages (protojson objects) sent in order before half-closing; server-streaming/unary methods take exactly one (default {})"`
	types.StreamLimits
	ConnOptions
	DescriptorOptions
	JSONOptions
}

type streamOut struct {
	*types.StreamResult
	Target   string            `json:"target"`
	Method   string            `json:"method"`
	Kind     string            `json:"kind"`
	Sent     int               `json:"sent"`
	Status   *grpcx.StatusInfo `json:"status,omitempty"`
	Headers  map[string]string `json:"headers"`
	Trailers map[string]string `json:"trailers"`
	TimingMS struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	TLS              *types.TLSInfo `json:"tls,omitempty"`
	DescriptorSource string         `json:"descriptor_source"`
	Note             string         `json:"note,omitempty"`
	Warnings         []string       `json:"warnings,omitempty"`
}

// resolveMethod dials, loads descriptors and resolves the method.
func resolveMethod(ctx context.Context, d *tools.Deps, target, method string, co ConnOptions, do DescriptorOptions) (*gconn, grpcx.Source, protoreflect.MethodDescriptor, error) {
	c, err := dial(d, target, co)
	if err != nil {
		return nil, nil, nil, err
	}
	src, err := source(ctx, d, do, c)
	if err != nil {
		c.Close()
		return nil, nil, nil, err
	}
	md, err := grpcx.FindMethod(ctx, src, method)
	src.Close()
	if err != nil {
		c.Close()
		if g := guardErr(err); g != nil {
			return nil, nil, nil, g
		}
		return nil, nil, nil, err
	}
	return c, src, md, nil
}

func requestsFor(codec *grpcx.Codec, md protoreflect.MethodDescriptor, vals []any) ([]proto.Message, error) {
	if !md.IsStreamingClient() {
		if len(vals) > 1 {
			return nil, fmt.Errorf("%s is %s: send exactly one message (got %d)", md.FullName(), grpcx.MethodKind(md), len(vals))
		}
		if len(vals) == 0 {
			vals = []any{nil}
		}
	}
	return buildMessages(codec, md.Input(), vals)
}

func registerStream(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "grpc_stream_request", "gRPC streaming call (one-shot)",
		"Bounded one-shot call for server-, client- and bidi-streaming methods: sends messages[] in order, half-closes, and collects responses until the server ends the stream "+
			"or max_messages / max_duration_seconds / idle_timeout_seconds is reached. Returns sent and received messages, final status (decoded details), headers and trailers. "+
			"Use grpc_stream_open for interactive streams.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in streamIn) (any, error) {
			maxMsgs, maxDur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
			setupTimeout := d.Cfg.Timeout(in.TimeoutSeconds)
			ctx, cancel := context.WithTimeout(ctx, setupTimeout+maxDur)
			defer cancel()
			c, src, md, err := resolveMethod(ctx, d, in.Target, in.Method, in.ConnOptions, in.DescriptorOptions)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			codec := newCodec(d, src, in.JSONOptions)
			reqs, err := requestsFor(codec, md, in.Messages)
			if err != nil {
				return nil, err
			}
			octx, err := c.outgoing(ctx, grpcx.FullMethod(md))
			if err != nil {
				return nil, err
			}
			col := types.NewCollector(maxMsgs, maxDur, idle, d.Cfg.ResponseBytes(0))
			o := grpcx.RunStream(octx, c.cc, md, reqs, codec, col)
			if g := guardErr(o.Err); g != nil {
				return nil, g
			}
			res := col.Result()
			out := streamOut{
				StreamResult: res,
				Target:       c.target, Method: grpcx.FullMethod(md), Kind: grpcx.MethodKind(md),
				Sent:             o.Sent,
				Headers:          grpcx.MDToMap(o.Header),
				Trailers:         grpcx.MDToMap(o.Trailer),
				TLS:              tlsInfo(o.TLS, c.insecure),
				DescriptorSource: src.Kind(),
				Warnings:         c.warnings(),
			}
			out.TimingMS.Total = types.MS(o.Duration)
			if o.Finished {
				st := grpcx.StatusFromError(o.Err, codec.Resolver)
				out.Status = &st
			} else {
				out.Note = "the stream was cancelled by the client after reaching " + res.EndedBy + "; no final status"
			}
			if o.SendErr != nil {
				out.Warnings = append(out.Warnings, "send failed: "+o.SendErr.Error())
			}
			return out, nil
		})
}

// ---- interactive sessions ----

type openIn struct {
	Target    string `json:"target" jsonschema:"gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS)"`
	Method    string `json:"method" jsonschema:"package.Service/Method of a streaming method"`
	Messages  []any  `json:"messages,omitempty" jsonschema:"optional request messages to send right away"`
	CloseSend bool   `json:"close_send,omitempty" jsonschema:"half-close the send side after sending messages"`
	ConnOptions
	DescriptorOptions
	JSONOptions
}

type openOut struct {
	SessionID        string           `json:"session_id"`
	Method           grpcx.MethodInfo `json:"method"`
	Sent             int              `json:"sent"`
	SendClosed       bool             `json:"send_closed"`
	DescriptorSource string           `json:"descriptor_source"`
	Warnings         []string         `json:"warnings,omitempty"`
}

type sendIn struct {
	SessionID      string  `json:"session_id" jsonschema:"handle from grpc_stream_open"`
	Messages       []any   `json:"messages,omitempty" jsonschema:"request messages (protojson objects) to send in order"`
	CloseSend      bool    `json:"close_send,omitempty" jsonschema:"half-close the send side after sending (signals end of client stream)"`
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty" jsonschema:"give up (and cancel the stream) if the server does not accept the messages within this many seconds (default 30)"`
}

type sendOut struct {
	SessionID  string `json:"session_id"`
	Sent       int    `json:"sent"`
	TotalSent  int    `json:"total_sent"`
	SendClosed bool   `json:"send_closed"`
	Ended      bool   `json:"stream_ended"`
}

type recvIn struct {
	SessionID   string  `json:"session_id" jsonschema:"handle from grpc_stream_open"`
	MaxMessages int     `json:"max_messages,omitempty" jsonschema:"return at most this many messages (default 100)"`
	WaitSeconds float64 `json:"wait_seconds,omitempty" jsonschema:"wait up to this long for the first message (default 5)"`
}

type recvOut struct {
	*types.StreamResult
	SessionID string            `json:"session_id"`
	Ended     bool              `json:"stream_ended"`
	Status    *grpcx.StatusInfo `json:"status,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Trailers  map[string]string `json:"trailers,omitempty"`
}

type closeIn struct {
	SessionID   string  `json:"session_id" jsonschema:"handle from grpc_stream_open"`
	WaitSeconds float64 `json:"wait_seconds,omitempty" jsonschema:"after half-closing, wait up to this long for the server to finish before cancelling (default 2)"`
}

type closeOut struct {
	SessionID string                `json:"session_id"`
	Status    grpcx.StatusInfo      `json:"status"`
	Cancelled bool                  `json:"cancelled_by_client"`
	Remaining []types.StreamMessage `json:"remaining_messages"`
	Dropped   int                   `json:"dropped,omitempty"`
	Headers   map[string]string     `json:"headers"`
	Trailers  map[string]string     `json:"trailers"`
	TotalSent int                   `json:"total_sent"`
}

// streamHandle wraps a session with its codec.
type streamHandle struct {
	*grpcx.StreamSession
	codec *grpcx.Codec
}

func waitDur(sec, def float64) time.Duration {
	if sec <= 0 {
		sec = def
	}
	if sec > 300 {
		sec = 300
	}
	return time.Duration(sec * float64(time.Second))
}

func registerSession(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "grpc_stream_open", "Open gRPC stream session",
		"Open an interactive gRPC stream (any streaming method) and return a session_id. Responses are buffered in the background; use grpc_stream_send, grpc_stream_recv and grpc_stream_close. "+
			"Sessions expire after the server's idle TTL.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in openIn) (any, error) {
			setup, cancel := context.WithTimeout(ctx, d.Cfg.Timeout(in.TimeoutSeconds))
			defer cancel()
			c, src, md, err := resolveMethod(setup, d, in.Target, in.Method, in.ConnOptions, in.DescriptorOptions)
			if err != nil {
				return nil, err
			}
			codec := newCodec(d, src, in.JSONOptions)
			var reqs []proto.Message
			if len(in.Messages) > 0 {
				if reqs, err = buildMessages(codec, md.Input(), in.Messages); err != nil {
					c.Close()
					return nil, err
				}
			}
			if !md.IsStreamingClient() && len(reqs) > 1 {
				c.Close()
				return nil, fmt.Errorf("%s is %s: send exactly one message", md.FullName(), grpcx.MethodKind(md))
			}
			octx, err := c.outgoing(ctx, grpcx.FullMethod(md))
			if err != nil {
				c.Close()
				return nil, err
			}
			buf := session.NewBuffer(d.Cfg.RingBufferSize)
			ss, err := grpcx.OpenStreamSession(octx, c.cc, md, codec, buf, c.target, nil)
			if err != nil {
				c.Close()
				if g := guardErr(err); g != nil {
					return nil, g
				}
				return nil, err
			}
			h := &streamHandle{StreamSession: ss, codec: codec}
			id, err := d.Sessions.Add(sessionKind, redact.URL("grpc://"+c.target)+grpcx.FullMethod(md), h)
			if err != nil {
				h.Close()
				return nil, err
			}
			out := openOut{SessionID: id, Method: grpcx.DescribeMethod(md), DescriptorSource: src.Kind(), Warnings: c.warnings()}
			if len(reqs) > 0 || in.CloseSend {
				n, err := ss.Send(setup, reqs, in.CloseSend)
				out.Sent = n
				if err != nil {
					out.Warnings = append(out.Warnings, "send failed: "+err.Error())
				}
			}
			out.SendClosed = ss.SendClosed()
			return out, nil
		})

	tools.Add(s, d, "grpc_stream_send", "Send on gRPC stream",
		"Send request messages on an open gRPC stream session; set close_send=true to half-close (end the client stream). "+
			"If the server stops reading, the send gives up after timeout_seconds and cancels the stream.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in sendIn) (any, error) {
			h, err := session.Get[*streamHandle](d.Sessions, in.SessionID, sessionKind)
			if err != nil {
				return nil, err
			}
			if len(in.Messages) == 0 && !in.CloseSend {
				return nil, fmt.Errorf("nothing to do: pass messages and/or close_send=true")
			}
			reqs, err := buildMessages(h.codec, h.Method.Input(), in.Messages)
			if err != nil {
				return nil, err
			}
			sctx, scancel := context.WithTimeout(ctx, d.Cfg.Timeout(in.TimeoutSeconds))
			defer scancel()
			n, err := h.Send(sctx, reqs, in.CloseSend)
			if err != nil {
				return nil, err
			}
			return sendOut{SessionID: in.SessionID, Sent: n, TotalSent: h.Sent(), SendClosed: h.SendClosed(), Ended: h.State().Finished}, nil
		})

	tools.Add(s, d, "grpc_stream_recv", "Receive from gRPC stream",
		"Return buffered response messages from a gRPC stream session, waiting up to wait_seconds for the first one. When the stream has ended, stream_ended is true and the final status and trailers are included.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in recvIn) (any, error) {
			h, err := session.Get[*streamHandle](d.Sessions, in.SessionID, sessionKind)
			if err != nil {
				return nil, err
			}
			max := d.Cfg.Messages(in.MaxMessages)
			res := h.Buf.Take(ctx, max, waitDur(in.WaitSeconds, 5))
			st := h.State()
			out := recvOut{StreamResult: res, SessionID: in.SessionID, Headers: grpcx.MDToMap(st.Header)}
			if st.Finished && h.Buf.Pending() == 0 {
				out.Ended = true
				si := grpcx.StatusFromError(st.Err, h.codec.Resolver)
				out.Status = &si
				out.Trailers = grpcx.MDToMap(st.Trailer)
			}
			return out, nil
		})

	tools.Add(s, d, "grpc_stream_close", "Close gRPC stream session",
		"Half-close and close a gRPC stream session: waits up to wait_seconds for the server to finish, then cancels. Returns the final status, trailers and any messages still buffered.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in closeIn) (any, error) {
			h, err := session.Get[*streamHandle](d.Sessions, in.SessionID, sessionKind)
			if err != nil {
				return nil, err
			}
			d.Sessions.Remove(in.SessionID)
			fin := h.Shutdown(waitDur(in.WaitSeconds, 2))
			rest := h.Buf.Take(ctx, d.Cfg.RingBufferSize+1, 0)
			out := closeOut{
				SessionID: in.SessionID,
				Status:    grpcx.StatusFromError(fin.Err, h.codec.Resolver),
				Cancelled: fin.Canceled || !fin.Finished,
				Remaining: rest.Messages,
				Dropped:   rest.Dropped,
				Headers:   grpcx.MDToMap(fin.Header),
				Trailers:  grpcx.MDToMap(fin.Trailer),
				TotalSent: h.Sent(),
			}
			return out, nil
		})
}
