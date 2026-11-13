package grpctools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/HamedFathi/NetKitMCP/internal/grpcx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

func init() { tools.RegisterGroup(tools.GroupGRPC, register) }

func register(s *mcp.Server, d *tools.Deps) {
	registerDescribe(s, d)
	registerUnary(s, d)
	registerStream(s, d)
	registerSession(s, d)
	registerHealth(s, d)
	registerGRPCWeb(s, d)
	registerConnect(s, d)
}

// ---- grpc_describe ----

type describeIn struct {
	Target string `json:"target,omitempty" jsonschema:"gRPC server host:port for server reflection (optional when proto_files or descriptor_sets are given)"`
	Symbol string `json:"symbol,omitempty" jsonschema:"fully-qualified service, method (pkg.Service/Method or pkg.Service.Method), message or enum name; empty lists all services and methods"`
	ConnOptions
	DescriptorOptions
}

type describeOut struct {
	Source          string              `json:"source"`
	Services        []grpcx.ServiceInfo `json:"services,omitempty"`
	Symbol          string              `json:"symbol,omitempty"`
	Kind            string              `json:"kind,omitempty"`
	Text            string              `json:"text,omitempty"`
	Service         *grpcx.ServiceInfo  `json:"service,omitempty"`
	Method          *grpcx.MethodInfo   `json:"method,omitempty"`
	Message         *grpcx.MessageInfo  `json:"message,omitempty"`
	Enum            *grpcx.EnumInfo     `json:"enum,omitempty"`
	Input           *grpcx.MessageInfo  `json:"input,omitempty"`
	Output          *grpcx.MessageInfo  `json:"output,omitempty"`
	RequestTemplate any                 `json:"request_template,omitempty"`
	Warnings        []string            `json:"warnings,omitempty"`
}

func registerDescribe(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "grpc_describe", "Describe gRPC services",
		"List a gRPC server's services and methods, or describe one service, method, message or enum by full name. "+
			"Descriptors come from server reflection (v1, falling back to v1alpha) on target, or from proto_files / descriptor_sets compiled in-process. "+
			"Returns proto-like text plus a structured form (fields, types, streaming flags) and, for methods, a request JSON template.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in describeIn) (any, error) {
			var c *gconn
			timeout := d.Cfg.Timeout(in.TimeoutSeconds)
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			if in.Target != "" && !in.DescriptorOptions.any() {
				var err error
				if c, err = dial(d, in.Target, in.ConnOptions); err != nil {
					return nil, err
				}
				defer c.Close()
			} else if in.Target == "" && !in.DescriptorOptions.any() {
				return nil, fmt.Errorf("set target (server reflection) or proto_files / descriptor_sets")
			}
			src, err := source(ctx, d, in.DescriptorOptions, c)
			if err != nil {
				return nil, err
			}
			defer src.Close()
			out := describeOut{}
			if c != nil {
				out.Warnings = c.warnings()
			}
			if in.Symbol == "" {
				names, err := src.ListServices(ctx)
				if err != nil {
					if g := guardErr(err); g != nil {
						return nil, g
					}
					return nil, fmt.Errorf("list services: %w", err)
				}
				out.Services = []grpcx.ServiceInfo{}
				for _, n := range names {
					dsc, err := src.FindSymbol(ctx, n)
					if err != nil {
						out.Services = append(out.Services, grpcx.ServiceInfo{Name: n, Methods: []grpcx.MethodInfo{}, Error: err.Error()})
						continue
					}
					if sd, ok := dsc.(protoreflect.ServiceDescriptor); ok {
						out.Services = append(out.Services, grpcx.DescribeService(sd))
					}
				}
				out.Source = src.Kind()
				return out, nil
			}
			sym := in.Symbol
			var dsc protoreflect.Descriptor
			if svc, m, perr := grpcx.ParseMethodName(sym); perr == nil && containsSlash(sym) {
				md, err := grpcx.FindMethod(ctx, src, svc+"/"+m)
				if err != nil {
					if g := guardErr(err); g != nil {
						return nil, g
					}
					return nil, err
				}
				dsc = md
			} else {
				dsc, err = src.FindSymbol(ctx, sym)
				if err != nil {
					if g := guardErr(err); g != nil {
						return nil, g
					}
					return nil, err
				}
			}
			out.Source = src.Kind()
			out.Symbol = string(dsc.FullName())
			out.Kind = grpcx.KindOf(dsc)
			out.Text = grpcx.ProtoText(dsc)
			switch v := dsc.(type) {
			case protoreflect.ServiceDescriptor:
				si := grpcx.DescribeService(v)
				out.Service = &si
			case protoreflect.MethodDescriptor:
				mi := grpcx.DescribeMethod(v)
				out.Method = &mi
				in, outm := grpcx.DescribeMessage(v.Input()), grpcx.DescribeMessage(v.Output())
				out.Input, out.Output = &in, &outm
				out.Text += "\n" + grpcx.ProtoText(v.Input()) + "\n" + grpcx.ProtoText(v.Output())
				out.RequestTemplate = grpcx.Template(v.Input())
			case protoreflect.MessageDescriptor:
				mi := grpcx.DescribeMessage(v)
				out.Message = &mi
				out.RequestTemplate = grpcx.Template(v)
			case protoreflect.EnumDescriptor:
				ei := grpcx.DescribeEnum(v)
				out.Enum = &ei
			case protoreflect.FieldDescriptor:
				if p, ok := v.Parent().(protoreflect.MessageDescriptor); ok {
					mi := grpcx.DescribeMessage(p)
					out.Message = &mi
				}
			}
			return out, nil
		})
}

func containsSlash(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}

// ---- grpc_unary_request ----

type unaryIn struct {
	Target  string `json:"target" jsonschema:"gRPC server host:port (grpc:// = plaintext, grpcs:// = TLS)"`
	Method  string `json:"method" jsonschema:"package.Service/Method (or package.Service.Method)"`
	Request any    `json:"request,omitempty" jsonschema:"request message as protojson (object); bytes fields take base64 or {\"$file\": \"path\"}"`
	ConnOptions
	DescriptorOptions
	JSONOptions
}

type unaryOut struct {
	Target   string            `json:"target"`
	Method   string            `json:"method"`
	Status   grpcx.StatusInfo  `json:"status"`
	Response json.RawMessage   `json:"response,omitempty"`
	Headers  map[string]string `json:"headers"`
	Trailers map[string]string `json:"trailers"`
	TimingMS struct {
		Total float64 `json:"total"`
	} `json:"timing_ms"`
	TLS              *types.TLSInfo `json:"tls,omitempty"`
	DescriptorSource string         `json:"descriptor_source"`
	Warnings         []string       `json:"warnings,omitempty"`
}

func registerUnary(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "grpc_unary_request", "gRPC unary call",
		"Call a unary gRPC method with a JSON request and get the JSON response, status (code, message, decoded google.rpc details), headers, trailers and timing. "+
			"TLS by default (plaintext=true for h2c); TLS/mTLS options and auth become credentials and metadata. Descriptors come from server reflection unless proto_files/descriptor_sets are given. "+
			"Non-OK gRPC statuses are results, not tool errors. Use grpc_stream_request for streaming methods.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in unaryIn) (any, error) {
			c, err := dial(d, in.Target, in.ConnOptions)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(ctx, c.timeout)
			defer cancel()
			src, err := source(ctx, d, in.DescriptorOptions, c)
			if err != nil {
				return nil, err
			}
			md, err := grpcx.FindMethod(ctx, src, in.Method)
			src.Close()
			if err != nil {
				if g := guardErr(err); g != nil {
					return nil, g
				}
				return nil, err
			}
			if md.IsStreamingClient() || md.IsStreamingServer() {
				return nil, fmt.Errorf("%s is %s; use grpc_stream_request or grpc_stream_open", md.FullName(), grpcx.MethodKind(md))
			}
			codec := newCodec(d, src, in.JSONOptions)
			msg, err := codec.NewMessage(md.Input(), in.Request)
			if err != nil {
				return nil, err
			}
			octx, err := c.outgoing(ctx, grpcx.FullMethod(md))
			if err != nil {
				return nil, err
			}
			r := grpcx.InvokeUnary(octx, c.cc, md, msg)
			if g := guardErr(r.Err); g != nil {
				return nil, g
			}
			out := unaryOut{
				Target: c.target, Method: grpcx.FullMethod(md),
				Status:           grpcx.StatusFromError(r.Err, codec.Resolver),
				Headers:          grpcx.MDToMap(r.Header),
				Trailers:         grpcx.MDToMap(r.Trailer),
				TLS:              tlsInfo(r.TLS, c.insecure),
				DescriptorSource: src.Kind(),
				Warnings:         c.warnings(),
			}
			out.TimingMS.Total = types.MS(r.Duration)
			if r.Response != nil {
				js, err := codec.ToJSON(r.Response)
				if err != nil {
					return nil, fmt.Errorf("render response: %w", err)
				}
				out.Response = js
			}
			return out, nil
		})
}
