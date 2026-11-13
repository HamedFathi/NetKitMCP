package grpctools

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/grpcx"
	"github.com/HamedFathi/NetKitMCP/internal/netguard"
	"github.com/HamedFathi/NetKitMCP/internal/tlsx"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// ConnOptions are the connection options shared by the native gRPC tools.
type ConnOptions struct {
	Plaintext bool              `json:"plaintext,omitempty" jsonschema:"use plaintext HTTP/2 (h2c) instead of TLS (default TLS)"`
	Authority string            `json:"authority,omitempty" jsonschema:"override the :authority header"`
	Metadata  map[string]string `json:"metadata,omitempty" jsonschema:"request metadata; keys ending in -bin take base64 values"`
	types.NetOptions
	Auth *auth.Config `json:"auth,omitempty"`
}

// DescriptorOptions select where descriptors come from. Without them the
// server's reflection service is used.
type DescriptorOptions struct {
	ProtoFiles     []string `json:"proto_files,omitempty" jsonschema:".proto files or directories compiled in-process instead of server reflection (paths inside allowed read dirs)"`
	ImportPaths    []string `json:"import_paths,omitempty" jsonschema:"import paths for proto_files (default: each file's directory); well-known google/protobuf imports are built in"`
	DescriptorSets []string `json:"descriptor_sets,omitempty" jsonschema:"binary FileDescriptorSet files (protoc -o / buf build -o) instead of server reflection"`
}

func (o DescriptorOptions) any() bool { return len(o.ProtoFiles) > 0 || len(o.DescriptorSets) > 0 }

// JSONOptions shape response JSON.
type JSONOptions struct {
	EmitDefaults  bool `json:"emit_defaults,omitempty" jsonschema:"include fields that have default values in response JSON"`
	UseProtoNames bool `json:"use_proto_names,omitempty" jsonschema:"use proto field names (snake_case) instead of lowerCamelCase in response JSON"`
}

// maxFileRef bounds {"$file": ...} bytes field contents (held in memory).
const maxFileRef = 64 << 20

func fileLoader(d *tools.Deps) grpcx.FileLoader {
	limit := d.Cfg.UploadBytes(0)
	if limit > maxFileRef {
		limit = maxFileRef
	}
	return func(p string) ([]byte, error) { return d.Files.ReadSmall(p, limit) }
}

func newCodec(d *tools.Deps, src grpcx.Source, jo JSONOptions) *grpcx.Codec {
	c := grpcx.NewCodec(src.Files(), fileLoader(d))
	c.EmitDefaults, c.UseProtoNames = jo.EmitDefaults, jo.UseProtoNames
	return c
}

// gconn is an open (lazily connecting) client plus call settings.
type gconn struct {
	cc       *grpc.ClientConn
	target   string
	timeout  time.Duration
	insecure bool
	plain    bool
	co       ConnOptions
	d        *tools.Deps
}

func (c *gconn) Close() {
	if c.cc != nil {
		c.cc.Close()
	}
}

func (c *gconn) warnings() []string {
	if c.insecure {
		return []string{"insecure_skip_verify is set: the server certificate was not verified"}
	}
	return nil
}

// dial validates the target against the guard and creates a client.
func dial(d *tools.Deps, target string, co ConnOptions) (*gconn, error) {
	hostport, plaintext, err := grpcx.ParseTarget(target, co.Plaintext)
	if err != nil {
		return nil, err
	}
	timeout := d.Cfg.Timeout(co.TimeoutSeconds)
	dialer := d.Guard.Dialer(co.AllowPrivate, timeout)
	if err := dialer.CheckAddress(hostport); err != nil {
		return nil, err
	}
	var tlsCfg *tls.Config
	opts := co.TLSOptions
	if co.Auth != nil {
		auth.ApplyTLS(co.Auth, &opts)
	}
	if !plaintext {
		host, _, _ := net.SplitHostPort(hostport)
		tlsCfg, err = tlsx.Config(d.Files, opts, host, nil)
		if err != nil {
			return nil, err
		}
	} else if opts.ClientCert != "" || opts.CACert != "" {
		return nil, fmt.Errorf("TLS options were given but plaintext=true; remove plaintext to use TLS")
	}
	cc, err := grpcx.Dial(grpcx.DialConfig{
		Target:         hostport,
		Dial:           dialer.DialContext,
		TLS:            tlsCfg,
		Authority:      co.Authority,
		MaxMessageSize: int(d.Cfg.MaxResponseBytes),
		UserAgent:      d.Cfg.UserAgent,
	})
	if err != nil {
		return nil, err
	}
	return &gconn{cc: cc, target: hostport, timeout: timeout, insecure: tlsCfg != nil && opts.InsecureSkipVerify, plain: plaintext, co: co, d: d}, nil
}

// outgoing returns ctx with user metadata plus auth credentials computed
// for the given method path.
func (c *gconn) outgoing(ctx context.Context, path string) (context.Context, error) {
	var authHeaders map[string][]string
	if c.co.Auth != nil && c.co.Auth.Kind() != "none" {
		scheme := "https"
		if c.plain {
			scheme = "http"
		}
		h, _, err := c.d.Auth.Headers(ctx, c.co.Auth, c.d.AuthEnv(c.co.AllowPrivate), "POST", scheme+"://"+c.target+path)
		if err != nil {
			return nil, fmt.Errorf("auth: %w", err)
		}
		authHeaders = h
	}
	md, err := grpcx.OutgoingMD(c.co.Metadata, authHeaders)
	if err != nil {
		return nil, err
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

// source returns the descriptor source: compiled files / descriptor sets
// when given, else server reflection over c (which may then not be nil).
func source(ctx context.Context, d *tools.Deps, o DescriptorOptions, c *gconn) (grpcx.Source, error) {
	if o.any() {
		files, err := grpcx.LoadFiles(ctx, d.Files, o.ProtoFiles, o.ImportPaths, o.DescriptorSets)
		if err != nil {
			return nil, err
		}
		kind := "proto_files"
		if len(o.ProtoFiles) == 0 {
			kind = "descriptor_set"
		} else if len(o.DescriptorSets) > 0 {
			kind = "proto_files+descriptor_set"
		}
		return grpcx.NewStaticSource(kind, files), nil
	}
	if c == nil {
		return nil, fmt.Errorf("no descriptor source: set target (server reflection), proto_files or descriptor_sets")
	}
	rctx, err := c.outgoing(ctx, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
	if err != nil {
		return nil, err
	}
	return grpcx.NewReflection(rctx, c.cc), nil
}

// guardErr turns an RPC failure caused by the SSRF guard into a tool error.
func guardErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if st, ok := status.FromError(err); ok {
		msg = st.Message()
	}
	if strings.Contains(msg, netguard.ErrBlocked.Error()) {
		if i := strings.Index(msg, netguard.ErrBlocked.Error()); i >= 0 {
			msg = msg[i:]
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// buildMessages converts JSON values into request messages.
func buildMessages(c *grpcx.Codec, md protoreflect.MessageDescriptor, vals []any) ([]proto.Message, error) {
	out := make([]proto.Message, 0, len(vals))
	for i, v := range vals {
		m, err := c.NewMessage(md, v)
		if err != nil {
			return nil, fmt.Errorf("messages[%d]: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

func tlsInfo(cs *tls.ConnectionState, insecure bool) *types.TLSInfo {
	return tlsx.Info(cs, insecure)
}
