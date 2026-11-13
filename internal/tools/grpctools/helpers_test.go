package grpctools_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bufbuild/protocompile"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	reflv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	reflv1alpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	_ "github.com/HamedFathi/NetKitMCP/internal/tools/grpctools" // registers the tools
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
)

// ---- test protos ----

const commonProto = `syntax = "proto3";

package netkit.test.v1;

// Kind selects a behaviour.
enum Kind {
  KIND_UNSPECIFIED = 0;
  KIND_FAST = 1;
}

// Item carries a named blob.
message Item {
  string name = 1;
  bytes blob = 2;
}
`

const echoProto = `syntax = "proto3";

package netkit.test.v1;

import "common.proto";
import "google/protobuf/timestamp.proto";

// EchoRequest is echoed back by every method.
message EchoRequest {
  string text = 1;
  bytes data = 2;
  // count is the number of responses a server stream sends (-1 = endless).
  int32 count = 3;
  int32 delay_ms = 4;
  // fail_code makes the server return this gRPC status code.
  int32 fail_code = 5;
  Kind kind = 6;
  google.protobuf.Timestamp at = 7;
  map<string, string> labels = 8;
  repeated Item items = 9;
}

message EchoResponse {
  string text = 1;
  bytes data = 2;
  int32 index = 3;
  map<string, string> metadata = 4;
  int32 received = 5;
  repeated Item items = 6;
  google.protobuf.Timestamp at = 7;
}

// Echo is the test service.
service Echo {
  // Unary echoes one request.
  rpc Unary(EchoRequest) returns (EchoResponse);
  rpc ServerStream(EchoRequest) returns (stream EchoResponse);
  rpc ClientStream(stream EchoRequest) returns (EchoResponse);
  rpc Bidi(stream EchoRequest) returns (stream EchoResponse);
}
`

const (
	svcName = "netkit.test.v1.Echo"
	reqName = "netkit.test.v1.EchoRequest"
)

var testFiles = map[string]string{"common.proto": commonProto, "echo.proto": echoProto}

// compileTestProtos compiles the test protos into a registry (server side).
func compileTestProtos(t testing.TB) *protoregistry.Files {
	t.Helper()
	comp := protocompile.Compiler{
		Resolver:       protocompile.WithStandardImports(&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(testFiles)}),
		SourceInfoMode: protocompile.SourceInfoStandard,
	}
	res, err := comp.Compile(context.Background(), "echo.proto")
	if err != nil {
		t.Fatal(err)
	}
	reg := new(protoregistry.Files)
	var add func(fd protoreflect.FileDescriptor)
	add = func(fd protoreflect.FileDescriptor) {
		if _, err := reg.FindFileByPath(fd.Path()); err == nil {
			return
		}
		for i := 0; i < fd.Imports().Len(); i++ {
			add(fd.Imports().Get(i).FileDescriptor)
		}
		if err := reg.RegisterFile(fd); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range res {
		add(f)
	}
	return reg
}

// writeProtos writes the test protos to the harness read dir and returns
// the path of echo.proto.
func writeProtos(h *tooltest.Harness) string {
	h.WriteInput("common.proto", []byte(commonProto))
	return h.WriteInput("echo.proto", []byte(echoProto))
}

// writeDescriptorSet writes a FileDescriptorSet (with imports) and returns its path.
func writeDescriptorSet(t *testing.T, h *tooltest.Harness, reg *protoregistry.Files) string {
	t.Helper()
	set := &descriptorpb.FileDescriptorSet{}
	reg.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
		return true
	})
	b, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	return h.WriteInput("echo.pb", b)
}

// ---- echo server (dynamic messages) ----

type echoItem struct {
	Name string `json:"name,omitempty"`
	Blob []byte `json:"blob,omitempty"`
}

type echoReq struct {
	Text     string            `json:"text"`
	Data     []byte            `json:"data"`
	Count    int               `json:"count"`
	DelayMs  int               `json:"delayMs"`
	FailCode int               `json:"failCode"`
	Kind     string            `json:"kind"`
	At       string            `json:"at"`
	Labels   map[string]string `json:"labels"`
	Items    []echoItem        `json:"items"`
}

type echoResp struct {
	Text     string            `json:"text,omitempty"`
	Data     []byte            `json:"data,omitempty"`
	Index    int               `json:"index,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Received int               `json:"received,omitempty"`
	Items    []echoItem        `json:"items,omitempty"`
	At       string            `json:"at,omitempty"`
}

type echoEnv struct {
	reg     *protoregistry.Files
	reqMD   protoreflect.MessageDescriptor
	respMD  protoreflect.MessageDescriptor
	active  atomic.Int32 // running stream handlers
	streams atomic.Int32 // stream handlers started
}

func newEchoEnv(t testing.TB) *echoEnv {
	reg := compileTestProtos(t)
	find := func(n string) protoreflect.MessageDescriptor {
		d, err := reg.FindDescriptorByName(protoreflect.FullName(n))
		if err != nil {
			t.Fatal(err)
		}
		return d.(protoreflect.MessageDescriptor)
	}
	return &echoEnv{reg: reg, reqMD: find(reqName), respMD: find("netkit.test.v1.EchoResponse")}
}

func (e *echoEnv) newReq() *dynamicpb.Message { return dynamicpb.NewMessage(e.reqMD) }

func (e *echoEnv) decode(m proto.Message) echoReq {
	b, err := protojson.Marshal(m)
	if err != nil {
		panic(err)
	}
	var r echoReq
	if err := json.Unmarshal(b, &r); err != nil {
		panic(err)
	}
	return r
}

func (e *echoEnv) decodeBinary(b []byte) (echoReq, error) {
	m := e.newReq()
	if err := proto.Unmarshal(b, m); err != nil {
		return echoReq{}, err
	}
	return e.decode(m), nil
}

func (e *echoEnv) encode(r echoResp) *dynamicpb.Message {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	m := dynamicpb.NewMessage(e.respMD)
	if err := protojson.Unmarshal(b, m); err != nil {
		panic(fmt.Sprintf("encode response %s: %v", b, err))
	}
	return m
}

func (e *echoEnv) encodeBinary(r echoResp) []byte {
	b, err := proto.Marshal(e.encode(r))
	if err != nil {
		panic(err)
	}
	return b
}

func failStatus(code int) *status.Status {
	st := status.New(codes.Code(code), "requested failure: 100% on purpose")
	st, _ = st.WithDetails(&errdetails.ErrorInfo{Reason: "TEST_FAILURE", Domain: "netkit.test"})
	return st
}

func incomingMap(ctx context.Context) map[string]string {
	md, _ := metadata.FromIncomingContext(ctx)
	out := map[string]string{}
	for k, vs := range md {
		v := strings.Join(vs, ",")
		if strings.HasSuffix(k, "-bin") {
			v = base64.StdEncoding.EncodeToString([]byte(v))
		}
		out[k] = v
	}
	return out
}

func sleepCtx(ctx context.Context, ms int) error {
	if ms <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return status.FromContextError(ctx.Err()).Err()
	case <-time.After(time.Duration(ms) * time.Millisecond):
		return nil
	}
}

func (e *echoEnv) serviceDesc() *grpc.ServiceDesc {
	return &grpc.ServiceDesc{
		ServiceName: svcName,
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Unary",
			Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				m := e.newReq()
				if err := dec(m); err != nil {
					return nil, err
				}
				r := e.decode(m)
				grpc.SetHeader(ctx, metadata.Pairs("x-echo-header", "h1"))
				grpc.SetTrailer(ctx, metadata.Pairs("x-echo-trailer", "t1", "x-trace-bin", string([]byte{0, 1, 2, 255})))
				if err := sleepCtx(ctx, r.DelayMs); err != nil {
					return nil, err
				}
				if r.FailCode != 0 {
					return nil, failStatus(r.FailCode).Err()
				}
				return e.encode(echoResp{Text: r.Text, Data: r.Data, Metadata: incomingMap(ctx), Received: 1, Items: r.Items, At: r.At}), nil
			},
		}},
		Streams: []grpc.StreamDesc{
			{StreamName: "ServerStream", ServerStreams: true, Handler: func(_ any, ss grpc.ServerStream) error {
				e.streams.Add(1)
				e.active.Add(1)
				defer e.active.Add(-1)
				m := e.newReq()
				if err := ss.RecvMsg(m); err != nil {
					return err
				}
				r := e.decode(m)
				ss.SetHeader(metadata.Pairs("x-echo-header", "h1"))
				ss.SetTrailer(metadata.Pairs("x-echo-trailer", "t1"))
				for i := 0; r.Count < 0 || i < r.Count; i++ {
					if err := ss.SendMsg(e.encode(echoResp{Text: fmt.Sprintf("%s-%d", r.Text, i), Index: i})); err != nil {
						return err
					}
					if err := sleepCtx(ss.Context(), r.DelayMs); err != nil {
						return err
					}
				}
				if r.FailCode != 0 {
					return failStatus(r.FailCode).Err()
				}
				return nil
			}},
			{StreamName: "ClientStream", ClientStreams: true, Handler: func(_ any, ss grpc.ServerStream) error {
				e.streams.Add(1)
				e.active.Add(1)
				defer e.active.Add(-1)
				var texts []string
				for {
					m := e.newReq()
					err := ss.RecvMsg(m)
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						return err
					}
					texts = append(texts, e.decode(m).Text)
				}
				ss.SetTrailer(metadata.Pairs("x-echo-trailer", "t1"))
				return ss.SendMsg(e.encode(echoResp{Text: strings.Join(texts, ","), Received: len(texts)}))
			}},
			{StreamName: "Bidi", ClientStreams: true, ServerStreams: true, Handler: func(_ any, ss grpc.ServerStream) error {
				e.streams.Add(1)
				e.active.Add(1)
				defer e.active.Add(-1)
				ss.SetHeader(metadata.Pairs("x-echo-header", "h1"))
				n := 0
				for {
					m := e.newReq()
					err := ss.RecvMsg(m)
					if errors.Is(err, io.EOF) {
						ss.SetTrailer(metadata.Pairs("x-echo-trailer", "t1"))
						return nil
					}
					if err != nil {
						return err
					}
					r := e.decode(m)
					if r.FailCode != 0 {
						return failStatus(r.FailCode).Err()
					}
					// delay_ms stalls the reader (exercises client flow control).
					if err := sleepCtx(ss.Context(), r.DelayMs); err != nil {
						return err
					}
					n++
					if err := ss.SendMsg(e.encode(echoResp{Text: "echo:" + r.Text, Index: n, Data: r.Data})); err != nil {
						return err
					}
				}
			}},
		},
		Metadata: "echo.proto",
	}
}

// waitIdle waits until no stream handler is running (the client cancelled).
func (e *echoEnv) waitIdle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d server stream handler(s) still running: the client did not cancel", e.active.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type serverOpts struct {
	cert       *tls.Certificate
	reflection string // "v1" (default), "v1alpha", "none"
}

type testServer struct {
	addr   string
	env    *echoEnv
	health *health.Server
}

// startServer runs the echo + health (+ reflection) server on loopback.
func startServer(t *testing.T, o serverOpts) *testServer {
	t.Helper()
	env := newEchoEnv(t)
	var sopts []grpc.ServerOption
	if o.cert != nil {
		sopts = append(sopts, grpc.Creds(credentials.NewServerTLSFromCert(o.cert)))
	}
	s := grpc.NewServer(sopts...)
	s.RegisterService(env.serviceDesc(), nil)
	hs := health.NewServer()
	hs.SetServingStatus(svcName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, hs)
	ropts := reflection.ServerOptions{Services: s, DescriptorResolver: chainResolver{env.reg, protoregistry.GlobalFiles}}
	switch o.reflection {
	case "", "v1":
		reflv1.RegisterServerReflectionServer(s, reflection.NewServerV1(ropts))
	case "v1alpha":
		reflv1alpha.RegisterServerReflectionServer(s, reflection.NewServer(ropts))
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(lis)
	t.Cleanup(func() {
		done := make(chan struct{})
		go func() { s.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			s.Stop()
			t.Errorf("server did not stop gracefully: a stream was left open")
		}
	})
	return &testServer{addr: lis.Addr().String(), env: env, health: hs}
}

// args merges maps into a new argument map.
func args(ms ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// selfSigned returns a certificate for 127.0.0.1/localhost and its PEM.
func selfSigned(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "netkit-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert, string(certPEM)
}

// mustJSON decodes a JSON string (a stream message's data).
func mustJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %q: %v", s, err)
	}
	return m
}

// chainResolver looks descriptors up in the test registry, then in the
// global one (health, reflection).
type chainResolver []*protoregistry.Files

func (c chainResolver) FindFileByPath(p string) (protoreflect.FileDescriptor, error) {
	for _, r := range c {
		if fd, err := r.FindFileByPath(p); err == nil {
			return fd, nil
		}
	}
	return nil, protoregistry.NotFound
}

func (c chainResolver) FindDescriptorByName(n protoreflect.FullName) (protoreflect.Descriptor, error) {
	for _, r := range c {
		if d, err := r.FindDescriptorByName(n); err == nil {
			return d, nil
		}
	}
	return nil, protoregistry.NotFound
}
