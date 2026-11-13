package grpcx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	rpbalpha "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Reflection is a server-reflection descriptor source. It speaks
// grpc.reflection.v1 and falls back to v1alpha when the server does not
// implement v1. Descriptors are fetched lazily (file containing symbol,
// file by name for dependencies) and registered in a growing registry.
type Reflection struct {
	cc  grpc.ClientConnInterface
	ctx context.Context

	mu      sync.Mutex
	stream  reflStream
	cancel  context.CancelFunc
	version string // "v1" or "v1alpha"
	files   *protoregistry.Files
	protos  map[string]*descriptorpb.FileDescriptorProto
}

// NewReflection creates a reflection source. ctx carries outgoing metadata
// (auth) and bounds the reflection stream; Close must be called.
func NewReflection(ctx context.Context, cc grpc.ClientConnInterface) *Reflection {
	return &Reflection{cc: cc, ctx: ctx, files: new(protoregistry.Files), protos: map[string]*descriptorpb.FileDescriptorProto{}}
}

// Kind implements Source.
func (r *Reflection) Kind() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.version == "" {
		return "reflection"
	}
	return "reflection_" + r.version
}

// Files implements Source.
func (r *Reflection) Files() *protoregistry.Files { return r.files }

// Close implements Source.
func (r *Reflection) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closeStreamLocked()
}

func (r *Reflection) closeStreamLocked() {
	if r.stream != nil {
		r.stream.CloseSend()
		r.stream = nil
	}
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
}

// reflStream abstracts over the v1 and v1alpha stubs; requests and
// responses are always the v1 types (the wire format is identical).
type reflStream interface {
	Send(*rpb.ServerReflectionRequest) error
	Recv() (*rpb.ServerReflectionResponse, error)
	CloseSend() error
}

type alphaStream struct {
	s rpbalpha.ServerReflection_ServerReflectionInfoClient
}

func (a alphaStream) Send(req *rpb.ServerReflectionRequest) error {
	b, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	var areq rpbalpha.ServerReflectionRequest
	if err := proto.Unmarshal(b, &areq); err != nil {
		return err
	}
	return a.s.Send(&areq)
}

func (a alphaStream) Recv() (*rpb.ServerReflectionResponse, error) {
	aresp, err := a.s.Recv()
	if err != nil {
		return nil, err
	}
	b, err := proto.Marshal(aresp)
	if err != nil {
		return nil, err
	}
	var resp rpb.ServerReflectionResponse
	if err := proto.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (a alphaStream) CloseSend() error { return a.s.CloseSend() }

func (r *Reflection) openLocked(version string) error {
	r.closeStreamLocked()
	ctx, cancel := context.WithCancel(r.ctx)
	var (
		s   reflStream
		err error
	)
	if version == "v1" {
		s, err = rpb.NewServerReflectionClient(r.cc).ServerReflectionInfo(ctx)
	} else {
		var as rpbalpha.ServerReflection_ServerReflectionInfoClient
		as, err = rpbalpha.NewServerReflectionClient(r.cc).ServerReflectionInfo(ctx)
		if err == nil {
			s = alphaStream{as}
		}
	}
	if err != nil {
		cancel()
		return err
	}
	r.stream, r.cancel, r.version = s, cancel, version
	return nil
}

// roundTrip sends one request and reads its response, opening the stream
// (and falling back to v1alpha) as needed.
func (r *Reflection) roundTrip(req *rpb.ServerReflectionRequest) (*rpb.ServerReflectionResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	first := r.stream == nil && r.version == ""
	if r.stream == nil {
		v := r.version
		if v == "" {
			v = "v1"
		}
		if err := r.openLocked(v); err != nil {
			return nil, reflErr(err)
		}
	}
	resp, err := r.exchangeLocked(req)
	if err != nil && first && r.version == "v1" && status.Code(err) == codes.Unimplemented {
		if oerr := r.openLocked("v1alpha"); oerr != nil {
			return nil, reflErr(oerr)
		}
		resp, err = r.exchangeLocked(req)
	}
	if err != nil {
		r.closeStreamLocked()
		return nil, reflErr(err)
	}
	if er := resp.GetErrorResponse(); er != nil {
		return nil, status.Error(codes.Code(er.GetErrorCode()), er.GetErrorMessage())
	}
	return resp, nil
}

func (r *Reflection) exchangeLocked(req *rpb.ServerReflectionRequest) (*rpb.ServerReflectionResponse, error) {
	if err := r.stream.Send(req); err != nil {
		if errors.Is(err, io.EOF) {
			// The real status is reported by Recv.
			_, rerr := r.stream.Recv()
			if rerr != nil {
				return nil, rerr
			}
		}
		return nil, err
	}
	return r.stream.Recv()
}

func reflErr(err error) error {
	if status.Code(err) == codes.Unimplemented {
		return fmt.Errorf("server reflection is not available on this server (%v); pass proto_files or descriptor_sets instead", status.Convert(err).Message())
	}
	return err
}

// isNotFound reports whether err is a NotFound status (a lookup miss).
func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// ListServices implements Source.
func (r *Reflection) ListServices(context.Context) ([]string, error) {
	resp, err := r.roundTrip(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_ListServices{ListServices: "*"},
	})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range resp.GetListServicesResponse().GetService() {
		out = append(out, s.GetName())
	}
	sort.Strings(out)
	return out, nil
}

// FindSymbol implements Source.
func (r *Reflection) FindSymbol(ctx context.Context, name string) (protoreflect.Descriptor, error) {
	name = strings.TrimPrefix(name, ".")
	if d, err := r.files.FindDescriptorByName(protoreflect.FullName(name)); err == nil {
		return d, nil
	}
	lookup := name
	for {
		err := r.loadSymbol(lookup)
		if err == nil {
			break
		}
		// Servers may not index methods/fields/nested names; retry with the
		// enclosing name.
		i := strings.LastIndexByte(lookup, '.')
		if !isNotFound(err) || i <= 0 {
			if isNotFound(err) {
				return nil, fmt.Errorf("symbol %q not found via server reflection", name)
			}
			return nil, err
		}
		lookup = lookup[:i]
	}
	d, err := r.files.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, fmt.Errorf("symbol %q not found via server reflection", name)
	}
	return d, nil
}

func (r *Reflection) loadSymbol(sym string) error {
	resp, err := r.roundTrip(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: sym},
	})
	if err != nil {
		return err
	}
	names, err := r.storeProtos(resp)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return status.Errorf(codes.NotFound, "no file returned for %s", sym)
	}
	return r.register(names[0], map[string]bool{})
}

// storeProtos parses the file descriptors in resp and returns their names
// in order (the first is the file that was asked for).
func (r *Reflection) storeProtos(resp *rpb.ServerReflectionResponse) ([]string, error) {
	var names []string
	for _, b := range resp.GetFileDescriptorResponse().GetFileDescriptorProto() {
		fdp := new(descriptorpb.FileDescriptorProto)
		if err := proto.Unmarshal(b, fdp); err != nil {
			return nil, fmt.Errorf("bad file descriptor from reflection: %w", err)
		}
		r.mu.Lock()
		if _, ok := r.protos[fdp.GetName()]; !ok {
			r.protos[fdp.GetName()] = fdp
		}
		r.mu.Unlock()
		names = append(names, fdp.GetName())
	}
	return names, nil
}

func (r *Reflection) fileProto(name string) (*descriptorpb.FileDescriptorProto, error) {
	r.mu.Lock()
	fdp, ok := r.protos[name]
	r.mu.Unlock()
	if ok {
		return fdp, nil
	}
	resp, err := r.roundTrip(&rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_FileByFilename{FileByFilename: name},
	})
	if err != nil {
		return nil, err
	}
	if _, err := r.storeProtos(resp); err != nil {
		return nil, err
	}
	r.mu.Lock()
	fdp, ok = r.protos[name]
	r.mu.Unlock()
	if !ok {
		return nil, status.Errorf(codes.NotFound, "server did not return %s", name)
	}
	return fdp, nil
}

// register builds and registers name and its dependencies.
func (r *Reflection) register(name string, visiting map[string]bool) error {
	if _, err := r.files.FindFileByPath(name); err == nil {
		return nil
	}
	if visiting[name] {
		return fmt.Errorf("import cycle involving %q", name)
	}
	visiting[name] = true
	fdp, err := r.fileProto(name)
	if err != nil {
		// Fall back to compiled-in well-known types.
		if gd, gerr := protoregistry.GlobalFiles.FindFileByPath(name); gerr == nil {
			return registerFileDesc(r.files, gd)
		}
		return fmt.Errorf("resolve dependency %q via reflection: %w", name, err)
	}
	for _, dep := range fdp.GetDependency() {
		if err := r.register(dep, visiting); err != nil {
			return err
		}
	}
	fd, err := protodesc.NewFile(fdp, r.files)
	if err != nil {
		fd, err = protodesc.FileOptions{AllowUnresolvable: true}.New(fdp, r.files)
		if err != nil {
			return fmt.Errorf("build descriptor %q: %w", name, err)
		}
	}
	if err := r.files.RegisterFile(fd); err != nil {
		if _, err2 := r.files.FindFileByPath(name); err2 == nil {
			return nil
		}
		return fmt.Errorf("register %q: %w", name, err)
	}
	return nil
}
