package grpcx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/HamedFathi/NetKitMCP/internal/fileio"
)

// Source provides descriptors.
type Source interface {
	// Kind is "reflection", "proto_files", "descriptor_set" or a combination.
	Kind() string
	// ListServices returns fully-qualified service names.
	ListServices(ctx context.Context) ([]string, error)
	// FindSymbol resolves a fully-qualified name (service, method, message,
	// enum, field, ...).
	FindSymbol(ctx context.Context, name string) (protoreflect.Descriptor, error)
	// Files is the registry of loaded descriptors (grows lazily for reflection).
	Files() *protoregistry.Files
	// Close releases resources (the reflection stream). Files stays usable.
	Close()
}

// StaticSource serves descriptors from a fixed registry.
type StaticSource struct {
	kind  string
	files *protoregistry.Files
}

// NewStaticSource wraps files.
func NewStaticSource(kind string, files *protoregistry.Files) *StaticSource {
	return &StaticSource{kind: kind, files: files}
}

// Kind implements Source.
func (s *StaticSource) Kind() string { return s.kind }

// Files implements Source.
func (s *StaticSource) Files() *protoregistry.Files { return s.files }

// Close implements Source.
func (s *StaticSource) Close() {}

// ListServices implements Source.
func (s *StaticSource) ListServices(context.Context) ([]string, error) {
	seen := map[string]bool{}
	s.files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		for i := 0; i < fd.Services().Len(); i++ {
			seen[string(fd.Services().Get(i).FullName())] = true
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// FindSymbol implements Source.
func (s *StaticSource) FindSymbol(_ context.Context, name string) (protoreflect.Descriptor, error) {
	d, err := s.files.FindDescriptorByName(protoreflect.FullName(strings.TrimPrefix(name, ".")))
	if err != nil {
		return nil, fmt.Errorf("symbol %q not found in the loaded descriptors", name)
	}
	return d, nil
}

// maxProtoSource bounds a single .proto file or descriptor set.
const maxProtoSource = 16 << 20

// LoadFiles builds a registry from .proto files/directories and descriptor
// set files, all read through the file policy. protoPaths entries may be
// files or directories (walked for *.proto). importPaths default to the
// directory of each file (or the directory itself).
func LoadFiles(ctx context.Context, files *fileio.Policy, protoPaths, importPaths, descriptorSets []string) (*protoregistry.Files, error) {
	reg := new(protoregistry.Files)
	if len(protoPaths) > 0 {
		if err := compileProtos(ctx, files, protoPaths, importPaths, reg); err != nil {
			return nil, err
		}
	}
	if len(descriptorSets) > 0 {
		var all []*descriptorpb.FileDescriptorProto
		for _, p := range descriptorSets {
			data, err := files.ReadSmall(p, maxProtoSource)
			if err != nil {
				return nil, fmt.Errorf("descriptor set %q: %w", p, err)
			}
			var set descriptorpb.FileDescriptorSet
			if err := proto.Unmarshal(data, &set); err != nil {
				return nil, fmt.Errorf("descriptor set %q is not a binary FileDescriptorSet: %w", p, err)
			}
			all = append(all, set.GetFile()...)
		}
		if err := RegisterProtos(reg, all); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// RegisterProtos registers file descriptor protos (in any order) into reg,
// skipping files already present. Dependencies missing from the set are
// taken from the global registry (well-known types) when available.
func RegisterProtos(reg *protoregistry.Files, fdps []*descriptorpb.FileDescriptorProto) error {
	byName := map[string]*descriptorpb.FileDescriptorProto{}
	for _, f := range fdps {
		if _, dup := byName[f.GetName()]; !dup {
			byName[f.GetName()] = f
		}
	}
	visiting := map[string]bool{}
	var register func(name string) error
	register = func(name string) error {
		if _, err := reg.FindFileByPath(name); err == nil {
			return nil
		}
		if visiting[name] {
			return fmt.Errorf("import cycle involving %q", name)
		}
		visiting[name] = true
		fdp, ok := byName[name]
		if !ok {
			if gd, err := protoregistry.GlobalFiles.FindFileByPath(name); err == nil {
				return registerFileDesc(reg, gd)
			}
			return fmt.Errorf("descriptor for %q (a dependency) is missing", name)
		}
		for _, dep := range fdp.GetDependency() {
			if err := register(dep); err != nil {
				return err
			}
		}
		fd, err := protodesc.NewFile(fdp, reg)
		if err != nil {
			fd, err = protodesc.FileOptions{AllowUnresolvable: true}.New(fdp, reg)
			if err != nil {
				return fmt.Errorf("build descriptor %q: %w", name, err)
			}
		}
		if err := reg.RegisterFile(fd); err != nil {
			return fmt.Errorf("register %q: %w", name, err)
		}
		return nil
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := register(n); err != nil {
			return err
		}
	}
	return nil
}

// registerFileDesc registers fd and, first, its imports.
func registerFileDesc(reg *protoregistry.Files, fd protoreflect.FileDescriptor) error {
	if _, err := reg.FindFileByPath(fd.Path()); err == nil {
		return nil
	}
	imps := fd.Imports()
	for i := 0; i < imps.Len(); i++ {
		if err := registerFileDesc(reg, imps.Get(i).FileDescriptor); err != nil {
			return err
		}
	}
	if err := reg.RegisterFile(fd); err != nil {
		// Conflicting duplicates (same symbol in another file) are tolerated.
		if _, err2 := reg.FindFileByPath(fd.Path()); err2 == nil {
			return nil
		}
		return fmt.Errorf("register %q: %w", fd.Path(), err)
	}
	return nil
}

func compileProtos(ctx context.Context, files *fileio.Policy, protoPaths, importPaths []string, reg *protoregistry.Files) error {
	var ips []string
	for _, ip := range importPaths {
		dir, err := files.ResolveDir(ip)
		if err != nil {
			return fmt.Errorf("import path %q: %w", ip, err)
		}
		ips = append(ips, dir)
	}
	userImports := len(ips) > 0
	addImport := func(dir string) {
		for _, d := range ips {
			if samePath(d, dir) {
				return
			}
		}
		ips = append(ips, dir)
	}
	var names []string
	seen := map[string]bool{}
	addName := func(n string) {
		n = filepath.ToSlash(n)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, p := range protoPaths {
		// A relative name that exists under a user import path is used
		// as-is (protoc semantics).
		if userImports && !filepath.IsAbs(p) {
			found := false
			for _, ip := range ips {
				if _, err := files.ResolveRead(filepath.Join(ip, p)); err == nil {
					addName(p)
					found = true
					break
				}
			}
			if found {
				continue
			}
		}
		if dir, err := files.ResolveDir(p); err == nil {
			base := containing(ips, dir)
			if base == "" {
				addImport(dir)
				base = dir
			}
			err := filepath.WalkDir(dir, func(path string, de fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if de.IsDir() || !strings.HasSuffix(de.Name(), ".proto") {
					return nil
				}
				rel, err := filepath.Rel(base, path)
				if err != nil {
					return err
				}
				addName(rel)
				return nil
			})
			if err != nil {
				return fmt.Errorf("scan %q: %w", p, err)
			}
			continue
		}
		real, err := files.ResolveRead(p)
		if err != nil {
			return fmt.Errorf("proto file %q: %w", p, err)
		}
		base := containing(ips, filepath.Dir(real))
		if base == "" {
			addImport(filepath.Dir(real))
			base = filepath.Dir(real)
		}
		rel, err := filepath.Rel(base, real)
		if err != nil {
			return err
		}
		addName(rel)
	}
	if len(names) == 0 {
		return fmt.Errorf("no .proto files found in %v", protoPaths)
	}
	accessor := func(path string) (io.ReadCloser, error) {
		data, err := files.ReadSmall(path, maxProtoSource)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist) {
				return nil, fs.ErrNotExist
			}
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(data)), nil
	}
	comp := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(&protocompile.SourceResolver{
			ImportPaths: ips,
			Accessor:    accessor,
		}),
		SourceInfoMode: protocompile.SourceInfoStandard,
	}
	res, err := comp.Compile(ctx, names...)
	if err != nil {
		return fmt.Errorf("compile .proto files: %w", err)
	}
	for _, f := range res {
		if err := registerFileDesc(reg, f); err != nil {
			return err
		}
	}
	return nil
}

// containing returns the first dir in dirs that contains p (or equals it).
func containing(dirs []string, p string) string {
	for _, d := range dirs {
		rel, err := filepath.Rel(d, p)
		if err != nil {
			continue
		}
		if rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)) {
			return d
		}
	}
	return ""
}

func samePath(a, b string) bool {
	if filepath.Separator == '\\' {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// ParseMethodName splits "pkg.Service/Method", "/pkg.Service/Method" or
// "pkg.Service.Method" into service and method names.
func ParseMethodName(s string) (service, method string, err error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "/")
	if i := strings.LastIndexByte(s, '/'); i > 0 {
		service, method = s[:i], s[i+1:]
	} else if i := strings.LastIndexByte(s, '.'); i > 0 {
		service, method = s[:i], s[i+1:]
	}
	if service == "" || method == "" {
		return "", "", fmt.Errorf("method %q must look like package.Service/Method", s)
	}
	return service, method, nil
}

// FindMethod resolves a method name against a source.
func FindMethod(ctx context.Context, src Source, name string) (protoreflect.MethodDescriptor, error) {
	svc, m, err := ParseMethodName(name)
	if err != nil {
		return nil, err
	}
	d, err := src.FindSymbol(ctx, svc)
	if err != nil {
		return nil, fmt.Errorf("service %q: %w", svc, err)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q is a %s, not a service", svc, kindOf(d))
	}
	md := sd.Methods().ByName(protoreflect.Name(m))
	if md == nil {
		var names []string
		for i := 0; i < sd.Methods().Len(); i++ {
			names = append(names, string(sd.Methods().Get(i).Name()))
		}
		return nil, fmt.Errorf("service %s has no method %q (methods: %s)", svc, m, strings.Join(names, ", "))
	}
	return md, nil
}

// FullMethod returns the HTTP/2 path of a method: /pkg.Service/Method.
func FullMethod(md protoreflect.MethodDescriptor) string {
	return "/" + string(md.Parent().FullName()) + "/" + string(md.Name())
}
