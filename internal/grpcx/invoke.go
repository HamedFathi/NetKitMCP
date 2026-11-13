package grpcx

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/HamedFathi/NetKitMCP/internal/session"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// UnaryResult is the outcome of a unary call.
type UnaryResult struct {
	Response *dynamicpb.Message // nil when Err != nil
	Header   metadata.MD
	Trailer  metadata.MD
	Err      error
	Duration time.Duration
	TLS      *tls.ConnectionState
}

// PeerTLS extracts the TLS state from a peer.
func PeerTLS(p *peer.Peer) *tls.ConnectionState {
	if p == nil || p.AuthInfo == nil {
		return nil
	}
	if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok {
		st := ti.State
		return &st
	}
	return nil
}

// InvokeUnary calls a unary method. ctx should carry outgoing metadata and
// a deadline.
func InvokeUnary(ctx context.Context, cc grpc.ClientConnInterface, md protoreflect.MethodDescriptor, req proto.Message, opts ...grpc.CallOption) *UnaryResult {
	res := &UnaryResult{}
	var p peer.Peer
	resp := dynamicpb.NewMessage(md.Output())
	opts = append(opts, grpc.Header(&res.Header), grpc.Trailer(&res.Trailer), grpc.Peer(&p))
	start := time.Now()
	err := cc.Invoke(ctx, FullMethod(md), req, resp, opts...)
	res.Duration = time.Since(start)
	res.TLS = PeerTLS(&p)
	if err != nil {
		res.Err = err
		return res
	}
	res.Response = resp
	return res
}

// StreamDesc returns the grpc stream description for a method.
func StreamDesc(md protoreflect.MethodDescriptor) *grpc.StreamDesc {
	return &grpc.StreamDesc{
		StreamName:    string(md.Name()),
		ClientStreams: md.IsStreamingClient(),
		ServerStreams: md.IsStreamingServer(),
	}
}

// StreamOutcome is the result of a bounded one-shot stream.
type StreamOutcome struct {
	Header  metadata.MD
	Trailer metadata.MD
	// Finished is true when the server ended the stream (Err then holds the
	// final status; nil = OK). False when a client-side limit stopped it.
	Finished bool
	Err      error
	Sent     int
	SendErr  error
	TLS      *tls.ConnectionState
	Duration time.Duration
}

// RunStream runs a bounded stream for any method type: it sends reqs (then
// half-closes) while collecting responses into col, until the server ends
// the stream or a collector limit fires (the stream is then cancelled).
func RunStream(ctx context.Context, cc grpc.ClientConnInterface, md protoreflect.MethodDescriptor, reqs []proto.Message, codec *Codec, col *types.Collector, opts ...grpc.CallOption) *StreamOutcome {
	out := &StreamOutcome{}
	start := time.Now()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var p peer.Peer
	cs, err := cc.NewStream(sctx, StreamDesc(md), FullMethod(md), append(opts, grpc.Peer(&p))...)
	if err != nil {
		out.Finished, out.Err = true, err
		col.Finish(types.EndedError, err)
		out.Duration = time.Since(start)
		return out
	}

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for _, r := range reqs {
			if err := cs.SendMsg(r); err != nil {
				if !errors.Is(err, io.EOF) {
					out.SendErr = err
				}
				return
			}
			out.Sent++
			if js, err := codec.ToJSON(r); err == nil {
				col.Add(types.StreamMessage{Dir: "out", Type: "json", Data: string(js), Encoding: "text"})
			}
		}
		cs.CloseSend()
	}()

	recvDone := make(chan struct{})
	var finalErr error
	finished := false
	go func() {
		defer close(recvDone)
		for {
			m := dynamicpb.NewMessage(md.Output())
			err := cs.RecvMsg(m)
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				if sctx.Err() == nil || err == nil {
					finished, finalErr = true, err
				}
				if err == nil {
					col.Finish(types.EndedComplete, nil)
				} else {
					col.Finish(types.EndedError, err)
				}
				return
			}
			js, jerr := codec.ToJSON(m)
			if jerr != nil {
				col.Add(types.StreamMessage{Dir: "in", Type: "error", Data: jerr.Error(), Encoding: "text"})
				continue
			}
			col.Add(types.StreamMessage{Dir: "in", Type: "json", Data: string(js), Encoding: "text"})
		}
	}()

	col.Wait(ctx)
	select {
	case <-recvDone:
	default:
		cancel()
		<-recvDone
	}
	cancel()
	<-sendDone
	out.Finished, out.Err = finished, finalErr
	if h, err := cs.Header(); err == nil {
		out.Header = h
	}
	out.Trailer = cs.Trailer()
	out.TLS = PeerTLS(&p)
	out.Duration = time.Since(start)
	return out
}

// StreamSession is an interactive stream: a background goroutine reads
// responses into Buf; Send writes requests.
type StreamSession struct {
	Method protoreflect.MethodDescriptor
	Target string
	Buf    *session.Buffer

	cc     io.Closer
	cs     grpc.ClientStream
	cancel context.CancelFunc
	codec  *Codec
	extra  func()

	sendMu     sync.Mutex
	sendClosed bool
	sent       int

	mu       sync.Mutex
	header   metadata.MD
	trailer  metadata.MD
	finished bool
	final    error
	canceled bool
	tls      *tls.ConnectionState

	recvDone  chan struct{}
	closeOnce sync.Once
}

// OpenStreamSession starts a stream that lives until Close. ctx is used only
// to carry outgoing metadata (it is detached from the caller's deadline).
// cc is closed when the session closes; onClose (may be nil) runs too.
func OpenStreamSession(ctx context.Context, cc *grpc.ClientConn, md protoreflect.MethodDescriptor, codec *Codec, buf *session.Buffer, target string, onClose func()) (*StreamSession, error) {
	base := context.WithoutCancel(ctx)
	sctx, cancel := context.WithCancel(base)
	var p peer.Peer
	cs, err := cc.NewStream(sctx, StreamDesc(md), FullMethod(md), grpc.Peer(&p))
	if err != nil {
		cancel()
		return nil, err
	}
	s := &StreamSession{
		Method: md, Target: target, Buf: buf,
		cc: cc, cs: cs, cancel: cancel, codec: codec, extra: onClose,
		recvDone: make(chan struct{}),
	}
	go s.readLoop(sctx, &p)
	return s, nil
}

func (s *StreamSession) readLoop(ctx context.Context, p *peer.Peer) {
	defer close(s.recvDone)
	gotHeader := false
	for {
		m := dynamicpb.NewMessage(s.Method.Output())
		err := s.cs.RecvMsg(m)
		if !gotHeader {
			if h, herr := s.cs.Header(); herr == nil {
				s.mu.Lock()
				s.header = h
				s.tls = PeerTLS(p)
				s.mu.Unlock()
			}
			gotHeader = true
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = nil
			}
			s.mu.Lock()
			s.finished = true
			s.final = err
			s.canceled = ctx.Err() != nil && err != nil
			s.trailer = s.cs.Trailer()
			s.mu.Unlock()
			si := StatusFromError(err, s.codec.Resolver)
			s.Buf.CloseWith(&types.CloseInfo{Code: si.Code, Reason: si.Name + ": " + si.Message}, err)
			return
		}
		js, jerr := s.codec.ToJSON(m)
		if jerr != nil {
			s.Buf.Push(types.StreamMessage{Dir: "in", Type: "error", Data: jerr.Error(), Encoding: "text"})
			continue
		}
		s.Buf.Push(types.StreamMessage{Dir: "in", Type: "json", Data: string(js), Encoding: "text"})
	}
}

// ErrSendClosed is returned when sending after close_send.
var ErrSendClosed = errors.New("the send side of this stream is already closed (close_send was set)")

// ErrSendTimeout is returned when a send could not complete before the
// caller's deadline (the server stopped reading and flow control is full).
var ErrSendTimeout = errors.New("send timed out: the server is not reading (flow-control window full); the stream was cancelled, call grpc_stream_close for the final status")

// Send writes messages and optionally half-closes the stream. It returns
// the number of messages written. grpc-go's SendMsg blocks while the
// flow-control window is full and cannot be interrupted except by
// cancelling the stream, so when ctx ends before the send completes the
// stream is cancelled and ErrSendTimeout is returned.
func (s *StreamSession) Send(ctx context.Context, msgs []proto.Message, closeSend bool) (int, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	var (
		n    int
		err  error
		done = make(chan struct{})
	)
	go func() {
		defer close(done)
		n, err = s.sendLocked(msgs, closeSend)
	}()
	select {
	case <-done:
		return n, err
	case <-ctx.Done():
		s.cancel()
		<-done
		return n, ErrSendTimeout
	}
}

func (s *StreamSession) sendLocked(msgs []proto.Message, closeSend bool) (int, error) {
	if s.sendClosed {
		if len(msgs) == 0 && closeSend {
			return 0, nil
		}
		return 0, ErrSendClosed
	}
	if !s.Method.IsStreamingClient() && s.sent+len(msgs) > 1 {
		return 0, errors.New("this method is not client-streaming: exactly one request message may be sent")
	}
	n := 0
	for _, m := range msgs {
		if err := s.cs.SendMsg(m); err != nil {
			if errors.Is(err, io.EOF) {
				return n, errors.New("the server has already ended the stream; call grpc_stream_recv or grpc_stream_close for the final status")
			}
			return n, err
		}
		n++
		s.sent++
	}
	if closeSend || (!s.Method.IsStreamingClient() && s.sent == 1) {
		s.cs.CloseSend()
		s.sendClosed = true
	}
	return n, nil
}

// SendClosed reports whether the client side has been half-closed.
func (s *StreamSession) SendClosed() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sendClosed
}

// Sent returns the number of messages sent so far.
func (s *StreamSession) Sent() int {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.sent
}

// Final reports whether the stream has ended and its status.
type Final struct {
	Finished bool
	Canceled bool
	Err      error
	Header   metadata.MD
	Trailer  metadata.MD
	TLS      *tls.ConnectionState
}

// State returns the current final state.
func (s *StreamSession) State() Final {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Final{Finished: s.finished, Canceled: s.canceled, Err: s.final, Header: s.header, Trailer: s.trailer, TLS: s.tls}
}

// Shutdown half-closes the stream, waits up to grace for the server to end
// it, then cancels it. It returns the final state.
func (s *StreamSession) Shutdown(grace time.Duration) Final {
	s.sendMu.Lock()
	if !s.sendClosed {
		s.cs.CloseSend()
		s.sendClosed = true
	}
	s.sendMu.Unlock()
	if grace > 0 {
		t := time.NewTimer(grace)
		select {
		case <-s.recvDone:
		case <-t.C:
		}
		t.Stop()
	}
	s.Close()
	return s.State()
}

// Close cancels the stream, waits for the reader and closes the connection.
func (s *StreamSession) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.recvDone
		if s.cc != nil {
			s.cc.Close()
		}
		if s.extra != nil {
			s.extra()
		}
	})
	return nil
}

// MarshalJSONMessages renders messages as JSON values (for echoing sent requests).
func MarshalJSONMessages(c *Codec, msgs []proto.Message) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(msgs))
	for _, m := range msgs {
		if js, err := c.ToJSON(m); err == nil {
			out = append(out, js)
		}
	}
	return out
}
