package wstools

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/httpx"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/session"
	"github.com/HamedFathi/NetKitMCP/internal/sio"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// sioSession is an interactive Socket.IO connection.
type sioSession struct {
	id          string
	client      *sio.Client
	hc          *httpx.Client
	buf         *session.Buffer
	authPayload any
	timeout     time.Duration
	closeOnce   sync.Once
}

// Close implements session.Handle.
func (s *sioSession) Close() error {
	s.closeOnce.Do(func() {
		s.client.Close()
		s.hc.Close()
		live.Delete(s.id)
	})
	return nil
}

func (s *sioSession) state() map[string]any {
	m := engineInfo(s.client)
	st := "open"
	select {
	case <-s.client.Done():
		st = "closed"
		if err := s.client.Engine().Err(); err != nil {
			m["error"] = err.Error()
		}
	default:
	}
	m["state"] = st
	m["pending"] = s.buf.Pending()
	return m
}

// join connects a namespace if it is not connected yet.
func (s *sioSession) join(ctx context.Context, ns string) (bool, error) {
	for _, n := range s.client.Namespaces() {
		if n.Namespace == ns && n.State == sio.StateConnected {
			return false, nil
		}
	}
	cctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	_, err := s.client.Connect(cctx, ns, s.authPayload)
	return err == nil, err
}

type sioConnectIn struct {
	sioTarget
	Namespaces  []string `json:"namespaces,omitempty" jsonschema:"namespaces to join on this connection (default: the URL path namespace or /)"`
	AuthPayload any      `json:"auth_payload,omitempty" jsonschema:"Socket.IO CONNECT auth payload (JSON object) sent when joining each namespace"`
}

type sioConnectOut struct {
	SessionID      string         `json:"session_id"`
	URL            string         `json:"url"`
	Engine         map[string]any `json:"engine"`
	BufferCapacity int            `json:"buffer_capacity"`
	Warnings       []string       `json:"warnings,omitempty"`
}

type sioEmitIn struct {
	SessionID      string          `json:"session_id" jsonschema:"session handle from sio_connect"`
	Namespace      string          `json:"namespace,omitempty" jsonschema:"namespace (default /); joined automatically if needed"`
	Event          string          `json:"event,omitempty" jsonschema:"event name (required unless ack_id is set)"`
	Args           []any           `json:"args,omitempty" jsonschema:"event (or ack) arguments as JSON values"`
	Attachments    []types.Payload `json:"attachments,omitempty" jsonschema:"binary attachments (base64 or file), appended after args as placeholders unless args contain {\"_placeholder\":true,\"num\":N}"`
	Ack            bool            `json:"ack,omitempty" jsonschema:"request an acknowledgement; it arrives in sio_receive as type ack with meta.ack_id"`
	WaitAckSeconds float64         `json:"wait_ack_seconds,omitempty" jsonschema:"request an ack and wait up to this many seconds for it (returned in ack)"`
	AckID          *int64          `json:"ack_id,omitempty" jsonschema:"answer the server's ack request with this id (from meta.ack_id of a received event) instead of emitting an event"`
}

type sioEmitOut struct {
	SessionID  string               `json:"session_id"`
	Joined     string               `json:"joined_namespace,omitempty"`
	Sent       types.StreamMessage  `json:"sent"`
	Ack        *types.StreamMessage `json:"ack,omitempty"`
	AckPending bool                 `json:"ack_pending,omitempty"`
}

type sioCloseIn struct {
	SessionID string `json:"session_id" jsonschema:"session handle"`
}

func registerSIOSession(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "sio_connect", "Socket.IO connect",
		"Open an interactive Socket.IO session (Engine.IO v4 over websocket, or long-polling with optional upgrade) and join "+
			"one or more namespaces with an optional CONNECT auth_payload. Incoming events, acks and disconnects are buffered "+
			"until read with sio_receive. Returns session_id, engine sid, transport and namespace states.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in sioConnectIn) (any, error) {
			_, urlNS, err := in.resolve()
			if err != nil {
				return nil, err
			}
			nss := in.Namespaces
			if len(nss) == 0 {
				nss = []string{urlNS}
			}
			buf := session.NewBuffer(d.Cfg.RingBufferSize)
			onMessage := func(m sio.Message) {
				if m.Kind == sio.KindClose {
					if m.Err != "" {
						buf.CloseWith(nil, errors.New(m.Err))
					} else {
						buf.CloseWith(nil, nil)
					}
					return
				}
				buf.Push(sioMessage(m))
			}
			c, hc, err := in.dial(ctx, d, onMessage)
			if err != nil {
				return nil, err
			}
			sess := &sioSession{client: c, hc: hc, buf: buf, authPayload: in.AuthPayload, timeout: in.connectTimeout(d)}
			for _, ns := range nss {
				if _, err := sess.join(ctx, sio.NormalizeNamespace(ns)); err != nil {
					sess.Close()
					return nil, err
				}
			}
			id, err := d.Sessions.Add(kindSIO, redact.URL(in.URL), sess)
			if err != nil {
				sess.Close()
				return nil, err
			}
			sess.id = id
			live.Store(id, sess)
			return sioConnectOut{SessionID: id, URL: redact.URL(in.URL), Engine: engineInfo(c), BufferCapacity: bufferCap(d),
				Warnings: in.warnings()}, nil
		})

	tools.Add(s, d, "sio_emit", "Socket.IO emit",
		"Emit an event on a sio_connect session (JSON args plus optional binary attachments). ack=true requests an "+
			"acknowledgement (delivered to sio_receive); wait_ack_seconds waits for it and returns it here. Set ack_id to "+
			"answer an ack the server requested (meta.ack_id of a received event). Unjoined namespaces are joined automatically.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in sioEmitIn) (any, error) {
			sess, err := session.Get[*sioSession](d.Sessions, in.SessionID, kindSIO)
			if err != nil {
				return nil, err
			}
			select {
			case <-sess.client.Done():
				return nil, fmt.Errorf("session %s is closed (read remaining messages with sio_receive, then sio_close)", in.SessionID)
			default:
			}
			if in.AckID == nil && in.Event == "" {
				return nil, errors.New("event is required (or set ack_id to answer a server ack request)")
			}
			bufs, err := resolveAttachments(d, in.Attachments)
			if err != nil {
				return nil, err
			}
			ns := sio.NormalizeNamespace(in.Namespace)
			out := sioEmitOut{SessionID: in.SessionID}
			joined, err := sess.join(ctx, ns)
			if err != nil {
				return nil, err
			}
			if joined {
				out.Joined = ns
			}
			sctx, cancel := context.WithTimeout(ctx, sess.timeout)
			defer cancel()
			if in.AckID != nil {
				pkt, err := sess.client.Ack(sctx, ns, *in.AckID, in.Args, bufs)
				if err != nil {
					return nil, err
				}
				out.Sent = outMessage("ack", pkt, "", in.AckID)
				out.Sent.Seq = sess.buf.NextSeq()
				out.Sent.TS = types.Now()
				return out, nil
			}
			wait := in.WaitAckSeconds > 0
			em, err := sess.client.Emit(sctx, ns, in.Event, in.Args, bufs, sio.EmitOptions{Ack: in.Ack || wait, Wait: wait})
			if err != nil {
				return nil, err
			}
			out.Sent = outMessage("event", em.Packet, in.Event, em.AckID)
			out.Sent.Seq = sess.buf.NextSeq()
			out.Sent.TS = types.Now()
			if wait {
				w := secs(in.WaitAckSeconds)
				if w > d.Cfg.MaxStreamTime {
					w = d.Cfg.MaxStreamTime
				}
				actx, acancel := context.WithTimeout(ctx, w)
				defer acancel()
				m, err := sess.client.AwaitAck(actx, em)
				if err != nil {
					return nil, err
				}
				if m == nil {
					out.AckPending = true
				} else {
					sm := sioMessage(*m)
					sm.Seq = sess.buf.NextSeq()
					sm.TS = types.Now()
					out.Ack = &sm
				}
			}
			return out, nil
		})

	tools.Add(s, d, "sio_receive", "Socket.IO receive",
		"Drain buffered incoming Socket.IO messages from a sio_connect session (events with name and JSON args, acks with "+
			"meta.ack_id, disconnects). Waits up to wait_seconds when empty; dropped counts messages lost to buffer overflow.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in receiveIn) (any, error) {
			sess, err := session.Get[*sioSession](d.Sessions, in.SessionID, kindSIO)
			if err != nil {
				return nil, err
			}
			res := sess.buf.Take(ctx, in.MaxMessages, in.wait(d))
			res.Meta = sess.state()
			return res, nil
		})

	tools.Add(s, d, "sio_close", "Socket.IO close",
		"Disconnect all namespaces, close a sio_connect session and return any messages still buffered.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in sioCloseIn) (any, error) {
			sess, err := session.Get[*sioSession](d.Sessions, in.SessionID, kindSIO)
			if err != nil {
				return nil, err
			}
			d.Sessions.Remove(in.SessionID)
			sess.Close()
			return closeOut{SessionID: in.SessionID, Closed: true, Remaining: drain(ctx, sess.buf, d.Cfg.RingBufferSize)}, nil
		})
}
