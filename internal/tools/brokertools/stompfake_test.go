package brokertools_test

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-stomp/stomp/v3/frame"
)

// fakeSTOMP is a minimal STOMP 1.0-1.2 broker for tests: CONNECT/STOMP ->
// CONNECTED (or ERROR on bad credentials), heart-beat negotiation, SEND,
// SUBSCRIBE/UNSUBSCRIBE -> MESSAGE, ACK/NACK, RECEIPT and DISCONNECT.
// Messages sent to a destination without subscribers are queued and
// delivered to the next subscriber.
type fakeSTOMP struct {
	t    *testing.T
	l    net.Listener
	Addr string

	// Users maps login -> passcode; nil accepts any login.
	Users map[string]string
	// HeartBeat is the server's heart-beat header ("sx,sy"); "" = "0,0".
	HeartBeat string
	// SendHeartBeats makes the server emit heart-beats when negotiated.
	SendHeartBeats bool
	// SilentConnect: never answer CONNECT.
	SilentConnect bool
	// SilentAfterConnect: answer CONNECT, then ignore everything (no
	// RECEIPTs, no MESSAGEs).
	SilentAfterConnect bool
	// ErrorOnSend: answer SEND with an ERROR frame.
	ErrorOnSend bool

	mu      sync.Mutex
	conns   []net.Conn
	subs    map[string][]*fakeSub // destination -> subscriptions
	queued  map[string][]*frame.Frame
	msgID   int
	Frames  chan *frame.Frame // every client frame (CONNECT, SEND, SUBSCRIBE, ACK, ...)
	Connect chan *frame.Frame // CONNECT frames
}

type fakeSub struct {
	id, dest, ack string
	w             *lockedWriter
}

type lockedWriter struct {
	mu sync.Mutex
	w  *frame.Writer
}

func (lw *lockedWriter) write(f *frame.Frame) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(f)
}

func startSTOMP(t *testing.T, tlsCfg *tls.Config, configure func(*fakeSTOMP)) *fakeSTOMP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		l = tls.NewListener(l, tlsCfg)
	}
	f := &fakeSTOMP{t: t, l: l, Addr: l.Addr().String(), subs: map[string][]*fakeSub{}, queued: map[string][]*frame.Frame{},
		Frames: make(chan *frame.Frame, 256), Connect: make(chan *frame.Frame, 16)}
	if configure != nil {
		configure(f)
	}
	go f.serve()
	t.Cleanup(f.Close)
	return f
}

func (f *fakeSTOMP) Close() {
	f.l.Close()
	f.mu.Lock()
	for _, c := range f.conns {
		c.Close()
	}
	f.mu.Unlock()
}

func (f *fakeSTOMP) serve() {
	for {
		c, err := f.l.Accept()
		if err != nil {
			return
		}
		f.mu.Lock()
		f.conns = append(f.conns, c)
		f.mu.Unlock()
		go f.handle(c)
	}
}

func (f *fakeSTOMP) record(fr *frame.Frame) {
	select {
	case f.Frames <- fr:
	default:
	}
}

// Expect returns the next client frame with the given command.
func (f *fakeSTOMP) Expect(t *testing.T, command string) *frame.Frame {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case fr := <-f.Frames:
			if fr.Command == command {
				return fr
			}
		case <-timeout:
			t.Fatalf("fake STOMP broker did not receive %s", command)
			return nil
		}
	}
}

// Publish delivers a message as if another client had sent it.
func (f *fakeSTOMP) Publish(dest, contentType string, body []byte, headers ...string) {
	send := frame.New(frame.SEND, append([]string{frame.Destination, dest, frame.ContentType, contentType}, headers...)...)
	send.Body = body
	f.deliver(send)
}

func (f *fakeSTOMP) deliver(send *frame.Frame) {
	f.mu.Lock()
	dest := send.Header.Get(frame.Destination)
	subs := append([]*fakeSub(nil), f.subs[dest]...)
	if len(subs) == 0 {
		f.queued[dest] = append(f.queued[dest], send)
		f.mu.Unlock()
		return
	}
	f.msgID++
	id := f.msgID
	f.mu.Unlock()
	for _, s := range subs {
		_ = s.w.write(f.message(s, send, id))
	}
}

func (f *fakeSTOMP) message(s *fakeSub, send *frame.Frame, id int) *frame.Frame {
	m := frame.New(frame.MESSAGE)
	for i := 0; i < send.Header.Len(); i++ {
		k, v := send.Header.GetAt(i)
		switch k {
		case frame.Receipt, frame.ContentLength, frame.Transaction:
			continue
		}
		m.Header.Add(k, v)
	}
	m.Header.Set(frame.Subscription, s.id)
	m.Header.Set(frame.MessageId, "m-"+strconv.Itoa(id))
	if s.ack != "auto" && s.ack != "" {
		m.Header.Set(frame.Ack, "a-"+strconv.Itoa(id))
	}
	m.Header.Set(frame.ContentLength, strconv.Itoa(len(send.Body)))
	m.Body = send.Body
	return m
}

func negotiate(client, server string) (sendEvery time.Duration) {
	cx, cy := parseHB(client)
	sx, sy := parseHB(server)
	_ = cx
	_ = sy
	// The server sends every max(sx, cy) when both are non-zero.
	if sx == 0 || cy == 0 {
		return 0
	}
	if cy > sx {
		sx = cy
	}
	return time.Duration(sx) * time.Millisecond
}

func parseHB(s string) (int, int) {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		return 0, 0
	}
	a, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
	return a, b
}

func (f *fakeSTOMP) handle(c net.Conn) {
	defer c.Close()
	r := frame.NewReader(c)
	w := &lockedWriter{w: frame.NewWriter(c)}
	stop := make(chan struct{})
	defer close(stop)
	var mySubs []*fakeSub
	defer func() {
		f.mu.Lock()
		for _, s := range mySubs {
			f.removeSub(s)
		}
		f.mu.Unlock()
	}()

	connected := false
	for {
		fr, err := r.Read()
		if err != nil {
			return
		}
		if fr == nil { // heart-beat
			continue
		}
		f.record(fr)
		if !connected {
			if fr.Command != frame.CONNECT && fr.Command != frame.STOMP {
				_ = w.write(frame.New(frame.ERROR, frame.Message, "expected CONNECT"))
				return
			}
			select {
			case f.Connect <- fr:
			default:
			}
			if f.SilentConnect {
				continue
			}
			if f.Users != nil {
				if p, ok := f.Users[fr.Header.Get(frame.Login)]; !ok || p != fr.Header.Get(frame.Passcode) {
					e := frame.New(frame.ERROR, frame.Message, "Access refused for user '"+fr.Header.Get(frame.Login)+"'", frame.ContentType, "text/plain")
					e.Body = []byte("bad credentials")
					_ = w.write(e)
					return
				}
			}
			version := "1.0"
			if av := fr.Header.Get(frame.AcceptVersion); av != "" {
				for _, v := range []string{"1.2", "1.1", "1.0"} {
					if strings.Contains(av, v) {
						version = v
						break
					}
				}
			}
			hb := f.HeartBeat
			if hb == "" {
				hb = "0,0"
			}
			resp := frame.New(frame.CONNECTED, frame.Version, version, frame.Server, "fakestomp/1.0", frame.Session, fmt.Sprintf("sess-%p", c))
			if version != "1.0" {
				resp.Header.Set(frame.HeartBeat, hb)
			}
			if err := w.write(resp); err != nil {
				return
			}
			connected = true
			if every := negotiate(fr.Header.Get(frame.HeartBeat), hb); every > 0 && f.SendHeartBeats {
				go func() {
					tk := time.NewTicker(every)
					defer tk.Stop()
					for {
						select {
						case <-stop:
							return
						case <-tk.C:
							w.mu.Lock()
							_, err := c.Write([]byte("\n"))
							w.mu.Unlock()
							if err != nil {
								return
							}
						}
					}
				}()
			}
			continue
		}
		if f.SilentAfterConnect {
			continue
		}
		receipt := func() bool {
			if id := fr.Header.Get(frame.Receipt); id != "" {
				return w.write(frame.New(frame.RECEIPT, frame.ReceiptId, id)) == nil
			}
			return true
		}
		switch fr.Command {
		case frame.SEND:
			if f.ErrorOnSend {
				e := frame.New(frame.ERROR, frame.Message, "destination is read-only")
				if id := fr.Header.Get(frame.Receipt); id != "" {
					e.Header.Set(frame.ReceiptId, id)
				}
				_ = w.write(e)
				return
			}
			f.deliver(fr)
			if !receipt() {
				return
			}
		case frame.SUBSCRIBE:
			ack := fr.Header.Get(frame.Ack)
			if ack == "" {
				ack = "auto"
			}
			s := &fakeSub{id: fr.Header.Get(frame.Id), dest: fr.Header.Get(frame.Destination), ack: ack, w: w}
			f.mu.Lock()
			f.subs[s.dest] = append(f.subs[s.dest], s)
			mySubs = append(mySubs, s)
			queued := f.queued[s.dest]
			delete(f.queued, s.dest)
			var ids []int
			for range queued {
				f.msgID++
				ids = append(ids, f.msgID)
			}
			f.mu.Unlock()
			if !receipt() {
				return
			}
			for i, q := range queued {
				_ = w.write(f.message(s, q, ids[i]))
			}
		case frame.UNSUBSCRIBE:
			id := fr.Header.Get(frame.Id)
			f.mu.Lock()
			for _, s := range mySubs {
				if s.id == id {
					f.removeSub(s)
				}
			}
			f.mu.Unlock()
			if !receipt() {
				return
			}
		case frame.ACK, frame.NACK, frame.BEGIN, frame.COMMIT, frame.ABORT:
			if !receipt() {
				return
			}
		case frame.DISCONNECT:
			receipt()
			return
		default:
			_ = w.write(frame.New(frame.ERROR, frame.Message, "unknown command "+fr.Command))
			return
		}
	}
}

// removeSub must be called with f.mu held.
func (f *fakeSTOMP) removeSub(s *fakeSub) {
	list := f.subs[s.dest]
	for i, x := range list {
		if x == s {
			f.subs[s.dest] = append(list[:i:i], list[i+1:]...)
			break
		}
	}
}

// SubCount returns the number of active subscriptions on dest.
func (f *fakeSTOMP) SubCount(dest string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs[dest])
}

// waitSub waits until dest has a subscriber.
func (f *fakeSTOMP) waitSub(t *testing.T, dest string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f.SubCount(dest) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no subscriber on %s", dest)
}
