// Package amqpfake is a small in-memory AMQP 0-9-1 broker for tests. It
// speaks enough of the protocol to drive github.com/rabbitmq/amqp091-go end
// to end: connection/channel lifecycle, exchange/queue declare and bind
// (default, direct, fanout and topic routing), basic.publish with mandatory
// returns, publisher confirms, basic.consume/deliver with prefetch,
// basic.get, and ack/reject/nack with requeue. Message properties are kept
// as the raw encoded bytes and replayed verbatim on delivery.
package amqpfake

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Message is a routed message.
type Message struct {
	Exchange    string
	RoutingKey  string
	Mandatory   bool
	Props       []byte // property flags + property list, as sent
	Body        []byte
	Redelivered bool
}

// Option configures the broker.
type Option func(*Broker)

// WithUsers enables PLAIN authentication against the given user -> password map.
func WithUsers(users map[string]string) Option {
	return func(b *Broker) { b.users = users }
}

// WithNackExchange makes publisher confirms nack publishes to this exchange.
func WithNackExchange(name string) Option {
	return func(b *Broker) { b.nackExchange = name }
}

// WithTLS serves AMQPS with the given server config.
func WithTLS(cfg *tls.Config) Option {
	return func(b *Broker) { b.tls = cfg }
}

// Broker is the fake broker.
type Broker struct {
	ln           net.Listener
	users        map[string]string
	nackExchange string
	tls          *tls.Config

	mu        sync.Mutex
	exchanges map[string]*exchange
	queues    map[string]*queue
	conns     map[*conn]struct{}
	published []Message
	vhosts    []string
	seq       int
	wg        sync.WaitGroup
}

type exchange struct {
	name, kind string
	bindings   []binding
}

type binding struct{ queue, key string }

type queue struct {
	name       string
	msgs       []*Message
	consumers  []*consumer
	owner      *conn
	autoDelete bool
	rr         int
}

type consumer struct {
	tag   string
	ch    *channel
	noAck bool
	q     *queue
}

// Start listens on 127.0.0.1 and serves until Close.
func Start(opts ...Option) (*Broker, error) {
	b := &Broker{
		exchanges: map[string]*exchange{},
		queues:    map[string]*queue{},
		conns:     map[*conn]struct{}{},
	}
	for _, o := range opts {
		o(b)
	}
	for _, e := range []struct{ n, k string }{{"", "direct"}, {"amq.direct", "direct"}, {"amq.fanout", "fanout"}, {"amq.topic", "topic"}, {"amq.headers", "headers"}} {
		b.exchanges[e.n] = &exchange{name: e.n, kind: e.k}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if b.tls != nil {
		ln = tls.NewListener(ln, b.tls)
	}
	b.ln = ln
	b.wg.Add(1)
	go b.accept()
	return b, nil
}

// Addr returns host:port.
func (b *Broker) Addr() string { return b.ln.Addr().String() }

// URL returns an amqp:// (or amqps:// with TLS) URL with guest credentials.
func (b *Broker) URL() string {
	scheme := "amqp"
	if b.tls != nil {
		scheme = "amqps"
	}
	return scheme + "://guest:guest@" + b.Addr() + "/"
}

// Close stops the broker and drops all connections.
func (b *Broker) Close() {
	b.ln.Close()
	b.mu.Lock()
	for c := range b.conns {
		c.nc.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

// Published returns every message published so far (routed or not).
func (b *Broker) Published() []Message {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Message(nil), b.published...)
}

// Vhosts returns the virtual hosts clients opened, in order.
func (b *Broker) Vhosts() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.vhosts...)
}

// QueueLen returns the number of ready messages in a queue (-1 if missing).
func (b *Broker) QueueLen(name string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	q, ok := b.queues[name]
	if !ok {
		return -1
	}
	return len(q.msgs)
}

// DeclareQueue creates a durable-style queue (bound to the default exchange).
func (b *Broker) DeclareQueue(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.queues[name]; !ok {
		b.queues[name] = &queue{name: name}
	}
}

// Publish routes a message as if a client had published it and reports
// whether any queue received it. contentType and headers (string values)
// are encoded as message properties.
func (b *Broker) Publish(exchangeName, key string, body []byte, contentType string, headers map[string]string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ex, ok := b.exchanges[exchangeName]
	if !ok {
		return false, fmt.Errorf("no exchange %q", exchangeName)
	}
	m := &Message{Exchange: exchangeName, RoutingKey: key, Body: body, Props: encodeProps(contentType, headers)}
	routed := b.route(ex, m)
	b.dispatch()
	return routed, nil
}

func encodeProps(contentType string, headers map[string]string) []byte {
	var flags uint16
	e := &enc{}
	if contentType != "" {
		flags |= 1 << 15
		e.shortstr(contentType)
	}
	if len(headers) > 0 {
		flags |= 1 << 13
		kv := map[string]any{}
		for k, v := range headers {
			kv[k] = v
		}
		e.table(kv)
	}
	return append((&enc{}).short(flags).b, e.b...)
}

func (b *Broker) accept() {
	defer b.wg.Done()
	for {
		nc, err := b.ln.Accept()
		if err != nil {
			return
		}
		c := &conn{b: b, nc: nc, channels: map[uint16]*channel{}, out: make(chan []byte, 4096), done: make(chan struct{})}
		b.mu.Lock()
		b.conns[c] = struct{}{}
		b.mu.Unlock()
		b.wg.Add(2)
		go c.writer()
		go c.serve()
	}
}

// route enqueues m on every matching queue and reports whether it routed.
// Caller holds b.mu.
func (b *Broker) route(ex *exchange, m *Message) bool {
	b.published = append(b.published, *m)
	var targets []*queue
	if ex.name == "" {
		if q, ok := b.queues[m.RoutingKey]; ok {
			targets = append(targets, q)
		}
	} else {
		seen := map[*queue]bool{}
		for _, bd := range ex.bindings {
			q, ok := b.queues[bd.queue]
			if !ok || seen[q] {
				continue
			}
			match := false
			switch ex.kind {
			case "fanout":
				match = true
			case "direct":
				match = bd.key == m.RoutingKey
			case "topic":
				match = topicMatch(bd.key, m.RoutingKey)
			}
			if match {
				seen[q] = true
				targets = append(targets, q)
			}
		}
	}
	for _, q := range targets {
		cp := *m
		q.msgs = append(q.msgs, &cp)
	}
	return len(targets) > 0
}

func topicMatch(pattern, key string) bool {
	return matchWords(strings.Split(pattern, "."), strings.Split(key, "."))
}

func matchWords(p, k []string) bool {
	if len(p) == 0 {
		return len(k) == 0
	}
	if p[0] == "#" {
		for i := 0; i <= len(k); i++ {
			if matchWords(p[1:], k[i:]) {
				return true
			}
		}
		return false
	}
	if len(k) == 0 {
		return false
	}
	if p[0] == "*" || p[0] == k[0] {
		return matchWords(p[1:], k[1:])
	}
	return false
}

// dispatch delivers ready messages to consumers with prefetch capacity.
// Caller holds b.mu.
func (b *Broker) dispatch() {
	for _, q := range b.queues {
		for len(q.msgs) > 0 && len(q.consumers) > 0 {
			var picked *consumer
			for i := 0; i < len(q.consumers); i++ {
				c := q.consumers[(q.rr+i)%len(q.consumers)]
				if c.noAck || c.ch.prefetch == 0 || len(c.ch.unacked) < c.ch.prefetch {
					picked = c
					q.rr = (q.rr + i + 1) % len(q.consumers)
					break
				}
			}
			if picked == nil {
				break
			}
			m := q.msgs[0]
			q.msgs = q.msgs[1:]
			ch := picked.ch
			ch.nextTag++
			tag := ch.nextTag
			if !picked.noAck {
				ch.unacked[tag] = unacked{q: q, m: m}
			}
			e := method(60, 60).shortstr(picked.tag).longlong(tag).octet(boolBit(m.Redelivered)).shortstr(m.Exchange).shortstr(m.RoutingKey)
			ch.c.sendContent(ch.id, e.b, m)
		}
	}
}

func (b *Broker) newName(prefix string) string {
	b.seq++
	return fmt.Sprintf("%s%d", prefix, b.seq)
}

func boolBit(v bool) byte {
	if v {
		return 1
	}
	return 0
}

type unacked struct {
	q *queue
	m *Message
}

type pendingPublish struct {
	exchange, key string
	mandatory     bool
	props         []byte
	size          uint64
	body          bytes.Buffer
	haveHeader    bool
}

type channel struct {
	id         uint16
	c          *conn
	prefetch   int
	unacked    map[uint64]unacked
	nextTag    uint64
	confirm    bool
	publishSeq uint64
	pending    *pendingPublish
	consumers  map[string]*consumer
	closing    bool
}

type conn struct {
	b        *Broker
	nc       net.Conn
	out      chan []byte
	done     chan struct{}
	once     sync.Once
	channels map[uint16]*channel
	frameMax uint32
}

// writer drains the outbound queue. After a write error it keeps draining
// (discarding) so senders never block.
func (c *conn) writer() {
	defer c.b.wg.Done()
	failed := false
	for {
		select {
		case f := <-c.out:
			if !failed {
				if _, err := c.nc.Write(f); err != nil {
					failed = true
					c.nc.Close()
				}
			}
		case <-c.done:
			// Flush what is queued, then stop.
			for {
				select {
				case f := <-c.out:
					if !failed {
						c.nc.Write(f)
					}
				default:
					return
				}
			}
		}
	}
}

func (c *conn) push(f []byte) {
	select {
	case c.out <- f:
	case <-c.done:
	}
}

func (c *conn) send(channel uint16, payload []byte) {
	c.push(encodeFrame(frameMethod, channel, payload))
}

func (c *conn) sendContent(channel uint16, methodPayload []byte, m *Message) {
	c.send(channel, methodPayload)
	h := (&enc{}).short(60).short(0).longlong(uint64(len(m.Body)))
	h.b = append(h.b, m.Props...)
	c.push(encodeFrame(frameHeader, channel, h.b))
	max := int(c.frameMax) - 8
	if max <= 0 {
		max = len(m.Body)
	}
	for off := 0; off < len(m.Body); off += max {
		end := off + max
		if end > len(m.Body) {
			end = len(m.Body)
		}
		c.push(encodeFrame(frameBody, channel, m.Body[off:end]))
	}
}

func (c *conn) shutdown() {
	c.once.Do(func() {
		b := c.b
		b.mu.Lock()
		for _, ch := range c.channels {
			c.cleanupChannel(ch)
		}
		for name, q := range b.queues {
			if q.owner == c {
				delete(b.queues, name)
			}
		}
		delete(b.conns, c)
		b.dispatch()
		b.mu.Unlock()
		close(c.done)
	})
}

// cleanupChannel cancels consumers and requeues unacked messages.
// Caller holds b.mu.
func (c *conn) cleanupChannel(ch *channel) {
	for _, cons := range ch.consumers {
		c.removeConsumer(cons)
	}
	ch.consumers = map[string]*consumer{}
	requeue(ch, func(uint64) bool { return true })
	delete(c.channels, ch.id)
}

func (c *conn) removeConsumer(cons *consumer) {
	q := cons.q
	for i, x := range q.consumers {
		if x == cons {
			q.consumers = append(q.consumers[:i], q.consumers[i+1:]...)
			break
		}
	}
	if q.autoDelete && len(q.consumers) == 0 {
		delete(c.b.queues, q.name)
	}
}

// requeue puts selected unacked messages back at the head of their queues,
// in delivery order, marked redelivered.
func requeue(ch *channel, sel func(uint64) bool) {
	var tags []uint64
	for t := range ch.unacked {
		if sel(t) {
			tags = append(tags, t)
		}
	}
	sortTags(tags)
	for i := len(tags) - 1; i >= 0; i-- {
		u := ch.unacked[tags[i]]
		delete(ch.unacked, tags[i])
		u.m.Redelivered = true
		u.q.msgs = append([]*Message{u.m}, u.q.msgs...)
	}
}

func sortTags(t []uint64) {
	for i := 1; i < len(t); i++ {
		for j := i; j > 0 && t[j] < t[j-1]; j-- {
			t[j], t[j-1] = t[j-1], t[j]
		}
	}
}

func (c *conn) serve() {
	defer c.b.wg.Done()
	defer c.nc.Close()
	defer c.shutdown()
	r := bufio.NewReader(c.nc)
	if err := c.handshake(r); err != nil {
		return
	}
	for {
		f, err := readFrame(r, c.frameMax)
		if err != nil {
			return
		}
		if !c.handle(f) {
			return
		}
	}
}

func (c *conn) handshake(r *bufio.Reader) error {
	hdr := make([]byte, 8)
	if _, err := readFull(r, hdr); err != nil {
		return err
	}
	if !bytes.Equal(hdr, protocolHeader) {
		c.nc.Write(protocolHeader)
		return fmt.Errorf("bad protocol header")
	}
	start := method(10, 10).octet(0).octet(9).table(map[string]any{
		"product": "netkit-amqpfake", "version": "0.1",
		"capabilities": map[string]any{"publisher_confirms": true, "basic.nack": true, "consumer_cancel_notify": true},
	}).longstr([]byte("PLAIN AMQPLAIN EXTERNAL")).longstr([]byte("en_US"))
	c.send(0, start.b)

	f, err := readFrame(r, 0)
	if err != nil {
		return err
	}
	a := &args{b: f.payload}
	if a.short() != 10 || a.short() != 11 {
		return fmt.Errorf("expected connection.start-ok")
	}
	a.table()
	mech := a.shortstr()
	resp := a.longstr()
	if c.b.users != nil {
		ok := false
		if mech == "PLAIN" {
			parts := strings.Split(string(resp), "\x00")
			if len(parts) == 3 {
				pw, found := c.b.users[parts[1]]
				ok = found && pw == parts[2]
			}
		}
		if !ok {
			c.send(0, method(10, 50).short(403).shortstr("ACCESS_REFUSED - Login was refused using authentication mechanism "+mech).short(0).short(0).b)
			return fmt.Errorf("auth failed")
		}
	}
	c.send(0, method(10, 30).short(2047).long(131072).short(0).b)
	f, err = readFrame(r, 0)
	if err != nil {
		return err
	}
	a = &args{b: f.payload}
	if a.short() != 10 || a.short() != 31 {
		return fmt.Errorf("expected connection.tune-ok")
	}
	a.short()
	c.frameMax = a.long()
	f, err = readFrame(r, c.frameMax)
	if err != nil {
		return err
	}
	a = &args{b: f.payload}
	if a.short() != 10 || a.short() != 40 {
		return fmt.Errorf("expected connection.open")
	}
	vhost := a.shortstr()
	c.b.mu.Lock()
	c.b.vhosts = append(c.b.vhosts, vhost)
	c.b.mu.Unlock()
	c.send(0, method(10, 41).shortstr("").b)
	return nil
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// channelError closes a channel with an exception. Caller holds b.mu.
func (c *conn) channelError(ch *channel, code uint16, text string, class, id uint16) {
	c.cleanupChannel(ch)
	c.channels[ch.id] = &channel{id: ch.id, c: c, closing: true, unacked: map[uint64]unacked{}, consumers: map[string]*consumer{}}
	c.send(ch.id, method(20, 40).short(code).shortstr(text).short(class).short(id).b)
}

// handle processes one frame; it returns false to close the connection.
func (c *conn) handle(f frame) bool {
	b := c.b
	b.mu.Lock()
	defer b.mu.Unlock()
	switch f.typ {
	case frameHeartbeat:
		return true
	case frameHeader, frameBody:
		ch := c.channels[f.channel]
		if ch == nil || ch.closing || ch.pending == nil {
			return true
		}
		p := ch.pending
		if f.typ == frameHeader {
			a := &args{b: f.payload}
			a.short()
			a.short()
			p.size = a.longlong()
			p.props = append([]byte(nil), a.b...)
			p.haveHeader = true
		} else {
			p.body.Write(f.payload)
		}
		if p.haveHeader && uint64(p.body.Len()) >= p.size {
			ch.pending = nil
			c.completePublish(ch, p)
		}
		return true
	case frameMethod:
	default:
		return false
	}
	a := &args{b: f.payload}
	class, id := a.short(), a.short()
	if class == 10 {
		switch id {
		case 50:
			c.send(0, method(10, 51).b)
			return false
		case 51:
			return false
		}
		c.send(0, method(10, 50).short(540).shortstr("NOT_IMPLEMENTED").short(class).short(id).b)
		return false
	}
	ch := c.channels[f.channel]
	if class == 20 && id == 10 {
		c.channels[f.channel] = &channel{id: f.channel, c: c, unacked: map[uint64]unacked{}, consumers: map[string]*consumer{}}
		c.send(f.channel, method(20, 11).longstr(nil).b)
		return true
	}
	if ch == nil {
		c.send(0, method(10, 50).short(504).shortstr("CHANNEL_ERROR - unknown channel").short(class).short(id).b)
		return false
	}
	if ch.closing {
		if class == 20 && (id == 41 || id == 40) {
			if id == 40 {
				c.send(ch.id, method(20, 41).b)
			}
			delete(c.channels, ch.id)
		}
		return true
	}
	switch {
	case class == 20 && id == 40: // channel.close
		c.cleanupChannel(ch)
		c.send(ch.id, method(20, 41).b)
		b.dispatch()
	case class == 20 && id == 20: // channel.flow
		active := a.octet()
		c.send(ch.id, method(20, 21).octet(active).b)
	case class == 40 && id == 10: // exchange.declare
		a.short()
		name, kind := a.shortstr(), a.shortstr()
		bits := a.octet()
		a.table()
		ex, ok := b.exchanges[name]
		switch {
		case !ok && a.bit(bits, 0):
			c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no exchange '%s' in vhost '/'", name), class, id)
			return true
		case ok && !a.bit(bits, 0) && ex.kind != kind:
			c.channelError(ch, 406, fmt.Sprintf("PRECONDITION_FAILED - inequivalent arg 'type' for exchange '%s'", name), class, id)
			return true
		case !ok:
			b.exchanges[name] = &exchange{name: name, kind: kind}
		}
		if !a.bit(bits, 4) {
			c.send(ch.id, method(40, 11).b)
		}
	case class == 40 && id == 20: // exchange.delete
		a.short()
		name := a.shortstr()
		bits := a.octet()
		delete(b.exchanges, name)
		if !a.bit(bits, 1) {
			c.send(ch.id, method(40, 21).b)
		}
	case class == 50 && id == 10: // queue.declare
		a.short()
		name := a.shortstr()
		bits := a.octet()
		a.table()
		passive, exclusive, autoDel, noWait := a.bit(bits, 0), a.bit(bits, 2), a.bit(bits, 3), a.bit(bits, 4)
		q, ok := b.queues[name]
		if !ok && passive {
			c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no queue '%s' in vhost '/'", name), class, id)
			return true
		}
		if !ok {
			if name == "" {
				name = b.newName("amq.gen-")
			}
			q = &queue{name: name, autoDelete: autoDel}
			if exclusive {
				q.owner = c
			}
			b.queues[name] = q
		}
		if !noWait {
			c.send(ch.id, method(50, 11).shortstr(q.name).long(uint32(len(q.msgs))).long(uint32(len(q.consumers))).b)
		}
	case class == 50 && (id == 20 || id == 50): // queue.bind / unbind
		a.short()
		qn, en, key := a.shortstr(), a.shortstr(), a.shortstr()
		noWait := false
		if id == 20 {
			noWait = a.bit(a.octet(), 0)
		}
		a.table()
		ex, ok := b.exchanges[en]
		if !ok || en == "" {
			c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no exchange '%s' in vhost '/'", en), class, id)
			return true
		}
		if _, ok := b.queues[qn]; !ok {
			c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no queue '%s' in vhost '/'", qn), class, id)
			return true
		}
		if id == 20 {
			ex.bindings = append(ex.bindings, binding{queue: qn, key: key})
			if !noWait {
				c.send(ch.id, method(50, 21).b)
			}
		} else {
			for i, bd := range ex.bindings {
				if bd.queue == qn && bd.key == key {
					ex.bindings = append(ex.bindings[:i], ex.bindings[i+1:]...)
					break
				}
			}
			c.send(ch.id, method(50, 51).b)
		}
	case class == 50 && id == 30: // queue.purge
		a.short()
		q := b.queues[a.shortstr()]
		n := 0
		if q != nil {
			n = len(q.msgs)
			q.msgs = nil
		}
		c.send(ch.id, method(50, 31).long(uint32(n)).b)
	case class == 50 && id == 40: // queue.delete
		a.short()
		name := a.shortstr()
		n := 0
		if q := b.queues[name]; q != nil {
			n = len(q.msgs)
			delete(b.queues, name)
		}
		c.send(ch.id, method(50, 41).long(uint32(n)).b)
	case class == 60 && id == 10: // basic.qos
		a.long()
		ch.prefetch = int(a.short())
		c.send(ch.id, method(60, 11).b)
		b.dispatch()
	case class == 60 && id == 20: // basic.consume
		a.short()
		qn, tag := a.shortstr(), a.shortstr()
		bits := a.octet()
		a.table()
		q, ok := b.queues[qn]
		if !ok {
			c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no queue '%s' in vhost '/'", qn), class, id)
			return true
		}
		if tag == "" {
			tag = b.newName("amq.ctag-")
		}
		cons := &consumer{tag: tag, ch: ch, noAck: a.bit(bits, 1), q: q}
		ch.consumers[tag] = cons
		q.consumers = append(q.consumers, cons)
		if !a.bit(bits, 3) {
			c.send(ch.id, method(60, 21).shortstr(tag).b)
		}
		b.dispatch()
	case class == 60 && id == 30: // basic.cancel
		tag := a.shortstr()
		noWait := a.bit(a.octet(), 0)
		if cons, ok := ch.consumers[tag]; ok {
			c.removeConsumer(cons)
			delete(ch.consumers, tag)
		}
		if !noWait {
			c.send(ch.id, method(60, 31).shortstr(tag).b)
		}
	case class == 60 && id == 40: // basic.publish
		a.short()
		ex, key := a.shortstr(), a.shortstr()
		bits := a.octet()
		ch.pending = &pendingPublish{exchange: ex, key: key, mandatory: a.bit(bits, 0)}
	case class == 60 && id == 70: // basic.get
		a.short()
		qn := a.shortstr()
		noAck := a.bit(a.octet(), 0)
		q, ok := b.queues[qn]
		if !ok {
			c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no queue '%s' in vhost '/'", qn), class, id)
			return true
		}
		if len(q.msgs) == 0 {
			c.send(ch.id, method(60, 72).shortstr("").b)
			return true
		}
		m := q.msgs[0]
		q.msgs = q.msgs[1:]
		ch.nextTag++
		if !noAck {
			ch.unacked[ch.nextTag] = unacked{q: q, m: m}
		}
		e := method(60, 71).longlong(ch.nextTag).octet(boolBit(m.Redelivered)).shortstr(m.Exchange).shortstr(m.RoutingKey).long(uint32(len(q.msgs)))
		c.sendContent(ch.id, e.b, m)
	case class == 60 && (id == 80 || id == 90 || id == 120): // ack / reject / nack
		tag := a.longlong()
		bits := a.octet()
		multiple, requeueIt := false, false
		switch id {
		case 80:
			multiple = a.bit(bits, 0)
		case 90:
			requeueIt = a.bit(bits, 0)
		case 120:
			multiple, requeueIt = a.bit(bits, 0), a.bit(bits, 1)
		}
		sel := func(t uint64) bool { return t == tag || (multiple && (tag == 0 || t <= tag)) }
		if _, ok := ch.unacked[tag]; !ok && !multiple {
			c.channelError(ch, 406, fmt.Sprintf("PRECONDITION_FAILED - unknown delivery tag %d", tag), class, id)
			return true
		}
		if requeueIt {
			requeue(ch, sel)
		} else {
			for t := range ch.unacked {
				if sel(t) {
					delete(ch.unacked, t)
				}
			}
		}
		b.dispatch()
	case class == 60 && (id == 100 || id == 110): // basic.recover
		requeue(ch, func(uint64) bool { return true })
		if id == 110 {
			c.send(ch.id, method(60, 111).b)
		}
		b.dispatch()
	case class == 85 && id == 10: // confirm.select
		ch.confirm = true
		if !a.bit(a.octet(), 0) {
			c.send(ch.id, method(85, 11).b)
		}
	case class == 90: // tx.*
		c.send(ch.id, method(90, id+1).b)
	default:
		c.send(0, method(10, 50).short(540).shortstr(fmt.Sprintf("NOT_IMPLEMENTED - method %d.%d", class, id)).short(class).short(id).b)
		return false
	}
	return true
}

// completePublish routes a fully received publish. Caller holds b.mu.
func (c *conn) completePublish(ch *channel, p *pendingPublish) {
	b := c.b
	ex, ok := b.exchanges[p.exchange]
	if !ok {
		c.channelError(ch, 404, fmt.Sprintf("NOT_FOUND - no exchange '%s' in vhost '/'", p.exchange), 60, 40)
		return
	}
	m := &Message{Exchange: p.exchange, RoutingKey: p.key, Mandatory: p.mandatory, Props: p.props, Body: p.body.Bytes()}
	routed := b.route(ex, m)
	if !routed && p.mandatory {
		e := method(60, 50).short(312).shortstr("NO_ROUTE").shortstr(p.exchange).shortstr(p.key)
		c.sendContent(ch.id, e.b, m)
	}
	if ch.confirm {
		ch.publishSeq++
		if b.nackExchange != "" && p.exchange == b.nackExchange {
			c.send(ch.id, method(60, 120).longlong(ch.publishSeq).octet(0).b)
		} else {
			c.send(ch.id, method(60, 80).longlong(ch.publishSeq).octet(0).b)
		}
	}
	b.dispatch()
}
