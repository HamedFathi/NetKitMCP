package brokertools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/HamedFathi/NetKitMCP/internal/amqpx"
	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/redact"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type amqpConnIn struct {
	URL              string  `json:"url" jsonschema:"amqp://user:pass@host:5672/vhost or amqps://... (vhost is the URL path; %2F for /)"`
	Vhost            string  `json:"vhost,omitempty" jsonschema:"override the virtual host from the URL"`
	SASLMechanism    string  `json:"sasl_mechanism,omitempty" jsonschema:"PLAIN (default), AMQPLAIN or EXTERNAL (client certificate)"`
	HeartbeatSeconds float64 `json:"heartbeat_seconds,omitempty" jsonschema:"requested heartbeat interval (default 10)"`
	types.NetOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"credentials: basic (username/password), bearer (token as password) or mtls; default: credentials in the URL"`
}

type amqpPublishIn struct {
	amqpConnIn
	Exchange   string            `json:"exchange,omitempty" jsonschema:"exchange to publish to (default \"\" = default exchange, routing_key = queue name)"`
	RoutingKey string            `json:"routing_key,omitempty" jsonschema:"routing key"`
	Payload    *types.Payload    `json:"payload,omitempty" jsonschema:"message body: text, json, base64 or file"`
	Properties *amqpx.Properties `json:"properties,omitempty" jsonschema:"message properties and headers"`
	Mandatory  bool              `json:"mandatory,omitempty" jsonschema:"ask the broker to return the message if it cannot be routed to any queue"`
	Confirm    *bool             `json:"confirm,omitempty" jsonschema:"use publisher confirms and wait for ack/nack (default true)"`
	Declare    *amqpx.Declare    `json:"declare,omitempty" jsonschema:"exchange/queue/bindings to declare before publishing"`
}

type amqpReturn struct {
	ReplyCode  int    `json:"reply_code"`
	ReplyText  string `json:"reply_text"`
	Exchange   string `json:"exchange"`
	RoutingKey string `json:"routing_key"`
}

type amqpPublishOut struct {
	Target     string               `json:"target"`
	Exchange   string               `json:"exchange"`
	RoutingKey string               `json:"routing_key"`
	SizeBytes  int                  `json:"size_bytes"`
	File       *types.FileInfo      `json:"file,omitempty"`
	Confirmed  string               `json:"confirm" jsonschema:"ack, nack or disabled"`
	Routed     *bool                `json:"routed,omitempty"`
	Returned   *amqpReturn          `json:"returned,omitempty"`
	Declared   *amqpx.DeclareResult `json:"declared,omitempty"`
	Server     map[string]any       `json:"server,omitempty"`
	TLS        *types.TLSInfo       `json:"tls,omitempty"`
	TimingMS   map[string]float64   `json:"timing_ms"`
	Warnings   []string             `json:"warnings,omitempty"`
}

type amqpConsumeIn struct {
	amqpConnIn
	Queue             string         `json:"queue,omitempty" jsonschema:"queue to consume from; when empty, a temporary exclusive queue is declared and bound to exchange"`
	Exchange          string         `json:"exchange,omitempty" jsonschema:"bind the queue (or a temporary queue) to this exchange before consuming"`
	RoutingKey        string         `json:"routing_key,omitempty" jsonschema:"binding key used with exchange (topic patterns allowed)"`
	BindingArguments  map[string]any `json:"binding_arguments,omitempty" jsonschema:"binding arguments (e.g. x-match for headers exchanges)"`
	Mode              string         `json:"mode,omitempty" jsonschema:"consume (default: push delivery, waits for messages) or get (basic.get polling; stops when the queue is empty)"`
	AckMode           string         `json:"ack_mode,omitempty" jsonschema:"ack (default: remove collected messages), reject (drop or dead-letter), requeue (peek: leave messages on the queue) or none (auto-ack)"`
	Prefetch          int            `json:"prefetch,omitempty" jsonschema:"basic.qos prefetch count (default: max_messages)"`
	ConsumerTag       string         `json:"consumer_tag,omitempty"`
	Exclusive         bool           `json:"exclusive,omitempty" jsonschema:"request exclusive consumer access"`
	ConsumerArguments map[string]any `json:"consumer_arguments,omitempty" jsonschema:"basic.consume arguments, e.g. x-stream-offset for streams"`
	Declare           *amqpx.Declare `json:"declare,omitempty" jsonschema:"exchange/queue/bindings to declare before consuming"`
	types.StreamLimits
	MaxResponseBytes int64 `json:"max_response_bytes,omitempty" jsonschema:"maximum total message bytes returned (default 1 MiB)"`
}

func registerAMQP(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "amqp_publish", "AMQP publish",
		"Publish one message to an AMQP 0-9-1 broker (RabbitMQ): exchange, routing_key, payload (text/json/base64/file), "+
			"properties (content_type, delivery_mode, headers, ...). Publisher confirms are on by default and the result reports ack/nack; "+
			"with mandatory=true an unroutable message is reported under returned. Optional declare sets up exchange/queue/bindings first.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in amqpPublishIn) (any, error) {
			return amqpPublish(ctx, d, in)
		})
	tools.Add(s, d, "amqp_consume", "AMQP consume",
		"Bounded consume from an AMQP 0-9-1 queue (RabbitMQ): collects up to max_messages within max_duration_seconds (or until idle). "+
			"Give queue, or exchange (+routing_key) to bind a temporary queue. ack_mode: ack (default), reject, requeue (peek without removing), none (auto-ack). "+
			"mode=get polls with basic.get and stops when the queue is empty. Returns body, properties, headers, delivery tag, redelivered flag, exchange and routing key.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in amqpConsumeIn) (any, error) {
			return amqpConsume(ctx, d, in)
		})
}

type amqpSession struct {
	conn     *amqp.Connection
	ch       *amqp.Channel
	target   string
	warnings []string
	tls      *types.TLSInfo
	server   map[string]any
	connMS   float64
}

func (s *amqpSession) close() {
	if s.ch != nil {
		s.ch.Close()
	}
	s.conn.Close()
}

func openAMQP(ctx context.Context, d *tools.Deps, in amqpConnIn, timeout time.Duration) (*amqpSession, error) {
	if strings.TrimSpace(in.URL) == "" {
		return nil, fmt.Errorf("url is required (amqp://user:pass@host:5672/vhost)")
	}
	uri, err := amqpx.ParseURL(in.URL)
	if err != nil {
		return nil, err
	}
	user, pass, err := credentials(in.Auth)
	if err != nil {
		return nil, err
	}
	o := amqpx.DialOptions{
		Dialer:    d.Guard.Dialer(in.AllowPrivate, timeout),
		Username:  user,
		Password:  pass,
		Mechanism: in.SASLMechanism,
		Vhost:     in.Vhost,
		Timeout:   timeout,
	}
	if in.HeartbeatSeconds > 0 {
		o.Heartbeat = time.Duration(in.HeartbeatSeconds * float64(time.Second))
	}
	if uri.Scheme == "amqps" {
		o.TLS, err = tlsConfig(d, in.TLSOptions, in.Auth, uri.Host)
		if err != nil {
			return nil, err
		}
	}
	start := time.Now()
	conn, err := amqpx.Dial(ctx, in.URL, o)
	if err != nil {
		return nil, err
	}
	s := &amqpSession{conn: conn, target: redact.URL(in.URL), connMS: ms(start)}
	if uri.Scheme == "amqps" {
		s.tls = tlsInfo(amqpx.TLSState(conn), in.TLSOptions)
		s.warnings = insecureWarnings(in.TLSOptions)
	}
	if p := conn.Properties; p != nil {
		s.server = map[string]any{}
		for _, k := range []string{"product", "version", "cluster_name", "platform"} {
			if v, ok := p[k]; ok {
				s.server[k] = fmt.Sprint(v)
			}
		}
	}
	s.ch, err = conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("open channel: %w", err)
	}
	return s, nil
}

func amqpPublish(ctx context.Context, d *tools.Deps, in amqpPublishIn) (any, error) {
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, ct, file, err := payload(d, in.Payload)
	if err != nil {
		return nil, err
	}
	pub, err := in.Properties.Publishing(body, ct)
	if err != nil {
		return nil, err
	}
	s, err := openAMQP(ctx, d, in.amqpConnIn, timeout)
	if err != nil {
		return nil, err
	}
	defer s.close()
	out := &amqpPublishOut{
		Target: s.target, Exchange: in.Exchange, RoutingKey: in.RoutingKey, SizeBytes: len(body), File: file,
		Server: s.server, TLS: s.tls, Warnings: s.warnings,
		TimingMS: map[string]float64{"connect": s.connMS},
	}
	closed := s.ch.NotifyClose(make(chan *amqp.Error, 1))
	returns := s.ch.NotifyReturn(make(chan amqp.Return, 1))
	if out.Declared, err = in.Declare.Apply(s.ch); err != nil {
		return nil, err
	}
	confirm := types.BoolDefault(in.Confirm, true)
	start := time.Now()
	if confirm {
		if err := s.ch.Confirm(false); err != nil {
			return nil, fmt.Errorf("confirm.select: %w", err)
		}
		dc, err := s.ch.PublishWithDeferredConfirmWithContext(ctx, in.Exchange, in.RoutingKey, in.Mandatory, false, pub)
		if err != nil {
			return nil, fmt.Errorf("publish: %w", err)
		}
		ack, err := dc.WaitContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("timed out waiting for the publisher confirm: %w", err)
		}
		if !ack {
			// A channel exception (e.g. missing exchange) also nacks.
			select {
			case e := <-closed:
				if e != nil {
					return nil, fmt.Errorf("broker closed the channel: %s (code %d)", e.Reason, e.Code)
				}
			case <-time.After(200 * time.Millisecond):
			}
			out.Confirmed = "nack"
		} else {
			out.Confirmed = "ack"
		}
	} else {
		out.Confirmed = "disabled"
		if err := s.ch.PublishWithContext(ctx, in.Exchange, in.RoutingKey, in.Mandatory, false, pub); err != nil {
			return nil, fmt.Errorf("publish: %w", err)
		}
		// Without confirms there is no completion signal; give the broker a
		// moment to report a channel error or a mandatory return.
		wait := 300 * time.Millisecond
		select {
		case e := <-closed:
			if e != nil {
				return nil, fmt.Errorf("broker closed the channel: %s (code %d)", e.Reason, e.Code)
			}
		case r := <-returns:
			returns <- r
		case <-time.After(wait):
		}
		if in.Mandatory {
			out.Warnings = append(out.Warnings, "without confirm, an unroutable-message return may arrive after the call ends")
		}
	}
	out.TimingMS["publish"] = ms(start)
	select {
	case r := <-returns:
		out.Returned = &amqpReturn{ReplyCode: int(r.ReplyCode), ReplyText: r.ReplyText, Exchange: r.Exchange, RoutingKey: r.RoutingKey}
	default:
	}
	if in.Mandatory && confirm {
		routed := out.Returned == nil
		out.Routed = &routed
	}
	out.TimingMS["total"] = out.TimingMS["connect"] + out.TimingMS["publish"]
	return out, nil
}

func amqpConsume(ctx context.Context, d *tools.Deps, in amqpConsumeIn) (any, error) {
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	n, dur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	ackMode := strings.ToLower(strings.TrimSpace(in.AckMode))
	switch ackMode {
	case "":
		ackMode = "ack"
	case "ack", "reject", "requeue", "none":
	default:
		return nil, fmt.Errorf("ack_mode must be ack, reject, requeue or none")
	}
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	switch mode {
	case "":
		mode = "consume"
	case "consume", "get":
	default:
		return nil, fmt.Errorf("mode must be consume or get")
	}
	consumerArgs, err := amqpx.ToTable(in.ConsumerArguments)
	if err != nil {
		return nil, fmt.Errorf("consumer_arguments: %w", err)
	}
	bindArgs, err := amqpx.ToTable(in.BindingArguments)
	if err != nil {
		return nil, fmt.Errorf("binding_arguments: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout+dur)
	defer cancel()
	dctx, dcancel := context.WithTimeout(ctx, timeout)
	defer dcancel()
	s, err := openAMQP(dctx, d, in.amqpConnIn, timeout)
	if err != nil {
		return nil, err
	}
	defer s.close()
	ch := s.ch
	closed := ch.NotifyClose(make(chan *amqp.Error, 1))

	declared, err := in.Declare.Apply(ch)
	if err != nil {
		return nil, err
	}
	queue := in.Queue
	if queue == "" && declared != nil && declared.Queue != nil {
		queue = declared.Queue.Name
	}
	temporary := false
	if queue == "" {
		if in.Exchange == "" {
			return nil, fmt.Errorf("queue is required (or give exchange to bind a temporary queue)")
		}
		q, err := ch.QueueDeclare("", false, true, true, false, nil)
		if err != nil {
			return nil, fmt.Errorf("declare temporary queue: %w", err)
		}
		queue, temporary = q.Name, true
	}
	if in.Exchange != "" {
		if err := ch.QueueBind(queue, in.RoutingKey, in.Exchange, false, bindArgs); err != nil {
			return nil, fmt.Errorf("bind queue %q to exchange %q: %w", queue, in.Exchange, err)
		}
	}
	autoAck := ackMode == "none"
	prefetch := in.Prefetch
	if prefetch <= 0 {
		prefetch = n
	}
	if prefetch > 65535 {
		prefetch = 65535
	}
	if !autoAck {
		if err := ch.Qos(prefetch, 0, false); err != nil {
			return nil, fmt.Errorf("basic.qos: %w", err)
		}
	}

	coll := types.NewCollector(n, dur, idle, d.Cfg.ResponseBytes(in.MaxResponseBytes))
	var (
		mu       sync.Mutex
		settled  int
		settleEr string
		dropped  int
	)
	settle := func(dl *amqp.Delivery) {
		var err error
		switch ackMode {
		case "ack":
			err = dl.Ack(false)
		case "reject":
			err = dl.Reject(false)
		default:
			return // requeue: left unacked, requeued when the channel closes; none: auto-acked
		}
		mu.Lock()
		if err != nil && settleEr == "" {
			settleEr = err.Error()
		} else if err == nil {
			settled++
		}
		mu.Unlock()
	}
	add := func(dl *amqp.Delivery, withCount bool) bool {
		data, enc, typ := encodeBody(dl.Body, dl.ContentType)
		meta := map[string]any{
			"delivery_tag": dl.DeliveryTag,
			"redelivered":  dl.Redelivered,
			"exchange":     dl.Exchange,
			"routing_key":  dl.RoutingKey,
			"size_bytes":   len(dl.Body),
		}
		if props := amqpx.DeliveryProperties(dl); len(props) > 0 {
			meta["properties"] = props
		}
		if withCount {
			meta["message_count"] = dl.MessageCount
		}
		if dl.ConsumerTag != "" {
			meta["consumer_tag"] = dl.ConsumerTag
		}
		return coll.Add(types.StreamMessage{Dir: "in", Type: typ, Topic: dl.RoutingKey, ID: dl.MessageId, Data: data, Encoding: enc, Meta: meta})
	}

	done := make(chan struct{})
	consumerTag := in.ConsumerTag
	if mode == "consume" {
		deliveries, err := ch.ConsumeWithContext(ctx, queue, consumerTag, autoAck, in.Exclusive, false, false, consumerArgs)
		if err != nil {
			return nil, fmt.Errorf("basic.consume on %q: %w", queue, err)
		}
		go func() {
			defer close(done)
			for dl := range deliveries {
				if !add(&dl, false) {
					if autoAck {
						mu.Lock()
						dropped++
						mu.Unlock()
					}
					continue
				}
				settle(&dl)
			}
			select {
			case e := <-closed:
				if e != nil {
					coll.Finish(types.EndedError, fmt.Errorf("broker closed the channel: %s (code %d)", e.Reason, e.Code))
					return
				}
			default:
			}
			coll.Finish(types.EndedPeerClosed, nil)
		}()
	} else {
		go func() {
			defer close(done)
			for {
				select {
				case <-coll.Done():
					return
				case <-ctx.Done():
					return
				default:
				}
				dl, ok, err := ch.Get(queue, autoAck)
				if err != nil {
					coll.Finish(types.EndedError, fmt.Errorf("basic.get on %q: %w", queue, err))
					return
				}
				if !ok {
					coll.Finish(types.EndedComplete, nil)
					return
				}
				if !add(&dl, true) {
					return
				}
				settle(&dl)
			}
		}()
	}
	res := coll.Wait(ctx)
	// Closing the channel cancels the consumer and requeues anything
	// delivered but not settled.
	ch.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	mu.Lock()
	defer mu.Unlock()
	res.Dropped = dropped
	meta := map[string]any{
		"target":    s.target,
		"queue":     queue,
		"mode":      mode,
		"ack_mode":  ackMode,
		"temporary": temporary,
	}
	if !autoAck {
		meta["prefetch"] = prefetch
		meta["settled"] = settled
	}
	if settleEr != "" {
		meta["settle_error"] = settleEr
	}
	if declared != nil {
		meta["declared"] = declared
	}
	if s.tls != nil {
		meta["tls"] = s.tls
	}
	if s.server != nil {
		meta["server"] = s.server
	}
	warnings := s.warnings
	if mode == "get" && res.EndedBy == types.EndedComplete {
		meta["queue_empty"] = true
	}
	if dropped > 0 {
		warnings = append(warnings, fmt.Sprintf("%d auto-acked message(s) arrived after the limit and were discarded; use ack_mode=ack to avoid losing messages", dropped))
	}
	if len(warnings) > 0 {
		meta["warnings"] = warnings
	}
	res.Meta = meta
	return res, nil
}
