package amqpx

import (
	"fmt"
	"strings"

	amqp "github.com/rabbitmq/amqp091-go"
)

// ExchangeDecl declares an exchange.
type ExchangeDecl struct {
	Name       string         `json:"name" jsonschema:"exchange name"`
	Type       string         `json:"type,omitempty" jsonschema:"direct (default), fanout, topic, headers or a plugin type"`
	Durable    bool           `json:"durable,omitempty"`
	AutoDelete bool           `json:"auto_delete,omitempty"`
	Internal   bool           `json:"internal,omitempty"`
	Passive    bool           `json:"passive,omitempty" jsonschema:"only check that the exchange exists"`
	Arguments  map[string]any `json:"arguments,omitempty" jsonschema:"x-arguments, e.g. alternate-exchange"`
}

// QueueDecl declares a queue. An empty name asks the server to generate one.
type QueueDecl struct {
	Name       string         `json:"name,omitempty" jsonschema:"queue name (empty = server-generated)"`
	Durable    bool           `json:"durable,omitempty"`
	AutoDelete bool           `json:"auto_delete,omitempty"`
	Exclusive  bool           `json:"exclusive,omitempty" jsonschema:"exclusive to this connection (deleted when the call ends)"`
	Passive    bool           `json:"passive,omitempty" jsonschema:"only check that the queue exists (returns its message count)"`
	Arguments  map[string]any `json:"arguments,omitempty" jsonschema:"x-arguments, e.g. x-message-ttl, x-queue-type, x-dead-letter-exchange"`
}

// BindingDecl binds a queue to an exchange.
type BindingDecl struct {
	Queue      string         `json:"queue,omitempty" jsonschema:"queue name (default: the declared queue)"`
	Exchange   string         `json:"exchange" jsonschema:"source exchange"`
	RoutingKey string         `json:"routing_key,omitempty" jsonschema:"binding key (topic patterns allowed for topic exchanges)"`
	Arguments  map[string]any `json:"arguments,omitempty" jsonschema:"binding arguments, e.g. x-match for headers exchanges"`
}

// Declare is the optional topology set up before publishing or consuming.
type Declare struct {
	Exchange *ExchangeDecl `json:"exchange,omitempty"`
	Queue    *QueueDecl    `json:"queue,omitempty"`
	Bindings []BindingDecl `json:"bindings,omitempty"`
}

// QueueInfo reports a declared queue.
type QueueInfo struct {
	Name      string `json:"name"`
	Messages  int    `json:"messages"`
	Consumers int    `json:"consumers"`
}

// DeclareResult describes what was declared.
type DeclareResult struct {
	Exchange string     `json:"exchange,omitempty"`
	Queue    *QueueInfo `json:"queue,omitempty"`
	Bindings int        `json:"bindings,omitempty"`
}

// Apply declares the topology on ch. It is a no-op for a nil receiver.
func (d *Declare) Apply(ch *amqp.Channel) (*DeclareResult, error) {
	if d == nil {
		return nil, nil
	}
	res := &DeclareResult{}
	if e := d.Exchange; e != nil {
		if strings.TrimSpace(e.Name) == "" {
			return nil, fmt.Errorf("declare.exchange.name is required")
		}
		kind := e.Type
		if kind == "" {
			kind = amqp.ExchangeDirect
		}
		args, err := ToTable(e.Arguments)
		if err != nil {
			return nil, fmt.Errorf("declare.exchange.arguments: %w", err)
		}
		if e.Passive {
			err = ch.ExchangeDeclarePassive(e.Name, kind, e.Durable, e.AutoDelete, e.Internal, false, args)
		} else {
			err = ch.ExchangeDeclare(e.Name, kind, e.Durable, e.AutoDelete, e.Internal, false, args)
		}
		if err != nil {
			return nil, fmt.Errorf("exchange.declare %q: %w", e.Name, err)
		}
		res.Exchange = e.Name
	}
	if q := d.Queue; q != nil {
		args, err := ToTable(q.Arguments)
		if err != nil {
			return nil, fmt.Errorf("declare.queue.arguments: %w", err)
		}
		var dq amqp.Queue
		if q.Passive {
			dq, err = ch.QueueDeclarePassive(q.Name, q.Durable, q.AutoDelete, q.Exclusive, false, args)
		} else {
			dq, err = ch.QueueDeclare(q.Name, q.Durable, q.AutoDelete, q.Exclusive, false, args)
		}
		if err != nil {
			return nil, fmt.Errorf("queue.declare %q: %w", q.Name, err)
		}
		res.Queue = &QueueInfo{Name: dq.Name, Messages: dq.Messages, Consumers: dq.Consumers}
	}
	for i, b := range d.Bindings {
		queue := b.Queue
		if queue == "" && res.Queue != nil {
			queue = res.Queue.Name
		}
		if queue == "" {
			return nil, fmt.Errorf("declare.bindings[%d]: queue is required (or declare a queue)", i)
		}
		args, err := ToTable(b.Arguments)
		if err != nil {
			return nil, fmt.Errorf("declare.bindings[%d].arguments: %w", i, err)
		}
		if err := ch.QueueBind(queue, b.RoutingKey, b.Exchange, false, args); err != nil {
			return nil, fmt.Errorf("queue.bind %q -> %q: %w", b.Exchange, queue, err)
		}
		res.Bindings++
	}
	return res, nil
}
