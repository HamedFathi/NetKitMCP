// Package amqpx wraps github.com/rabbitmq/amqp091-go for the AMQP 0-9-1
// tools: guarded dialing, JSON <-> AMQP table conversion and message
// property mapping.
package amqpx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/HamedFathi/NetKitMCP/internal/netguard"
)

// DialOptions configure a guarded AMQP connection.
type DialOptions struct {
	// Dialer is the SSRF-guarded dialer every connection goes through.
	Dialer *netguard.Dialer
	// TLS is used for amqps:// URLs. When nil an empty config is used (never
	// the URL's cacertfile/certfile/keyfile parameters, which would bypass
	// the file policy).
	TLS *tls.Config
	// Username/Password override credentials embedded in the URL when
	// Username or Password is non-empty.
	Username, Password string
	// Mechanism is PLAIN (default), AMQPLAIN or EXTERNAL.
	Mechanism string
	// Vhost overrides the URL's virtual host when non-empty.
	Vhost string
	// Heartbeat is the requested heartbeat interval (0 = library default).
	Heartbeat time.Duration
	// Timeout bounds the TCP connect, TLS handshake and AMQP handshake.
	Timeout time.Duration
}

// ParseURL validates an amqp:// or amqps:// URL.
func ParseURL(raw string) (amqp.URI, error) {
	u, err := amqp.ParseURI(strings.TrimSpace(raw))
	if err != nil {
		return u, fmt.Errorf("invalid AMQP url (expected amqp://user:pass@host:5672/vhost or amqps://...): %w", err)
	}
	return u, nil
}

// Dial opens a connection through the guard. TLS (for amqps) is layered by
// the library on top of the guarded TCP connection.
func Dial(ctx context.Context, rawURL string, o DialOptions) (*amqp.Connection, error) {
	if o.Dialer == nil {
		return nil, fmt.Errorf("amqpx: no dialer")
	}
	uri, err := ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	if err := o.Dialer.CheckHost(uri.Host); err != nil {
		return nil, err
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cfg := amqp.Config{
		Vhost:     o.Vhost,
		Heartbeat: o.Heartbeat,
		Locale:    "en_US",
	}
	props := amqp.NewConnectionProperties()
	props.SetClientConnectionName("netkit-mcp")
	cfg.Properties = props

	user, pass := uri.Username, uri.Password
	if o.Username != "" || o.Password != "" {
		user, pass = o.Username, o.Password
	}
	mech := strings.ToUpper(strings.TrimSpace(o.Mechanism))
	if mech == "" && len(uri.AuthMechanism) > 0 {
		mech = strings.ToUpper(uri.AuthMechanism[0])
	}
	switch mech {
	case "", "PLAIN":
		cfg.SASL = []amqp.Authentication{&amqp.PlainAuth{Username: user, Password: pass}}
	case "AMQPLAIN":
		cfg.SASL = []amqp.Authentication{&amqp.AMQPlainAuth{Username: user, Password: pass}}
	case "EXTERNAL":
		cfg.SASL = []amqp.Authentication{&amqp.ExternalAuth{}}
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism %q (use PLAIN, AMQPLAIN or EXTERNAL)", o.Mechanism)
	}
	if uri.Scheme == "amqps" {
		if o.TLS != nil {
			cfg.TLSClientConfig = o.TLS.Clone()
		} else {
			cfg.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
	}
	cfg.Dial = func(network, addr string) (net.Conn, error) {
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		c, err := o.Dialer.DialContext(dctx, network, addr)
		if err != nil {
			return nil, err
		}
		// Bound the TLS and AMQP handshakes; the library clears the
		// deadline once the connection is open.
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := c.SetDeadline(deadline); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	conn, err := amqp.DialConfig(strings.TrimSpace(rawURL), cfg)
	if err != nil {
		return nil, describeDialError(err)
	}
	return conn, nil
}

func describeDialError(err error) error {
	switch {
	case errors.Is(err, amqp.ErrSASL):
		return fmt.Errorf("AMQP authentication failed: no SASL mechanism accepted by the server: %w", err)
	case errors.Is(err, amqp.ErrCredentials):
		return fmt.Errorf("AMQP authentication failed (check username/password): %w", err)
	case errors.Is(err, amqp.ErrVhost):
		return fmt.Errorf("AMQP virtual host not accessible: %w", err)
	}
	var e *amqp.Error
	if errors.As(err, &e) && e.Code == amqp.AccessRefused {
		return fmt.Errorf("AMQP access refused (check credentials and vhost permissions): %w", err)
	}
	return fmt.Errorf("AMQP connect: %w", err)
}

// TLSState returns the TLS connection state when the connection uses TLS.
func TLSState(c *amqp.Connection) *tls.ConnectionState {
	cs := c.ConnectionState()
	if !cs.HandshakeComplete {
		return nil
	}
	return &cs
}
