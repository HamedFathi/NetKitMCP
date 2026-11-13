package mqttx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/netguard"
)

// ParseBroker parses a broker URL. A bare host[:port] means tcp://. Default
// ports: 1883 (tcp, mqtt), 8883 (ssl, tls, mqtts), 80 (ws), 443 (wss).
// WebSocket URLs without a path get "/mqtt".
func ParseBroker(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("broker is required (e.g. tcp://host:1883)")
	}
	if !strings.Contains(raw, "://") {
		raw = "tcp://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid broker URL: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	var port string
	switch u.Scheme {
	case "tcp", "mqtt":
		port = "1883"
	case "ssl", "tls", "mqtts", "tcps":
		port = "8883"
	case "ws":
		port = "80"
	case "wss":
		port = "443"
	default:
		return nil, fmt.Errorf("unsupported broker scheme %q (use tcp, mqtt, ssl, tls, mqtts, ws or wss)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("broker URL %q has no host", raw)
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), port)
	}
	if IsWebSocket(u.Scheme) && (u.Path == "" || u.Path == "/") && u.RawPath == "" {
		u.Path = "/mqtt"
	}
	return u, nil
}

// IsTLS reports whether the scheme uses TLS.
func IsTLS(scheme string) bool {
	switch scheme {
	case "ssl", "tls", "mqtts", "tcps", "wss":
		return true
	}
	return false
}

// IsWebSocket reports whether the scheme is MQTT over WebSocket.
func IsWebSocket(scheme string) bool { return scheme == "ws" || scheme == "wss" }

// DialConfig describes how to reach a broker.
type DialConfig struct {
	URL    *url.URL
	Dialer *netguard.Dialer // TCP schemes
	// TLS is used for ssl/tls/mqtts. ServerName defaults to the URL host.
	TLS *tls.Config
	// HTTPClient performs the WebSocket handshake (ws/wss). It must be a
	// guarded HTTP/1.1 client; its TLS settings apply to wss.
	HTTPClient *http.Client
	// Header is sent with the WebSocket handshake.
	Header http.Header
}

// Dial opens the network connection for a broker URL. It returns the TLS
// connection state when TLS was negotiated.
func Dial(ctx context.Context, dc DialConfig) (net.Conn, *tls.ConnectionState, error) {
	u := dc.URL
	if IsWebSocket(u.Scheme) {
		if dc.HTTPClient == nil {
			return nil, nil, fmt.Errorf("mqttx: websocket dial needs an HTTP client")
		}
		wu := *u
		wu.User = nil
		c, resp, err := websocket.Dial(ctx, wu.String(), &websocket.DialOptions{
			HTTPClient:   dc.HTTPClient,
			HTTPHeader:   dc.Header,
			Subprotocols: []string{"mqtt"},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("websocket connect to %s: %w", wu.Redacted(), err)
		}
		var cs *tls.ConnectionState
		if resp != nil && resp.TLS != nil {
			st := *resp.TLS
			cs = &st
		}
		return websocket.NetConn(context.Background(), c, websocket.MessageBinary), cs, nil
	}
	if dc.Dialer == nil {
		return nil, nil, fmt.Errorf("mqttx: no dialer")
	}
	conn, err := dc.Dialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, nil, err
	}
	if !IsTLS(u.Scheme) {
		return conn, nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if dc.TLS != nil {
		cfg = dc.TLS.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("TLS handshake with %s: %w", u.Host, err)
	}
	st := tc.ConnectionState()
	return tc, &st, nil
}
