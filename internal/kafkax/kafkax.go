// Package kafkax builds github.com/twmb/franz-go clients whose broker
// connections go through the SSRF guard, plus helpers for parsing the Kafka
// tool options (acks, compression, start offsets, SASL).
package kafkax

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/HamedFathi/NetKitMCP/internal/netguard"
)

// SASL holds SASL credentials.
type SASL struct {
	Mechanism string // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
	Username  string
	Password  string
}

// ClientOptions configure a guarded client.
type ClientOptions struct {
	Brokers  []string
	Dialer   *netguard.Dialer
	TLS      *tls.Config // nil = plaintext
	SASL     *SASL
	ClientID string
	Timeout  time.Duration
	// OnTLS, when set, is called with the state of each completed TLS handshake.
	OnTLS func(tls.ConnectionState)
}

// NormalizeBrokers trims and validates seed brokers, adding the default
// port 9092 when missing. URL-ish prefixes (kafka://, tcp://) are stripped.
func NormalizeBrokers(in []string) ([]string, error) {
	var out []string
	for _, b := range in {
		for _, part := range strings.Split(b, ",") {
			s := strings.TrimSpace(part)
			if s == "" {
				continue
			}
			if i := strings.Index(s, "://"); i >= 0 {
				s = s[i+3:]
			}
			s = strings.TrimSuffix(s, "/")
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(strings.Trim(s, "[]"), "9092")
			}
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("brokers is required (host:port of at least one seed broker)")
	}
	return out, nil
}

// Build returns the franz-go SASL mechanism.
func (s *SASL) Build() (sasl.Mechanism, error) {
	if s == nil {
		return nil, nil
	}
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s.Mechanism), "_", "-")) {
	case "", "PLAIN":
		return plain.Auth{User: s.Username, Pass: s.Password}.AsMechanism(), nil
	case "SCRAM-SHA-256":
		return scram.Auth{User: s.Username, Pass: s.Password}.AsSha256Mechanism(), nil
	case "SCRAM-SHA-512":
		return scram.Auth{User: s.Username, Pass: s.Password}.AsSha512Mechanism(), nil
	}
	return nil, fmt.Errorf("unsupported SASL mechanism %q (use PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512)", s.Mechanism)
}

// Opts returns the base client options: seeds, guarded dialer (with TLS
// layered on top), SASL and timeouts. Every broker address learned from
// metadata is dialed through the same guarded function.
func (o ClientOptions) Opts() ([]kgo.Opt, error) {
	if o.Dialer == nil {
		return nil, fmt.Errorf("kafkax: no dialer")
	}
	seeds, err := NormalizeBrokers(o.Brokers)
	if err != nil {
		return nil, err
	}
	for _, s := range seeds {
		if err := o.Dialer.CheckAddress(s); err != nil {
			return nil, err
		}
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	g := o.Dialer
	tlsCfg := o.TLS
	dial := func(ctx context.Context, network, host string) (net.Conn, error) {
		c, err := g.DialContext(ctx, network, host)
		if err != nil || tlsCfg == nil {
			return c, err
		}
		cfg := tlsCfg.Clone()
		if cfg.ServerName == "" {
			if h, _, err := net.SplitHostPort(host); err == nil {
				cfg.ServerName = h
			}
		}
		tc := tls.Client(c, cfg)
		hctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			c.Close()
			return nil, fmt.Errorf("TLS handshake with %s: %w", host, err)
		}
		if o.OnTLS != nil {
			o.OnTLS(tc.ConnectionState())
		}
		return tc, nil
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(seeds...),
		kgo.Dialer(dial),
		kgo.DialTimeout(timeout),
		kgo.RequestRetries(2),
		kgo.RetryTimeout(timeout),
		kgo.ClientID(clientID(o.ClientID)),
		kgo.SoftwareNameAndVersion("netkit-mcp", "1"),
		kgo.DisableClientMetrics(),
	}
	if o.SASL != nil {
		m, err := o.SASL.Build()
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.SASL(m))
	}
	return opts, nil
}

func clientID(s string) string {
	if s == "" {
		return "netkit-mcp"
	}
	return s
}

// Acks parses all|leader|none (also -1, 1, 0).
func Acks(s string) (kgo.Acks, bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "all", "-1":
		return kgo.AllISRAcks(), true, nil
	case "leader", "1":
		return kgo.LeaderAck(), false, nil
	case "none", "0":
		return kgo.NoAck(), false, nil
	}
	return kgo.Acks{}, false, fmt.Errorf("acks must be all, leader or none")
}

// Compression parses none|gzip|snappy|lz4|zstd.
func Compression(s string) (kgo.CompressionCodec, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return kgo.NoCompression(), nil
	case "gzip":
		return kgo.GzipCompression(), nil
	case "snappy":
		return kgo.SnappyCompression(), nil
	case "lz4":
		return kgo.Lz4Compression(), nil
	case "zstd":
		return kgo.ZstdCompression(), nil
	}
	return kgo.CompressionCodec{}, fmt.Errorf("compression must be none, gzip, snappy, lz4 or zstd")
}

// StartOffset parses a consume start position.
//
//	earliest | latest           log start / end
//	offset   (n = offset)       exact offset
//	tail     (n = count)        n records before the end
//	timestamp (ts)              first record at or after ts (RFC 3339 or unix ms)
func StartOffset(start string, n *int64, ts string) (kgo.Offset, error) {
	switch strings.ToLower(strings.TrimSpace(start)) {
	case "", "earliest", "beginning", "start":
		return kgo.NewOffset().AtStart(), nil
	case "latest", "end":
		return kgo.NewOffset().AtEnd(), nil
	case "offset":
		if n == nil || *n < 0 {
			return kgo.Offset{}, fmt.Errorf("start=offset requires a non-negative offset")
		}
		return kgo.NewOffset().At(*n), nil
	case "tail":
		if n == nil || *n <= 0 {
			return kgo.Offset{}, fmt.Errorf("start=tail requires offset = number of records before the end (> 0)")
		}
		return kgo.NewOffset().AtEnd().Relative(-*n), nil
	case "timestamp":
		ms, err := ParseMillis(ts)
		if err != nil {
			return kgo.Offset{}, err
		}
		return kgo.NewOffset().AfterMilli(ms), nil
	}
	return kgo.Offset{}, fmt.Errorf("start must be earliest, latest, offset, tail or timestamp")
}

// ParseMillis parses RFC 3339 or unix milliseconds.
func ParseMillis(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("timestamp is required (RFC 3339 or unix milliseconds)")
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return 0, fmt.Errorf("timestamp: expected RFC 3339 or unix milliseconds, got %q", s)
	}
	return t.UnixMilli(), nil
}

type explicitKey struct{}

// WithExplicitPartition marks a record so Partitioner keeps its Partition.
func WithExplicitPartition(r *kgo.Record, p int32) {
	r.Partition = p
	r.Context = context.WithValue(context.Background(), explicitKey{}, true)
}

// Partitioner honors explicit partitions (see WithExplicitPartition) and
// otherwise partitions like the Java client (murmur2 on the key, sticky for
// keyless records).
func Partitioner() kgo.Partitioner {
	return explicitPartitioner{kgo.StickyKeyPartitioner(nil)}
}

type explicitPartitioner struct{ inner kgo.Partitioner }

func (p explicitPartitioner) ForTopic(t string) kgo.TopicPartitioner {
	return &explicitTopic{inner: p.inner.ForTopic(t)}
}

type explicitTopic struct{ inner kgo.TopicPartitioner }

func isExplicit(r *kgo.Record) bool {
	return r.Context != nil && r.Context.Value(explicitKey{}) != nil
}

func (t *explicitTopic) RequiresConsistency(r *kgo.Record) bool {
	return isExplicit(r) || t.inner.RequiresConsistency(r)
}

func (t *explicitTopic) Partition(r *kgo.Record, n int) int {
	if isExplicit(r) {
		return int(r.Partition)
	}
	return t.inner.Partition(r, n)
}

func (t *explicitTopic) OnNewBatch() {
	if nb, ok := t.inner.(kgo.TopicPartitionerOnNewBatch); ok {
		nb.OnNewBatch()
	}
}
