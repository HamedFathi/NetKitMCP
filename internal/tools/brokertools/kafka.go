package brokertools

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/HamedFathi/NetKitMCP/internal/auth"
	"github.com/HamedFathi/NetKitMCP/internal/kafkax"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

type kafkaSASLIn struct {
	Mechanism string `json:"mechanism,omitempty" jsonschema:"PLAIN (default), SCRAM-SHA-256 or SCRAM-SHA-512"`
	Username  string `json:"username,omitempty" jsonschema:"SASL username (default: from auth basic)"`
	Password  string `json:"password,omitempty" jsonschema:"SASL password (default: from auth basic)"`
}

type kafkaConnIn struct {
	Brokers  []string     `json:"brokers" jsonschema:"seed brokers as host:port (default port 9092)"`
	SASL     *kafkaSASLIn `json:"sasl,omitempty" jsonschema:"SASL authentication; auth basic alone implies SASL PLAIN"`
	TLS      bool         `json:"tls,omitempty" jsonschema:"connect with TLS (implied by ca_cert, client_cert, server_name, insecure_skip_verify or auth mtls)"`
	ClientID string       `json:"client_id,omitempty" jsonschema:"Kafka client.id (default netkit-mcp)"`
	types.NetOptions
	Auth *auth.Config `json:"auth,omitempty" jsonschema:"basic (SASL username/password) or mtls"`
}

type kafkaRecordIn struct {
	Key       *types.Payload    `json:"key,omitempty" jsonschema:"record key (text, json, base64 or file); omitted = null key"`
	Value     *types.Payload    `json:"value,omitempty" jsonschema:"record value (text, json, base64 or file); omitted = null value (tombstone)"`
	Headers   map[string]string `json:"headers,omitempty" jsonschema:"record headers"`
	Partition *int32            `json:"partition,omitempty" jsonschema:"explicit partition (default: murmur2 hash of the key, like the Java client)"`
	Topic     string            `json:"topic,omitempty" jsonschema:"override the call's topic for this record"`
	Timestamp string            `json:"timestamp,omitempty" jsonschema:"record timestamp, RFC 3339 or unix milliseconds (default: now)"`
}

type kafkaProduceIn struct {
	kafkaConnIn
	Topic                  string          `json:"topic,omitempty" jsonschema:"topic for records that do not set their own"`
	Records                []kafkaRecordIn `json:"records" jsonschema:"records to produce, in order"`
	Acks                   string          `json:"acks,omitempty" jsonschema:"all (default), leader or none"`
	Compression            string          `json:"compression,omitempty" jsonschema:"none (default), gzip, snappy, lz4 or zstd"`
	Idempotent             *bool           `json:"idempotent,omitempty" jsonschema:"idempotent producer (default true; requires acks=all)"`
	AllowAutoTopicCreation bool            `json:"allow_auto_topic_creation,omitempty" jsonschema:"let the broker auto-create a missing topic (if enabled on the broker)"`
}

type kafkaRecordResult struct {
	Index     int    `json:"index"`
	Topic     string `json:"topic"`
	Partition int32  `json:"partition"`
	Offset    int64  `json:"offset"`
	Timestamp string `json:"timestamp,omitempty"`
	SizeBytes int    `json:"size_bytes"`
	Error     string `json:"error,omitempty"`
}

type kafkaProduceOut struct {
	Brokers     []string            `json:"brokers"`
	Results     []kafkaRecordResult `json:"results"`
	Produced    int                 `json:"produced"`
	Failed      int                 `json:"failed"`
	Acks        string              `json:"acks"`
	Compression string              `json:"compression"`
	Idempotent  bool                `json:"idempotent"`
	TLS         *types.TLSInfo      `json:"tls,omitempty"`
	TimingMS    map[string]float64  `json:"timing_ms"`
	Warnings    []string            `json:"warnings,omitempty"`
}

type kafkaConsumeIn struct {
	kafkaConnIn
	Topics           []string         `json:"topics" jsonschema:"topics to consume"`
	Start            string           `json:"start,omitempty" jsonschema:"earliest (default), latest, offset (uses offset), tail (last <offset> records per partition) or timestamp (uses timestamp)"`
	Offset           *int64           `json:"offset,omitempty" jsonschema:"offset for start=offset, or record count for start=tail"`
	Timestamp        string           `json:"timestamp,omitempty" jsonschema:"for start=timestamp: RFC 3339 or unix milliseconds"`
	Partitions       []int32          `json:"partitions,omitempty" jsonschema:"only these partitions (direct consuming, no group)"`
	PartitionOffsets map[string]int64 `json:"partition_offsets,omitempty" jsonschema:"exact start offset per partition, e.g. {\"0\": 42, \"3\": 0} (direct consuming, no group)"`
	Group            string           `json:"group,omitempty" jsonschema:"consumer group id (default: none, read partitions directly without committing)"`
	Commit           bool             `json:"commit,omitempty" jsonschema:"with group: commit offsets of the returned records"`
	IsolationLevel   string           `json:"isolation_level,omitempty" jsonschema:"read_uncommitted (default) or read_committed"`
	types.StreamLimits
	MaxResponseBytes int64 `json:"max_response_bytes,omitempty" jsonschema:"maximum total value bytes returned (default 1 MiB)"`
}

func registerKafka(s *mcp.Server, d *tools.Deps) {
	tools.Add(s, d, "kafka_produce", "Kafka produce",
		"Produce records to Kafka and wait for the broker acks. Each record has key/value (text, json, base64 or file), headers and an optional partition. "+
			"Supports acks (all/leader/none), compression (gzip/snappy/lz4/zstd), idempotence (default on), SASL PLAIN/SCRAM and TLS. "+
			"Returns partition, offset, timestamp or error per record.",
		tools.Mutating, func(ctx context.Context, req *mcp.CallToolRequest, in kafkaProduceIn) (any, error) {
			return kafkaProduce(ctx, d, in)
		})
	tools.Add(s, d, "kafka_consume", "Kafka consume",
		"Bounded consume from Kafka topics: collects up to max_messages within max_duration_seconds (or until idle). "+
			"start: earliest (default), latest, offset, tail or timestamp; or exact partition_offsets. Without group, partitions are read directly and nothing is committed; "+
			"with group (and commit=true) offsets of returned records are committed. Returns topic, partition, offset, timestamp, key, value and headers.",
		tools.ReadOnly, func(ctx context.Context, req *mcp.CallToolRequest, in kafkaConsumeIn) (any, error) {
			return kafkaConsume(ctx, d, in)
		})
}

type kafkaClient struct {
	cl       *kgo.Client
	brokers  []string
	mu       sync.Mutex
	tlsState *tls.ConnectionState
	opts     types.TLSOptions
	warnings []string
}

func (k *kafkaClient) tlsInfo() *types.TLSInfo {
	k.mu.Lock()
	defer k.mu.Unlock()
	return tlsInfo(k.tlsState, k.opts)
}

func newKafkaClient(ctx context.Context, d *tools.Deps, in kafkaConnIn, timeout time.Duration, extra ...kgo.Opt) (*kafkaClient, error) {
	brokers, err := kafkax.NormalizeBrokers(in.Brokers)
	if err != nil {
		return nil, err
	}
	k := &kafkaClient{brokers: brokers, opts: in.TLSOptions}
	o := kafkax.ClientOptions{
		Brokers:  brokers,
		Dialer:   d.Guard.Dialer(in.AllowPrivate, timeout),
		ClientID: in.ClientID,
		Timeout:  timeout,
		OnTLS: func(cs tls.ConnectionState) {
			k.mu.Lock()
			if k.tlsState == nil {
				k.tlsState = &cs
			}
			k.mu.Unlock()
		},
	}
	if in.TLS || wantsTLS(in.TLSOptions, in.Auth) {
		if o.TLS, err = tlsConfig(d, in.TLSOptions, in.Auth, ""); err != nil {
			return nil, err
		}
		k.warnings = insecureWarnings(in.TLSOptions)
	}
	user, pass, err := credentials(in.Auth)
	if err != nil {
		return nil, err
	}
	if in.SASL != nil {
		o.SASL = &kafkax.SASL{Mechanism: in.SASL.Mechanism, Username: in.SASL.Username, Password: in.SASL.Password}
		if o.SASL.Username == "" && o.SASL.Password == "" {
			o.SASL.Username, o.SASL.Password = user, pass
		}
	} else if user != "" || pass != "" {
		o.SASL = &kafkax.SASL{Mechanism: "PLAIN", Username: user, Password: pass}
	}
	opts, err := o.Opts()
	if err != nil {
		return nil, err
	}
	cl, err := kgo.NewClient(append(opts, extra...)...)
	if err != nil {
		return nil, fmt.Errorf("kafka client: %w", err)
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := cl.Ping(pctx); err != nil {
		cl.Close()
		return nil, fmt.Errorf("cannot reach any Kafka broker (%s): %w", strings.Join(brokers, ", "), err)
	}
	k.cl = cl
	return k, nil
}

func kafkaProduce(ctx context.Context, d *tools.Deps, in kafkaProduceIn) (any, error) {
	if len(in.Records) == 0 {
		return nil, fmt.Errorf("records is required (at least one record)")
	}
	if len(in.Records) > d.Cfg.MaxMessages {
		return nil, fmt.Errorf("at most %d records per call", d.Cfg.MaxMessages)
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	acks, all, err := kafkax.Acks(in.Acks)
	if err != nil {
		return nil, err
	}
	codec, err := kafkax.Compression(in.Compression)
	if err != nil {
		return nil, err
	}
	idem := types.BoolDefault(in.Idempotent, true)
	if !all {
		if in.Idempotent != nil && *in.Idempotent {
			return nil, fmt.Errorf("idempotent=true requires acks=all")
		}
		idem = false
	}

	records := make([]*kgo.Record, len(in.Records))
	var total int64
	maxRecord := 0
	for i, ri := range in.Records {
		topic := ri.Topic
		if topic == "" {
			topic = in.Topic
		}
		if topic == "" {
			return nil, fmt.Errorf("records[%d]: topic is required (set topic on the call or the record)", i)
		}
		r := &kgo.Record{Topic: topic}
		if !ri.Key.IsZero() {
			if r.Key, _, _, err = payload(d, ri.Key); err != nil {
				return nil, fmt.Errorf("records[%d].key: %w", i, err)
			}
			if r.Key == nil {
				r.Key = []byte{}
			}
		}
		if !ri.Value.IsZero() {
			if r.Value, _, _, err = payload(d, ri.Value); err != nil {
				return nil, fmt.Errorf("records[%d].value: %w", i, err)
			}
			if r.Value == nil {
				r.Value = []byte{}
			}
		}
		for k, v := range ri.Headers {
			r.Headers = append(r.Headers, kgo.RecordHeader{Key: k, Value: []byte(v)})
		}
		if ri.Timestamp != "" {
			msTS, err := kafkax.ParseMillis(ri.Timestamp)
			if err != nil {
				return nil, fmt.Errorf("records[%d]: %w", i, err)
			}
			r.Timestamp = time.UnixMilli(msTS)
		}
		if ri.Partition != nil {
			if *ri.Partition < 0 {
				return nil, fmt.Errorf("records[%d]: partition must be >= 0", i)
			}
			kafkax.WithExplicitPartition(r, *ri.Partition)
		}
		size := len(r.Key) + len(r.Value)
		total += int64(size)
		if size > maxRecord {
			maxRecord = size
		}
		records[i] = r
	}
	if total > maxBrokerPayload {
		return nil, fmt.Errorf("records total %d bytes, above the %d byte limit per call", total, maxBrokerPayload)
	}
	batchMax := int32(1 << 20)
	if need := int32(maxRecord + 64<<10); need > batchMax {
		batchMax = need
	}
	extra := []kgo.Opt{
		kgo.RequiredAcks(acks),
		kgo.ProducerBatchCompression(codec),
		kgo.RecordPartitioner(kafkax.Partitioner()),
		kgo.RecordDeliveryTimeout(timeout),
		kgo.ProduceRequestTimeout(timeout),
		kgo.ProducerBatchMaxBytes(batchMax),
		kgo.ProducerLinger(0),
	}
	if !idem {
		extra = append(extra, kgo.DisableIdempotentWrite())
	}
	if in.AllowAutoTopicCreation {
		extra = append(extra, kgo.AllowAutoTopicCreation())
	}
	start := time.Now()
	k, err := newKafkaClient(ctx, d, in.kafkaConnIn, timeout, extra...)
	if err != nil {
		return nil, err
	}
	defer k.cl.Close()
	connMS := ms(start)
	pstart := time.Now()
	results := k.cl.ProduceSync(ctx, records...)
	out := &kafkaProduceOut{
		Brokers: k.brokers, Acks: strings.ToLower(defaultStr(in.Acks, "all")), Compression: strings.ToLower(defaultStr(in.Compression, "none")),
		Idempotent: idem, Warnings: k.warnings,
		TimingMS: map[string]float64{"connect": connMS, "produce": ms(pstart), "total": ms(start)},
	}
	for i, pr := range results {
		res := kafkaRecordResult{Index: i, Topic: pr.Record.Topic, Partition: pr.Record.Partition, Offset: pr.Record.Offset,
			SizeBytes: len(pr.Record.Key) + len(pr.Record.Value)}
		if !pr.Record.Timestamp.IsZero() {
			res.Timestamp = pr.Record.Timestamp.UTC().Format(time.RFC3339Nano)
		}
		if pr.Err != nil {
			res.Error = pr.Err.Error()
			res.Offset = -1
			out.Failed++
		} else {
			out.Produced++
		}
		out.Results = append(out.Results, res)
	}
	out.TLS = k.tlsInfo()
	return out, nil
}

func defaultStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return strings.TrimSpace(s)
}

func kafkaConsume(ctx context.Context, d *tools.Deps, in kafkaConsumeIn) (any, error) {
	var topics []string
	for _, t := range in.Topics {
		if t = strings.TrimSpace(t); t != "" {
			topics = append(topics, t)
		}
	}
	if len(topics) == 0 {
		return nil, fmt.Errorf("topics is required")
	}
	timeout := d.Cfg.Timeout(in.TimeoutSeconds)
	n, dur, idle := in.StreamLimits.Resolve(d.Cfg.DefaultMaxMessages, d.Cfg.MaxMessages, d.Cfg.DefaultStreamTime, d.Cfg.MaxStreamTime)
	startOff, err := kafkax.StartOffset(in.Start, in.Offset, in.Timestamp)
	if err != nil {
		return nil, err
	}
	direct := len(in.Partitions) > 0 || len(in.PartitionOffsets) > 0
	if in.Group != "" && direct {
		return nil, fmt.Errorf("partitions/partition_offsets cannot be combined with group (group assignment decides partitions)")
	}
	if in.Commit && in.Group == "" {
		return nil, fmt.Errorf("commit requires group")
	}
	extra := []kgo.Opt{kgo.FetchMaxWait(500 * time.Millisecond)}
	switch strings.ToLower(strings.TrimSpace(in.IsolationLevel)) {
	case "", "read_uncommitted":
	case "read_committed":
		extra = append(extra, kgo.FetchIsolationLevel(kgo.ReadCommitted()))
	default:
		return nil, fmt.Errorf("isolation_level must be read_uncommitted or read_committed")
	}
	switch {
	case in.Group != "":
		extra = append(extra, kgo.ConsumerGroup(in.Group), kgo.ConsumeTopics(topics...), kgo.ConsumeResetOffset(startOff), kgo.DisableAutoCommit())
	case direct:
		parts := map[int32]kgo.Offset{}
		for _, p := range in.Partitions {
			parts[p] = startOff
		}
		for ps, off := range in.PartitionOffsets {
			p, err := strconv.ParseInt(strings.TrimSpace(ps), 10, 32)
			if err != nil || p < 0 {
				return nil, fmt.Errorf("partition_offsets: key %q is not a partition number", ps)
			}
			if off < 0 {
				return nil, fmt.Errorf("partition_offsets[%s]: offset must be >= 0", ps)
			}
			parts[int32(p)] = kgo.NewOffset().At(off)
		}
		m := map[string]map[int32]kgo.Offset{}
		for _, t := range topics {
			m[t] = parts
		}
		extra = append(extra, kgo.ConsumePartitions(m))
	default:
		extra = append(extra, kgo.ConsumeTopics(topics...), kgo.ConsumeResetOffset(startOff))
	}

	ctx, cancel := context.WithTimeout(ctx, timeout+dur+5*time.Second)
	defer cancel()
	k, err := newKafkaClient(ctx, d, in.kafkaConnIn, timeout, extra...)
	if err != nil {
		return nil, err
	}
	defer k.cl.Close()

	coll := types.NewCollector(n, dur, idle, d.Cfg.ResponseBytes(in.MaxResponseBytes))
	pctx, pcancel := context.WithCancel(ctx)
	var (
		mu       sync.Mutex
		accepted []*kgo.Record
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			fs := k.cl.PollFetches(pctx)
			if fs.IsClientClosed() || pctx.Err() != nil {
				return
			}
			var ferr error
			fs.EachError(func(t string, p int32, err error) {
				if ferr == nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					ferr = fmt.Errorf("fetch %s[%d]: %w", t, p, err)
				}
			})
			for _, r := range fs.Records() {
				if !coll.Add(kafkaMessage(r)) {
					return
				}
				mu.Lock()
				accepted = append(accepted, r)
				mu.Unlock()
			}
			if ferr != nil {
				coll.Finish(types.EndedError, ferr)
				return
			}
		}
	}()
	res := coll.Wait(ctx)
	pcancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
	meta := map[string]any{
		"brokers": k.brokers,
		"topics":  topics,
		"start":   defaultStr(in.Start, "earliest"),
	}
	if in.Group != "" {
		meta["group"] = in.Group
		meta["committed"] = false
	}
	mu.Lock()
	recs := append([]*kgo.Record(nil), accepted...)
	mu.Unlock()
	if in.Commit && len(recs) > 0 {
		cctx, ccancel := context.WithTimeout(context.Background(), timeout)
		err := k.cl.CommitRecords(cctx, recs...)
		ccancel()
		if err != nil {
			meta["commit_error"] = err.Error()
		} else {
			meta["committed"] = true
			meta["committed_offsets"] = nextOffsets(recs)
		}
	}
	if ti := k.tlsInfo(); ti != nil {
		meta["tls"] = ti
	}
	if len(k.warnings) > 0 {
		meta["warnings"] = k.warnings
	}
	res.Meta = meta
	return res, nil
}

// nextOffsets returns topic -> partition -> next offset to read.
func nextOffsets(recs []*kgo.Record) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for _, r := range recs {
		m := out[r.Topic]
		if m == nil {
			m = map[string]int64{}
			out[r.Topic] = m
		}
		key := strconv.Itoa(int(r.Partition))
		if r.Offset+1 > m[key] {
			m[key] = r.Offset + 1
		}
	}
	return out
}

func kafkaMessage(r *kgo.Record) types.StreamMessage {
	data, enc, typ := encodeBody(r.Value, "")
	meta := map[string]any{
		"partition":  r.Partition,
		"offset":     r.Offset,
		"timestamp":  r.Timestamp.UTC().Format(time.RFC3339Nano),
		"size_bytes": len(r.Value),
	}
	if r.Value == nil {
		meta["null_value"] = true
	}
	if r.Key != nil {
		kd, ke := types.EncodeBody(r.Key, "")
		meta["key"] = kd
		meta["key_encoding"] = ke
	}
	var headers map[string]string
	var binHeaders []string
	for _, h := range r.Headers {
		if headers == nil {
			headers = map[string]string{}
		}
		if utf8.Valid(h.Value) {
			headers[h.Key] = string(h.Value)
		} else {
			v, _ := types.EncodeBody(h.Value, "application/octet-stream")
			headers[h.Key] = v
			binHeaders = append(binHeaders, h.Key)
		}
	}
	if len(binHeaders) > 0 {
		meta["base64_headers"] = binHeaders
	}
	return types.StreamMessage{
		Dir: "in", Type: typ, Topic: r.Topic,
		ID:   fmt.Sprintf("%s/%d/%d", r.Topic, r.Partition, r.Offset),
		Data: data, Encoding: enc, Headers: headers, Meta: meta,
	}
}
