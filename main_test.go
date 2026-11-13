package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools"
)

// Tools per group, from Plan.md §2.1-2.8.
var planTools = map[string][]string{
	tools.GroupHTTP: {
		"http_request", "http_form_request", "http_multipart_request", "http_upload",
		"jsonrpc_request", "xmlrpc_request", "graphql_request", "graphql_introspect",
		"graphql_subscribe", "sse_listen", "fetch_web", "curl_to_request",
	},
	tools.GroupGRPC: {
		"grpc_describe", "grpc_unary_request", "grpc_stream_request", "grpc_stream_open",
		"grpc_stream_send", "grpc_stream_recv", "grpc_stream_close", "grpc_health_check",
		"grpcweb_request", "connect_request",
	},
	tools.GroupWS: {
		"ws_exchange", "ws_connect", "ws_send", "ws_receive", "ws_close", "ws_list",
		"sio_exchange", "sio_connect", "sio_emit", "sio_receive", "sio_close",
	},
	tools.GroupSOAP: {"soap_describe", "soap_request"},
	tools.GroupMQTT: {"mqtt_publish", "mqtt_subscribe"},
	tools.GroupMessaging: {
		"amqp_publish", "amqp_consume", "nats_publish", "nats_request", "nats_subscribe",
		"kafka_produce", "kafka_consume", "coap_request", "stomp_send", "stomp_subscribe",
	},
	tools.GroupTransfer: {
		"tus_upload", "s3_multipart_upload", "sftp_upload", "sftp_download", "sftp_list",
		"ftp_upload", "ftp_download", "ftp_list",
	},
	tools.GroupLowLevel: {"tcp_request", "udp_request", "dns_query", "tls_inspect"},
	tools.GroupMCP:      {"mcp_client_list_tools", "mcp_client_call_tool"},
	tools.GroupAuth: {
		"oauth2_get_token", "oauth2_auth_url", "oauth2_exchange_code",
		"oauth2_device_start", "oauth2_device_poll",
	},
}

func expectedTools(groups ...string) []string {
	out := []string{"netkit_info"}
	for _, g := range groups {
		out = append(out, planTools[g]...)
	}
	sort.Strings(out)
	return out
}

// startServer parses args like main does, wires the real server and
// connects an in-memory client.
func startServer(t *testing.T, args ...string) *mcp.ClientSession {
	t.Helper()
	dir := t.TempDir()
	args = append([]string{"--allow-write-dir", dir}, args...)
	o, err := parseOptions(args, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := tools.NewDeps(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(deps, o.groups, o.logger)
	ctx, cancel := context.WithCancel(context.Background())
	ct, st := mcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "main-test", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cs.Close()
		ss.Close()
		deps.Sessions.CloseAll()
		cancel()
	})
	return cs
}

func listTools(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var names []string
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func diff(got, want []string) (missing, extra []string) {
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			extra = append(extra, g)
		}
	}
	return
}

func assertTools(t *testing.T, got, want []string) {
	t.Helper()
	if missing, extra := diff(got, want); len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("registered tools differ from Plan.md\nmissing: %v\nextra:   %v", missing, extra)
	}
	for i := 1; i < len(got); i++ {
		if got[i] == got[i-1] {
			t.Fatalf("tool %s registered twice", got[i])
		}
	}
}

func TestDefaultGroupsMatchPlan(t *testing.T) {
	// Plan.md §2.9: http, grpc, ws, soap, auth and MQTT are on by default.
	want := []string{tools.GroupHTTP, tools.GroupGRPC, tools.GroupWS, tools.GroupSOAP, tools.GroupAuth, tools.GroupMQTT}
	if !sameSet(tools.DefaultGroups, want) {
		t.Fatalf("DefaultGroups %v, plan says %v", tools.DefaultGroups, want)
	}
	cs := startServer(t)
	assertTools(t, listTools(t, cs), expectedTools(want...))

	// The explicit "default" keyword is the same set.
	assertTools(t, listTools(t, startServer(t, "--groups", "default")), expectedTools(want...))
}

func TestAllGroups(t *testing.T) {
	got := listTools(t, startServer(t, "--groups", "all"))
	assertTools(t, got, expectedTools(tools.AllGroups...))
	for _, name := range []string{"jsonrpc_request", "xmlrpc_request", "sse_listen", "fetch_web", "netkit_info"} {
		if !slices.Contains(got, name) {
			t.Errorf("%s not registered with --groups all", name)
		}
	}
}

func TestSelectedGroups(t *testing.T) {
	// "messaging" implies mqtt; netkit_info is always present.
	got := listTools(t, startServer(t, "--groups", "lowlevel, messaging"))
	assertTools(t, got, expectedTools(tools.GroupLowLevel, tools.GroupMessaging, tools.GroupMQTT))

	// netkit_info reports the enabled groups.
	cs := startServer(t, "--groups", "soap")
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "netkit_info", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("netkit_info: %v %+v", err, res)
	}
	m, _ := res.StructuredContent.(map[string]any)
	if gs, _ := m["enabled_groups"].([]any); len(gs) != 1 || gs[0] != "soap" {
		t.Fatalf("enabled_groups %v", m["enabled_groups"])
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	sort.Strings(a)
	sort.Strings(b)
	return slices.Equal(a, b)
}

func TestParseOptions(t *testing.T) {
	env := map[string]string{
		"NETKIT_GROUPS":           "http",
		"NETKIT_PRIVATE_NETWORKS": "deny",
		"NETKIT_ALLOW_HOSTS":      "a.example, *.b.example",
		"NETKIT_ALLOW_PORTS":      "80,443",
	}
	o, err := parseOptions([]string{"--allow-ports", "8080", "--max-timeout", "5s", "--transport", "http", "--http-token", "t"},
		func(k string) string { return env[k] }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !o.groups[tools.GroupHTTP] || o.groups[tools.GroupGRPC] || o.cfg.PrivateMode != config.PrivateDeny {
		t.Fatalf("groups %v private %s", o.groups, o.cfg.PrivateMode)
	}
	if !slices.Equal(o.cfg.AllowHosts, []string{"a.example", "*.b.example"}) || !slices.Equal(o.cfg.AllowPorts, []int{80, 443, 8080}) {
		t.Fatalf("hosts %v ports %v", o.cfg.AllowHosts, o.cfg.AllowPorts)
	}
	if o.cfg.MaxTimeout != 5*time.Second || o.cfg.DefaultTimeout != 5*time.Second {
		t.Fatalf("timeouts %s %s (default must be clamped to the ceiling)", o.cfg.MaxTimeout, o.cfg.DefaultTimeout)
	}
	if o.transport != "http" || o.token != "t" || o.httpPath != "/mcp" {
		t.Fatalf("%+v", o)
	}

	for _, bad := range [][]string{
		{"--groups", "bogus"},
		{"--private-networks", "maybe"},
		{"--allow-ports", "70000"},
		{"--transport", "carrier-pigeon"},
		{"--log-level", "loud"},
		{"--transport", "http", "--path", "mcp"},
		{"stray"},
	} {
		if _, err := parseOptions(bad, func(string) string { return "" }, io.Discard); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}

	var out bytes.Buffer
	if err := run(context.Background(), []string{"--version"}, func(string) string { return "" }, &out, io.Discard); err != nil || !strings.Contains(out.String(), config.Version) {
		t.Fatalf("--version: %v %q", err, out.String())
	}
}

// bearerTransport adds an Authorization header to every request.
type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestStreamableHTTPBearer(t *testing.T) {
	o, err := parseOptions([]string{"--transport", "http", "--http-token", "s3cret", "--groups", "http"}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := tools.NewDeps(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(httpHandler(newServer(deps, o.groups, o.logger), o.httpPath, o.token, o.logger))
	defer hs.Close()
	endpoint := hs.URL + o.httpPath

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`
	post := func(auth string) *http.Response {
		req, _ := http.NewRequest("POST", endpoint, strings.NewReader(initBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	for _, auth := range []string{"", "Bearer wrong", "Basic czNjcmV0", "s3cret", "Bearer s3cret-and-more"} {
		resp := post(auth)
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Fatalf("auth %q: status %d (want 401 with WWW-Authenticate)", auth, resp.StatusCode)
		}
	}
	for _, auth := range []string{"Bearer s3cret", "bearer s3cret"} {
		if resp := post(auth); resp.StatusCode != http.StatusOK {
			t.Fatalf("auth %q: status %d", auth, resp.StatusCode)
		}
	}

	// /healthz is open.
	resp, err := http.Get(hs.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", err, resp)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connect := func(token string) (*mcp.ClientSession, error) {
		tr := &mcp.StreamableClientTransport{
			Endpoint:             endpoint,
			HTTPClient:           &http.Client{Transport: bearerTransport{token}},
			MaxRetries:           -1,
			DisableStandaloneSSE: true,
		}
		return mcp.NewClient(&mcp.Implementation{Name: "http-test", Version: "test"}, nil).Connect(ctx, tr, nil)
	}
	if cs, err := connect("Bearer nope"); err == nil {
		cs.Close()
		t.Fatal("client connected with a wrong token")
	}
	cs, err := connect("Bearer s3cret")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	// Stateless streamable HTTP speaks the newest MCP revision (Plan §8).
	if v := cs.InitializeResult().ProtocolVersion; v != "2026-07-28" {
		t.Fatalf("negotiated MCP protocol %q over HTTP, want 2026-07-28", v)
	}
	assertTools(t, listTools(t, cs), expectedTools(tools.GroupHTTP))

	// A tool call works over the stateless transport.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "curl_to_request", Arguments: map[string]any{"command": "curl https://example.com"}})
	if err != nil || res.IsError {
		t.Fatalf("curl_to_request over HTTP: %v %+v", err, res)
	}
}

// TestProtocolVersionInProcess reports what a current SDK client negotiates
// over a session-based transport (the stdio case).
func TestProtocolVersionInProcess(t *testing.T) {
	o, err := parseOptions([]string{"--groups", "http"}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	deps, err := tools.NewDeps(o.cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := newServer(deps, o.groups, o.logger).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "v", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	v := cs.InitializeResult().ProtocolVersion
	t.Logf("negotiated MCP protocol over a session transport: %s", v)
	if v < "2025-11-25" {
		t.Fatalf("negotiated %q, want 2025-11-25 or newer", v)
	}
}
