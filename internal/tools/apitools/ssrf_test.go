package apitools_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/HamedFathi/NetKitMCP/internal/config"
	"github.com/HamedFathi/NetKitMCP/internal/tools/tooltest"
	"github.com/HamedFathi/NetKitMCP/internal/types"
)

// TestSSRFGuard checks that every tool refuses a loopback target in opt-in
// mode unless allow_private is set, and that a blocked call never reaches
// the server.
func TestSSRFGuard(t *testing.T) {
	h := newHarness(t, tooltest.WithPrivateMode(config.PrivateOptIn))
	var hits atomic.Int32
	srv := server(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case r.URL.Path == "/ws":
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"graphql-transport-ws"}})
			if err != nil {
				return
			}
			defer c.CloseNow()
			ctx := r.Context()
			c.Read(ctx) // connection_init
			c.Write(ctx, websocket.MessageText, []byte(`{"type":"connection_ack"}`))
			c.Read(ctx) // subscribe
			c.Write(ctx, websocket.MessageText, []byte(`{"id":"1","type":"complete"}`))
			c.Read(ctx)
		case r.URL.Path == "/sse" || r.Header.Get("Accept") == "text/event-stream":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "event: complete\ndata: ok\n\n")
		case r.URL.Path == "/xml":
			w.Header().Set("Content-Type", "text/xml")
			io.WriteString(w, `<methodResponse><params><param><value><int>1</int></value></param></params></methodResponse>`)
		case r.URL.Path == "/rpc":
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": 1, "result": true})
		case r.URL.Path == "/intro":
			w.Header().Set("Content-Type", "application/json")
			w.Write(testdata(t, "graphqlx/testdata/introspection.json"))
		case r.URL.Path == "/page":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "hello")
		default:
			writeJSON(w, map[string]any{"data": map[string]any{"ok": true}})
		}
	})
	ws := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	localhost := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	cases := []struct {
		tool string
		args map[string]any
	}{
		{"graphql_request", map[string]any{"url": srv.URL + "/gql", "query": "{ ok }"}},
		{"graphql_request", map[string]any{"url": localhost + "/gql", "query": "{ ok }"}},
		{"graphql_introspect", map[string]any{"url": srv.URL + "/intro"}},
		{"graphql_subscribe", map[string]any{"url": ws, "query": "subscription { x }"}},
		{"graphql_subscribe", map[string]any{"url": srv.URL + "/sse", "query": "subscription { x }", "protocol": "sse"}},
		{"jsonrpc_request", map[string]any{"url": srv.URL + "/rpc", "method": "m"}},
		{"xmlrpc_request", map[string]any{"url": srv.URL + "/xml", "method": "m"}},
		{"sse_listen", map[string]any{"url": srv.URL + "/sse"}},
		{"fetch_web", map[string]any{"url": srv.URL + "/page"}},
		{"fetch_web", map[string]any{"url": "http://[::1]:1/page"}},
	}
	// No subtests: the harness reports through the parent *testing.T.
	for i, c := range cases {
		func() {
			before := hits.Load()
			timed(t, 10*time.Second, func() {
				h.MustFail(c.tool, c.args, "allow_private")
			})
			if hits.Load() != before {
				t.Fatalf("case %d %s: blocked call reached the server", i, c.tool)
			}
			if strings.Contains(c.args["url"].(string), "[::1]:1") {
				return
			}
			args := map[string]any{}
			for k, v := range c.args {
				args[k] = v
			}
			args["allow_private"] = true
			r := h.MustOK(c.tool, args)
			if hits.Load() == before {
				t.Fatalf("case %d %s: allowed call did not reach the server", i, c.tool)
			}
			var sr types.StreamResult
			if json.Unmarshal(r.Raw, &sr) == nil && sr.EndedBy == types.EndedError {
				t.Fatalf("case %d %s: stream failed: %s", i, c.tool, r.Raw)
			}
		}()
	}
}
