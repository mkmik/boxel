package hub_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mkmik/boxel/internal/hub"
	"github.com/mkmik/boxel/internal/hubagent"
	"github.com/mkmik/boxel/internal/policy"
	"github.com/mkmik/boxel/internal/session"
	"github.com/mkmik/boxel/internal/tunnel"
)

// newTunnelServer builds a real leaf tunnel-mcp server over workspace ws in
// bypassPermissions (the pull-mode agent default), as a dispatch backend.
func newTunnelServer(t *testing.T, ws string) *mcp.Server {
	t.Helper()
	engine, err := policy.NewEngine(policy.Config{}, policy.ModeBypassPermissions, ws)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return tunnel.New(tunnel.Config{Engine: engine, Sessions: session.NewManager(ws, 0)})
}

// agentMux serves srv's MCP at /mcp the way a --hub-connect agent does
// in-process over the reverse channel.
func agentMux(srv *mcp.Server) http.Handler {
	m := http.NewServeMux()
	m.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true},
	))
	return m
}

// testLogf returns a t.Logf-backed logger plus a mute function. Tests `defer
// mute()` so the hub's and agents' background goroutines (ping loops, agent
// reconnects), which outlive the test body and log during cleanup teardown,
// cannot call t.Logf after the test has completed.
func testLogf(t *testing.T) (logf func(string, ...any), mute func()) {
	var mu sync.Mutex
	done := false
	logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if !done {
			t.Logf(format, args...)
		}
	}
	mute = func() {
		mu.Lock()
		done = true
		mu.Unlock()
	}
	return logf, mute
}

// dispatchFixture is the assembled test rig: hub + dispatcher endpoint + a
// client session driving it.
type dispatchFixture struct {
	hub     *hub.Hub
	ts      *httptest.Server
	cs      *mcp.ClientSession
	localWS string
}

func newDispatchFixture(t *testing.T, cfg hub.Config) *dispatchFixture {
	t.Helper()
	localWS := t.TempDir()
	h := hub.New(cfg)
	disp := hub.NewDispatcher(hub.DispatcherConfig{
		Hub:        h,
		Local:      newTunnelServer(t, localWS),
		SessionTTL: time.Hour,
		Logf:       cfg.Logf,
	})
	mux := http.NewServeMux()
	h.AttachRoutes(mux, nil)
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return disp },
		&mcp.StreamableHTTPOptions{DisableLocalhostProtection: true},
	))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return &dispatchFixture{hub: h, ts: ts, cs: cs, localWS: localWS}
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError
}

// TestDispatchEndToEnd drives the fleet dispatcher through the full flow: the
// default target is the local sandbox, describe advertises the fleet, a
// session bound to a fleet VM routes subsequent invokes over the reverse
// channel, and an unknown VM yields a structured vm_not_connected error.
func TestDispatchEndToEnd(t *testing.T) {
	logf, mute := testLogf(t)
	defer mute()
	f := newDispatchFixture(t, hub.Config{AgentToken: "tok", Logf: logf})

	agentWS := t.TempDir()
	startAgent(t, hubagent.Config{
		HubURL: f.ts.URL, Token: "tok", Name: "worker", Logf: logf,
		Handler: agentMux(newTunnelServer(t, agentWS)),
	})
	waitRegistered(t, f.hub, "worker", time.Time{})

	// Default target: the hub's own sandbox ("local").
	text, isErr := callTool(t, f.cs, "invoke", map[string]any{
		"tool":  "Write",
		"input": map[string]any{"file_path": filepath.Join(f.localWS, "here.txt"), "content": "local\n"},
	})
	if isErr {
		t.Fatalf("local write errored: %s", text)
	}
	if b, err := os.ReadFile(filepath.Join(f.localWS, "here.txt")); err != nil || string(b) != "local\n" {
		t.Fatalf("local write landed wrong: %q, %v", b, err)
	}

	// describe (no vm) reports the fleet with the agent and the local default.
	text, isErr = callTool(t, f.cs, "describe", map[string]any{})
	if isErr {
		t.Fatalf("describe errored: %s", text)
	}
	var desc map[string]any
	if err := json.Unmarshal([]byte(text), &desc); err != nil {
		t.Fatalf("describe not JSON: %v\n%s", err, text)
	}
	if desc["vm"] != "local" {
		t.Errorf("describe vm = %v, want local", desc["vm"])
	}
	fleet, _ := desc["fleet"].(map[string]any)
	if fleet == nil {
		t.Fatalf("describe missing fleet: %s", text)
	}
	names := []string{}
	for _, v := range fleet["vms"].([]any) {
		names = append(names, v.(map[string]any)["name"].(string))
	}
	if !strings.Contains(strings.Join(names, ","), "local") || !strings.Contains(strings.Join(names, ","), "worker") {
		t.Errorf("fleet vms = %v, want local and worker", names)
	}

	// Bind a session to the fleet VM; invokes carrying it route there with no
	// per-call vm.
	text, isErr = callTool(t, f.cs, "session", map[string]any{"action": "create", "session": "job", "vm": "worker"})
	if isErr {
		t.Fatalf("session create errored: %s", text)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(text), &created); err != nil || created["vm"] != "worker" {
		t.Fatalf("session create = %s (err %v), want vm worker", text, err)
	}

	text, isErr = callTool(t, f.cs, "invoke", map[string]any{
		"tool":    "Write",
		"input":   map[string]any{"file_path": filepath.Join(agentWS, "there.txt"), "content": "remote\n"},
		"session": "job",
	})
	if isErr {
		t.Fatalf("routed write errored: %s", text)
	}
	if b, err := os.ReadFile(filepath.Join(agentWS, "there.txt")); err != nil || string(b) != "remote\n" {
		t.Fatalf("routed write landed wrong: %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(f.localWS, "there.txt")); !os.IsNotExist(err) {
		t.Errorf("routed write leaked into the local workspace")
	}

	// An explicit vm on invoke wins over the binding, for that call only.
	text, isErr = callTool(t, f.cs, "invoke", map[string]any{
		"tool":    "Read",
		"input":   map[string]any{"file_path": filepath.Join(f.localWS, "here.txt")},
		"session": "job",
		"vm":      "local",
	})
	if isErr || !strings.Contains(text, "local") {
		t.Fatalf("explicit-vm read: isErr=%v text=%s", isErr, text)
	}

	// session list (no vm) reports the binding table.
	text, isErr = callTool(t, f.cs, "session", map[string]any{"action": "list"})
	if isErr {
		t.Fatalf("session list errored: %s", text)
	}
	var listed struct {
		Bindings map[string]string `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(text), &listed); err != nil || listed.Bindings["job"] != "worker" {
		t.Fatalf("session list = %s (err %v), want binding job→worker", text, err)
	}

	// Unknown VM → structured vm_not_connected tool error, like the proxy's 502.
	text, isErr = callTool(t, f.cs, "invoke", map[string]any{
		"tool": "Bash", "input": map[string]any{"command": "true"}, "vm": "ghost",
	})
	if !isErr || !strings.Contains(text, "vm_not_connected") {
		t.Fatalf("unknown vm: isErr=%v text=%s", isErr, text)
	}

	// Invalid VM handle → invalid_vm.
	text, isErr = callTool(t, f.cs, "invoke", map[string]any{
		"tool": "Bash", "input": map[string]any{"command": "true"}, "vm": "Bad_Name!",
	})
	if !isErr || !strings.Contains(text, "invalid_vm") {
		t.Fatalf("invalid vm: isErr=%v text=%s", isErr, text)
	}
}

// TestDispatchAgentRestart: an agent restart (new process, new channel, fresh
// MCP server with no memory of the dispatcher's backend session) must be
// survived transparently — the dispatcher re-dials on the replaced channel
// generation instead of reusing the stale session.
func TestDispatchAgentRestart(t *testing.T) {
	logf, mute := testLogf(t)
	defer mute()
	f := newDispatchFixture(t, hub.Config{AgentToken: "tok", PingInterval: 20 * time.Millisecond, Logf: logf})

	ws1 := t.TempDir()
	cancel1 := startAgent(t, hubagent.Config{
		HubURL: f.ts.URL, Token: "tok", Name: "phoenix", Logf: logf,
		Handler: agentMux(newTunnelServer(t, ws1)),
	})
	waitRegistered(t, f.hub, "phoenix", time.Time{})

	if text, isErr := callTool(t, f.cs, "session", map[string]any{"action": "create", "session": "s", "vm": "phoenix"}); isErr {
		t.Fatalf("bind: %s", text)
	}
	if text, isErr := callTool(t, f.cs, "invoke", map[string]any{
		"tool": "Write", "input": map[string]any{"file_path": filepath.Join(ws1, "a.txt"), "content": "1"}, "session": "s",
	}); isErr {
		t.Fatalf("first write: %s", text)
	}

	// Kill the agent and wait until the hub notices, so the replacement's
	// registration can't race the old reconnect loop.
	cancel1()
	deadline := time.Now().Add(5 * time.Second)
	for {
		agents := f.hub.Agents()
		if len(agents) == 1 && !agents[0].Connected {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent never marked disconnected: %+v", agents)
		}
		time.Sleep(10 * time.Millisecond)
	}
	restartedAfter := time.Now()

	// "Restart": a brand-new server instance (fresh MCP session store) on a
	// new channel, same name.
	ws2 := t.TempDir()
	startAgent(t, hubagent.Config{
		HubURL: f.ts.URL, Token: "tok", Name: "phoenix", Logf: logf,
		Handler: agentMux(newTunnelServer(t, ws2)),
	})
	waitRegistered(t, f.hub, "phoenix", restartedAfter)

	text, isErr := callTool(t, f.cs, "invoke", map[string]any{
		"tool": "Write", "input": map[string]any{"file_path": filepath.Join(ws2, "b.txt"), "content": "2"}, "session": "s",
	})
	if isErr {
		t.Fatalf("post-restart write errored: %s", text)
	}
	if b, err := os.ReadFile(filepath.Join(ws2, "b.txt")); err != nil || string(b) != "2" {
		t.Fatalf("post-restart write landed wrong: %q, %v", b, err)
	}
}
