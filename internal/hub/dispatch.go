// Fleet dispatcher: a single MCP endpoint that fronts every VM behind the
// hub. It advertises the same generic surface as a leaf tunnel-mcp server
// (invoke / describe / session), extended with an optional "vm" argument that
// names the target sandbox. A logical session can be bound to a VM at
// creation, after which invoke calls carrying that session route there
// automatically — so one MCP connector (one URL, one credential) covers the
// whole fleet, with the VM chosen at the tool layer rather than in the
// connector URL. The per-VM /vm/<name>/mcp proxy remains available unchanged
// as the direct-addressing fallback.
//
// Forwarding rides the same reverse HTTP/2 channels the dumb proxy uses: the
// dispatcher keeps one MCP client session per agent (dialed lazily against
// the agent's in-process /mcp) and re-dials when the agent's channel is
// replaced. The reserved handle "local" — the default — addresses the hub's
// own tunnel server in-process.
package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mkmik/boxel/internal/session"
	"github.com/mkmik/boxel/internal/version"
)

// LocalVM is the reserved vm handle addressing the hub's own tunnel server.
// It is the default target when neither an explicit vm nor a session binding
// selects one, which keeps a pre-dispatcher client of the hub's /mcp working
// unchanged.
const LocalVM = "local"

// DispatcherConfig assembles the fleet dispatcher's collaborators.
type DispatcherConfig struct {
	// Hub provides the agent registry and the reverse channels to forward on.
	Hub *Hub
	// Local is the hub instance's own tunnel MCP server, addressed as vm
	// "local" (connected in-process; never over HTTP).
	Local *mcp.Server
	// SessionTTL is the idle TTL after which a session→vm binding is pruned;
	// mirror the tunnel session GC TTL. 0 disables pruning.
	SessionTTL time.Duration
	// Logf is the logging sink. Default log.Printf.
	Logf func(format string, args ...any)
}

// NewDispatcher builds the fleet dispatcher MCP server.
func NewDispatcher(cfg DispatcherConfig) *mcp.Server {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	d := &dispatcher{
		cfg:      cfg,
		clients:  map[string]*backendClient{},
		bindings: map[string]*vmBinding{},
	}
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "boxel-hub", Title: "Boxel fleet dispatcher", Version: version.String()},
		&mcp.ServerOptions{Instructions: dispatchInstructions},
	)
	mcp.AddTool(srv, &mcp.Tool{Name: "invoke", Description: dispatchInvokeDescription}, d.invoke)
	mcp.AddTool(srv, &mcp.Tool{Name: "describe", Description: dispatchDescribeDescription}, d.describe)
	mcp.AddTool(srv, &mcp.Tool{Name: "session", Description: dispatchSessionDescription}, d.session)
	return srv
}

const dispatchInstructions = `This server fronts a fleet of boxel sandbox VMs behind a single MCP endpoint. Call describe (no arguments) to list the available VMs. Every tool accepts an optional "vm" argument naming the target sandbox; "local" (the hub's own sandbox) is the default. To work on a fleet VM, bind a logical session to it once — session {"action": "create", "session": <id>, "vm": <name>} — and subsequent invoke calls carrying that session route there automatically. invoke bodies are Claude Code tool calls with native schemas (Bash, BashOutput, KillShell, Read, Write, Edit, Glob, Grep).`

const dispatchInvokeDescription = `Execute a Claude Code tool call on a sandbox VM of the fleet. The body is a Claude Code tool call: {"tool": <name>, "input": <tool input>, "session": <optional session id>, "vm": <optional target VM>}. Supported tools: Bash, BashOutput, KillShell, Read, Write, Edit, Glob, Grep, with the exact input schemas you use natively. Target resolution: an explicit "vm" wins for this call only; otherwise the session's bound VM (see the session tool); otherwise "local", the hub's own sandbox. File paths resolve on the target VM's filesystem. Call describe to list VMs and tool schemas.`

const dispatchDescribeDescription = `Describe the fleet and a sandbox. Input: {"vm": <optional target VM>}. Without vm: describes the hub's own sandbox ("local") and additionally reports the fleet — every registered VM with its connection state — plus how to route calls to one. With vm: describes that VM's sandbox (tool schemas, permission policy, sessions, limits).`

const dispatchSessionDescription = `Manage logical sandbox sessions across the fleet. Input: {"action": "create"|"list"|"reset", "session": <id>, "vm": <optional target VM>}. create with vm binds the session to that VM: later invoke calls carrying the session route there without repeating vm (create again with a different vm rebinds). A session owns a working directory, environment overrides, background shells, and session-scoped permission grants on its VM. list without vm reports the hub's session→vm bindings alongside the local sessions; pass vm to list sessions on a specific VM. Omitting a session on invoke uses "default".`

// DispatchInvokeArgs is the dispatcher's invoke input: the leaf envelope plus
// the optional target VM.
type DispatchInvokeArgs struct {
	Tool    string         `json:"tool"`
	Input   map[string]any `json:"input,omitempty"`
	Session string         `json:"session,omitempty"`
	VM      string         `json:"vm,omitempty"`
}

// DispatchDescribeArgs is the dispatcher's describe input.
type DispatchDescribeArgs struct {
	VM string `json:"vm,omitempty"`
}

// DispatchSessionArgs is the dispatcher's session input.
type DispatchSessionArgs struct {
	Action  string `json:"action"`
	Session string `json:"session,omitempty"`
	VM      string `json:"vm,omitempty"`
}

// dispatcher routes tool calls to per-VM backends and owns the session→vm
// binding table.
type dispatcher struct {
	cfg DispatcherConfig

	mu       sync.Mutex
	clients  map[string]*backendClient
	bindings map[string]*vmBinding
}

// backendClient is a live MCP client session to one backend. conn is the
// agent channel generation observed at dial time (nil for the local backend):
// when the hub's current channel for the name differs, the cached session is
// stale — the agent restarted or reconnected — and must be re-dialed.
type backendClient struct {
	sess *mcp.ClientSession
	conn *agentConn
}

// vmBinding routes a logical session to a VM.
type vmBinding struct {
	vm       string
	lastUsed time.Time
}

// invoke forwards a Claude Code tool call to the resolved VM. The result is
// passed through byte-exact — tool output is a frozen contract the model's
// recovery behavior depends on, so the dispatcher never annotates it.
func (d *dispatcher) invoke(ctx context.Context, req *mcp.CallToolRequest, args DispatchInvokeArgs) (*mcp.CallToolResult, any, error) {
	vm, errRes := d.resolveVM(args.VM, args.Session)
	if errRes != nil {
		return errRes, nil, nil
	}
	fwd := map[string]any{"tool": args.Tool}
	if args.Input != nil {
		fwd["input"] = args.Input
	}
	if args.Session != "" {
		fwd["session"] = args.Session
	}
	res, err := d.call(ctx, vm, "invoke", fwd)
	if err != nil {
		return dispatchError(vm, err), nil, nil
	}
	return res, nil, nil
}

// describe forwards describe to the target VM; without a vm it describes the
// local sandbox and injects the fleet roster.
func (d *dispatcher) describe(ctx context.Context, req *mcp.CallToolRequest, args DispatchDescribeArgs) (*mcp.CallToolResult, any, error) {
	vm, errRes := d.resolveExplicitVM(args.VM)
	if errRes != nil {
		return errRes, nil, nil
	}
	res, err := d.call(ctx, vm, "describe", map[string]any{})
	if err != nil {
		return dispatchError(vm, err), nil, nil
	}
	extra := map[string]any{"vm": vm}
	if args.VM == "" {
		extra["fleet"] = d.fleetView()
	}
	return augment(res, extra), nil, nil
}

// session manages logical sessions and their VM bindings.
func (d *dispatcher) session(ctx context.Context, req *mcp.CallToolRequest, args DispatchSessionArgs) (*mcp.CallToolResult, any, error) {
	switch args.Action {
	case "create":
		vm, errRes := d.resolveExplicitVM(args.VM)
		if errRes != nil {
			return errRes, nil, nil
		}
		res, err := d.call(ctx, vm, "session", map[string]any{"action": "create", "session": args.Session})
		if err != nil {
			return dispatchError(vm, err), nil, nil
		}
		if !res.IsError {
			d.bind(sessionKey(args.Session), vm)
		}
		return augment(res, map[string]any{"vm": vm}), nil, nil
	case "reset":
		vm, errRes := d.resolveVM(args.VM, args.Session)
		if errRes != nil {
			return errRes, nil, nil
		}
		res, err := d.call(ctx, vm, "session", map[string]any{"action": "reset", "session": args.Session})
		if err != nil {
			return dispatchError(vm, err), nil, nil
		}
		return augment(res, map[string]any{"vm": vm}), nil, nil
	case "list", "":
		vm, errRes := d.resolveExplicitVM(args.VM)
		if errRes != nil {
			return errRes, nil, nil
		}
		res, err := d.call(ctx, vm, "session", map[string]any{"action": "list"})
		if err != nil {
			return dispatchError(vm, err), nil, nil
		}
		extra := map[string]any{"vm": vm}
		if args.VM == "" {
			extra["bindings"] = d.bindingsView()
		}
		return augment(res, extra), nil, nil
	default:
		return jsonToolResult(map[string]any{
			"error":   "invalid_action",
			"message": fmt.Sprintf("unknown action %q: must be create, list, or reset", args.Action),
		}, true), nil, nil
	}
}

// resolveVM picks the target VM for a call: an explicit vm wins, then the
// session's binding, then "local". The non-nil result is a tool-error to
// return verbatim (invalid vm handle).
func (d *dispatcher) resolveVM(explicit, sess string) (string, *mcp.CallToolResult) {
	if explicit != "" {
		return d.resolveExplicitVM(explicit)
	}
	if vm := d.boundVM(sessionKey(sess)); vm != "" {
		return vm, nil
	}
	return LocalVM, nil
}

// resolveExplicitVM validates an explicit vm handle, defaulting to "local".
func (d *dispatcher) resolveExplicitVM(explicit string) (string, *mcp.CallToolResult) {
	if explicit == "" || explicit == LocalVM {
		return LocalVM, nil
	}
	if !ValidName(explicit) {
		return "", jsonToolResult(map[string]any{
			"error":   "invalid_vm",
			"vm":      explicit,
			"message": fmt.Sprintf("invalid vm handle %q: want %q or 1-63 chars of [a-z0-9-], not starting/ending with -", explicit, LocalVM),
		}, true)
	}
	return explicit, nil
}

// sessionKey normalizes the binding-table key the same way the leaf session
// manager does: no session means "default".
func sessionKey(s string) string {
	if s == "" {
		return session.DefaultID
	}
	return s
}

// bind records (or replaces) a session→vm binding.
func (d *dispatcher) bind(key, vm string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	d.bindings[key] = &vmBinding{vm: vm, lastUsed: time.Now()}
}

// boundVM returns the VM a session is bound to ("" if unbound), touching the
// binding.
func (d *dispatcher) boundVM(key string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	b := d.bindings[key]
	if b == nil {
		return ""
	}
	b.lastUsed = time.Now()
	return b.vm
}

// pruneLocked drops idle bindings past the TTL. Caller holds d.mu.
func (d *dispatcher) pruneLocked() {
	if d.cfg.SessionTTL <= 0 {
		return
	}
	cutoff := time.Now().Add(-d.cfg.SessionTTL)
	for key, b := range d.bindings {
		if b.lastUsed.Before(cutoff) {
			delete(d.bindings, key)
		}
	}
}

// bindingsView snapshots the binding table for session list output.
func (d *dispatcher) bindingsView() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked()
	out := make(map[string]string, len(d.bindings))
	for key, b := range d.bindings {
		out[key] = b.vm
	}
	return out
}

// fleetView is the VM roster injected into describe: the local sandbox plus
// every agent the hub has seen, with connection state.
func (d *dispatcher) fleetView() map[string]any {
	vms := []map[string]any{{
		"name":        LocalVM,
		"connected":   true,
		"description": "this hub's own sandbox (the default target)",
	}}
	for _, a := range d.cfg.Hub.Agents() {
		vm := map[string]any{"name": a.Name, "connected": a.Connected}
		if a.Version != "" {
			vm["version"] = a.Version
		}
		vms = append(vms, vm)
	}
	return map[string]any{
		"vms":   vms,
		"usage": `pass {"vm": <name>} on invoke/session/describe; session {"action": "create", "session": <id>, "vm": <name>} binds the session so later invoke calls route automatically`,
	}
}

// call forwards one tool call to the named backend. On a transport-level
// failure the cached client is invalidated; the call is retried once only
// when the failure provably preceded execution (a stale MCP session id
// rejected with 404 — e.g. the agent restarted between calls), never after a
// failure that may have executed the tool.
func (d *dispatcher) call(ctx context.Context, vm, tool string, fwdArgs any) (*mcp.CallToolResult, error) {
	cs, err := d.clientFor(ctx, vm)
	if err != nil {
		return nil, err
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: fwdArgs})
	if err == nil {
		return res, nil
	}
	d.invalidate(vm, cs)
	if ctx.Err() == nil && staleSessionErr(err) {
		cs, rerr := d.clientFor(ctx, vm)
		if rerr != nil {
			return nil, fmt.Errorf("%w (re-dial after stale session: %v)", err, rerr)
		}
		res, rerr := cs.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: fwdArgs})
		if rerr != nil {
			d.invalidate(vm, cs)
			return nil, rerr
		}
		return res, nil
	}
	return nil, err
}

// staleSessionErr reports whether a CallTool failure indicates the backend
// rejected our MCP session id before dispatching the call (streamable HTTP
// answers 404 for an unknown/expired session), making a retry safe.
func staleSessionErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "404") || strings.Contains(msg, "session not found")
}

// clientFor returns a live MCP client session to the named backend, dialing
// lazily. Agent-backed sessions are keyed to the agent's current channel
// generation: a replaced channel (agent restart/reconnect) invalidates the
// cached session and triggers a fresh dial + initialize.
func (d *dispatcher) clientFor(ctx context.Context, vm string) (*mcp.ClientSession, error) {
	var cur *agentConn // nil for the local backend
	if vm != LocalVM {
		cur = d.cfg.Hub.lookup(vm)
		if cur == nil {
			return nil, errNotConnected{vm}
		}
	}

	d.mu.Lock()
	if bc := d.clients[vm]; bc != nil {
		if bc.conn == cur {
			sess := bc.sess
			d.mu.Unlock()
			return sess, nil
		}
		delete(d.clients, vm)
		go closeQuietly(bc.sess) // stale generation: the old channel is gone
	}
	d.mu.Unlock()

	sess, err := d.dial(ctx, vm, cur)
	if err != nil {
		return nil, err
	}

	// A concurrent dial may have won the race; keep the first and close ours.
	d.mu.Lock()
	if bc := d.clients[vm]; bc != nil && bc.conn == cur {
		d.mu.Unlock()
		go closeQuietly(sess)
		return bc.sess, nil
	}
	d.clients[vm] = &backendClient{sess: sess, conn: cur}
	d.mu.Unlock()
	return sess, nil
}

// dial connects and initializes an MCP client session to one backend: the
// local server over an in-memory transport, an agent over its reverse channel
// (the same round tripper the dumb /vm/<name>/ proxy uses).
func (d *dispatcher) dial(ctx context.Context, vm string, conn *agentConn) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "boxel-hub-dispatch", Version: version.String()}, nil)
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if vm == LocalVM {
		ct, st := mcp.NewInMemoryTransports()
		if _, err := d.cfg.Local.Connect(dctx, st, nil); err != nil {
			return nil, fmt.Errorf("connect local backend: %w", err)
		}
		return client.Connect(dctx, ct, nil)
	}
	tr := &mcp.StreamableClientTransport{
		Endpoint: "http://" + vm + "/mcp",
		// The endpoint host is the routing key, not a DNS name: the round
		// tripper resolves it against the hub registry and speaks over the
		// agent's reverse HTTP/2 channel.
		HTTPClient: &http.Client{Transport: agentRoundTripper{d.cfg.Hub}},
		// Request/response only: server-initiated messages are not relayed to
		// the dispatcher's own client, so skip the standalone SSE stream and
		// its per-agent hanging GET.
		DisableStandaloneSSE: true,
	}
	sess, err := client.Connect(dctx, tr, nil)
	if err != nil {
		return nil, fmt.Errorf("dial vm %q: %w", vm, err)
	}
	d.cfg.Logf("hub dispatch: connected MCP backend session to vm %q", vm)
	return sess, nil
}

// invalidate drops the cached client for vm if it still is sess.
func (d *dispatcher) invalidate(vm string, sess *mcp.ClientSession) {
	d.mu.Lock()
	if bc := d.clients[vm]; bc != nil && bc.sess == sess {
		delete(d.clients, vm)
	}
	d.mu.Unlock()
	go closeQuietly(sess)
}

// closeQuietly closes a backend session, ignoring errors (the transport under
// it may already be dead).
func closeQuietly(sess *mcp.ClientSession) { _ = sess.Close() }

// dispatchError converts a forwarding failure into the structured tool error
// the model can react to, mirroring the dumb proxy's 502 JSON bodies.
func dispatchError(vm string, err error) *mcp.CallToolResult {
	code := "vm_unreachable"
	if _, ok := err.(errNotConnected); ok {
		code = "vm_not_connected"
	}
	return jsonToolResult(map[string]any{
		"error":   code,
		"vm":      vm,
		"message": err.Error(),
	}, true)
}

// jsonToolResult marshals v as pretty JSON into a CallToolResult.
func jsonToolResult(v any, isError bool) *mcp.CallToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("internal error: %v", err)}},
			IsError: true,
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
		IsError: isError,
	}
}

// augment merges extra keys into a forwarded JSON tool result (describe /
// session output — never invoke, whose output is byte-exact by contract). A
// result whose first content is not a JSON object is returned unchanged.
func augment(res *mcp.CallToolResult, extra map[string]any) *mcp.CallToolResult {
	if res == nil || len(res.Content) == 0 {
		return res
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return res
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &obj); err != nil || obj == nil {
		return res
	}
	for k, v := range extra {
		obj[k] = v
	}
	b, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return res
	}
	out := *res
	out.Content = append([]mcp.Content{&mcp.TextContent{Text: string(b)}}, res.Content[1:]...)
	return &out
}
