package tunnel_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mkmik/boxel/internal/audit"
	"github.com/mkmik/boxel/internal/metrics"
	"github.com/mkmik/boxel/internal/policy"
	"github.com/mkmik/boxel/internal/session"
	"github.com/mkmik/boxel/internal/tunnel"
	"github.com/prometheus/client_golang/prometheus"
)

// harnessFixture builds a live tunnel server over an in-memory transport and
// returns a connected client session. elicit, if non-nil, answers approval
// prompts.
func connect(t *testing.T, cfg tunnel.Config, elicit func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error)) (*mcp.ClientSession, context.Context) {
	t.Helper()
	ctx := context.Background()
	srv := tunnel.New(cfg)
	clientT, serverT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ClientOptions{
		ElicitationHandler: elicit,
	})
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, ctx
}

func newCfg(t *testing.T, workspace string, mode policy.Mode, cfg policy.Config) tunnel.Config {
	t.Helper()
	engine, err := policy.NewEngine(cfg, mode, workspace)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	auditLog, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	sessions := session.NewManager(workspace, 0)
	return tunnel.Config{
		Engine:   engine,
		Sessions: sessions,
		Audit:    auditLog,
		Metrics:  metrics.New(prometheus.NewRegistry(), func() float64 { return 0 }, func() float64 { return 0 }),
	}
}

func invoke(t *testing.T, cs *mcp.ClientSession, ctx context.Context, tool string, input map[string]any, sess string) *mcp.CallToolResult {
	t.Helper()
	args := map[string]any{"tool": tool, "input": input}
	if sess != "" {
		args["session"] = sess
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "invoke", Arguments: args})
	if err != nil {
		t.Fatalf("invoke %s: %v", tool, err)
	}
	return res
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// TestE2EReadFileThroughTunnel is the M0 exit criterion: Claude reads a file
// on the VM end-to-end.
func TestE2EReadFileThroughTunnel(t *testing.T) {
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "hello.txt"), []byte("line one\nline two\n"), 0o644)
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{})
	cs, ctx := connect(t, cfg, nil)

	res := invoke(t, cs, ctx, "Read", map[string]any{"file_path": filepath.Join(ws, "hello.txt")}, "")
	text := resultText(t, res)
	if res.IsError {
		t.Fatalf("read errored: %s", text)
	}
	if !strings.Contains(text, "line one") || !strings.Contains(text, "     1\t") {
		t.Fatalf("unexpected read output: %q", text)
	}
}

// TestE2EDescribe verifies the describe tool advertises the envelope, schemas
// and policy (M0: the connector lists tools).
func TestE2EDescribe(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{})
	cs, ctx := connect(t, cfg, nil)

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "describe", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &got); err != nil {
		t.Fatalf("describe not JSON: %v", err)
	}
	env, _ := got["envelope"].(map[string]any)
	tools, _ := env["supported_tools"].([]any)
	if len(tools) != 8 {
		t.Fatalf("expected 8 supported tools, got %v", tools)
	}
	if _, ok := got["permissions"]; !ok {
		t.Fatal("describe missing permissions")
	}
	if _, ok := got["sandbox"]; !ok {
		t.Fatal("describe missing sandbox metadata")
	}
}

// TestE2EEditRoundTrip is the M1 exit criterion: an Edit round-trip with
// Claude Code failure semantics, gated by acceptEdits mode.
func TestE2EEditRoundTrip(t *testing.T) {
	ws := t.TempDir()
	p := filepath.Join(ws, "code.go")
	os.WriteFile(p, []byte("package main\n\nfunc main() {}\n"), 0o644)
	cfg := newCfg(t, ws, policy.ModeAcceptEdits, policy.Config{})
	cs, ctx := connect(t, cfg, nil)

	// Successful edit.
	res := invoke(t, cs, ctx, "Edit", map[string]any{
		"file_path": p, "old_string": "func main() {}", "new_string": "func main() { println(\"hi\") }",
	}, "")
	if res.IsError {
		t.Fatalf("edit failed: %s", resultText(t, res))
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), "println") {
		t.Fatalf("edit not applied: %s", data)
	}

	// Not-found failure semantics transfer through the tunnel.
	res = invoke(t, cs, ctx, "Edit", map[string]any{
		"file_path": p, "old_string": "does not exist", "new_string": "x",
	}, "")
	if !res.IsError || !strings.Contains(resultText(t, res), "String to replace not found") {
		t.Fatalf("expected not-found error, got: %s", resultText(t, res))
	}
}

// TestE2EBackgroundBash is the M2 exit criterion: run a command in the
// background and poll it to completion.
func TestE2EBackgroundBash(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeBypassPermissions, policy.Config{})
	cs, ctx := connect(t, cfg, nil)

	res := invoke(t, cs, ctx, "Bash", map[string]any{
		"command": "echo start; sleep 0.3; echo done", "run_in_background": true,
	}, "")
	text := resultText(t, res)
	if res.IsError || !strings.Contains(text, "ID:") {
		t.Fatalf("background start failed: %s", text)
	}
	id := strings.TrimSpace(text[strings.LastIndex(text, "ID:")+3:])

	deadline := time.Now().Add(5 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		out := invoke(t, cs, ctx, "BashOutput", map[string]any{"bash_id": id}, "")
		last += resultText(t, out)
		if strings.Contains(resultText(t, out), "completed") {
			if !strings.Contains(last, "done") {
				t.Fatalf("completed without 'done' output: %s", last)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("background command did not complete; last output: %s", last)
}

// TestE2ECwdPersistence verifies cd persists across Bash calls in a session.
func TestE2ECwdPersistence(t *testing.T) {
	ws := t.TempDir()
	sub := filepath.Join(ws, "sub")
	os.MkdirAll(sub, 0o755)
	cfg := newCfg(t, ws, policy.ModeBypassPermissions, policy.Config{})
	cs, ctx := connect(t, cfg, nil)

	invoke(t, cs, ctx, "Bash", map[string]any{"command": "cd sub"}, "s1")
	res := invoke(t, cs, ctx, "Bash", map[string]any{"command": "pwd"}, "s1")
	if got := strings.TrimSpace(resultText(t, res)); !strings.HasSuffix(got, "/sub") {
		t.Fatalf("cwd did not persist, pwd=%q", got)
	}
}

// TestE2EElicitationAllowOnce is the M3 exit criterion: an "ask" decision
// triggers an approval prompt; allow-once runs the call.
func TestE2EElicitationAllowOnce(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{}) // Bash → ask in default mode
	var prompts int
	cs, ctx := connect(t, cfg, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		prompts++
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"decision": "allow_once"}}, nil
	})

	res := invoke(t, cs, ctx, "Bash", map[string]any{"command": "echo approved"}, "")
	if res.IsError || !strings.Contains(resultText(t, res), "approved") {
		t.Fatalf("allow-once did not run the command: %s", resultText(t, res))
	}
	if prompts != 1 {
		t.Fatalf("expected 1 elicitation, got %d", prompts)
	}

	// allow_once does not persist: a second call prompts again.
	invoke(t, cs, ctx, "Bash", map[string]any{"command": "echo again"}, "")
	if prompts != 2 {
		t.Fatalf("allow_once should not persist; prompts=%d", prompts)
	}
}

// TestE2EElicitationAllowAlways verifies allow-always adds a session overlay
// rule so the exact call is not re-prompted.
func TestE2EElicitationAllowAlways(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{})
	var prompts int
	cs, ctx := connect(t, cfg, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		prompts++
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"decision": "allow_always"}}, nil
	})

	invoke(t, cs, ctx, "Bash", map[string]any{"command": "echo x"}, "s")
	invoke(t, cs, ctx, "Bash", map[string]any{"command": "echo x"}, "s")
	if prompts != 1 {
		t.Fatalf("allow_always should prompt once for the same command; prompts=%d", prompts)
	}
}

// TestE2EElicitationDeny verifies a denied approval yields a structured refusal.
func TestE2EElicitationDeny(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{})
	cs, ctx := connect(t, cfg, func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		return &mcp.ElicitResult{Action: "decline"}, nil
	})
	res := invoke(t, cs, ctx, "Bash", map[string]any{"command": "echo nope"}, "")
	if !res.IsError || !strings.Contains(resultText(t, res), "permission_denied") {
		t.Fatalf("expected permission_denied refusal, got: %s", resultText(t, res))
	}
}

// TestE2EJailDeny verifies a path outside the workspace is hard-denied even in
// bypassPermissions mode.
func TestE2EJailDeny(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeBypassPermissions, policy.Config{})
	cs, ctx := connect(t, cfg, nil)
	res := invoke(t, cs, ctx, "Read", map[string]any{"file_path": "/etc/hostname"}, "")
	if !res.IsError || !strings.Contains(resultText(t, res), "builtin:jail") {
		t.Fatalf("expected jail denial, got: %s", resultText(t, res))
	}
}

// TestE2EGlobAbsolutePatternJailed is the regression for the Glob
// absolute-pattern jail bypass: a pattern rooted outside the workspace must be
// denied even though in.Path is empty (the search root comes from the pattern).
func TestE2EGlobAbsolutePatternJailed(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{})
	cs, ctx := connect(t, cfg, nil)
	res := invoke(t, cs, ctx, "Glob", map[string]any{"pattern": "/etc/**"}, "")
	if !res.IsError || !strings.Contains(resultText(t, res), "builtin:jail") {
		t.Fatalf("absolute Glob pattern not jailed, got: %s", resultText(t, res))
	}
	// An in-jail absolute pattern still works.
	os.WriteFile(filepath.Join(ws, "x.go"), []byte("package x\n"), 0o644)
	res = invoke(t, cs, ctx, "Glob", map[string]any{"pattern": filepath.Join(ws, "**", "*.go")}, "")
	if res.IsError {
		t.Fatalf("in-jail absolute Glob denied: %s", resultText(t, res))
	}
}

// TestE2EUnknownTool verifies the structured unknown_tool error.
func TestE2EUnknownTool(t *testing.T) {
	ws := t.TempDir()
	cfg := newCfg(t, ws, policy.ModeDefault, policy.Config{})
	cs, ctx := connect(t, cfg, nil)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "invoke", Arguments: map[string]any{
		"tool": "Frobnicate", "input": map[string]any{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), "unknown_tool") {
		t.Fatalf("expected unknown_tool, got: %s", resultText(t, res))
	}
}
