// Package tunnel wires the tunnel-mcp MCP server: it advertises the generic
// `invoke` operation (plus `describe` and `session` helpers), parses the
// Claude Code tool-call envelope, evaluates the permission engine, surfaces
// "ask" decisions to the human via MCP elicitation, executes the harness,
// and records audit entries and metrics.
package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mkmik/boxel/internal/audit"
	"github.com/mkmik/boxel/internal/envelope"
	"github.com/mkmik/boxel/internal/harness"
	"github.com/mkmik/boxel/internal/metrics"
	"github.com/mkmik/boxel/internal/policy"
	"github.com/mkmik/boxel/internal/session"
)

// Version is the server version reported over MCP and in `describe`.
const Version = "0.1.0"

// Config assembles the tunnel server's collaborators.
type Config struct {
	Engine   *policy.Engine
	Sessions *session.Manager
	Audit    *audit.Logger
	Metrics  *metrics.Metrics
}

// Server is the tunnel-mcp server.
type Server struct {
	cfg Config
}

// InvokeArgs is the MCP-level input of the `invoke` tool: a Claude Code tool
// call envelope.
type InvokeArgs struct {
	Tool    string         `json:"tool"`
	Input   map[string]any `json:"input,omitempty"`
	Session string         `json:"session,omitempty"`
}

// DescribeArgs is the (empty) input of the `describe` tool.
type DescribeArgs struct{}

// SessionArgs is the input of the `session` tool.
type SessionArgs struct {
	Action  string `json:"action"`
	Session string `json:"session,omitempty"`
}

const invokeDescription = `Execute a Claude Code tool call on the remote sandbox. The body is a Claude Code tool call: {"tool": <name>, "input": <tool input>, "session": <optional session id>}. Supported tools: Bash, BashOutput, KillShell, Read, Write, Edit, Glob, Grep. Use the exact input schemas you use natively (e.g. Read takes {"file_path": ...}, Bash takes {"command": ..., "run_in_background": ...}). File paths resolve on the sandbox filesystem; relative paths resolve against the session working directory, and cd in Bash persists per session. Call describe if unsure about schemas, the permission policy, or sandbox metadata.`

const describeDescription = `Describe the sandbox tunnel: supported tool names with their expected input schemas, the active permission mode and redacted policy, sandbox metadata (hostname, OS, workspace root), sessions, and limits. Call this to self-correct instead of guessing input shapes.`

const sessionDescription = `Manage logical sandbox sessions. Input: {"action": "create"|"list"|"reset", "session": <id>}. A session owns a working directory, environment overrides, background shells, and session-scoped permission grants. Omitting a session on invoke uses "default".`

const serverInstructions = `This server tunnels the Claude Code tool-call protocol to a remote sandbox VM. Call invoke with {"tool", "input", "session"} using native Claude Code tool schemas (Bash, BashOutput, KillShell, Read, Write, Edit, Glob, Grep). Call describe for schemas, sandbox metadata, and the active permission policy. Some calls require interactive user approval; if a call is denied, respect the refusal and adjust.`

// New builds the MCP server with the invoke/describe/session tools.
func New(cfg Config) *mcp.Server {
	s := &Server{cfg: cfg}
	srv := mcp.NewServer(
		&mcp.Implementation{Name: "tunnel-mcp", Title: "Tunnel MCP sandbox", Version: Version},
		&mcp.ServerOptions{Instructions: serverInstructions},
	)
	mcp.AddTool(srv, &mcp.Tool{Name: "invoke", Description: invokeDescription}, s.invoke)
	mcp.AddTool(srv, &mcp.Tool{Name: "describe", Description: describeDescription}, s.describe)
	mcp.AddTool(srv, &mcp.Tool{Name: "session", Description: sessionDescription}, s.session)
	return srv
}

// textResult wraps text into a CallToolResult.
func textResult(text string, isError bool) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: isError,
	}
}

// jsonResult marshals v as pretty JSON into a CallToolResult.
func jsonResult(v any, isError bool) *mcp.CallToolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return textResult(fmt.Sprintf("internal error: %v", err), true)
	}
	return textResult(string(b), isError)
}

// refusal is the structured permission-refusal payload returned to the model.
func refusal(tool string, d policy.Decision) *mcp.CallToolResult {
	return jsonResult(map[string]any{
		"error":  "permission_denied",
		"tool":   tool,
		"rule":   d.Rule,
		"reason": d.Reason,
	}, true)
}

// toolCallFor projects a typed envelope input onto the policy-relevant view.
func toolCallFor(tool string, typed any, sess *session.Session) policy.ToolCall {
	hctx := &harness.Context{Session: sess}
	call := policy.ToolCall{Tool: tool}
	switch in := typed.(type) {
	case *envelope.BashInput:
		call.Command = in.Command
	case *envelope.ReadInput:
		call.Paths = []string{hctx.Abs(in.FilePath)}
	case *envelope.WriteInput:
		call.Paths = []string{hctx.Abs(in.FilePath)}
	case *envelope.EditInput:
		call.Paths = []string{hctx.Abs(in.FilePath)}
	case *envelope.GlobInput:
		call.Paths = []string{hctx.Abs(in.Path)}
	case *envelope.GrepInput:
		call.Paths = []string{hctx.Abs(in.Path)}
	case *envelope.BashOutputInput, *envelope.KillShellInput:
		// No filesystem or command surface; policy sees only the tool name.
	}
	return call
}

// specifierFor is the session-overlay specifier recorded on "allow always":
// the exact command for Bash, the exact resolved path for file tools.
func specifierFor(call policy.ToolCall) string {
	if call.Command != "" {
		return call.Command
	}
	if len(call.Paths) > 0 {
		return call.Paths[0]
	}
	return ""
}

// elicitDecisionSchema is the flat elicitation form schema for approvals.
var elicitDecisionSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    "decision": {
      "type": "string",
      "enum": ["allow_once", "allow_always", "deny"],
      "description": "allow_once: run this call only. allow_always: allow this exact call for the rest of the session. deny: refuse."
    }
  },
  "required": ["decision"]
}`)

// askUser surfaces an "ask" decision through MCP elicitation and returns the
// user's verdict. Any transport error, decline, or cancel counts as a deny.
func (s *Server) askUser(ctx context.Context, ss *mcp.ServerSession, sess *session.Session, call policy.ToolCall, d policy.Decision) (allowed bool, reason string) {
	summary := call.Tool
	switch {
	case call.Command != "":
		summary = fmt.Sprintf("%s: %s", call.Tool, audit.RedactCommand(call.Command))
	case len(call.Paths) > 0:
		summary = fmt.Sprintf("%s: %s", call.Tool, call.Paths[0])
	}
	start := time.Now()
	res, err := ss.Elicit(ctx, &mcp.ElicitParams{
		Message:         fmt.Sprintf("Allow %s? (session %q)", summary, sess.ID),
		RequestedSchema: elicitDecisionSchema,
	})
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.ObserveElicitation(time.Since(start))
	}
	if err != nil {
		return false, fmt.Sprintf("approval unavailable: elicitation failed (%v); the client may not support elicitation", err)
	}
	if res.Action != "accept" {
		return false, fmt.Sprintf("user did not approve (action: %s)", res.Action)
	}
	decision, _ := res.Content["decision"].(string)
	switch decision {
	case "allow_once":
		return true, ""
	case "allow_always":
		sess.Overlay.AddAllow(call.Tool, specifierFor(call))
		return true, ""
	default:
		return false, "user denied the request"
	}
}

// invoke is the generic-operation handler: parse envelope → policy →
// (elicitation) → harness → audit/metrics.
func (s *Server) invoke(ctx context.Context, req *mcp.CallToolRequest, args InvokeArgs) (*mcp.CallToolResult, any, error) {
	start := time.Now()

	if !envelope.IsSupported(args.Tool) {
		return textResult(string(envelope.UnknownToolError(args.Tool)), true), nil, nil
	}

	rawInput, err := json.Marshal(args.Input)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal input: %w", err)
	}
	typed, err := envelope.ParseInput(args.Tool, rawInput)
	if err != nil {
		return textResult(string(envelope.SchemaError(args.Tool, err)), true), nil, nil
	}

	sess := s.cfg.Sessions.Get(args.Session)
	call := toolCallFor(args.Tool, typed, sess)
	decision := s.cfg.Engine.Evaluate(call, sess.Overlay)

	if decision.Behavior == policy.Ask {
		allowed, denyReason := s.askUser(ctx, req.Session, sess, call, decision)
		if allowed {
			decision = policy.Decision{Behavior: policy.Allow, Rule: "elicitation", Reason: "approved by user"}
		} else {
			decision = policy.Decision{Behavior: policy.Deny, Rule: "elicitation", Reason: denyReason}
		}
	}

	entry := audit.Entry{
		Session:     sess.ID,
		Tool:        args.Tool,
		InputDigest: audit.Digest(rawInput),
		Target:      auditTarget(call),
		Decision:    string(decision.Behavior),
		Rule:        decision.Rule,
		Mode:        string(s.cfg.Engine.Mode()),
	}

	if decision.Behavior != policy.Allow {
		entry.DurationMS = time.Since(start).Milliseconds()
		s.record(entry, args.Tool, string(decision.Behavior), time.Since(start))
		return refusal(args.Tool, decision), nil, nil
	}

	hctx := &harness.Context{Session: sess, WorkspaceRoot: s.cfg.Engine.WorkspaceRoot()}
	res, err := harness.Dispatch(ctx, hctx, args.Tool, typed)
	elapsed := time.Since(start)
	if err != nil {
		entry.Error = err.Error()
		entry.DurationMS = elapsed.Milliseconds()
		s.record(entry, args.Tool, "error", elapsed)
		return nil, nil, err
	}

	entry.ExitStatus = res.ExitStatus
	entry.DurationMS = elapsed.Milliseconds()
	if res.IsError {
		entry.Error = "tool_error"
	}
	s.record(entry, args.Tool, string(decision.Behavior), elapsed)
	return textResult(res.Text, res.IsError), nil, nil
}

// auditTarget is the redacted, non-sensitive target summary for the log.
func auditTarget(call policy.ToolCall) string {
	if call.Command != "" {
		return audit.RedactCommand(call.Command)
	}
	if len(call.Paths) > 0 {
		return call.Paths[0]
	}
	return ""
}

func (s *Server) record(e audit.Entry, tool, decision string, d time.Duration) {
	if s.cfg.Audit != nil {
		_ = s.cfg.Audit.Record(e)
	}
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.ObserveInvocation(tool, decision, d)
	}
}

// describe reports supported tools, schemas, policy, and sandbox metadata.
func (s *Server) describe(ctx context.Context, req *mcp.CallToolRequest, args DescribeArgs) (*mcp.CallToolResult, any, error) {
	hostname, _ := os.Hostname()
	tools := map[string]json.RawMessage{}
	for _, name := range envelope.SupportedTools() {
		tools[name] = envelope.SchemaFor(name)
	}
	sessions := []map[string]any{}
	for _, sess := range s.cfg.Sessions.List() {
		sessions = append(sessions, map[string]any{
			"id":            sess.ID,
			"cwd":           sess.Cwd(),
			"active_shells": sess.Shells.ActiveCount(),
			"created":       sess.Created().UTC().Format(time.RFC3339),
			"last_used":     sess.LastUsed().UTC().Format(time.RFC3339),
		})
	}
	return jsonResult(map[string]any{
		"server":  map[string]any{"name": "tunnel-mcp", "version": Version},
		"sandbox": map[string]any{"hostname": hostname, "os": runtime.GOOS, "arch": runtime.GOARCH, "workspace_root": s.cfg.Engine.WorkspaceRoot()},
		"envelope": map[string]any{
			"description":     "invoke body: {\"tool\": <name>, \"input\": <native Claude Code tool input>, \"session\": <optional id>}",
			"supported_tools": envelope.SupportedTools(),
			"input_schemas":   tools,
		},
		"permissions": s.cfg.Engine.RedactedPolicy(),
		"sessions":    sessions,
		"limits": map[string]any{
			"bash_default_timeout_ms": harness.BashDefaultTimeout,
			"bash_max_timeout_ms":     harness.BashMaxTimeout,
			"max_output_bytes":        harness.MaxOutputBytes,
			"read_default_line_limit": harness.ReadDefaultLimit,
		},
	}, false), nil, nil
}

// session implements the create/list/reset session helper.
func (s *Server) session(ctx context.Context, req *mcp.CallToolRequest, args SessionArgs) (*mcp.CallToolResult, any, error) {
	switch args.Action {
	case "create":
		sess := s.cfg.Sessions.Get(args.Session)
		return jsonResult(map[string]any{"id": sess.ID, "cwd": sess.Cwd()}, false), nil, nil
	case "reset":
		sess := s.cfg.Sessions.Reset(args.Session)
		return jsonResult(map[string]any{"id": sess.ID, "cwd": sess.Cwd(), "reset": true}, false), nil, nil
	case "list", "":
		out := []map[string]any{}
		for _, sess := range s.cfg.Sessions.List() {
			out = append(out, map[string]any{
				"id":            sess.ID,
				"cwd":           sess.Cwd(),
				"active_shells": sess.Shells.ActiveCount(),
				"created":       sess.Created().UTC().Format(time.RFC3339),
				"last_used":     sess.LastUsed().UTC().Format(time.RFC3339),
			})
		}
		return jsonResult(map[string]any{"sessions": out}, false), nil, nil
	default:
		return jsonResult(map[string]any{
			"error":   "invalid_action",
			"message": fmt.Sprintf("unknown action %q: must be create, list, or reset", args.Action),
		}, true), nil, nil
	}
}
