// Package harness implements the Claude Code tool repertoire natively
// (Read/Write/Edit/Glob/Grep/Bash/BashOutput/KillShell) against the sandbox
// filesystem and process table. Implementations aim for byte-exact semantics
// with Claude Code — identical output formats and failure modes — so the
// model's recovery behavior transfers.
package harness

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/mkmik/boxel/internal/session"
)

// Default limits mirroring Claude Code behavior.
const (
	// MaxOutputBytes is the truncation threshold for tool output.
	MaxOutputBytes = 30000
	// ReadDefaultLimit is the default number of lines Read returns.
	ReadDefaultLimit = 2000
	// ReadMaxLineLen is the per-line truncation threshold for Read.
	ReadMaxLineLen = 2000
	// BashDefaultTimeout / BashMaxTimeout in milliseconds.
	BashDefaultTimeout = 120_000
	BashMaxTimeout     = 600_000
)

// Result is the outcome of a tunneled tool execution.
type Result struct {
	// Text is the tool's textual output, formatted exactly as Claude Code
	// would present it.
	Text string
	// IsError marks tool-level failures (file not found, non-unique edit
	// match, non-zero exit...) that the model is expected to recover from.
	IsError bool
	// ExitStatus is the process exit code for Bash-family tools, if any.
	ExitStatus *int
}

// Errorf builds an error Result.
func Errorf(format string, args ...any) *Result {
	return &Result{Text: fmt.Sprintf(format, args...), IsError: true}
}

// Context carries per-call execution context into tool implementations.
type Context struct {
	// Session is the logical session the call runs in.
	Session *session.Session
	// WorkspaceRoot is the absolute jail root; harness helpers resolve
	// relative paths against the session cwd.
	WorkspaceRoot string
}

// Abs resolves p against the session working directory and cleans it.
func (h *Context) Abs(p string) string {
	if p == "" {
		return h.Session.Cwd()
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(h.Session.Cwd(), p)
	}
	return filepath.Clean(p)
}

// Func executes one tunneled tool. Input is the already schema-validated
// typed input returned by envelope.ParseInput.
type Func func(ctx context.Context, hctx *Context, input any) (*Result, error)

var registry = map[string]Func{}

// register wires a tool implementation; called from init() in the per-tool
// files of this package.
func register(name string, fn Func) {
	registry[name] = fn
}

// Names returns registered tool names in stable order.
func Names() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Dispatch runs the named tool. The caller is responsible for envelope
// validation and permission checks; unknown names indicate a programming
// error at the call site.
func Dispatch(ctx context.Context, hctx *Context, tool string, input any) (*Result, error) {
	fn, ok := registry[tool]
	if !ok {
		return nil, fmt.Errorf("harness: no implementation for tool %q", tool)
	}
	return fn(ctx, hctx, input)
}

// Truncate caps s at max bytes, appending a marker with the elided count,
// mirroring Claude Code's middle-agnostic tail truncation.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	elided := len(s) - max
	return s[:max] + fmt.Sprintf("\n... [%d bytes truncated] ...", elided)
}
