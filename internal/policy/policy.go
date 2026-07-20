// Package policy implements the server-side permission engine: Claude Code
// compatible permission rules, permission modes, session-scoped overlays, and
// hard built-in denies (workspace jail, credential paths).
//
// Rule precedence is deny > ask > allow. Rules use Claude Code's
// settings.json format:
//
//	Bash                 — any Bash command
//	Bash(git *)          — glob over the command line
//	Bash(git commit:*)   — Claude Code prefix form: commands starting "git commit"
//	Edit(/work/**)       — doublestar glob over the resolved absolute path
//	Read(**)             — any path
package policy

import "sync"

// Mode is a permission mode, mirroring Claude Code's permission modes.
type Mode string

const (
	// ModeDefault asks on any mutating call not matched by a rule.
	ModeDefault Mode = "default"
	// ModeAcceptEdits auto-approves Write/Edit within the workspace jail.
	ModeAcceptEdits Mode = "acceptEdits"
	// ModeBypassPermissions approves everything except hard denies.
	// Server-flag only; never client-selectable.
	ModeBypassPermissions Mode = "bypassPermissions"
)

// ValidMode reports whether s names a known permission mode.
func ValidMode(s string) bool {
	switch Mode(s) {
	case ModeDefault, ModeAcceptEdits, ModeBypassPermissions:
		return true
	}
	return false
}

// Behavior is the outcome class of a permission evaluation.
type Behavior string

const (
	Allow Behavior = "allow"
	Ask   Behavior = "ask"
	Deny  Behavior = "deny"
)

// Decision is the result of evaluating a tool call against policy.
type Decision struct {
	Behavior Behavior
	// Rule is the matched rule text (e.g. "Bash(git *)") or a built-in
	// reason tag such as "builtin:jail" or "mode:acceptEdits".
	Rule string
	// Reason is a human-readable explanation, suitable for returning to the
	// model in a structured refusal.
	Reason string
}

// Rule is a parsed permission rule.
type Rule struct {
	// Raw is the original rule text, e.g. "Bash(git *)".
	Raw string
	// Tool is the tool name the rule applies to, e.g. "Bash", "Edit".
	Tool string
	// Specifier is the parenthesized argument pattern; empty matches any.
	Specifier string
	// Behavior is which list the rule came from.
	Behavior Behavior
}

// Config is the subset of Claude Code's settings.json that the engine
// consumes (a server-side permissions.json).
type Config struct {
	Permissions struct {
		Allow []string `json:"allow"`
		Ask   []string `json:"ask"`
		Deny  []string `json:"deny"`
	} `json:"permissions"`
}

// ToolCall is the policy-relevant projection of a tunneled tool call.
type ToolCall struct {
	// Tool is the Claude Code tool name.
	Tool string
	// Command is the full command line (Bash only).
	Command string
	// Paths are the resolved absolute filesystem paths the call touches
	// (file tools: file_path; Glob/Grep: the search root).
	Paths []string
}

// Overlay is a session-scoped set of extra allow rules accumulated from
// "allow always" elicitation responses. It never touches the persistent
// rules file.
type Overlay struct {
	mu    sync.Mutex
	rules []Rule
}

// NewOverlay returns an empty overlay.
func NewOverlay() *Overlay { return &Overlay{} }

// AddAllow appends a session-scoped allow rule.
func (o *Overlay) AddAllow(tool, specifier string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	raw := tool
	if specifier != "" {
		raw = tool + "(" + specifier + ")"
	}
	o.rules = append(o.rules, Rule{Raw: raw, Tool: tool, Specifier: specifier, Behavior: Allow})
}

// Rules returns a snapshot of the overlay rules.
func (o *Overlay) Rules() []Rule {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]Rule, len(o.rules))
	copy(out, o.rules)
	return out
}
