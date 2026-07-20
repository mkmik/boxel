package policy

// This file is a stub; the full engine implementation replaces it.
// Contract (frozen):
//
//	LoadConfig(path) (Config, error)          — read permissions.json
//	ParseRules(list, behavior) ([]Rule, error) — parse rule strings
//	NewEngine(cfg, mode, workspaceRoot) (*Engine, error)
//	(*Engine).Mode() Mode
//	(*Engine).WorkspaceRoot() string
//	(*Engine).Evaluate(call ToolCall, overlay *Overlay) Decision
//	(*Engine).RedactedPolicy() map[string]any  — for `describe`
//
// Evaluation order:
//  1. Hard denies (jail escape, credential paths) — always, even in
//     bypassPermissions mode.
//  2. Deny rules, then ask rules, then allow rules (persistent config),
//     then overlay allow rules.
//  3. Mode defaults: bypassPermissions → allow; acceptEdits → allow
//     Write/Edit inside the jail; read-only tools (Read/Glob/Grep/
//     BashOutput/KillShell) inside the jail → allow; otherwise ask.

import "errors"

// Engine evaluates tool calls against the loaded policy.
type Engine struct {
	cfg           Config
	mode          Mode
	workspaceRoot string
	rules         []Rule // deny, ask, allow — precedence handled in Evaluate
}

// LoadConfig reads a permissions.json file.
func LoadConfig(path string) (Config, error) {
	return Config{}, errors.New("policy: not implemented")
}

// ParseRules parses rule strings into Rules with the given behavior.
func ParseRules(list []string, behavior Behavior) ([]Rule, error) {
	return nil, errors.New("policy: not implemented")
}

// NewEngine builds an engine from config, mode and the workspace jail root.
func NewEngine(cfg Config, mode Mode, workspaceRoot string) (*Engine, error) {
	return nil, errors.New("policy: not implemented")
}

// Mode returns the engine's permission mode.
func (e *Engine) Mode() Mode { return e.mode }

// WorkspaceRoot returns the absolute workspace jail root.
func (e *Engine) WorkspaceRoot() string { return e.workspaceRoot }

// Evaluate decides allow/ask/deny for a tool call.
func (e *Engine) Evaluate(call ToolCall, overlay *Overlay) Decision {
	return Decision{Behavior: Deny, Rule: "builtin:unimplemented", Reason: "policy engine not implemented"}
}

// RedactedPolicy returns a safe view of the active policy for `describe`.
func (e *Engine) RedactedPolicy() map[string]any {
	return map[string]any{}
}
