package policy

// Engine implementation of the frozen contract:
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

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// validTools is the set of tool names permission rules may reference.
// Names are case-sensitive and match Claude Code's tool names.
var validTools = map[string]bool{
	"Bash":       true,
	"BashOutput": true,
	"KillShell":  true,
	"Read":       true,
	"Write":      true,
	"Edit":       true,
	"Glob":       true,
	"Grep":       true,
}

// validToolList is the human-readable form used in error messages.
const validToolList = "Bash, BashOutput, KillShell, Read, Write, Edit, Glob, Grep"

// pathTools are the tools whose rule specifiers are path patterns.
var pathTools = map[string]bool{
	"Read":  true,
	"Write": true,
	"Edit":  true,
	"Glob":  true,
	"Grep":  true,
}

// Engine evaluates tool calls against the loaded policy.
type Engine struct {
	cfg           Config
	mode          Mode
	workspaceRoot string
	deny          []Rule
	ask           []Rule
	allow         []Rule
	// home is the current user's home directory, resolved once at engine
	// construction; empty if it could not be determined.
	home string
	// credPatterns are the built-in credential path patterns, with ~
	// already expanded to home. Patterns without glob metacharacters are
	// matched exactly; the rest via doublestar.
	credPatterns []string
}

// LoadConfig reads a permissions.json file. A missing file is an error;
// callers that want "no config" semantics must not call LoadConfig.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("policy: reading config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("policy: parsing config %s: %w", path, err)
	}
	return cfg, nil
}

// ParseRules parses rule strings into Rules with the given behavior.
// Accepted forms are "Tool" and "Tool(specifier)".
func ParseRules(list []string, behavior Behavior) ([]Rule, error) {
	rules := make([]Rule, 0, len(list))
	for _, raw := range list {
		r, err := parseRule(raw, behavior)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func parseRule(raw string, behavior Behavior) (Rule, error) {
	s := strings.TrimSpace(raw)
	tool, spec := s, ""
	if i := strings.IndexByte(s, '('); i >= 0 {
		if !strings.HasSuffix(s, ")") || len(s) < i+2 {
			return Rule{}, fmt.Errorf("policy: bad rule %q: unbalanced parenthesis", raw)
		}
		tool, spec = s[:i], s[i+1:len(s)-1]
	} else if strings.Contains(s, ")") {
		return Rule{}, fmt.Errorf("policy: bad rule %q: unbalanced parenthesis", raw)
	}
	if tool == "" {
		return Rule{}, fmt.Errorf("policy: bad rule %q: empty tool name", raw)
	}
	if !validTools[tool] {
		return Rule{}, fmt.Errorf("policy: bad rule %q: unknown tool %q (valid tools: %s)", raw, tool, validToolList)
	}
	return Rule{Raw: s, Tool: tool, Specifier: spec, Behavior: behavior}, nil
}

// NewEngine builds an engine from config, mode and the workspace jail root.
func NewEngine(cfg Config, mode Mode, workspaceRoot string) (*Engine, error) {
	if !ValidMode(string(mode)) {
		return nil, fmt.Errorf("policy: invalid permission mode %q", mode)
	}
	root, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("policy: resolving workspace root %q: %w", workspaceRoot, err)
	}
	root = filepath.Clean(root)
	deny, err := ParseRules(cfg.Permissions.Deny, Deny)
	if err != nil {
		return nil, err
	}
	ask, err := ParseRules(cfg.Permissions.Ask, Ask)
	if err != nil {
		return nil, err
	}
	allow, err := ParseRules(cfg.Permissions.Allow, Allow)
	if err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "" // home-relative credential patterns disabled; "/.ssh/" substring still applies
	} else {
		home = filepath.Clean(home)
	}
	return &Engine{
		cfg:           cfg,
		mode:          mode,
		workspaceRoot: root,
		deny:          deny,
		ask:           ask,
		allow:         allow,
		home:          home,
		credPatterns:  credentialPatterns(home),
	}, nil
}

// Mode returns the engine's permission mode.
func (e *Engine) Mode() Mode { return e.mode }

// WorkspaceRoot returns the absolute workspace jail root.
func (e *Engine) WorkspaceRoot() string { return e.workspaceRoot }

// Evaluate decides allow/ask/deny for a tool call.
func (e *Engine) Evaluate(call ToolCall, overlay *Overlay) Decision {
	// 1a. Hard deny: workspace jail. Applies even in bypassPermissions.
	for _, p := range call.Paths {
		cp := filepath.Clean(p)
		if !pathWithin(cp, e.workspaceRoot) {
			return Decision{
				Behavior: Deny,
				Rule:     "builtin:jail",
				Reason:   fmt.Sprintf("path %s is outside the sandbox workspace %s", cp, e.workspaceRoot),
			}
		}
	}
	// 1b. Hard deny: credential paths, unless explicitly allowlisted by a
	// persistent (non-overlay, non-catch-all) config allow rule.
	for _, p := range call.Paths {
		cp := filepath.Clean(p)
		if e.isCredentialPath(cp) && !e.credentialAllowlisted(cp) {
			return Decision{
				Behavior: Deny,
				Rule:     "builtin:credentials",
				Reason:   fmt.Sprintf("credential path %s is blocked (add an explicit allow rule to permit)", cp),
			}
		}
	}
	// 2. Deny rules (config), first match wins.
	for _, r := range e.deny {
		if e.ruleMatches(r, call) {
			return Decision{Behavior: Deny, Rule: r.Raw, Reason: "blocked by deny rule " + r.Raw}
		}
	}
	// 3. Ask rules (config).
	for _, r := range e.ask {
		if e.ruleMatches(r, call) {
			return Decision{Behavior: Ask, Rule: r.Raw, Reason: "rule " + r.Raw + " requires approval"}
		}
	}
	// 4. Allow rules: config first, then the session overlay.
	for _, r := range e.allow {
		if e.ruleMatches(r, call) {
			return Decision{Behavior: Allow, Rule: r.Raw, Reason: "allowed by rule " + r.Raw}
		}
	}
	if overlay != nil {
		for _, r := range overlay.Rules() {
			if e.ruleMatches(r, call) {
				return Decision{Behavior: Allow, Rule: r.Raw, Reason: "allowed by session rule " + r.Raw}
			}
		}
	}
	// 5. Mode defaults.
	if e.mode == ModeBypassPermissions {
		return Decision{Behavior: Allow, Rule: "mode:bypassPermissions", Reason: "permission mode is bypassPermissions"}
	}
	switch call.Tool {
	case "BashOutput", "KillShell":
		// No new side effects beyond the session's own shells.
		return Decision{Behavior: Allow, Rule: "builtin:readonly", Reason: "read-only tool auto-approved"}
	case "Read", "Glob", "Grep":
		// All paths already proven inside the jail by step 1a.
		return Decision{Behavior: Allow, Rule: "builtin:readonly", Reason: "read-only tool inside workspace auto-approved"}
	case "Write", "Edit":
		if e.mode == ModeAcceptEdits {
			// All paths already proven inside the jail by step 1a.
			return Decision{Behavior: Allow, Rule: "mode:acceptEdits", Reason: "edit inside workspace auto-approved by acceptEdits mode"}
		}
	}
	return Decision{Behavior: Ask, Rule: "mode:default", Reason: "no rule matched; permission mode is default"}
}

// RedactedPolicy returns a safe view of the active policy for `describe`.
// Rule strings are not secret and are included verbatim.
func (e *Engine) RedactedPolicy() map[string]any {
	raws := func(rules []Rule) []string {
		out := make([]string, len(rules))
		for i, r := range rules {
			out[i] = r.Raw
		}
		return out
	}
	return map[string]any{
		"mode":           string(e.mode),
		"workspace_root": e.workspaceRoot,
		"counts": map[string]int{
			"allow": len(e.allow),
			"ask":   len(e.ask),
			"deny":  len(e.deny),
		},
		"allow": raws(e.allow),
		"ask":   raws(e.ask),
		"deny":  raws(e.deny),
		"builtin": map[string]any{
			"jail":                     e.workspaceRoot,
			"credential_paths_blocked": true,
		},
	}
}
