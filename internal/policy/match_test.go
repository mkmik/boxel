package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// mustEngine builds an engine or fails the test.
func mustEngine(t *testing.T, cfg Config, mode Mode, root string) *Engine {
	t.Helper()
	e, err := NewEngine(cfg, mode, root)
	if err != nil {
		t.Fatalf("NewEngine(%v, %q, %q): %v", cfg, mode, root, err)
	}
	return e
}

func mustHome(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	return filepath.Clean(home)
}

func TestPathWithin(t *testing.T) {
	tests := []struct {
		p, root string
		want    bool
	}{
		{"/work", "/work", true},
		{"/work/a.txt", "/work", true},
		{"/work/a/b/c", "/work", true},
		{"/work2", "/work", false},
		{"/work2/a.txt", "/work", false},
		{"/wor", "/work", false},
		{"/", "/work", false},
		{"/etc/passwd", "/work", false},
		{"/anything/at/all", "/", true},
		{"/", "/", true},
	}
	for _, tt := range tests {
		if got := pathWithin(tt.p, tt.root); got != tt.want {
			t.Errorf("pathWithin(%q, %q) = %v, want %v", tt.p, tt.root, got, tt.want)
		}
	}
}

func TestMatchBashSpec(t *testing.T) {
	tests := []struct {
		spec, cmd string
		want      bool
	}{
		// Exact match (no glob chars, no :* suffix).
		{"ls", "ls", true},
		{"ls", "ls -la", false},
		{"ls", "lsx", false},
		// Claude Code prefix form "prefix:*".
		{"git commit:*", "git commit", true},
		{"git commit:*", "git commit -m 'hello world'", true},
		{"git commit:*", "git committee", false},
		{"git commit:*", "git commitx", false},
		{"git commit:*", "git", false},
		{"npm run build:*", "npm run build --verbose", true},
		{"npm run build:*", "npm run buildx", false},
		// PRD glob form: * matches any run including spaces.
		{"git *", "git status", true},
		{"git *", "git commit -m 'a b c'", true},
		{"git *", "git", false}, // requires "git " prefix per the glob
		{"git *", "gitx status", false},
		{"* install *", "npm install left-pad", true},
		{"* install *", "npm remove left-pad", false},
		{"echo ?", "echo a", true},
		{"echo ?", "echo ab", false},
		// Regex metacharacters in the spec are literal.
		{"echo a.b*", "echo a.b or so", true},
		{"echo a.b*", "echo aXb", false},
	}
	for _, tt := range tests {
		if got := matchBashSpec(tt.spec, tt.cmd); got != tt.want {
			t.Errorf("matchBashSpec(%q, %q) = %v, want %v", tt.spec, tt.cmd, got, tt.want)
		}
	}
}

func TestMatchPathSpec(t *testing.T) {
	home := mustHome(t)
	e := mustEngine(t, Config{}, ModeDefault, "/work")
	tests := []struct {
		spec, path string
		want       bool
	}{
		// Absolute doublestar patterns.
		{"/work/**", "/work/a/b.go", true},
		{"/work/**", "/work", true}, // doublestar: /work/** matches /work itself
		{"/work/**", "/other/a.go", false},
		{"/work/**/*.go", "/work/src/deep/nested/x.go", true},
		{"/work/**/*.go", "/work/x.txt", false},
		// Relative patterns resolve against the workspace root.
		{"src/**/*.go", "/work/src/a/b.go", true},
		{"src/**/*.go", "/work/other/a.go", false},
		{"src/**/*.go", "/elsewhere/src/a/b.go", false}, // outside root: relative rules never match
		{"*.md", "/work/README.md", true},
		{"*.md", "/work/docs/README.md", false}, // single * does not cross separators
		// Home expansion.
		{"~/notes/**", home + "/notes/todo.md", true},
		{"~/notes/**", "/work/notes/todo.md", false},
		// "//" anchors at filesystem root.
		{"//etc/hosts", "/etc/hosts", true},
		{"//etc/hosts", "/etc/hostsx", false},
		// Non-glob pattern matches the path itself and anything under it.
		{"/work/src", "/work/src", true},
		{"/work/src", "/work/src/a/b.go", true},
		{"/work/src", "/work/srcx/a.go", false},
		{"sub", "/work/sub/deep/file", true},
		{"sub", "/work/subx/file", false},
		// Uncleaned input paths are cleaned before matching.
		{"/work/src", "/work/./src/../src/a.go", true},
	}
	for _, tt := range tests {
		if got := e.matchPathSpec(tt.spec, tt.path); got != tt.want {
			t.Errorf("matchPathSpec(%q, %q) = %v, want %v", tt.spec, tt.path, got, tt.want)
		}
	}
}

func TestRuleMatchesMultiPath(t *testing.T) {
	e := mustEngine(t, Config{}, ModeDefault, "/work")
	rule := Rule{Raw: "Edit(/work/src/**)", Tool: "Edit", Specifier: "/work/src/**", Behavior: Allow}

	all := ToolCall{Tool: "Edit", Paths: []string{"/work/src/a.go", "/work/src/b/c.go"}}
	if !e.ruleMatches(rule, all) {
		t.Errorf("rule should match when all paths are covered")
	}
	partial := ToolCall{Tool: "Edit", Paths: []string{"/work/src/a.go", "/work/other/b.go"}}
	if e.ruleMatches(rule, partial) {
		t.Errorf("rule must not match when any path is uncovered")
	}
	none := ToolCall{Tool: "Edit"}
	if e.ruleMatches(rule, none) {
		t.Errorf("path-specifier rule must not match a call with no paths")
	}
	wrongTool := ToolCall{Tool: "Write", Paths: []string{"/work/src/a.go"}}
	if e.ruleMatches(rule, wrongTool) {
		t.Errorf("rule must not match a different tool")
	}
	bare := Rule{Raw: "Edit", Tool: "Edit", Behavior: Allow}
	if !e.ruleMatches(bare, none) || !e.ruleMatches(bare, partial) {
		t.Errorf("bare tool rule must match every call of that tool")
	}
}
