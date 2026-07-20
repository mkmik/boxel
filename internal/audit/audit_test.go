package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan log: %v", err)
	}
	return lines
}

func TestRecordJSONLRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	exit := 0
	if err := l.Record(Entry{
		Session:     "s1",
		Tool:        "Read",
		InputDigest: Digest([]byte("input-1")),
		Target:      "/etc/hostname",
		Decision:    "allow",
		Rule:        "read-any",
		Mode:        "auto",
		ExitStatus:  &exit,
		DurationMS:  12,
	}); err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	if err := l.Record(Entry{
		Session:     "s1",
		Tool:        "Bash",
		InputDigest: Digest([]byte("input-2")),
		Target:      "go build ./...",
		Decision:    "deny",
		Mode:        "strict",
		DurationMS:  3,
		Error:       "denied by policy",
	}); err != nil {
		t.Fatalf("Record 2: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}

	for i, line := range lines {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("line %d not valid JSON: %v", i, err)
		}
		// Frozen json tag names.
		for _, key := range []string{"ts", "session", "tool", "input_digest", "decision", "mode", "duration_ms"} {
			if _, ok := raw[key]; !ok {
				t.Errorf("line %d missing key %q", i, key)
			}
		}
		// Time was zero at Record time; it must have been auto-set.
		ts, ok := raw["ts"].(string)
		if !ok {
			t.Fatalf("line %d: ts is not a string", i)
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			t.Fatalf("line %d: ts %q not RFC3339: %v", i, ts, err)
		}
		if parsed.IsZero() || time.Since(parsed) > time.Minute {
			t.Errorf("line %d: ts %v not auto-set to a recent time", i, parsed)
		}
	}

	// Optional-field tags on the entries that carry them.
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"target", "rule", "exit_status"} {
		if _, ok := first[key]; !ok {
			t.Errorf("line 0 missing key %q", key)
		}
	}
	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	if _, ok := second["error"]; !ok {
		t.Error("line 1 missing key \"error\"")
	}
}

func TestReopenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")

	l1, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger 1: %v", err)
	}
	if err := l1.Record(Entry{Session: "s1", Tool: "Read", Decision: "allow", Mode: "auto"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	l2, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger 2: %v", err)
	}
	if err := l2.Record(Entry{Session: "s2", Tool: "Write", Decision: "ask", Mode: "auto"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 2 {
		t.Fatalf("got %d lines after reopen, want 2 (reopen must append, not truncate)", len(lines))
	}
	if !strings.Contains(lines[0], `"s1"`) || !strings.Contains(lines[1], `"s2"`) {
		t.Errorf("lines out of order or truncated: %q", lines)
	}
}

func TestNoOpLogger(t *testing.T) {
	l, err := NewLogger("")
	if err != nil {
		t.Fatalf("NewLogger(\"\"): %v", err)
	}
	if err := l.Record(Entry{Tool: "Bash"}); err != nil {
		t.Errorf("no-op Record: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Errorf("no-op Close: %v", err)
	}
	// Close twice is safe.
	if err := l.Close(); err != nil {
		t.Errorf("no-op double Close: %v", err)
	}
}

func TestNewLoggerMissingParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "audit.jsonl")
	if _, err := NewLogger(path); err == nil {
		t.Fatal("expected error for missing parent directory, got nil")
	}
}

func TestLogFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer l.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("log file perms = %o, want 0600", perm)
	}
}

func TestDigestKnownVector(t *testing.T) {
	got := Digest([]byte("abc"))
	want := "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("Digest(\"abc\") = %q, want %q", got, want)
	}
}

func TestRedactCommand(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "  \t \n ", ""},
		{"short passthrough", "ls -la /tmp", "ls -la /tmp"},
		{"whitespace collapsed", "go \t build\n\n./...", "go build ./..."},
		{
			"long truncated with ellipsis",
			strings.Repeat("a", 100),
			strings.Repeat("a", 80) + "…",
		},
		{"secret api key", "export API_KEY=xyz", "export [redacted]"},
		{"secret password", "mysql --password=hunter2 -u root", "mysql [redacted]"},
		{"secret case-insensitive", "curl -H 'AUTHORIZATION: Bearer abc'", "curl [redacted]"},
		{"secret token", "git push https://token@github.com/x/y", "git [redacted]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactCommand(tt.in); got != tt.want {
				t.Errorf("RedactCommand(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestRedactCommandExactly80Runes(t *testing.T) {
	in := strings.Repeat("b", 80)
	if got := RedactCommand(in); got != in {
		t.Errorf("80-rune command must not be truncated: got %q", got)
	}
}
