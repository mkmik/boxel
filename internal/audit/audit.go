// Package audit implements the append-only JSONL audit log. Every tunneled
// invocation is recorded with input digest, permission decision, exit status
// and duration. File contents are never logged; Bash command lines are
// stored as digests plus a redacted prefix.
package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is one audit record.
type Entry struct {
	Time        time.Time `json:"ts"`
	Session     string    `json:"session"`
	Tool        string    `json:"tool"`
	InputDigest string    `json:"input_digest"`
	// Target is a redacted, non-sensitive summary: a file path for file
	// tools, a truncated command prefix for Bash. Never file contents.
	Target     string `json:"target,omitempty"`
	Decision   string `json:"decision"`
	Rule       string `json:"rule,omitempty"`
	Mode       string `json:"mode"`
	ExitStatus *int   `json:"exit_status,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// Logger writes entries as JSONL. A Logger created with an empty path is
// disabled: Record and Close are no-ops.
type Logger struct {
	mu sync.Mutex
	f  *os.File
}

// NewLogger opens the audit log at path in append-only mode with 0600
// permissions (command digests are sensitive-adjacent). The parent directory
// must already exist. An empty path returns a disabled no-op Logger.
func NewLogger(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: open log: %w", err)
	}
	return &Logger{f: f}, nil
}

// Record appends e as a single JSON line and syncs the file. If e.Time is
// zero it is set to the current UTC time. On a disabled Logger it is a no-op.
func (l *Logger) Record(e Entry) error {
	if l == nil || l.f == nil {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(b); err != nil {
		return fmt.Errorf("audit: write entry: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("audit: sync: %w", err)
	}
	return nil
}

// Close closes the underlying file. It is safe on a nil or disabled Logger.
func (l *Logger) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.f.Close()
	l.f = nil
	return err
}

// Digest returns "sha256:<hex>" of b.
func Digest(b []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(b))
}

// secretPattern matches substrings that suggest the command line carries a
// credential and must not be logged even in truncated form.
var secretPattern = regexp.MustCompile(`(?i)password|passwd|secret|token|api[_-]?key|bearer|authorization`)

// maxRedactedRunes is the display-prefix budget for RedactCommand.
const maxRedactedRunes = 80

// RedactCommand returns a display-safe truncated command prefix. Whitespace
// runs collapse to single spaces and the result is capped at 80 runes (with
// "…" appended when truncated). If the command looks like it contains a
// secret, only its first word plus " [redacted]" is returned. File contents
// are never logged.
func RedactCommand(cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	if secretPattern.MatchString(cmd) {
		return fields[0] + " [redacted]"
	}
	collapsed := strings.Join(fields, " ")
	runes := []rune(collapsed)
	if len(runes) <= maxRedactedRunes {
		return collapsed
	}
	return string(runes[:maxRedactedRunes]) + "…"
}
