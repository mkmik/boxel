// Package audit implements the append-only JSONL audit log. Every tunneled
// invocation is recorded with input digest, permission decision, exit status
// and duration. File contents are never logged; Bash command lines are
// stored as digests plus a redacted prefix.
package audit

// Stub: full implementation replaces this file.
// Contract (frozen):
//
//	NewLogger(path string) (*Logger, error)  — opens append-only; "" → disabled (no-op)
//	(*Logger).Record(e Entry) error          — one JSON object per line, synced
//	(*Logger).Close() error
//	Digest(b []byte) string                  — "sha256:<hex>"
//	RedactCommand(cmd string) string         — safe short prefix for display

import (
	"errors"
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

// Logger writes entries as JSONL.
type Logger struct{}

func NewLogger(path string) (*Logger, error) { return nil, errors.New("audit: not implemented") }
func (l *Logger) Record(e Entry) error       { return errors.New("audit: not implemented") }
func (l *Logger) Close() error               { return nil }

// Digest returns "sha256:<hex>" of b.
func Digest(b []byte) string { return "" }

// RedactCommand returns a display-safe truncated command prefix.
func RedactCommand(cmd string) string { return "" }
