// Package shellmgr manages bash execution for the tunnel harness: foreground
// runs with cwd persistence, and a table of background shells with
// incremental output buffers, mirroring Claude Code's Bash/BashOutput/
// KillShell lifecycle.
package shellmgr

// This file is a stub; the full implementation replaces it.
// Contract (frozen):
//
//	NewTable() *Table
//	(*Table).Start(command, dir string, env []string, timeout time.Duration) (*Shell, error)
//	(*Table).Get(id string) (*Shell, bool)
//	(*Table).List() []*Shell
//	(*Table).Kill(id string) error
//	(*Table).KillAll()
//	(*Table).ActiveCount() int
//	(*Shell).ID() string
//	(*Shell).CommandLine() string
//	(*Shell).Status() Status
//	(*Shell).ExitCode() (code int, done bool)
//	(*Shell).ReadNew(filter string) (stdout, stderr string, err error)
//	RunForeground(ctx, command, dir string, env []string, timeout time.Duration) (ForegroundResult, error)
//
// Foreground runs persist the working directory: the command is wrapped so
// the shell's final $PWD is captured and returned in ForegroundResult.NewCwd.
// Background shells run in their own process group so Kill terminates the
// whole tree.

import (
	"context"
	"errors"
	"time"
)

// Status describes a background shell's lifecycle state.
type Status string

const (
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusKilled    Status = "killed"
	StatusTimedOut  Status = "timed_out"
)

// ForegroundResult is the outcome of a foreground bash run.
type ForegroundResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	// NewCwd is the shell's working directory after the command ran, for
	// per-session cwd persistence. Empty if it could not be determined.
	NewCwd   string
	TimedOut bool
	// Duration is wall-clock execution time.
	Duration time.Duration
}

// Shell is a background shell process.
type Shell struct{}

// Table tracks background shells by ID.
type Table struct{}

// NewTable returns an empty shell table.
func NewTable() *Table { return &Table{} }

func (t *Table) Start(command, dir string, env []string, timeout time.Duration) (*Shell, error) {
	return nil, errors.New("shellmgr: not implemented")
}
func (t *Table) Get(id string) (*Shell, bool) { return nil, false }
func (t *Table) List() []*Shell               { return nil }
func (t *Table) Kill(id string) error         { return errors.New("shellmgr: not implemented") }
func (t *Table) KillAll()                     {}
func (t *Table) ActiveCount() int             { return 0 }

func (s *Shell) ID() string                { return "" }
func (s *Shell) CommandLine() string       { return "" }
func (s *Shell) Status() Status            { return StatusFailed }
func (s *Shell) ExitCode() (int, bool)     { return 0, false }
func (s *Shell) ReadNew(filter string) (string, string, error) {
	return "", "", errors.New("shellmgr: not implemented")
}

// RunForeground executes command via bash -c in dir with the given env and
// timeout, returning combined result with cwd persistence.
func RunForeground(ctx context.Context, command, dir string, env []string, timeout time.Duration) (ForegroundResult, error) {
	return ForegroundResult{}, errors.New("shellmgr: not implemented")
}
