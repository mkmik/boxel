// Package shellmgr manages bash execution for the tunnel harness: foreground
// runs with cwd persistence, and a table of background shells with
// incremental output buffers, mirroring Claude Code's Bash/BashOutput/
// KillShell lifecycle.
package shellmgr

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// shellQuote single-quotes s for safe interpolation into a bash script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// killGroup SIGKILLs the process group led by pid.
func killGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

// RunForeground executes command via bash -c in dir with the given env and
// timeout, returning combined result with cwd persistence.
//
// The command runs verbatim at the top of a wrapper script that captures the
// shell's final working directory into a temp file, so `cd` inside the
// command persists to the session. The process runs in its own process group
// and the whole group is SIGKILLed on timeout or context cancellation.
func RunForeground(ctx context.Context, command, dir string, env []string, timeout time.Duration) (ForegroundResult, error) {
	tmp, err := os.CreateTemp("", "boxel-cwd-*")
	if err != nil {
		return ForegroundResult{}, fmt.Errorf("shellmgr: create cwd file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	wrapped := command + "\n__boxel_ec=$?\nbuiltin pwd > " + shellQuote(tmpPath) + " 2>/dev/null\nexit $__boxel_ec"

	cmd := exec.Command("bash", "-c", wrapped)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return ForegroundResult{}, err
	}
	pgid := cmd.Process.Pid

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var timerC <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		timerC = timer.C
	}

	timedOut := false
	select {
	case <-timerC:
		timedOut = true
		killGroup(pgid)
		<-done
	case <-ctx.Done():
		killGroup(pgid)
		<-done
	case waitErr := <-done:
		var exitErr *exec.ExitError
		if waitErr != nil && !errors.As(waitErr, &exitErr) {
			return ForegroundResult{}, waitErr
		}
	}

	res := ForegroundResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		TimedOut: timedOut,
		Duration: time.Since(start),
	}
	if timedOut {
		res.ExitCode = -1
	} else if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		res.ExitCode = -1
	}
	if b, err := os.ReadFile(tmpPath); err == nil {
		res.NewCwd = strings.TrimSpace(string(b))
	}
	return res, nil
}

// Shell is a background shell process.
type Shell struct {
	id      string
	command string
	cmd     *exec.Cmd
	pgid    int
	timer   *time.Timer

	mu        sync.Mutex
	stdout    bytes.Buffer
	stderr    bytes.Buffer
	stdoutOff int
	stderrOff int
	status    Status
	exitCode  int
	done      bool
}

// lockedWriter appends to a shell output buffer under the shell mutex.
type lockedWriter struct {
	s   *Shell
	buf *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.buf.Write(p)
}

// ID returns the shell's table ID, e.g. "bash_1".
func (s *Shell) ID() string { return s.id }

// CommandLine returns the command the shell is running.
func (s *Shell) CommandLine() string { return s.command }

// Status returns the shell's lifecycle state.
func (s *Shell) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// ExitCode returns the exit code and whether the process has finished.
func (s *Shell) ExitCode() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitCode, s.done
}

// ReadNew returns output accumulated since the previous ReadNew call
// (consume-on-read). If filter is non-empty it is compiled as a regexp and
// applied line-wise to both streams, keeping only matching lines. A bad
// regexp returns an error without consuming any output. Note: no
// partial-last-line carry is kept — a line split across two reads is
// filtered as two fragments.
func (s *Shell) ReadNew(filter string) (string, string, error) {
	var re *regexp.Regexp
	if filter != "" {
		var err error
		re, err = regexp.Compile(filter)
		if err != nil {
			return "", "", err
		}
	}
	s.mu.Lock()
	outAll := s.stdout.Bytes()
	errAll := s.stderr.Bytes()
	newOut := string(outAll[s.stdoutOff:])
	newErr := string(errAll[s.stderrOff:])
	s.stdoutOff = len(outAll)
	s.stderrOff = len(errAll)
	s.mu.Unlock()
	if re != nil {
		newOut = filterLines(newOut, re)
		newErr = filterLines(newErr, re)
	}
	return newOut, newErr, nil
}

// filterLines keeps only lines of s matching re, each newline-terminated.
func filterLines(s string, re *regexp.Regexp) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if re.MatchString(line) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// kill marks a running shell with the given terminal status and SIGKILLs its
// process group. No-op for shells that already left the running state.
func (s *Shell) kill(status Status) {
	s.mu.Lock()
	if s.status != StatusRunning {
		s.mu.Unlock()
		return
	}
	s.status = status
	s.mu.Unlock()
	killGroup(s.pgid)
}

// Table tracks background shells by ID.
type Table struct {
	counter uint64

	mu     sync.Mutex
	shells map[string]*Shell
}

// NewTable returns an empty shell table.
func NewTable() *Table {
	return &Table{shells: make(map[string]*Shell)}
}

// Start launches command via bash -c in dir with the given env as a
// background shell in its own process group. timeout <= 0 means no timeout.
func (t *Table) Start(command, dir string, env []string, timeout time.Duration) (*Shell, error) {
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	s := &Shell{command: command, cmd: cmd, status: StatusRunning}
	cmd.Stdout = &lockedWriter{s: s, buf: &s.stdout}
	cmd.Stderr = &lockedWriter{s: s, buf: &s.stderr}

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	s.pgid = cmd.Process.Pid
	s.id = fmt.Sprintf("bash_%d", atomic.AddUint64(&t.counter, 1))

	t.mu.Lock()
	t.shells[s.id] = s
	t.mu.Unlock()

	if timeout > 0 {
		s.timer = time.AfterFunc(timeout, func() { s.kill(StatusTimedOut) })
	}

	go func() {
		waitErr := cmd.Wait()
		if s.timer != nil {
			s.timer.Stop()
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.done = true
		if cmd.ProcessState != nil {
			s.exitCode = cmd.ProcessState.ExitCode()
		} else {
			s.exitCode = -1
			_ = waitErr
		}
		if s.status == StatusRunning {
			if s.exitCode == 0 {
				s.status = StatusCompleted
			} else {
				s.status = StatusFailed
			}
		}
	}()

	return s, nil
}

// Get returns the shell with the given ID.
func (t *Table) Get(id string) (*Shell, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s, ok := t.shells[id]
	return s, ok
}

// List returns all shells sorted by numeric ID.
func (t *Table) List() []*Shell {
	t.mu.Lock()
	out := make([]*Shell, 0, len(t.shells))
	for _, s := range t.shells {
		out = append(out, s)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return numericID(out[i].id) < numericID(out[j].id) })
	return out
}

func numericID(id string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(id, "bash_"))
	return n
}

// Kill SIGKILLs the shell's process group. Idempotent: killing a shell that
// already finished is a no-op. Unknown IDs return an error.
func (t *Table) Kill(id string) error {
	s, ok := t.Get(id)
	if !ok {
		return fmt.Errorf("no shell with ID %s", id)
	}
	s.kill(StatusKilled)
	return nil
}

// KillAll kills every running shell in the table.
func (t *Table) KillAll() {
	for _, s := range t.List() {
		s.kill(StatusKilled)
	}
}

// ActiveCount returns the number of shells still running.
func (t *Table) ActiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, s := range t.shells {
		if s.Status() == StatusRunning {
			n++
		}
	}
	return n
}
