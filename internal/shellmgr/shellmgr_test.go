package shellmgr

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestForegroundEcho(t *testing.T) {
	dir := t.TempDir()
	res, err := RunForeground(context.Background(), "echo out; echo err >&2", dir, os.Environ(), 5*time.Second)
	if err != nil {
		t.Fatalf("RunForeground: %v", err)
	}
	if res.Stdout != "out\n" {
		t.Errorf("stdout = %q, want %q", res.Stdout, "out\n")
	}
	if res.Stderr != "err\n" {
		t.Errorf("stderr = %q, want %q", res.Stderr, "err\n")
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if res.TimedOut {
		t.Error("unexpected TimedOut")
	}
	want, _ := filepath.EvalSymlinks(dir)
	if got, _ := filepath.EvalSymlinks(res.NewCwd); got != want {
		t.Errorf("NewCwd = %q (resolved %q), want %q", res.NewCwd, got, want)
	}
	if res.Duration <= 0 {
		t.Error("Duration not set")
	}
}

func TestForegroundExitCode(t *testing.T) {
	res, err := RunForeground(context.Background(), "exit 3", t.TempDir(), os.Environ(), 5*time.Second)
	if err != nil {
		t.Fatalf("RunForeground: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}
}

func TestForegroundCwdPersistence(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := RunForeground(context.Background(), "cd sub", dir, os.Environ(), 5*time.Second)
	if err != nil {
		t.Fatalf("RunForeground: %v", err)
	}
	want, _ := filepath.EvalSymlinks(sub)
	if got, _ := filepath.EvalSymlinks(res.NewCwd); got != want {
		t.Errorf("NewCwd = %q, want %q", res.NewCwd, want)
	}
}

func TestForegroundTimeoutKillsGroup(t *testing.T) {
	start := time.Now()
	// Multi-line body keeps bash as the group leader with sleep as a child,
	// so only a group kill terminates the tree promptly.
	res, err := RunForeground(context.Background(), "sleep 30 &\nsleep 30", t.TempDir(), os.Environ(), 150*time.Millisecond)
	if err != nil {
		t.Fatalf("RunForeground: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s; group kill did not take effect", elapsed)
	}
	if !res.TimedOut {
		t.Error("TimedOut = false, want true")
	}
	if res.ExitCode != -1 {
		t.Errorf("exit code = %d, want -1", res.ExitCode)
	}
}

func TestForegroundContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	res, err := RunForeground(ctx, "sleep 30", t.TempDir(), os.Environ(), 10*time.Second)
	if err != nil {
		t.Fatalf("RunForeground: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s; cancellation did not kill process", elapsed)
	}
	if res.TimedOut {
		t.Error("TimedOut = true for ctx cancellation, want false")
	}
}

func TestForegroundEnv(t *testing.T) {
	env := append(os.Environ(), "BOXEL_FG_TEST=hello")
	res, err := RunForeground(context.Background(), `printf %s "$BOXEL_FG_TEST"`, t.TempDir(), env, 5*time.Second)
	if err != nil {
		t.Fatalf("RunForeground: %v", err)
	}
	if res.Stdout != "hello" {
		t.Errorf("stdout = %q, want %q", res.Stdout, "hello")
	}
}

func TestShellBackgroundIncrementalReadNew(t *testing.T) {
	dir := t.TempDir()
	syncFile := filepath.Join(dir, "go2")
	tbl := NewTable()
	cmd := `echo one; until [ -f ` + syncFile + ` ]; do sleep 0.02; done; echo two; echo err2 >&2`
	sh, err := tbl.Start(cmd, dir, os.Environ(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sh.ID() != "bash_1" {
		t.Errorf("ID = %q, want bash_1", sh.ID())
	}
	if sh.CommandLine() != cmd {
		t.Errorf("CommandLine = %q", sh.CommandLine())
	}

	var phase1 string
	waitFor(t, "first output", func() bool {
		out, _, err := sh.ReadNew("")
		if err != nil {
			t.Fatalf("ReadNew: %v", err)
		}
		phase1 += out
		return strings.Contains(phase1, "one\n")
	})
	if phase1 != "one\n" {
		t.Errorf("phase1 = %q, want %q", phase1, "one\n")
	}

	if err := os.WriteFile(syncFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	var phase2, phase2err string
	waitFor(t, "second output", func() bool {
		out, errOut, err := sh.ReadNew("")
		if err != nil {
			t.Fatalf("ReadNew: %v", err)
		}
		phase2 += out
		phase2err += errOut
		return strings.Contains(phase2, "two\n") && strings.Contains(phase2err, "err2\n")
	})
	if strings.Contains(phase2, "one") {
		t.Errorf("phase2 re-delivered consumed output: %q", phase2)
	}
	if phase2 != "two\n" {
		t.Errorf("phase2 stdout = %q, want %q", phase2, "two\n")
	}
	if phase2err != "err2\n" {
		t.Errorf("phase2 stderr = %q, want %q", phase2err, "err2\n")
	}
	waitFor(t, "completion", func() bool { return sh.Status() == StatusCompleted })
}

func TestShellBackgroundFilter(t *testing.T) {
	tbl := NewTable()
	sh, err := tbl.Start(`printf 'apple\nbanana\napricot\n'`, t.TempDir(), os.Environ(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, "completion", func() bool { return sh.Status() == StatusCompleted })

	// A bad regex errors without consuming.
	if _, _, err := sh.ReadNew("("); err == nil {
		t.Error("bad regex: got nil error")
	}
	out, errOut, err := sh.ReadNew("^ap")
	if err != nil {
		t.Fatalf("ReadNew: %v", err)
	}
	if out != "apple\napricot\n" {
		t.Errorf("filtered stdout = %q, want %q", out, "apple\napricot\n")
	}
	if errOut != "" {
		t.Errorf("filtered stderr = %q, want empty", errOut)
	}
	// Filtered-out lines are still consumed.
	out, _, err = sh.ReadNew("")
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Errorf("second read = %q, want empty (consume-on-read)", out)
	}
}

func TestKillBackgroundShell(t *testing.T) {
	tbl := NewTable()
	sh, err := tbl.Start("sleep 30", t.TempDir(), os.Environ(), 0)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	start := time.Now()
	if err := tbl.Kill(sh.ID()); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	waitFor(t, "killed status", func() bool {
		_, done := sh.ExitCode()
		return done && sh.Status() == StatusKilled
	})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("kill took %s", elapsed)
	}
	// Idempotent on a finished shell.
	if err := tbl.Kill(sh.ID()); err != nil {
		t.Errorf("second Kill: %v", err)
	}
	if sh.Status() != StatusKilled {
		t.Errorf("status = %q, want killed", sh.Status())
	}
	// Unknown ID.
	err = tbl.Kill("bash_99")
	if err == nil || err.Error() != "no shell with ID bash_99" {
		t.Errorf("unknown-ID error = %v", err)
	}
}

func TestKillAllAndActiveCount(t *testing.T) {
	tbl := NewTable()
	for i := 0; i < 2; i++ {
		if _, err := tbl.Start("sleep 30", t.TempDir(), os.Environ(), 0); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}
	if n := tbl.ActiveCount(); n != 2 {
		t.Errorf("ActiveCount = %d, want 2", n)
	}
	tbl.KillAll()
	waitFor(t, "all killed", func() bool { return tbl.ActiveCount() == 0 })
	for _, sh := range tbl.List() {
		if sh.Status() != StatusKilled {
			t.Errorf("shell %s status = %q, want killed", sh.ID(), sh.Status())
		}
	}
}

func TestShellBackgroundStatuses(t *testing.T) {
	tbl := NewTable()
	ok, err := tbl.Start("exit 0", t.TempDir(), os.Environ(), 0)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := tbl.Start("exit 7", t.TempDir(), os.Environ(), 0)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "completed", func() bool { return ok.Status() == StatusCompleted })
	waitFor(t, "failed", func() bool { return bad.Status() == StatusFailed })
	if code, done := ok.ExitCode(); !done || code != 0 {
		t.Errorf("ok ExitCode = (%d,%v), want (0,true)", code, done)
	}
	if code, done := bad.ExitCode(); !done || code != 7 {
		t.Errorf("bad ExitCode = (%d,%v), want (7,true)", code, done)
	}
}

func TestShellBackgroundTimeout(t *testing.T) {
	tbl := NewTable()
	sh, err := tbl.Start("sleep 30", t.TempDir(), os.Environ(), 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "timed_out status", func() bool { return sh.Status() == StatusTimedOut })
	waitFor(t, "process reaped", func() bool { _, done := sh.ExitCode(); return done })
}

func TestTableListNumericOrder(t *testing.T) {
	tbl := NewTable()
	const n = 11
	for i := 0; i < n; i++ {
		if _, err := tbl.Start("true", t.TempDir(), os.Environ(), 0); err != nil {
			t.Fatal(err)
		}
	}
	list := tbl.List()
	if len(list) != n {
		t.Fatalf("List len = %d, want %d", len(list), n)
	}
	for i, sh := range list {
		want := "bash_" + strconv.Itoa(i+1)
		if sh.ID() != want {
			t.Errorf("List[%d] = %q, want %q", i, sh.ID(), want)
		}
	}
	// Get round-trips.
	if sh, ok := tbl.Get("bash_10"); !ok || sh.ID() != "bash_10" {
		t.Errorf("Get(bash_10) = %v, %v", sh, ok)
	}
	if _, ok := tbl.Get("bash_404"); ok {
		t.Error("Get(bash_404) unexpectedly found")
	}
	waitFor(t, "all complete", func() bool { return tbl.ActiveCount() == 0 })
}
