package harness

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkmik/boxel/internal/envelope"
	"github.com/mkmik/boxel/internal/session"
	"github.com/mkmik/boxel/internal/shellmgr"
)

func newBashHCtx(t *testing.T) *Context {
	t.Helper()
	dir := t.TempDir()
	s := session.NewManager(dir, 0).Get("t")
	t.Cleanup(s.Shells.KillAll)
	return &Context{Session: s, WorkspaceRoot: dir}
}

func bashDispatch(t *testing.T, hctx *Context, tool string, input any) *Result {
	t.Helper()
	res, err := Dispatch(context.Background(), hctx, tool, input)
	if err != nil {
		t.Fatalf("Dispatch(%s): %v", tool, err)
	}
	return res
}

func bashWaitStatus(t *testing.T, hctx *Context, id string, want shellmgr.Status) {
	t.Helper()
	sh, ok := hctx.Session.Shells.Get(id)
	if !ok {
		t.Fatalf("no shell %s in table", id)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, done := sh.ExitCode(); done && sh.Status() == want {
			return
		}
		if sh.Status() == want && want == shellmgr.StatusRunning {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("shell %s status = %q, want %q", id, sh.Status(), want)
}

func TestBashForegroundStdout(t *testing.T) {
	hctx := newBashHCtx(t)
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo hi"})
	if res.IsError {
		t.Fatalf("unexpected error result: %q", res.Text)
	}
	if res.Text != "hi" {
		t.Errorf("Text = %q, want %q", res.Text, "hi")
	}
	if res.ExitStatus == nil || *res.ExitStatus != 0 {
		t.Errorf("ExitStatus = %v, want 0", res.ExitStatus)
	}
}

func TestBashStderrAppended(t *testing.T) {
	hctx := newBashHCtx(t)
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo out; echo err >&2"})
	if res.Text != "out\nerr" {
		t.Errorf("Text = %q, want %q", res.Text, "out\nerr")
	}
	// stderr only: no leading newline.
	res = bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo only-err >&2"})
	if res.Text != "only-err" {
		t.Errorf("Text = %q, want %q", res.Text, "only-err")
	}
}

func TestBashExitCodeLine(t *testing.T) {
	hctx := newBashHCtx(t)
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo bad >&2; exit 3"})
	if !res.IsError {
		t.Error("IsError = false, want true")
	}
	if res.Text != "bad\nExit code 3" {
		t.Errorf("Text = %q, want %q", res.Text, "bad\nExit code 3")
	}
	if res.ExitStatus == nil || *res.ExitStatus != 3 {
		t.Errorf("ExitStatus = %v, want 3", res.ExitStatus)
	}
	// No output at all: just the exit code line.
	res = bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "exit 5"})
	if res.Text != "Exit code 5" {
		t.Errorf("Text = %q, want %q", res.Text, "Exit code 5")
	}
}

func TestBashTimeoutMessage(t *testing.T) {
	hctx := newBashHCtx(t)
	start := time.Now()
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo started; sleep 30", Timeout: 1000})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s, want ~1s", elapsed)
	}
	if !res.IsError {
		t.Error("IsError = false, want true")
	}
	if res.Text != "started\nCommand timed out after 1s" {
		t.Errorf("Text = %q, want %q", res.Text, "started\nCommand timed out after 1s")
	}
}

func TestBashBackgroundID(t *testing.T) {
	hctx := newBashHCtx(t)
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "sleep 30", RunInBackground: true})
	if res.IsError {
		t.Fatalf("unexpected error result: %q", res.Text)
	}
	if res.Text != "Command running in background with ID: bash_1" {
		t.Errorf("Text = %q", res.Text)
	}
	if res.ExitStatus != nil {
		t.Errorf("ExitStatus = %v, want nil", *res.ExitStatus)
	}
}

func TestBashOutputLifecycle(t *testing.T) {
	hctx := newBashHCtx(t)
	syncFile := filepath.Join(t.TempDir(), "release")
	cmd := `until [ -f ` + syncFile + ` ]; do sleep 0.02; done; echo done-marker`
	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: cmd, RunInBackground: true})

	res := bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_1"})
	if res.IsError {
		t.Fatalf("unexpected error result: %q", res.Text)
	}
	if !strings.HasPrefix(res.Text, "<status>running</status>\n") {
		t.Errorf("first poll Text = %q, want running status", res.Text)
	}
	if strings.Contains(res.Text, "<exit_code>") {
		t.Errorf("first poll includes exit_code: %q", res.Text)
	}

	if err := os.WriteFile(syncFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	bashWaitStatus(t, hctx, "bash_1", shellmgr.StatusCompleted)

	res = bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_1"})
	want := "<status>completed</status>\n<exit_code>0</exit_code>\n<stdout>\ndone-marker\n</stdout>"
	if res.Text != want {
		t.Errorf("final poll Text = %q, want %q", res.Text, want)
	}
	if res.IsError {
		t.Error("final poll IsError = true, want false")
	}
}

func TestBashOutputStderrAndFailed(t *testing.T) {
	hctx := newBashHCtx(t)
	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo o; echo e >&2; exit 2", RunInBackground: true})
	bashWaitStatus(t, hctx, "bash_1", shellmgr.StatusFailed)

	res := bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_1"})
	want := "<status>failed</status>\n<exit_code>2</exit_code>\n<stdout>\no\n</stdout>\n<stderr>\ne\n</stderr>"
	if res.Text != want {
		t.Errorf("Text = %q, want %q", res.Text, want)
	}
	if res.IsError {
		t.Error("IsError = true for failed shell, want false (model reads exit_code)")
	}
}

func TestBashOutputUnknownID(t *testing.T) {
	hctx := newBashHCtx(t)
	res := bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_9"})
	if !res.IsError {
		t.Error("IsError = false, want true")
	}
	if res.Text != "No shell found with ID: bash_9" {
		t.Errorf("Text = %q", res.Text)
	}

	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "sleep 30", RunInBackground: true})
	res = bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_9"})
	want := "No shell found with ID: bash_9\nAvailable shells: bash_1"
	if res.Text != want {
		t.Errorf("Text = %q, want %q", res.Text, want)
	}
}

func TestBashOutputBadFilter(t *testing.T) {
	hctx := newBashHCtx(t)
	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "echo x", RunInBackground: true})
	res := bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_1", Filter: "("})
	if !res.IsError {
		t.Error("IsError = false, want true")
	}
	if !strings.Contains(res.Text, "error parsing regexp") {
		t.Errorf("Text = %q, want regexp error", res.Text)
	}
}

func TestBashOutputFilter(t *testing.T) {
	hctx := newBashHCtx(t)
	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: `printf 'apple\nbanana\napricot\n'`, RunInBackground: true})
	bashWaitStatus(t, hctx, "bash_1", shellmgr.StatusCompleted)
	res := bashDispatch(t, hctx, "BashOutput", &envelope.BashOutputInput{BashID: "bash_1", Filter: "^ap"})
	want := "<status>completed</status>\n<exit_code>0</exit_code>\n<stdout>\napple\napricot\n</stdout>"
	if res.Text != want {
		t.Errorf("Text = %q, want %q", res.Text, want)
	}
}

func TestKillShellFlow(t *testing.T) {
	hctx := newBashHCtx(t)
	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "sleep 30", RunInBackground: true})

	res := bashDispatch(t, hctx, "KillShell", &envelope.KillShellInput{ShellID: "bash_1"})
	if res.IsError {
		t.Fatalf("unexpected error result: %q", res.Text)
	}
	if res.Text != "Successfully killed shell: bash_1" {
		t.Errorf("Text = %q", res.Text)
	}
	bashWaitStatus(t, hctx, "bash_1", shellmgr.StatusKilled)

	// Killing an already-finished shell is an error result.
	res = bashDispatch(t, hctx, "KillShell", &envelope.KillShellInput{ShellID: "bash_1"})
	if !res.IsError {
		t.Error("IsError = false for finished shell, want true")
	}
	if res.Text != "Shell bash_1 is not running (status: killed)" {
		t.Errorf("Text = %q", res.Text)
	}

	// Unknown ID.
	res = bashDispatch(t, hctx, "KillShell", &envelope.KillShellInput{ShellID: "bash_42"})
	if !res.IsError || res.Text != "No shell found with ID: bash_42" {
		t.Errorf("unknown ID result = (%v, %q)", res.IsError, res.Text)
	}
}

func TestBashCwdPersists(t *testing.T) {
	hctx := newBashHCtx(t)
	startCwd := hctx.Session.Cwd()
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "mkdir -p subdir && cd subdir"})
	if res.IsError {
		t.Fatalf("cd failed: %q", res.Text)
	}
	got := hctx.Session.Cwd()
	if got == startCwd || filepath.Base(got) != "subdir" {
		t.Errorf("session cwd = %q, want a subdir of %q", got, startCwd)
	}
	// Second call actually runs there.
	res = bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "pwd"})
	if res.Text != got {
		t.Errorf("pwd = %q, want %q", res.Text, got)
	}
	// A failing command that never reaches the pwd capture keeps the cwd.
	bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "true"})
	if hctx.Session.Cwd() != got {
		t.Errorf("cwd changed unexpectedly to %q", hctx.Session.Cwd())
	}
}

func TestBashEnvOverride(t *testing.T) {
	hctx := newBashHCtx(t)
	hctx.Session.SetEnv("BOXEL_HARNESS_ENV", "zzz")
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: `printf %s "$BOXEL_HARNESS_ENV"`})
	if res.Text != "zzz" {
		t.Errorf("Text = %q, want %q", res.Text, "zzz")
	}
}

func TestBashTruncation(t *testing.T) {
	hctx := newBashHCtx(t)
	res := bashDispatch(t, hctx, "Bash", &envelope.BashInput{Command: "head -c 40000 /dev/zero | tr '\\0' a"})
	if res.IsError {
		t.Fatalf("unexpected error: %q", res.Text)
	}
	if !strings.Contains(res.Text, "[10000 bytes truncated]") {
		t.Errorf("missing truncation marker in %q...", res.Text[len(res.Text)-80:])
	}
	if len(res.Text) > MaxOutputBytes+100 {
		t.Errorf("len(Text) = %d, want ~%d", len(res.Text), MaxOutputBytes)
	}
}
