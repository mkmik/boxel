package harness

// Bash/BashOutput/KillShell tool implementations, built on internal/shellmgr,
// with Claude Code-compatible output formats:
//
//   - Bash runs bash -c in the session cwd with session env overrides; cwd
//     changes persist to the session. Non-zero exit appends "Exit code N";
//     timeout appends "Command timed out after Ns". run_in_background
//     returns the shell ID immediately.
//   - BashOutput returns output produced since the last BashOutput call for
//     that shell wrapped in <status>/<exit_code>/<stdout>/<stderr> blocks.
//   - KillShell kills the shell's process group.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mkmik/boxel/internal/envelope"
	"github.com/mkmik/boxel/internal/session"
	"github.com/mkmik/boxel/internal/shellmgr"
)

func init() {
	register("Bash", bashTool)
	register("BashOutput", bashOutputTool)
	register("KillShell", killShellTool)
}

// sessionEnviron builds the process environment: the server environment plus
// the session's overrides appended as KEY=VALUE (later entries win in bash).
func sessionEnviron(s *session.Session) []string {
	env := os.Environ()
	overrides := s.Env()
	keys := make([]string, 0, len(overrides))
	for k := range overrides {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, k+"="+overrides[k])
	}
	return env
}

// combineOutput joins stdout and stderr Claude Code-style: trailing newlines
// trimmed, stderr appended after stdout on its own line.
func combineOutput(stdout, stderr string) string {
	stdout = strings.TrimRight(stdout, "\n")
	stderr = strings.TrimRight(stderr, "\n")
	switch {
	case stderr == "":
		return stdout
	case stdout == "":
		return stderr
	default:
		return stdout + "\n" + stderr
	}
}

// appendFinalLine appends line after text, skipping the separator when there
// is no preceding output.
func appendFinalLine(text, line string) string {
	if text == "" {
		return line
	}
	return text + "\n" + line
}

func bashTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in := input.(*envelope.BashInput)
	cwd := hctx.Session.Cwd()
	env := sessionEnviron(hctx.Session)

	if in.RunInBackground {
		sh, err := hctx.Session.Shells.Start(in.Command, cwd, env, 0)
		if err != nil {
			return Errorf("Failed to start background shell: %v", err), nil
		}
		return &Result{Text: fmt.Sprintf("Command running in background with ID: %s", sh.ID())}, nil
	}

	timeoutMs := in.Timeout
	if timeoutMs <= 0 {
		timeoutMs = BashDefaultTimeout
	}
	if timeoutMs > BashMaxTimeout {
		timeoutMs = BashMaxTimeout
	}

	res, err := shellmgr.RunForeground(ctx, in.Command, cwd, env, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return nil, err
	}

	if res.NewCwd != "" && res.NewCwd != cwd {
		hctx.Session.Chdir(res.NewCwd)
	}

	text := Truncate(combineOutput(res.Stdout, res.Stderr), MaxOutputBytes)

	if res.TimedOut {
		// Report the requested timeout, rounded to seconds, not measured time.
		line := fmt.Sprintf("Command timed out after %s", time.Duration(timeoutMs/1000)*time.Second)
		return &Result{Text: appendFinalLine(text, line), IsError: true}, nil
	}
	ec := res.ExitCode
	if ec == 0 {
		return &Result{Text: text, ExitStatus: &ec}, nil
	}
	return &Result{
		Text:       appendFinalLine(text, fmt.Sprintf("Exit code %d", ec)),
		IsError:    true,
		ExitStatus: &ec,
	}, nil
}

// blockContent newline-terminates non-empty stream content so the closing
// tag lands on its own line.
func blockContent(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func bashOutputTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in := input.(*envelope.BashOutputInput)
	sh, ok := hctx.Session.Shells.Get(in.BashID)
	if !ok {
		msg := fmt.Sprintf("No shell found with ID: %s", in.BashID)
		if shells := hctx.Session.Shells.List(); len(shells) > 0 {
			ids := make([]string, len(shells))
			for i, s := range shells {
				ids[i] = s.ID()
			}
			msg += "\nAvailable shells: " + strings.Join(ids, ", ")
		}
		return &Result{Text: msg, IsError: true}, nil
	}

	// Snapshot status before draining output: if the shell finishes between
	// the two reads, the model sees "running" now and picks up the final
	// state (with any residual output) on the next poll.
	status := sh.Status()
	code, finished := sh.ExitCode()

	stdout, stderr, err := sh.ReadNew(in.Filter)
	if err != nil {
		return Errorf("%v", err), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "<status>%s</status>\n", status)
	if finished {
		fmt.Fprintf(&b, "<exit_code>%d</exit_code>\n", code)
	}
	b.WriteString("<stdout>\n")
	b.WriteString(blockContent(Truncate(stdout, MaxOutputBytes)))
	b.WriteString("</stdout>")
	if stderr != "" {
		b.WriteString("\n<stderr>\n")
		b.WriteString(blockContent(Truncate(stderr, MaxOutputBytes)))
		b.WriteString("</stderr>")
	}
	// Not an error result even for failed shells: the model reads exit_code.
	return &Result{Text: b.String()}, nil
}

func killShellTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in := input.(*envelope.KillShellInput)
	sh, ok := hctx.Session.Shells.Get(in.ShellID)
	if !ok {
		return Errorf("No shell found with ID: %s", in.ShellID), nil
	}
	if st := sh.Status(); st != shellmgr.StatusRunning {
		return Errorf("Shell %s is not running (status: %s)", in.ShellID, st), nil
	}
	if err := hctx.Session.Shells.Kill(in.ShellID); err != nil {
		return Errorf("%v", err), nil
	}
	return &Result{Text: fmt.Sprintf("Successfully killed shell: %s", in.ShellID)}, nil
}
