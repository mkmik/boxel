package harness

// Stub: Bash/BashOutput/KillShell implementations replace this file (may
// split; remove this stub when doing so). Built on internal/shellmgr.
//
// Semantics contract (must match Claude Code):
//
// Bash:
//   - bash -c, non-interactive, in the session cwd with session env
//     overrides; cwd changes persist to the session (shellmgr's
//     ForegroundResult.NewCwd → Session.Chdir).
//   - timeout ms: default BashDefaultTimeout, capped at BashMaxTimeout.
//   - Output: stdout, then stderr; truncated at MaxOutputBytes.
//   - Non-zero exit → IsError with "Exit code N" appended; ExitStatus set.
//   - Timeout → IsError "Command timed out after Ns".
//   - run_in_background → immediately returns the shell ID:
//     "Command running in background with ID: <id>".
//
// BashOutput:
//   - Returns output produced since the last BashOutput call for that
//     shell, wrapped with status; includes exit code once finished.
//   - Unknown ID → error Result listing known shells.
//   - filter: regex applied per line to the new output.
//
// KillShell:
//   - Kills the process group; "Successfully killed shell: <id>" or error
//     Result if unknown/already dead.

import "context"

func init() {
	for _, name := range []string{"Bash", "BashOutput", "KillShell"} {
		register(name, func(ctx context.Context, hctx *Context, input any) (*Result, error) {
			return Errorf("not implemented"), nil
		})
	}
}
