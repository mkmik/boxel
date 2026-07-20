package harness

// Stub: Glob/Grep implementations replace this file (may split into
// glob.go / grep.go; remove this stub when doing so).
//
// Semantics contract (must match Claude Code):
//
// Glob:
//   - doublestar patterns over the search root (input path or session cwd),
//     matching files only (not directories).
//   - Results are absolute paths sorted by modification time (oldest first,
//     ties by name), one per line; "No files found" when empty.
//   - Skips .git directories; caps result count to avoid flooding.
//
// Grep:
//   - Backed by the rg binary; same parameter names as Claude Code
//     (output_mode content/files_with_matches/count, -i, -n, -A/-B/-C,
//     glob, type, multiline, head_limit, offset).
//   - files_with_matches is the default output mode.
//   - content mode defaults to line numbers on.
//   - "No matches found" / "No files found" when empty.

import "context"

func init() {
	for _, name := range []string{"Glob", "Grep"} {
		register(name, func(ctx context.Context, hctx *Context, input any) (*Result, error) {
			return Errorf("not implemented"), nil
		})
	}
}
