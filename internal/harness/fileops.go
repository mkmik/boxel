package harness

// Stub: Read/Write/Edit implementations replace this file (may split into
// read.go / write.go / edit.go; remove this stub when doing so).
//
// Semantics contract (must match Claude Code byte-for-byte):
//
// Read:
//   - Output lines formatted as cat -n: 6-width right-aligned 1-based line
//     number, then a tab, then the line content.
//   - Default limit 2000 lines from offset (1-based; 0 → start).
//   - Lines longer than ReadMaxLineLen are truncated.
//   - Missing file → "File does not exist." style error Result.
//   - Empty file → system-reminder style warning text.
//
// Write:
//   - Full-file write, creating parent directories.
//   - Success text: "File created successfully at: <path>" or updated note.
//
// Edit:
//   - old_string not found →
//     "String to replace not found in file.\nString: <old_string>"
//   - multiple matches without replace_all →
//     "Found N matches of the string to replace, but replace_all is false.
//      To replace all occurrences, set replace_all to true. To replace only
//      one occurrence, please provide more context to uniquely identify the
//      instance.\nString: <old_string>"
//   - success → "The file <path> has been updated. Here's the result of
//     running `cat -n` on a snippet of the edited file:" + numbered snippet.

import "context"

func init() {
	for _, name := range []string{"Read", "Write", "Edit"} {
		register(name, func(ctx context.Context, hctx *Context, input any) (*Result, error) {
			return Errorf("not implemented"), nil
		})
	}
}
