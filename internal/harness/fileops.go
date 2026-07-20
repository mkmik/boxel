package harness

// Read/Write/Edit tool implementations with byte-exact Claude Code semantics:
// identical output formats and failure-mode strings, so the model's recovery
// behavior transfers unchanged through the tunnel.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/mkmik/boxel/internal/envelope"
)

func init() {
	register("Read", readTool)
	register("Write", writeTool)
	register("Edit", editTool)
}

// readTruncationMarker is appended when Read output would exceed MaxOutputBytes.
const readTruncationMarker = "\n... [output truncated: use offset/limit to view more] ..."

// splitFileLines splits file content into lines. A single trailing newline
// does not produce a phantom empty last line (cat -n behavior).
func splitFileLines(content string) []string {
	content = strings.TrimSuffix(content, "\n")
	return strings.Split(content, "\n")
}

// truncateLine caps a line at ReadMaxLineLen runes, with no marker.
func truncateLine(line string) string {
	if utf8.RuneCountInString(line) <= ReadMaxLineLen {
		return line
	}
	runes := []rune(line)
	return string(runes[:ReadMaxLineLen])
}

// catN formats a single line in cat -n style.
func catN(lineNo int, line string) string {
	return fmt.Sprintf("%6d\t%s", lineNo, line)
}

// didYouMean looks for a similarly-named file in the same directory as path:
// same name with different case, or same base name with a different
// extension. It returns the full path of the first such file, or "".
func didYouMean(path string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	baseNoExt := strings.TrimSuffix(base, filepath.Ext(base))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		name := e.Name()
		if name == base || e.IsDir() {
			continue
		}
		sameCaseFolded := strings.EqualFold(name, base)
		sameBase := strings.TrimSuffix(name, filepath.Ext(name)) == baseNoExt
		if sameCaseFolded || sameBase {
			return filepath.Join(dir, name)
		}
	}
	return ""
}

func readTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in, ok := input.(*envelope.ReadInput)
	if !ok {
		return nil, fmt.Errorf("harness: Read: unexpected input type %T", input)
	}
	path := hctx.Abs(in.FilePath)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			msg := "File does not exist."
			if suggestion := didYouMean(path); suggestion != "" {
				msg += "\nDid you mean " + suggestion + "?"
			}
			return Errorf("%s", msg), nil
		}
		return Errorf("%s", err.Error()), nil
	}
	if info.IsDir() {
		return Errorf("EISDIR: illegal operation on a directory, read"), nil
	}
	if info.Size() == 0 {
		return &Result{Text: "<system-reminder>Warning: the file exists but the contents are empty.</system-reminder>"}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Errorf("%s", err.Error()), nil
	}

	// Reject obviously-binary files: NUL byte within the first 8KB.
	probe := data
	if len(probe) > 8192 {
		probe = probe[:8192]
	}
	if bytes.IndexByte(probe, 0) >= 0 {
		return Errorf("Cannot read binary file: %s", path), nil
	}

	lines := splitFileLines(string(data))
	n := len(lines)

	offset := in.Offset
	if offset <= 0 {
		offset = 1
	}
	if offset > n {
		return Errorf("Offset %d is past the end of the file (file has %d lines)", in.Offset, n), nil
	}
	limit := in.Limit
	if limit <= 0 {
		limit = ReadDefaultLimit
	}
	end := offset + limit - 1
	if end > n {
		end = n
	}

	var b strings.Builder
	for lineNo := offset; lineNo <= end; lineNo++ {
		formatted := catN(lineNo, truncateLine(lines[lineNo-1]))
		sep := ""
		if b.Len() > 0 {
			sep = "\n"
		}
		if b.Len()+len(sep)+len(formatted) > MaxOutputBytes {
			b.WriteString(readTruncationMarker)
			break
		}
		b.WriteString(sep)
		b.WriteString(formatted)
	}
	return &Result{Text: b.String()}, nil
}

func writeTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in, ok := input.(*envelope.WriteInput)
	if !ok {
		return nil, fmt.Errorf("harness: Write: unexpected input type %T", input)
	}
	path := hctx.Abs(in.FilePath)

	info, err := os.Stat(path)
	existed := err == nil
	if existed && info.IsDir() {
		return Errorf("EISDIR: illegal operation on a directory, open '%s'", path), nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Errorf("%s", err.Error()), nil
	}
	if err := os.WriteFile(path, []byte(in.Content), 0o644); err != nil {
		return Errorf("%s", err.Error()), nil
	}

	if existed {
		return &Result{Text: fmt.Sprintf("The file %s has been updated.", path)}, nil
	}
	return &Result{Text: fmt.Sprintf("File created successfully at: %s", path)}, nil
}

func editTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in, ok := input.(*envelope.EditInput)
	if !ok {
		return nil, fmt.Errorf("harness: Edit: unexpected input type %T", input)
	}
	path := hctx.Abs(in.FilePath)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Errorf("File does not exist."), nil
		}
		return Errorf("%s", err.Error()), nil
	}
	content := string(data)

	count := strings.Count(content, in.OldString)
	if count == 0 {
		return Errorf("String to replace not found in file.\nString: %s", in.OldString), nil
	}
	if count > 1 && !in.ReplaceAll {
		return Errorf("Found %d matches of the string to replace, but replace_all is false. To replace all occurrences, set replace_all to true. To replace only one occurrence, please provide more context to uniquely identify the instance.\nString: %s", count, in.OldString), nil
	}

	replacements := 1
	if in.ReplaceAll {
		replacements = -1
	}
	newContent := strings.Replace(content, in.OldString, in.NewString, replacements)

	if err := os.WriteFile(path, []byte(newContent), 0o644); err != nil {
		return Errorf("%s", err.Error()), nil
	}

	// Snippet around the (first) replacement site, with ~4 lines of context
	// on each side, numbered with absolute line numbers.
	idx := strings.Index(content, in.OldString)
	startLine := strings.Count(content[:idx], "\n") + 1
	endLine := strings.Count(newContent[:idx+len(in.NewString)], "\n") + 1

	lines := splitFileLines(newContent)
	from := startLine - 4
	if from < 1 {
		from = 1
	}
	to := endLine + 4
	if to > len(lines) {
		to = len(lines)
	}
	snippet := make([]string, 0, to-from+1)
	for lineNo := from; lineNo <= to; lineNo++ {
		snippet = append(snippet, catN(lineNo, truncateLine(lines[lineNo-1])))
	}

	text := fmt.Sprintf("The file %s has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n%s", path, strings.Join(snippet, "\n"))
	return &Result{Text: text}, nil
}
