package harness

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mkmik/boxel/internal/envelope"
)

func init() {
	register("Grep", grepTool)
}

func grepTool(ctx context.Context, hctx *Context, input any) (*Result, error) {
	in := input.(*envelope.GrepInput)

	rgPath, err := exec.LookPath("rg")
	if err != nil {
		return Errorf("ripgrep (rg) not found on PATH"), nil
	}

	root := hctx.Abs(in.Path)

	mode := in.OutputMode
	if mode == "" {
		mode = "files_with_matches"
	}

	args := []string{"--color=never", "--no-heading"}
	switch mode {
	case "files_with_matches":
		args = append(args, "-l")
	case "count":
		args = append(args, "--count")
	case "content":
		// Claude Code shows line numbers in content mode by default; the
		// typed input carries no presence information for -n, so -n is
		// always passed here.
		args = append(args, "-n")
		if in.AfterContext > 0 {
			args = append(args, "-A", strconv.Itoa(in.AfterContext))
		}
		if in.BeforeContext > 0 {
			args = append(args, "-B", strconv.Itoa(in.BeforeContext))
		}
		if in.Context > 0 {
			args = append(args, "-C", strconv.Itoa(in.Context))
		}
	}
	if in.CaseInsensitive {
		args = append(args, "-i")
	}
	if in.Multiline {
		args = append(args, "-U", "--multiline-dotall")
	}
	if in.Glob != "" {
		args = append(args, "--glob", in.Glob)
	}
	if in.Type != "" {
		args = append(args, "--type", in.Type)
	}
	args = append(args, "--", in.Pattern, root)

	cmd := exec.CommandContext(ctx, rgPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			exitCode = ee.ExitCode()
		} else {
			return nil, runErr
		}
	}
	if exitCode != 0 && exitCode != 1 {
		// Exit 2: real error (invalid regex, bad path, unknown type...).
		// Surface rg's stderr so the model can fix the call.
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = "rg exited with code " + strconv.Itoa(exitCode)
		}
		return Errorf("%s", msg), nil
	}

	out := strings.TrimRight(stdout.String(), "\n")
	if exitCode == 1 || out == "" {
		if mode == "files_with_matches" {
			return &Result{Text: "No files found"}, nil
		}
		return &Result{Text: "No matches found"}, nil
	}

	lines := strings.Split(out, "\n")

	if mode == "files_with_matches" {
		// Claude Code returns most recently modified files first.
		type entry struct {
			path  string
			mtime time.Time
		}
		entries := make([]entry, 0, len(lines))
		for _, p := range lines {
			var mtime time.Time
			if fi, statErr := os.Stat(p); statErr == nil {
				mtime = fi.ModTime()
			}
			entries = append(entries, entry{path: p, mtime: mtime})
		}
		sort.Slice(entries, func(i, j int) bool {
			if !entries[i].mtime.Equal(entries[j].mtime) {
				return entries[i].mtime.After(entries[j].mtime)
			}
			return entries[i].path < entries[j].path
		})
		total := len(entries)
		paths := make([]string, 0, total)
		for _, e := range entries {
			paths = append(paths, e.path)
		}
		paths = sliceLines(paths, in.Offset, in.HeadLimit)
		text := "Found " + strconv.Itoa(total) + " files"
		if len(paths) > 0 {
			text += "\n" + strings.Join(paths, "\n")
		}
		return &Result{Text: Truncate(text, MaxOutputBytes)}, nil
	}

	lines = sliceLines(lines, in.Offset, in.HeadLimit)
	if len(lines) == 0 {
		return &Result{Text: "No matches found"}, nil
	}
	return &Result{Text: Truncate(strings.Join(lines, "\n"), MaxOutputBytes)}, nil
}

// sliceLines applies offset then head_limit line-wise. A zero limit means
// unlimited.
func sliceLines(lines []string, offset, limit int) []string {
	if offset > 0 {
		if offset >= len(lines) {
			return nil
		}
		lines = lines[offset:]
	}
	if limit > 0 && len(lines) > limit {
		lines = lines[:limit]
	}
	return lines
}
