package harness

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/mkmik/boxel/internal/envelope"
)

// globMaxResults caps the number of paths Glob returns, mirroring Claude
// Code's 100-result cap.
const globMaxResults = 100

// globTruncationNotice is appended when the result cap is hit.
const globTruncationNotice = "(Results are truncated. Consider using a more specific path or pattern.)"

func init() {
	register("Glob", globTool)
}

func globTool(_ context.Context, hctx *Context, input any) (*Result, error) {
	in := input.(*envelope.GlobInput)

	pattern := in.Pattern
	var root string
	if filepath.IsAbs(pattern) {
		// Absolute pattern: split its static prefix off as the search root
		// and match the remainder relative to it.
		root, pattern = doublestar.SplitPattern(filepath.ToSlash(pattern))
		root = filepath.Clean(filepath.FromSlash(root))
	} else {
		root = hctx.Abs(in.Path)
	}

	if _, err := doublestar.Match(pattern, "probe"); err != nil {
		return Errorf("Invalid glob pattern: %v", err), nil
	}

	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			return Errorf("Path does not exist: %s", root), nil
		}
		return Errorf("%v", err), nil
	}
	if !info.IsDir() {
		return Errorf("Path is not a directory: %s", root), nil
	}

	type match struct {
		path  string
		mtime time.Time
	}
	var matches []match
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// Skip unreadable entries rather than aborting the walk.
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return nil
		}
		ok, _ := doublestar.Match(pattern, filepath.ToSlash(rel))
		if !ok {
			return nil
		}
		var mtime time.Time
		if fi, infoErr := d.Info(); infoErr == nil {
			mtime = fi.ModTime()
		}
		matches = append(matches, match{path: p, mtime: mtime})
		return nil
	})
	if walkErr != nil {
		return Errorf("%v", walkErr), nil
	}

	if len(matches) == 0 {
		return &Result{Text: "No files found"}, nil
	}

	// Claude Code sorts by modification time ascending (oldest first);
	// ties break by path name for determinism.
	sort.Slice(matches, func(i, j int) bool {
		if !matches[i].mtime.Equal(matches[j].mtime) {
			return matches[i].mtime.Before(matches[j].mtime)
		}
		return matches[i].path < matches[j].path
	})

	truncated := false
	if len(matches) > globMaxResults {
		matches = matches[:globMaxResults]
		truncated = true
	}

	lines := make([]string, 0, len(matches)+1)
	for _, m := range matches {
		lines = append(lines, m.path)
	}
	if truncated {
		lines = append(lines, globTruncationNotice)
	}
	return &Result{Text: Truncate(strings.Join(lines, "\n"), MaxOutputBytes)}, nil
}
