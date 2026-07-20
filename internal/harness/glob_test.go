package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkmik/boxel/internal/envelope"
	"github.com/mkmik/boxel/internal/session"
)

// newSearchTestContext builds a harness Context whose session cwd is dir.
// (Named to avoid clashing with helpers in sibling test files.)
func newSearchTestContext(t *testing.T, dir string) *Context {
	t.Helper()
	mgr := session.NewManager(dir, 0)
	return &Context{Session: mgr.Get("search-test"), WorkspaceRoot: dir}
}

func writeSearchFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func chtimes(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func runGlob(t *testing.T, hctx *Context, in *envelope.GlobInput) *Result {
	t.Helper()
	res, err := globTool(context.Background(), hctx, in)
	if err != nil {
		t.Fatalf("globTool returned Go error: %v", err)
	}
	return res
}

func TestGlobBasic(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "a.go"), "package a\n")
	writeSearchFile(t, filepath.Join(dir, "b.txt"), "text\n")
	writeSearchFile(t, filepath.Join(dir, "sub", "c.go"), "package c\n")

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.go"})
	if res.IsError {
		t.Fatalf("unexpected error result: %s", res.Text)
	}
	want := filepath.Join(dir, "a.go")
	if res.Text != want {
		t.Errorf("got %q, want %q (basename pattern must not recurse)", res.Text, want)
	}
}

func TestGlobRecursive(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "a.go"), "package a\n")
	writeSearchFile(t, filepath.Join(dir, "sub", "deep", "c.go"), "package c\n")
	writeSearchFile(t, filepath.Join(dir, "sub", "d.txt"), "text\n")

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "**/*.go"})
	if res.IsError {
		t.Fatalf("unexpected error result: %s", res.Text)
	}
	lines := strings.Split(res.Text, "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d results, want 2: %q", len(lines), res.Text)
	}
	got := map[string]bool{lines[0]: true, lines[1]: true}
	for _, want := range []string{
		filepath.Join(dir, "a.go"),
		filepath.Join(dir, "sub", "deep", "c.go"),
	} {
		if !got[want] {
			t.Errorf("missing %q in output %q", want, res.Text)
		}
	}
}

func TestGlobMtimeOrdering(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)
	oldest := filepath.Join(dir, "z_oldest.go")
	middle := filepath.Join(dir, "a_middle.go")
	newest := filepath.Join(dir, "m_newest.go")
	for _, p := range []string{oldest, middle, newest} {
		writeSearchFile(t, p, "x")
	}
	chtimes(t, oldest, base)
	chtimes(t, middle, base.Add(1*time.Hour))
	chtimes(t, newest, base.Add(2*time.Hour))

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.go"})
	want := oldest + "\n" + middle + "\n" + newest
	if res.Text != want {
		t.Errorf("mtime ascending order wrong:\ngot:\n%s\nwant:\n%s", res.Text, want)
	}
}

func TestGlobSkipsGit(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "keep.go"), "x")
	writeSearchFile(t, filepath.Join(dir, ".git", "skip.go"), "x")
	writeSearchFile(t, filepath.Join(dir, ".git", "objects", "deep.go"), "x")

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "**/*.go"})
	if res.Text != filepath.Join(dir, "keep.go") {
		t.Errorf("expected .git contents skipped, got: %q", res.Text)
	}
}

func TestGlobNoMatches(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "a.txt"), "x")

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.rs"})
	if res.IsError || res.Text != "No files found" {
		t.Errorf("got (%v, %q), want No files found", res.IsError, res.Text)
	}
}

func TestGlobCapAt100(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 105; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%03d.txt", i))
		writeSearchFile(t, p, "x")
		chtimes(t, p, base.Add(time.Duration(i)*time.Minute))
	}

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.txt"})
	lines := strings.Split(res.Text, "\n")
	if len(lines) != 101 {
		t.Fatalf("got %d lines, want 100 paths + truncation notice", len(lines))
	}
	if lines[100] != globTruncationNotice {
		t.Errorf("last line = %q, want truncation notice", lines[100])
	}
	// Oldest 100 should be listed; the 5 newest fall off the end.
	if lines[0] != filepath.Join(dir, "f000.txt") {
		t.Errorf("first line = %q, want oldest file", lines[0])
	}
	if lines[99] != filepath.Join(dir, "f099.txt") {
		t.Errorf("100th line = %q, want f099.txt", lines[99])
	}
}

func TestGlobRootDoesNotExist(t *testing.T) {
	dir := t.TempDir()
	hctx := newSearchTestContext(t, dir)
	missing := filepath.Join(dir, "nope")
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.go", Path: missing})
	if !res.IsError {
		t.Fatalf("expected error result, got %q", res.Text)
	}
	if res.Text != "Path does not exist: "+missing {
		t.Errorf("got %q", res.Text)
	}
}

func TestGlobRootIsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain.txt")
	writeSearchFile(t, file, "x")
	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.go", Path: file})
	if !res.IsError || res.Text != "Path is not a directory: "+file {
		t.Errorf("got (%v, %q)", res.IsError, res.Text)
	}
}

func TestGlobInvalidPattern(t *testing.T) {
	dir := t.TempDir()
	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "[unclosed"})
	if !res.IsError || !strings.HasPrefix(res.Text, "Invalid glob pattern: ") {
		t.Errorf("got (%v, %q)", res.IsError, res.Text)
	}
}

func TestGlobAbsolutePattern(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "sub", "a.go"), "x")
	writeSearchFile(t, filepath.Join(dir, "sub", "b.txt"), "x")

	// Session cwd points elsewhere; the absolute pattern carries its own root.
	other := t.TempDir()
	hctx := newSearchTestContext(t, other)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: filepath.Join(dir, "sub", "*.go")})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Text)
	}
	if res.Text != filepath.Join(dir, "sub", "a.go") {
		t.Errorf("got %q", res.Text)
	}
}

func TestGlobFilesOnlyNotDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "match.go"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeSearchFile(t, filepath.Join(dir, "real.go"), "x")

	hctx := newSearchTestContext(t, dir)
	res := runGlob(t, hctx, &envelope.GlobInput{Pattern: "*.go"})
	if res.Text != filepath.Join(dir, "real.go") {
		t.Errorf("directories must not match; got %q", res.Text)
	}
}
