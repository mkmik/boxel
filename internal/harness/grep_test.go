package harness

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mkmik/boxel/internal/envelope"
)

func runGrep(t *testing.T, hctx *Context, in *envelope.GrepInput) *Result {
	t.Helper()
	res, err := grepTool(context.Background(), hctx, in)
	if err != nil {
		t.Fatalf("grepTool returned Go error: %v", err)
	}
	return res
}

func TestGrepFilesWithMatchesDefault(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "hit1.txt"), "needle here\n")
	writeSearchFile(t, filepath.Join(dir, "hit2.txt"), "another needle\n")
	writeSearchFile(t, filepath.Join(dir, "miss.txt"), "nothing\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Text)
	}
	lines := strings.Split(res.Text, "\n")
	if lines[0] != "Found 2 files" {
		t.Errorf("header = %q, want Found 2 files", lines[0])
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want header + 2 paths: %q", len(lines), res.Text)
	}
	got := map[string]bool{lines[1]: true, lines[2]: true}
	if !got[filepath.Join(dir, "hit1.txt")] || !got[filepath.Join(dir, "hit2.txt")] {
		t.Errorf("wrong paths: %q", res.Text)
	}
}

func TestGrepFilesWithMatchesMtimeDescending(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)
	older := filepath.Join(dir, "a_older.txt")
	newer := filepath.Join(dir, "z_newer.txt")
	writeSearchFile(t, older, "needle\n")
	writeSearchFile(t, newer, "needle\n")
	chtimes(t, older, base)
	chtimes(t, newer, base.Add(time.Hour))

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle"})
	want := "Found 2 files\n" + newer + "\n" + older
	if res.Text != want {
		t.Errorf("mtime descending order wrong:\ngot:\n%s\nwant:\n%s", res.Text, want)
	}
}

func TestGrepContentMode(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	writeSearchFile(t, file, "first\nneedle line\nlast\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", OutputMode: "content"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Text)
	}
	want := file + ":2:needle line"
	if res.Text != want {
		t.Errorf("got %q, want %q (line numbers on by default)", res.Text, want)
	}
}

func TestGrepCountMode(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	writeSearchFile(t, file, "needle\nno\nneedle\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", OutputMode: "count"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Text)
	}
	want := file + ":2"
	if res.Text != want {
		t.Errorf("got %q, want %q", res.Text, want)
	}
}

func TestGrepNoMatches(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "f.txt"), "nothing here\n")
	hctx := newSearchTestContext(t, dir)

	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "zzz_absent"})
	if res.IsError || res.Text != "No files found" {
		t.Errorf("files_with_matches: got (%v, %q), want No files found", res.IsError, res.Text)
	}
	res = runGrep(t, hctx, &envelope.GrepInput{Pattern: "zzz_absent", OutputMode: "content"})
	if res.IsError || res.Text != "No matches found" {
		t.Errorf("content: got (%v, %q), want No matches found", res.IsError, res.Text)
	}
	res = runGrep(t, hctx, &envelope.GrepInput{Pattern: "zzz_absent", OutputMode: "count"})
	if res.IsError || res.Text != "No matches found" {
		t.Errorf("count: got (%v, %q), want No matches found", res.IsError, res.Text)
	}
}

func TestGrepCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	writeSearchFile(t, file, "NEEDLE\n")
	hctx := newSearchTestContext(t, dir)

	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", OutputMode: "content"})
	if res.Text != "No matches found" {
		t.Fatalf("case-sensitive search unexpectedly matched: %q", res.Text)
	}
	res = runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", OutputMode: "content", CaseInsensitive: true})
	if res.Text != file+":1:NEEDLE" {
		t.Errorf("got %q", res.Text)
	}
}

func TestGrepContextLines(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	writeSearchFile(t, file, "one\ntwo\nneedle\nfour\nfive\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", OutputMode: "content", Context: 1})
	lines := strings.Split(res.Text, "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3 (match + 1 before + 1 after): %q", len(lines), res.Text)
	}
	if lines[0] != file+"-2-two" || lines[1] != file+":3:needle" || lines[2] != file+"-4-four" {
		t.Errorf("context output wrong: %q", res.Text)
	}
}

func TestGrepGlobFilter(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "a.go"), "needle\n")
	writeSearchFile(t, filepath.Join(dir, "b.txt"), "needle\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", Glob: "*.go"})
	want := "Found 1 files\n" + filepath.Join(dir, "a.go")
	if res.Text != want {
		t.Errorf("got %q, want %q", res.Text, want)
	}
}

func TestGrepTypeFilter(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "a.go"), "needle\n")
	writeSearchFile(t, filepath.Join(dir, "b.txt"), "needle\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", Type: "go"})
	want := "Found 1 files\n" + filepath.Join(dir, "a.go")
	if res.Text != want {
		t.Errorf("got %q, want %q", res.Text, want)
	}
}

func TestGrepHeadLimitAndOffset(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	writeSearchFile(t, file, "needle 1\nneedle 2\nneedle 3\nneedle 4\nneedle 5\n")
	hctx := newSearchTestContext(t, dir)

	res := runGrep(t, hctx, &envelope.GrepInput{
		Pattern: "needle", OutputMode: "content", Offset: 1, HeadLimit: 2,
	})
	want := file + ":2:needle 2\n" + file + ":3:needle 3"
	if res.Text != want {
		t.Errorf("got %q, want %q", res.Text, want)
	}

	// Offset beyond output -> no matches.
	res = runGrep(t, hctx, &envelope.GrepInput{
		Pattern: "needle", OutputMode: "content", Offset: 100,
	})
	if res.Text != "No matches found" {
		t.Errorf("got %q, want No matches found", res.Text)
	}
}

func TestGrepHeadLimitFilesWithMatchesHeader(t *testing.T) {
	dir := t.TempDir()
	base := time.Now().Add(-24 * time.Hour)
	for i, name := range []string{"a.txt", "b.txt", "c.txt"} {
		p := filepath.Join(dir, name)
		writeSearchFile(t, p, "needle\n")
		chtimes(t, p, base.Add(time.Duration(i)*time.Hour))
	}

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", HeadLimit: 2})
	lines := strings.Split(res.Text, "\n")
	if lines[0] != "Found 3 files" {
		t.Errorf("header must reflect total: got %q", lines[0])
	}
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want header + 2 limited paths: %q", len(lines), res.Text)
	}
	// Newest first: c.txt then b.txt.
	if lines[1] != filepath.Join(dir, "c.txt") || lines[2] != filepath.Join(dir, "b.txt") {
		t.Errorf("wrong limited paths: %q", res.Text)
	}
}

func TestGrepInvalidRegex(t *testing.T) {
	dir := t.TempDir()
	writeSearchFile(t, filepath.Join(dir, "f.txt"), "x\n")

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "(unclosed", OutputMode: "content"})
	if !res.IsError {
		t.Fatalf("expected error result, got %q", res.Text)
	}
	if !strings.Contains(res.Text, "regex") {
		t.Errorf("error should surface rg's regex message: %q", res.Text)
	}
}

func TestGrepOutputTruncation(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		sb.WriteString("needle abcdefghijklmnopqrstuvwxyz0123456789\n")
	}
	writeSearchFile(t, filepath.Join(dir, "big.txt"), sb.String())

	hctx := newSearchTestContext(t, dir)
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "needle", OutputMode: "content"})
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Text)
	}
	if !strings.Contains(res.Text, "bytes truncated") {
		t.Error("expected truncation marker in oversized output")
	}
	if len(res.Text) > MaxOutputBytes+100 {
		t.Errorf("output length %d exceeds cap plus marker", len(res.Text))
	}
}

func TestGrepRgMissing(t *testing.T) {
	dir := t.TempDir()
	hctx := newSearchTestContext(t, dir)
	t.Setenv("PATH", filepath.Join(dir, "empty-bin"))
	res := runGrep(t, hctx, &envelope.GrepInput{Pattern: "x"})
	if !res.IsError || res.Text != "ripgrep (rg) not found on PATH" {
		t.Errorf("got (%v, %q)", res.IsError, res.Text)
	}
}
