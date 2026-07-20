package harness

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mkmik/boxel/internal/envelope"
	"github.com/mkmik/boxel/internal/session"
)

// newTestContext builds a harness Context whose session cwd is dir.
func newTestContext(t *testing.T, dir string) *Context {
	t.Helper()
	mgr := session.NewManager(dir, 0)
	return &Context{Session: mgr.Get(""), WorkspaceRoot: dir}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func dispatch(t *testing.T, hctx *Context, tool string, input any) *Result {
	t.Helper()
	res, err := Dispatch(context.Background(), hctx, tool, input)
	if err != nil {
		t.Fatalf("Dispatch(%s) internal error: %v", tool, err)
	}
	if res == nil {
		t.Fatalf("Dispatch(%s) returned nil result", tool)
	}
	return res
}

func TestRead(t *testing.T) {
	type tc struct {
		name string
		// setup returns the file_path to read (relative or absolute) and
		// may create files under dir.
		setup     func(t *testing.T, dir string) string
		offset    int
		limit     int
		wantText  string // exact expected text ("" means use check)
		wantErr   bool
		check     func(t *testing.T, dir string, res *Result)
		wantTextF func(dir string) string // exact text depending on dir
	}
	tests := []tc{
		{
			name: "basic cat -n with trailing newline",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "a.txt"), "alpha\nbeta\ngamma\n")
				return filepath.Join(dir, "a.txt")
			},
			wantText: "     1\talpha\n     2\tbeta\n     3\tgamma",
		},
		{
			name: "no trailing newline",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "b.txt"), "alpha\nbeta")
				return filepath.Join(dir, "b.txt")
			},
			wantText: "     1\talpha\n     2\tbeta",
		},
		{
			name: "interior blank lines preserved, single trailing newline not phantom",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "blank.txt"), "a\n\nb\n")
				return filepath.Join(dir, "blank.txt")
			},
			wantText: "     1\ta\n     2\t\n     3\tb",
		},
		{
			name: "double trailing newline yields one empty last line",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "dbl.txt"), "a\n\n")
				return filepath.Join(dir, "dbl.txt")
			},
			wantText: "     1\ta\n     2\t",
		},
		{
			name: "offset and limit window",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "w.txt"), "l1\nl2\nl3\nl4\nl5\n")
				return filepath.Join(dir, "w.txt")
			},
			offset:   2,
			limit:    2,
			wantText: "     2\tl2\n     3\tl3",
		},
		{
			name: "offset zero starts at line one",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "z.txt"), "l1\nl2\n")
				return filepath.Join(dir, "z.txt")
			},
			offset:   0,
			limit:    1,
			wantText: "     1\tl1",
		},
		{
			name: "limit past EOF clamps",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "clamp.txt"), "l1\nl2\n")
				return filepath.Join(dir, "clamp.txt")
			},
			offset:   2,
			limit:    100,
			wantText: "     2\tl2",
		},
		{
			name: "offset past EOF",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "eof.txt"), "l1\nl2\nl3\n")
				return filepath.Join(dir, "eof.txt")
			},
			offset:   7,
			wantErr:  true,
			wantText: "Offset 7 is past the end of the file (file has 3 lines)",
		},
		{
			name: "empty file",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "empty.txt"), "")
				return filepath.Join(dir, "empty.txt")
			},
			wantText: "<system-reminder>Warning: the file exists but the contents are empty.</system-reminder>",
		},
		{
			name: "missing file no suggestion",
			setup: func(t *testing.T, dir string) string {
				return filepath.Join(dir, "nope.txt")
			},
			wantErr:  true,
			wantText: "File does not exist.",
		},
		{
			name: "missing file did-you-mean different case",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "README.md"), "hi\n")
				return filepath.Join(dir, "readme.md")
			},
			wantErr: true,
			wantTextF: func(dir string) string {
				return "File does not exist.\nDid you mean " + filepath.Join(dir, "README.md") + "?"
			},
		},
		{
			name: "missing file did-you-mean different extension",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "main.js"), "x\n")
				return filepath.Join(dir, "main.ts")
			},
			wantErr: true,
			wantTextF: func(dir string) string {
				return "File does not exist.\nDid you mean " + filepath.Join(dir, "main.js") + "?"
			},
		},
		{
			name: "directory read",
			setup: func(t *testing.T, dir string) string {
				sub := filepath.Join(dir, "subdir")
				if err := os.MkdirAll(sub, 0o755); err != nil {
					t.Fatal(err)
				}
				return sub
			},
			wantErr:  true,
			wantText: "EISDIR: illegal operation on a directory, read",
		},
		{
			name: "binary file rejected",
			setup: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "bin.dat")
				if err := os.WriteFile(p, []byte{0x89, 'P', 'N', 'G', 0x00, 0x01, 0x02}, 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: true,
			wantTextF: func(dir string) string {
				return "Cannot read binary file: " + filepath.Join(dir, "bin.dat")
			},
		},
		{
			name: "long line truncated to ReadMaxLineLen runes with no marker",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "long.txt"), strings.Repeat("x", 2500)+"\nshort\n")
				return filepath.Join(dir, "long.txt")
			},
			wantText: "     1\t" + strings.Repeat("x", 2000) + "\n     2\tshort",
		},
		{
			name: "long unicode line truncated by runes",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "uni.txt"), strings.Repeat("é", 2500)+"\n")
				return filepath.Join(dir, "uni.txt")
			},
			wantText: "     1\t" + strings.Repeat("é", 2000),
		},
		{
			name: "unicode content passes through",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "u.txt"), "héllo wörld\n日本語テキスト\n")
				return filepath.Join(dir, "u.txt")
			},
			wantText: "     1\théllo wörld\n     2\t日本語テキスト",
		},
		{
			name: "relative path resolved against session cwd",
			setup: func(t *testing.T, dir string) string {
				mustWriteFile(t, filepath.Join(dir, "rel.txt"), "rel\n")
				return "rel.txt"
			},
			wantText: "     1\trel",
		},
		{
			name: "default limit is 2000 lines",
			setup: func(t *testing.T, dir string) string {
				var b strings.Builder
				for i := 1; i <= 2500; i++ {
					fmt.Fprintf(&b, "%d\n", i)
				}
				mustWriteFile(t, filepath.Join(dir, "many.txt"), b.String())
				return filepath.Join(dir, "many.txt")
			},
			check: func(t *testing.T, dir string, res *Result) {
				lines := strings.Split(res.Text, "\n")
				if len(lines) != 2000 {
					t.Fatalf("got %d lines, want 2000", len(lines))
				}
				if lines[0] != "     1\t1" {
					t.Errorf("first line = %q", lines[0])
				}
				if lines[1999] != "  2000\t2000" {
					t.Errorf("last line = %q", lines[1999])
				}
			},
		},
		{
			name: "output capped at MaxOutputBytes with truncation marker",
			setup: func(t *testing.T, dir string) string {
				line := strings.Repeat("a", 100)
				var b strings.Builder
				for i := 0; i < 500; i++ {
					b.WriteString(line)
					b.WriteByte('\n')
				}
				mustWriteFile(t, filepath.Join(dir, "big.txt"), b.String())
				return filepath.Join(dir, "big.txt")
			},
			check: func(t *testing.T, dir string, res *Result) {
				if res.IsError {
					t.Fatalf("unexpected error result: %q", res.Text)
				}
				marker := "\n... [output truncated: use offset/limit to view more] ..."
				if !strings.HasSuffix(res.Text, marker) {
					t.Fatalf("output does not end with truncation marker; tail: %q", res.Text[len(res.Text)-80:])
				}
				body := strings.TrimSuffix(res.Text, marker)
				if len(body) > MaxOutputBytes {
					t.Errorf("body length %d exceeds MaxOutputBytes %d", len(body), MaxOutputBytes)
				}
				// Every retained line must be complete cat -n output.
				lines := strings.Split(body, "\n")
				want := "a"
				if !strings.HasSuffix(lines[len(lines)-1], strings.Repeat(want, 100)) {
					t.Errorf("last retained line is not complete: %q", lines[len(lines)-1])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			hctx := newTestContext(t, dir)
			path := tt.setup(t, dir)
			res := dispatch(t, hctx, "Read", &envelope.ReadInput{FilePath: path, Offset: tt.offset, Limit: tt.limit})
			if res.IsError != tt.wantErr {
				t.Fatalf("IsError = %v, want %v (text: %q)", res.IsError, tt.wantErr, res.Text)
			}
			want := tt.wantText
			if tt.wantTextF != nil {
				want = tt.wantTextF(dir)
			}
			if want != "" && res.Text != want {
				t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
			}
			if tt.check != nil {
				tt.check(t, dir, res)
			}
		})
	}
}

func TestWrite(t *testing.T) {
	t.Run("create new file", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "new.txt")
		res := dispatch(t, hctx, "Write", &envelope.WriteInput{FilePath: path, Content: "hello\n"})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		want := "File created successfully at: " + path
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "hello\n" {
			t.Errorf("file content = %q, err = %v", got, err)
		}
	})

	t.Run("create with missing parent directories", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "a", "b", "c", "deep.txt")
		res := dispatch(t, hctx, "Write", &envelope.WriteInput{FilePath: path, Content: "deep"})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		want := "File created successfully at: " + path
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "deep" {
			t.Errorf("file content = %q, err = %v", got, err)
		}
	})

	t.Run("overwrite existing file", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "exist.txt")
		mustWriteFile(t, path, "old content")
		res := dispatch(t, hctx, "Write", &envelope.WriteInput{FilePath: path, Content: "new content"})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		want := "The file " + path + " has been updated."
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
		got, _ := os.ReadFile(path)
		if string(got) != "new content" {
			t.Errorf("file content = %q", got)
		}
	})

	t.Run("target is a directory", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		sub := filepath.Join(dir, "somedir")
		if err := os.MkdirAll(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		res := dispatch(t, hctx, "Write", &envelope.WriteInput{FilePath: sub, Content: "x"})
		if !res.IsError {
			t.Fatalf("expected error result, got %q", res.Text)
		}
		want := "EISDIR: illegal operation on a directory, open '" + sub + "'"
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
	})

	t.Run("relative path resolved against session cwd", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		res := dispatch(t, hctx, "Write", &envelope.WriteInput{FilePath: "rel/out.txt", Content: "r"})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		abs := filepath.Join(dir, "rel", "out.txt")
		want := "File created successfully at: " + abs
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
		if _, err := os.Stat(abs); err != nil {
			t.Errorf("file not created: %v", err)
		}
	})

	t.Run("unicode content round-trips", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "uni.txt")
		content := "héllo\n日本語\n"
		res := dispatch(t, hctx, "Write", &envelope.WriteInput{FilePath: path, Content: content})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		got, _ := os.ReadFile(path)
		if string(got) != content {
			t.Errorf("file content = %q, want %q", got, content)
		}
	})
}

func TestEdit(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: filepath.Join(dir, "nope.txt"), OldString: "a", NewString: "b",
		})
		if !res.IsError || res.Text != "File does not exist." {
			t.Errorf("got IsError=%v text=%q", res.IsError, res.Text)
		}
	})

	t.Run("old_string not found", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		mustWriteFile(t, path, "hello world\n")
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "goodbye planet", NewString: "x",
		})
		if !res.IsError {
			t.Fatalf("expected error result, got %q", res.Text)
		}
		want := "String to replace not found in file.\nString: goodbye planet"
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
	})

	t.Run("multiple matches without replace_all", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		mustWriteFile(t, path, "foo\nbar\nfoo\nbaz\nfoo\n")
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "foo", NewString: "qux",
		})
		if !res.IsError {
			t.Fatalf("expected error result, got %q", res.Text)
		}
		want := "Found 3 matches of the string to replace, but replace_all is false. To replace all occurrences, set replace_all to true. To replace only one occurrence, please provide more context to uniquely identify the instance.\nString: foo"
		if res.Text != want {
			t.Errorf("text = %q, want %q", res.Text, want)
		}
		// File must be unmodified.
		got, _ := os.ReadFile(path)
		if string(got) != "foo\nbar\nfoo\nbaz\nfoo\n" {
			t.Errorf("file was modified: %q", got)
		}
	})

	t.Run("single replacement with snippet numbering", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		var b strings.Builder
		for i := 1; i <= 12; i++ {
			fmt.Fprintf(&b, "line%d\n", i)
		}
		mustWriteFile(t, path, b.String())
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "line6", NewString: "LINE-SIX",
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		want := "The file " + path + " has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n" +
			"     2\tline2\n" +
			"     3\tline3\n" +
			"     4\tline4\n" +
			"     5\tline5\n" +
			"     6\tLINE-SIX\n" +
			"     7\tline7\n" +
			"     8\tline8\n" +
			"     9\tline9\n" +
			"    10\tline10"
		if res.Text != want {
			t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
		}
		got, _ := os.ReadFile(path)
		if !strings.Contains(string(got), "LINE-SIX") || strings.Contains(string(got), "line6") {
			t.Errorf("file content wrong: %q", got)
		}
	})

	t.Run("replacement near top clamps snippet at line 1", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		mustWriteFile(t, path, "one\ntwo\nthree\nfour\nfive\nsix\nseven\n")
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "two", NewString: "TWO",
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		want := "The file " + path + " has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n" +
			"     1\tone\n" +
			"     2\tTWO\n" +
			"     3\tthree\n" +
			"     4\tfour\n" +
			"     5\tfive\n" +
			"     6\tsix"
		if res.Text != want {
			t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
		}
	})

	t.Run("replacement near bottom clamps snippet at EOF", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		mustWriteFile(t, path, "one\ntwo\nthree\nfour\nfive\n")
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "five", NewString: "FIVE",
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		want := "The file " + path + " has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n" +
			"     1\tone\n" +
			"     2\ttwo\n" +
			"     3\tthree\n" +
			"     4\tfour\n" +
			"     5\tFIVE"
		if res.Text != want {
			t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
		}
	})

	t.Run("replace_all replaces every occurrence, snippet around first", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		var b strings.Builder
		for i := 1; i <= 20; i++ {
			if i%5 == 0 {
				b.WriteString("target\n")
			} else {
				fmt.Fprintf(&b, "line%d\n", i)
			}
		}
		mustWriteFile(t, path, b.String())
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "target", NewString: "REPLACED", ReplaceAll: true,
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		got, _ := os.ReadFile(path)
		if strings.Contains(string(got), "target") {
			t.Errorf("not all occurrences replaced: %q", got)
		}
		if strings.Count(string(got), "REPLACED") != 4 {
			t.Errorf("replaced count = %d, want 4", strings.Count(string(got), "REPLACED"))
		}
		// First occurrence is on line 5; snippet spans lines 1..9.
		want := "The file " + path + " has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n" +
			"     1\tline1\n" +
			"     2\tline2\n" +
			"     3\tline3\n" +
			"     4\tline4\n" +
			"     5\tREPLACED\n" +
			"     6\tline6\n" +
			"     7\tline7\n" +
			"     8\tline8\n" +
			"     9\tline9"
		if res.Text != want {
			t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
		}
	})

	t.Run("multiline new_string extends snippet range", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		var b strings.Builder
		for i := 1; i <= 15; i++ {
			fmt.Fprintf(&b, "l%d\n", i)
		}
		mustWriteFile(t, path, b.String())
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "l7", NewString: "n1\nn2\nn3",
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		// Replacement spans new lines 7-9; snippet = lines 3..13.
		want := "The file " + path + " has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n" +
			"     3\tl3\n" +
			"     4\tl4\n" +
			"     5\tl5\n" +
			"     6\tl6\n" +
			"     7\tn1\n" +
			"     8\tn2\n" +
			"     9\tn3\n" +
			"    10\tl8\n" +
			"    11\tl9\n" +
			"    12\tl10\n" +
			"    13\tl11"
		if res.Text != want {
			t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
		}
	})

	t.Run("unicode replacement", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		path := filepath.Join(dir, "f.txt")
		mustWriteFile(t, path, "prefix\nこんにちは世界\nsuffix\n")
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: path, OldString: "こんにちは", NewString: "さようなら",
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		got, _ := os.ReadFile(path)
		if string(got) != "prefix\nさようなら世界\nsuffix\n" {
			t.Errorf("file content = %q", got)
		}
		want := "The file " + path + " has been updated. Here's the result of running `cat -n` on a snippet of the edited file:\n" +
			"     1\tprefix\n" +
			"     2\tさようなら世界\n" +
			"     3\tsuffix"
		if res.Text != want {
			t.Errorf("text mismatch\n got: %q\nwant: %q", res.Text, want)
		}
	})

	t.Run("relative path resolved against session cwd", func(t *testing.T) {
		dir := t.TempDir()
		hctx := newTestContext(t, dir)
		abs := filepath.Join(dir, "rel.txt")
		mustWriteFile(t, abs, "aaa\n")
		res := dispatch(t, hctx, "Edit", &envelope.EditInput{
			FilePath: "rel.txt", OldString: "aaa", NewString: "bbb",
		})
		if res.IsError {
			t.Fatalf("unexpected error: %q", res.Text)
		}
		if !strings.HasPrefix(res.Text, "The file "+abs+" has been updated.") {
			t.Errorf("message does not use absolute path: %q", res.Text)
		}
		got, _ := os.ReadFile(abs)
		if string(got) != "bbb\n" {
			t.Errorf("file content = %q", got)
		}
	})
}
