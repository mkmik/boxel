package envelope

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSupportedTools(t *testing.T) {
	got := SupportedTools()
	want := []string{"Bash", "BashOutput", "Edit", "Glob", "Grep", "KillShell", "Read", "Write"}
	if len(got) != len(want) {
		t.Fatalf("got %d tools, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tool[%d] = %q, want %q (must be sorted)", i, got[i], want[i])
		}
	}
	for _, name := range want {
		if !IsSupported(name) {
			t.Errorf("IsSupported(%q) = false", name)
		}
		if SchemaFor(name) == nil {
			t.Errorf("SchemaFor(%q) = nil", name)
		}
	}
	if IsSupported("Nope") {
		t.Error("IsSupported(Nope) = true")
	}
}

func TestSchemasAreValidJSON(t *testing.T) {
	for _, name := range SupportedTools() {
		var v any
		if err := json.Unmarshal(SchemaFor(name), &v); err != nil {
			t.Errorf("schema for %q is not valid JSON: %v", name, err)
		}
	}
}

func TestUnknownToolError(t *testing.T) {
	var m map[string]any
	if err := json.Unmarshal(UnknownToolError("Frob"), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "unknown_tool" || m["tool"] != "Frob" {
		t.Errorf("unexpected unknown_tool payload: %v", m)
	}
	if _, ok := m["supported"].([]any); !ok {
		t.Error("unknown_tool payload missing supported list")
	}
}

func TestParseInputValid(t *testing.T) {
	cases := []struct {
		tool  string
		input string
		check func(any) bool
	}{
		{"Read", `{"file_path":"/a","offset":2,"limit":5}`, func(v any) bool {
			r := v.(*ReadInput)
			return r.FilePath == "/a" && r.Offset == 2 && r.Limit == 5
		}},
		{"Write", `{"file_path":"/a","content":"x"}`, func(v any) bool {
			return v.(*WriteInput).Content == "x"
		}},
		{"Edit", `{"file_path":"/a","old_string":"x","new_string":"y","replace_all":true}`, func(v any) bool {
			e := v.(*EditInput)
			return e.OldString == "x" && e.NewString == "y" && e.ReplaceAll
		}},
		{"Glob", `{"pattern":"**/*.go"}`, func(v any) bool {
			return v.(*GlobInput).Pattern == "**/*.go"
		}},
		{"Grep", `{"pattern":"foo","output_mode":"content","-i":true,"-C":3}`, func(v any) bool {
			g := v.(*GrepInput)
			return g.Pattern == "foo" && g.OutputMode == "content" && g.CaseInsensitive && g.Context == 3
		}},
		{"Bash", `{"command":"ls","run_in_background":true,"timeout":5000}`, func(v any) bool {
			b := v.(*BashInput)
			return b.Command == "ls" && b.RunInBackground && b.Timeout == 5000
		}},
		{"BashOutput", `{"bash_id":"bash_1","filter":"x"}`, func(v any) bool {
			return v.(*BashOutputInput).BashID == "bash_1"
		}},
		{"KillShell", `{"shell_id":"bash_1"}`, func(v any) bool {
			return v.(*KillShellInput).ShellID == "bash_1"
		}},
	}
	for _, c := range cases {
		v, err := ParseInput(c.tool, json.RawMessage(c.input))
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.tool, err)
			continue
		}
		if !c.check(v) {
			t.Errorf("%s: check failed for %+v", c.tool, v)
		}
	}
}

func TestParseInputErrors(t *testing.T) {
	cases := []struct{ tool, input, wantSub string }{
		{"Read", `{}`, "file_path"},
		{"Write", `{"content":"x"}`, "file_path"},
		{"Edit", `{"file_path":"/a","new_string":"y"}`, "old_string"},
		{"Edit", `{"file_path":"/a","old_string":"x","new_string":"x"}`, "must be different"},
		{"Glob", `{}`, "pattern"},
		{"Grep", `{"pattern":"x","output_mode":"weird"}`, "invalid output_mode"},
		{"Bash", `{}`, "command"},
		{"Bash", `{"command":"x","timeout":-1}`, "non-negative"},
		{"BashOutput", `{}`, "bash_id"},
		{"KillShell", `{}`, "shell_id"},
		{"Nope", `{}`, "unknown tool"},
	}
	for _, c := range cases {
		_, err := ParseInput(c.tool, json.RawMessage(c.input))
		if err == nil {
			t.Errorf("%s %s: expected error", c.tool, c.input)
			continue
		}
		if !strings.Contains(err.Error(), c.wantSub) {
			t.Errorf("%s %s: error %q missing %q", c.tool, c.input, err, c.wantSub)
		}
	}
}

func TestParseInputEmptyDefaultsToObject(t *testing.T) {
	// Empty input for a tool with only optional-after-required fields still
	// errors on the required field rather than panicking.
	if _, err := ParseInput("Read", nil); err == nil {
		t.Error("expected error for empty Read input")
	}
}

func TestSchemaError(t *testing.T) {
	_, err := ParseInput("Read", json.RawMessage(`{}`))
	var m map[string]any
	if e := json.Unmarshal(SchemaError("Read", err), &m); e != nil {
		t.Fatal(e)
	}
	if m["error"] != "invalid_input" || m["tool"] != "Read" {
		t.Errorf("unexpected schema error payload: %v", m)
	}
	if _, ok := m["expected_schema"]; !ok {
		t.Error("schema error should echo expected_schema")
	}
}
