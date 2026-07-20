// Package envelope defines the generic-operation envelope tunneled over MCP
// and the typed input structures for each supported Claude Code tool.
//
// The envelope is the wire format of the `invoke` MCP tool:
//
//	{ "tool": "Read", "input": { "file_path": "/work/main.go" }, "session": "default" }
//
// Input schemas intentionally mirror Claude Code's native tool schemas so that
// a Claude model can use the exact parameter shapes it uses locally.
package envelope

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Envelope is the body of an `invoke` call: a Claude Code tool call.
type Envelope struct {
	// Tool is the Claude Code tool name, e.g. "Bash", "Read", "Edit".
	Tool string `json:"tool"`
	// Input is the tool input, using the exact schema Claude Code uses natively.
	Input json.RawMessage `json:"input"`
	// Session is an opaque logical-session ID. Absent means "default".
	Session string `json:"session,omitempty"`
}

// ReadInput mirrors Claude Code's Read tool input.
type ReadInput struct {
	FilePath string `json:"file_path"`
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

// WriteInput mirrors Claude Code's Write tool input.
type WriteInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

// EditInput mirrors Claude Code's Edit tool input.
type EditInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

// GlobInput mirrors Claude Code's Glob tool input.
type GlobInput struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path,omitempty"`
}

// GrepInput mirrors Claude Code's Grep tool input, including the
// dash-prefixed ripgrep flag parameters.
type GrepInput struct {
	Pattern         string `json:"pattern"`
	Path            string `json:"path,omitempty"`
	Glob            string `json:"glob,omitempty"`
	Type            string `json:"type,omitempty"`
	OutputMode      string `json:"output_mode,omitempty"` // content | files_with_matches | count
	CaseInsensitive bool   `json:"-i,omitempty"`
	LineNumbers     bool   `json:"-n,omitempty"`
	AfterContext    int    `json:"-A,omitempty"`
	BeforeContext   int    `json:"-B,omitempty"`
	Context         int    `json:"-C,omitempty"`
	Multiline       bool   `json:"multiline,omitempty"`
	HeadLimit       int    `json:"head_limit,omitempty"`
	Offset          int    `json:"offset,omitempty"`
}

// BashInput mirrors Claude Code's Bash tool input.
type BashInput struct {
	Command         string `json:"command"`
	Timeout         int    `json:"timeout,omitempty"` // milliseconds
	Description     string `json:"description,omitempty"`
	RunInBackground bool   `json:"run_in_background,omitempty"`
}

// BashOutputInput mirrors Claude Code's BashOutput tool input.
type BashOutputInput struct {
	BashID string `json:"bash_id"`
	Filter string `json:"filter,omitempty"`
}

// KillShellInput mirrors Claude Code's KillShell tool input.
type KillShellInput struct {
	ShellID string `json:"shell_id"`
}

// SupportedTools returns the tunneled tool names in stable order.
func SupportedTools() []string {
	names := make([]string, 0, len(schemas))
	for name := range schemas {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// IsSupported reports whether the tool name is a tunneled tool.
func IsSupported(tool string) bool {
	_, ok := schemas[tool]
	return ok
}

// SchemaFor returns the JSON schema for a tool's input, or nil if unknown.
func SchemaFor(tool string) json.RawMessage {
	return schemas[tool]
}

// UnknownToolError is the structured error returned for unrecognized tool
// names, per the PRD: {"error": "unknown_tool", "supported": [...]}.
func UnknownToolError(tool string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"error":     "unknown_tool",
		"tool":      tool,
		"supported": SupportedTools(),
	})
	return b
}

// SchemaError builds a structured schema-validation error that echoes the
// expected input shape back to the model so it can self-correct.
func SchemaError(tool string, cause error) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"error":           "invalid_input",
		"tool":            tool,
		"message":         cause.Error(),
		"expected_schema": SchemaFor(tool),
	})
	return b
}

// ParseInput decodes and validates a tool input into its typed form.
// It returns a descriptive error naming missing required fields.
func ParseInput(tool string, input json.RawMessage) (any, error) {
	if len(input) == 0 {
		input = json.RawMessage("{}")
	}
	switch tool {
	case "Read":
		var v ReadInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.FilePath == "" {
			return nil, fmt.Errorf("missing required field: file_path")
		}
		return &v, nil
	case "Write":
		var v WriteInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.FilePath == "" {
			return nil, fmt.Errorf("missing required field: file_path")
		}
		return &v, nil
	case "Edit":
		var v EditInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.FilePath == "" {
			return nil, fmt.Errorf("missing required field: file_path")
		}
		if v.OldString == "" {
			return nil, fmt.Errorf("missing required field: old_string")
		}
		if v.OldString == v.NewString {
			return nil, fmt.Errorf("old_string and new_string must be different")
		}
		return &v, nil
	case "Glob":
		var v GlobInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.Pattern == "" {
			return nil, fmt.Errorf("missing required field: pattern")
		}
		return &v, nil
	case "Grep":
		var v GrepInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.Pattern == "" {
			return nil, fmt.Errorf("missing required field: pattern")
		}
		switch v.OutputMode {
		case "", "content", "files_with_matches", "count":
		default:
			return nil, fmt.Errorf("invalid output_mode %q: must be content, files_with_matches, or count", v.OutputMode)
		}
		return &v, nil
	case "Bash":
		var v BashInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.Command == "" {
			return nil, fmt.Errorf("missing required field: command")
		}
		if v.Timeout < 0 {
			return nil, fmt.Errorf("timeout must be non-negative milliseconds")
		}
		return &v, nil
	case "BashOutput":
		var v BashOutputInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.BashID == "" {
			return nil, fmt.Errorf("missing required field: bash_id")
		}
		return &v, nil
	case "KillShell":
		var v KillShellInput
		if err := json.Unmarshal(input, &v); err != nil {
			return nil, err
		}
		if v.ShellID == "" {
			return nil, fmt.Errorf("missing required field: shell_id")
		}
		return &v, nil
	default:
		return nil, fmt.Errorf("unknown tool %q", tool)
	}
}
