package envelope

import "encoding/json"

// schemas holds the JSON input schema for each supported tool. These mirror
// Claude Code's native tool schemas; `describe` exposes them as the source of
// truth so the model can self-correct instead of guessing.
var schemas = map[string]json.RawMessage{
	"Read": json.RawMessage(`{
  "type": "object",
  "properties": {
    "file_path": {"type": "string", "description": "The absolute path to the file to read"},
    "offset": {"type": "integer", "description": "The line number to start reading from (1-based). Only provide for large files."},
    "limit": {"type": "integer", "description": "The number of lines to read. Only provide for large files."}
  },
  "required": ["file_path"]
}`),
	"Write": json.RawMessage(`{
  "type": "object",
  "properties": {
    "file_path": {"type": "string", "description": "The absolute path to the file to write"},
    "content": {"type": "string", "description": "The content to write to the file"}
  },
  "required": ["file_path", "content"]
}`),
	"Edit": json.RawMessage(`{
  "type": "object",
  "properties": {
    "file_path": {"type": "string", "description": "The absolute path to the file to modify"},
    "old_string": {"type": "string", "description": "The text to replace. Must match the file contents exactly, including whitespace, and be unique unless replace_all is set."},
    "new_string": {"type": "string", "description": "The text to replace it with (must differ from old_string)"},
    "replace_all": {"type": "boolean", "default": false, "description": "Replace all occurrences of old_string"}
  },
  "required": ["file_path", "old_string", "new_string"]
}`),
	"Glob": json.RawMessage(`{
  "type": "object",
  "properties": {
    "pattern": {"type": "string", "description": "The glob pattern to match files against, e.g. \"**/*.go\""},
    "path": {"type": "string", "description": "The directory to search in. Omit for the session working directory."}
  },
  "required": ["pattern"]
}`),
	"Grep": json.RawMessage(`{
  "type": "object",
  "properties": {
    "pattern": {"type": "string", "description": "The regular expression pattern to search for (ripgrep syntax)"},
    "path": {"type": "string", "description": "File or directory to search in. Defaults to the session working directory."},
    "glob": {"type": "string", "description": "Glob pattern to filter files, e.g. \"*.go\""},
    "type": {"type": "string", "description": "File type to search, e.g. \"go\", \"py\", \"js\""},
    "output_mode": {"type": "string", "enum": ["content", "files_with_matches", "count"], "description": "Output mode; defaults to files_with_matches"},
    "-i": {"type": "boolean", "description": "Case insensitive search"},
    "-n": {"type": "boolean", "description": "Show line numbers (content mode; defaults to true)"},
    "-A": {"type": "integer", "description": "Lines to show after each match (content mode)"},
    "-B": {"type": "integer", "description": "Lines to show before each match (content mode)"},
    "-C": {"type": "integer", "description": "Lines to show before and after each match (content mode)"},
    "multiline": {"type": "boolean", "description": "Enable multiline mode where patterns can span lines"},
    "head_limit": {"type": "integer", "description": "Limit output to first N lines/entries"},
    "offset": {"type": "integer", "description": "Skip first N lines/entries before applying head_limit"}
  },
  "required": ["pattern"]
}`),
	"Bash": json.RawMessage(`{
  "type": "object",
  "properties": {
    "command": {"type": "string", "description": "The command to execute (bash -c, non-interactive)"},
    "timeout": {"type": "integer", "description": "Optional timeout in milliseconds (default 120000, max 600000)"},
    "description": {"type": "string", "description": "Clear, concise description of what this command does"},
    "run_in_background": {"type": "boolean", "description": "Run in the background; poll with BashOutput"}
  },
  "required": ["command"]
}`),
	"BashOutput": json.RawMessage(`{
  "type": "object",
  "properties": {
    "bash_id": {"type": "string", "description": "The ID of the background shell to retrieve output from"},
    "filter": {"type": "string", "description": "Optional regex; only output lines matching it are returned"}
  },
  "required": ["bash_id"]
}`),
	"KillShell": json.RawMessage(`{
  "type": "object",
  "properties": {
    "shell_id": {"type": "string", "description": "The ID of the background shell to kill"}
  },
  "required": ["shell_id"]
}`),
}
