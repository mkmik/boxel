package policy

// Rule and built-in matching primitives: Bash command specifiers, path
// specifiers (doublestar), the workspace jail boundary check and the
// built-in credential path patterns.

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// pathWithin reports whether cleaned path p is root itself or lives under
// root, using a path-separator boundary (so /work2 is not inside /work).
// Both arguments must already be filepath.Clean'ed.
func pathWithin(p, root string) bool {
	if p == root {
		return true
	}
	r := root
	if !strings.HasSuffix(r, string(filepath.Separator)) {
		r += string(filepath.Separator)
	}
	return strings.HasPrefix(p, r)
}

// credentialPatterns returns the built-in credential path patterns with ~
// expanded to home (skipped when home is unknown). The "/.ssh/" substring
// rule is applied separately in isCredentialPath.
func credentialPatterns(home string) []string {
	pats := []string{"/etc/shadow", "/etc/sudoers"}
	if home != "" {
		pats = append(pats,
			home+"/.ssh/**",
			home+"/.aws/**",
			home+"/.config/gcloud/**",
			home+"/.gnupg/**",
			home+"/.kube/**",
			home+"/.docker/config.json",
			home+"/.netrc",
			home+"/.git-credentials",
		)
	}
	return pats
}

// isCredentialPath reports whether cleaned path p hits a built-in
// credential pattern.
func (e *Engine) isCredentialPath(p string) bool {
	if strings.Contains(p, "/.ssh/") {
		return true
	}
	for _, pat := range e.credPatterns {
		if hasGlobChars(pat) {
			if ok, err := doublestar.Match(pat, p); err == nil && ok {
				return true
			}
		} else if p == pat {
			return true
		}
	}
	return false
}

// bareCatchAlls are specifiers too broad to lift the credential hard deny.
var bareCatchAlls = map[string]bool{"**": true, "/**": true, "**/*": true, "*": true}

// credentialAllowlisted reports whether a persistent config allow rule
// (never the overlay) explicitly names cleaned path p. Only path-tool rules
// with a non-empty, non-catch-all specifier qualify.
func (e *Engine) credentialAllowlisted(p string) bool {
	for _, r := range e.allow {
		if !pathTools[r.Tool] {
			continue
		}
		spec := strings.TrimSpace(r.Specifier)
		if spec == "" || bareCatchAlls[spec] {
			continue
		}
		if e.matchPathSpec(spec, p) {
			return true
		}
	}
	return false
}

// ruleMatches reports whether rule r covers the call.
func (e *Engine) ruleMatches(r Rule, call ToolCall) bool {
	if r.Tool != call.Tool {
		return false
	}
	spec := strings.TrimSpace(r.Specifier)
	if spec == "" {
		return true // bare "Tool" matches every call of that tool
	}
	switch r.Tool {
	case "Bash":
		return matchBashSpec(spec, strings.TrimSpace(call.Command))
	case "Read", "Write", "Edit", "Glob", "Grep":
		// The rule covers the call only if it matches every path the call
		// touches; a call with no paths is not covered by a path specifier.
		if len(call.Paths) == 0 {
			return false
		}
		for _, p := range call.Paths {
			if !e.matchPathSpec(spec, p) {
				return false
			}
		}
		return true
	default:
		// BashOutput/KillShell take no meaningful specifier.
		return false
	}
}

// matchBashSpec matches a Bash rule specifier against a trimmed command line.
//
//   - "prefix:*" (Claude Code form): command == prefix, or command starts
//     with "prefix ".
//   - contains glob chars without the ":*" suffix (PRD form): anchored glob
//     over the whole command, where * matches any run including spaces.
//   - otherwise: exact match.
func matchBashSpec(spec, cmd string) bool {
	if strings.HasSuffix(spec, ":*") {
		prefix := strings.TrimSuffix(spec, ":*")
		return cmd == prefix || strings.HasPrefix(cmd, prefix+" ")
	}
	if strings.ContainsAny(spec, "*?") {
		return commandGlobToRegexp(spec).MatchString(cmd)
	}
	return spec == cmd
}

// commandGlobToRegexp translates a command glob into an anchored regexp:
// * → ".*" (any run, spaces included), ? → ".", everything else quoted.
func commandGlobToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// matchPathSpec matches a path-tool rule specifier against one absolute
// call path.
//
//   - "~/..." expands to the current user's home directory.
//   - "//..." is Claude Code's config-relative form; we anchor it at /.
//   - Absolute patterns match doublestar against the absolute path.
//   - Relative patterns match doublestar against the path relative to the
//     workspace root; paths outside the root never match relative rules.
//   - A pattern with no glob chars also matches any path under that
//     directory (Edit(/work/src) covers /work/src/a/b.go).
func (e *Engine) matchPathSpec(spec, p string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return true
	}
	if spec == "~" || strings.HasPrefix(spec, "~/") {
		if e.home == "" {
			return false
		}
		spec = e.home + spec[1:]
	}
	if strings.HasPrefix(spec, "//") {
		spec = spec[1:]
	}
	p = filepath.Clean(p)
	var pattern, target string
	if filepath.IsAbs(spec) {
		pattern, target = spec, p
	} else {
		rel, err := filepath.Rel(e.workspaceRoot, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return false
		}
		pattern, target = spec, rel
	}
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		pattern = "/"
	}
	if ok, err := doublestar.Match(pattern, target); err == nil && ok {
		return true
	}
	if !hasGlobChars(pattern) {
		if target == pattern || strings.HasPrefix(target, pattern+"/") {
			return true
		}
	}
	return false
}

// hasGlobChars reports whether s contains doublestar metacharacters.
func hasGlobChars(s string) bool {
	return strings.ContainsAny(s, "*?[{")
}
