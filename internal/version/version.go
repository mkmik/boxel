// Package version derives the backend version from the build info the Go
// toolchain embeds in every binary, so `go install module@version` builds
// report their real module version without any ldflags plumbing.
package version

import "runtime/debug"

// String returns the version of the main module: the module version for
// `go install module@version` builds (e.g. "v0.2.1"), otherwise the VCS
// revision for source builds, otherwise "(devel)".
func String() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}
	return fromBuildInfo(bi)
}

func fromBuildInfo(bi *debug.BuildInfo) string {
	v := bi.Main.Version
	if v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "(devel)"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}
