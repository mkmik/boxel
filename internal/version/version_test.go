package version

import (
	"runtime/debug"
	"testing"
)

func TestFromBuildInfo(t *testing.T) {
	cases := []struct {
		name string
		bi   debug.BuildInfo
		want string
	}{
		{
			name: "module version from go install",
			bi:   debug.BuildInfo{Main: debug.Module{Version: "v0.2.1"}},
			want: "v0.2.1",
		},
		{
			name: "devel build with vcs revision",
			bi: debug.BuildInfo{
				Main: debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
					{Key: "vcs.modified", Value: "false"},
				},
			},
			want: "0123456789ab",
		},
		{
			name: "dirty worktree",
			bi: debug.BuildInfo{
				Main: debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			want: "0123456789ab-dirty",
		},
		{
			name: "no version at all",
			bi:   debug.BuildInfo{},
			want: "(devel)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fromBuildInfo(&tc.bi); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStringNonEmpty(t *testing.T) {
	if String() == "" {
		t.Error("String() returned empty version")
	}
}
