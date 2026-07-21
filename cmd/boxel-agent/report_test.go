package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

// TestReportHubStatusNotReady: when the hub integration is not attached yet,
// setup must present the outcome as a SUCCESS with explicit follow-up
// instructions — an unattended installer (e.g. Shelley acting on VM
// description notes) runs before the owner creates the integration, and must
// neither fail nor retry the install.
func TestReportHubStatusNotReady(t *testing.T) {
	out := captureStdout(t, func() {
		// Unreachable reflection endpoint → discovery fails like on a VM
		// where the peer integration (and reflection route) isn't set up.
		reportHubStatus("", "boxel-hub", "http://127.0.0.1:1/nowhere", "foobar")
	})
	for _, want := range []string{
		"ACTION REQUIRED",
		"integrations add http-proxy --name boxel-hub",
		"ssh exe.dev tag",
		"installation has\nSUCCEEDED",
		"journalctl -u boxel-agent.service",
		"/vm/foobar/mcp",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("not-ready report missing %q; got:\n%s", want, out)
		}
	}
}

// TestReportHubStatusExplicitHub: with a configured hub URL there is nothing
// to discover and the report is a plain success.
func TestReportHubStatusExplicitHub(t *testing.T) {
	out := captureStdout(t, func() {
		reportHubStatus("http://hub:8081", "", "", "foobar")
	})
	if strings.Contains(out, "ACTION REQUIRED") {
		t.Errorf("explicit-hub report should not demand action; got:\n%s", out)
	}
	if !strings.Contains(out, "registering with http://hub:8081") {
		t.Errorf("explicit-hub report missing hub URL; got:\n%s", out)
	}
}
