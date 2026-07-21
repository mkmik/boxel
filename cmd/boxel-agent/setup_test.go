package main

import "testing"

func TestSetupEnvContent(t *testing.T) {
	// Identity-mode exe.dev install: no hub URL (autodiscovery), no token.
	got := setupEnvContent("", "", "", "foobar", "http://127.0.0.1:8080", "")
	want := "BOXEL_AGENT_NAME=foobar\nBOXEL_AGENT_TARGET=http://127.0.0.1:8080\n"
	if got != want {
		t.Errorf("identity mode env = %q, want %q", got, want)
	}

	// Fully specified token-mode install.
	got = setupEnvContent("http://hub:8081", "custom-hub", "tok", "foobar", "http://127.0.0.1:9000", "/etc/boxel-agent/target-token")
	want = "BOXEL_HUB_URL=http://hub:8081\n" +
		"BOXEL_HUB_INTEGRATION=custom-hub\n" +
		"BOXEL_AGENT_TOKEN=tok\n" +
		"BOXEL_AGENT_NAME=foobar\n" +
		"BOXEL_AGENT_TARGET=http://127.0.0.1:9000\n" +
		"BOXEL_AGENT_TARGET_TOKEN_FILE=/etc/boxel-agent/target-token\n"
	if got != want {
		t.Errorf("token mode env = %q, want %q", got, want)
	}
}
