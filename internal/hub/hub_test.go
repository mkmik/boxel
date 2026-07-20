package hub_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mkmik/boxel/internal/hub"
	"github.com/mkmik/boxel/internal/hubagent"
)

// startHub builds a hub with its routes on a real TCP test server (agent
// registration needs a hijackable HTTP/1.1 listener).
func startHub(t *testing.T, cfg hub.Config) (*hub.Hub, *httptest.Server) {
	t.Helper()
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	h := hub.New(cfg)
	mux := http.NewServeMux()
	h.AttachRoutes(mux, nil)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return h, ts
}

// startAgent runs a hubagent against the hub until the test ends.
func startAgent(t *testing.T, cfg hubagent.Config) context.CancelFunc {
	t.Helper()
	if cfg.Logf == nil {
		cfg.Logf = t.Logf
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = 50 * time.Millisecond
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = hubagent.Run(ctx, cfg) }()
	return cancel
}

// waitRegistered polls until name shows up in the hub registry after `after`.
func waitRegistered(t *testing.T, h *hub.Hub, name string, after time.Time) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range h.Agents() {
			if a.Name == name && a.ConnectedAt.After(after) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent %q did not register in time; registry: %+v", name, h.Agents())
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPullModeEndToEnd(t *testing.T) {
	// Local "boxel" the agent forwards to: echoes method, URL, auth header.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s auth=%q body=%q", r.Method, r.URL.String(), r.Header.Get("Authorization"), body)
	}))
	defer target.Close()

	h, ts := startHub(t, hub.Config{AgentToken: "sekrit"})
	startAgent(t, hubagent.Config{
		HubURL: ts.URL, Token: "sekrit", Name: "foobar",
		Target: target.URL, TargetToken: "localtok",
	})
	waitRegistered(t, h, "foobar", time.Time{})

	// GET through the multiplexer: prefix stripped, query preserved, local
	// bearer injected by the agent.
	code, body := get(t, ts.URL+"/vm/foobar/echo/sub?x=1")
	if code != http.StatusOK {
		t.Fatalf("GET code %d, body %s", code, body)
	}
	if want := `GET /echo/sub?x=1 auth="Bearer localtok" body=""`; body != want {
		t.Errorf("GET body = %q, want %q", body, want)
	}

	// POST with a body (the MCP endpoint shape).
	resp, err := http.Post(ts.URL+"/vm/foobar/mcp", "application/json", strings.NewReader(`{"hi":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := `POST /mcp auth="Bearer localtok" body="{\"hi\":1}"`; string(b) != want {
		t.Errorf("POST body = %q, want %q", b, want)
	}

	// Unknown VM → 502 vm_not_connected.
	code, body = get(t, ts.URL+"/vm/nope/echo")
	if code != http.StatusBadGateway || !strings.Contains(body, "vm_not_connected") {
		t.Errorf("unknown vm: code %d, body %s", code, body)
	}

	// /agents lists the registration.
	code, body = get(t, ts.URL+"/agents")
	if code != http.StatusOK || !strings.Contains(body, `"foobar"`) {
		t.Errorf("/agents: code %d, body %s", code, body)
	}

	// /vm/foobar redirects to the slash form.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/vm/foobar?y=2", nil)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	rr, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rr.Body.Close()
	if rr.StatusCode != http.StatusPermanentRedirect || rr.Header.Get("Location") != "/vm/foobar/?y=2" {
		t.Errorf("redirect: code %d, location %q", rr.StatusCode, rr.Header.Get("Location"))
	}
}

// TestStreamingFlush verifies that response bytes flow through both proxy hops
// incrementally — the property MCP streamable HTTP (SSE) depends on.
func TestStreamingFlush(t *testing.T) {
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		io.WriteString(w, "first\n")
		fl.Flush()
		<-release
		io.WriteString(w, "second\n")
	}))
	defer target.Close()

	h, ts := startHub(t, hub.Config{AgentToken: "tok"})
	startAgent(t, hubagent.Config{HubURL: ts.URL, Token: "tok", Name: "streamer", Target: target.URL})
	waitRegistered(t, h, "streamer", time.Time{})

	resp, err := http.Get(ts.URL + "/vm/streamer/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("first chunk: %q, %v", line, err)
	}
	close(release) // only released after the first chunk crossed both hops
	line, err = br.ReadString('\n')
	if err != nil || line != "second\n" {
		t.Fatalf("second chunk: %q, %v", line, err)
	}
}

// TestAgentReplacement: a re-registration under the same name atomically takes
// over the handle (agent restart while the hub still holds the old channel).
func TestAgentReplacement(t *testing.T) {
	mk := func(tag string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, tag)
		}))
	}
	t1, t2 := mk("one"), mk("two")
	defer t1.Close()
	defer t2.Close()

	h, ts := startHub(t, hub.Config{AgentToken: "tok"})
	cancel1 := startAgent(t, hubagent.Config{HubURL: ts.URL, Token: "tok", Name: "dup", Target: t1.URL})
	waitRegistered(t, h, "dup", time.Time{})
	firstAt := h.Agents()[0].ConnectedAt

	if _, body := get(t, ts.URL+"/vm/dup/"); body != "one" {
		t.Fatalf("pre-replacement body %q", body)
	}

	startAgent(t, hubagent.Config{HubURL: ts.URL, Token: "tok", Name: "dup", Target: t2.URL})
	waitRegistered(t, h, "dup", firstAt)
	cancel1() // old agent going away must not unregister the new channel

	time.Sleep(50 * time.Millisecond)
	code, body := get(t, ts.URL+"/vm/dup/")
	if code != http.StatusOK || body != "two" {
		t.Fatalf("post-replacement: code %d, body %q", code, body)
	}
}

func TestConnectRejectsBadCredentials(t *testing.T) {
	_, ts := startHub(t, hub.Config{AgentToken: "right"})

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"wrong token", map[string]string{
			"Authorization": "Bearer wrong", "Upgrade": hub.UpgradeProtocol, "Connection": "Upgrade",
			hub.HeaderAgentName: "x",
		}, http.StatusUnauthorized},
		{"missing upgrade", map[string]string{
			"Authorization": "Bearer right", hub.HeaderAgentName: "x",
		}, http.StatusBadRequest},
		{"bad name", map[string]string{
			"Authorization": "Bearer right", "Upgrade": hub.UpgradeProtocol, "Connection": "Upgrade",
			hub.HeaderAgentName: "Bad_Name!",
		}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+hub.ConnectPath, nil)
		for k, v := range tc.headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: code %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}

func TestInstallerTokenEmbedding(t *testing.T) {
	_, ts := startHub(t, hub.Config{
		AgentToken:   "sekrit-token",
		AdvertiseURL: "http://boxel.internal:8081",
		InstallerAuth: func(r *http.Request) bool {
			return r.Header.Get("Authorization") == "Bearer owner"
		},
	})

	// Unauthenticated: a working script, but no token inside.
	code, body := get(t, ts.URL+hub.InstallerPath)
	if code != http.StatusOK {
		t.Fatalf("installer code %d", code)
	}
	if strings.Contains(body, "sekrit-token") {
		t.Error("unauthenticated installer leaked the agent token")
	}
	for _, want := range []string{"#!/usr/bin/env bash", "http://boxel.internal:8081", "go install", "boxel-agent.service", "systemctl enable --now boxel-agent"} {
		if !strings.Contains(body, want) {
			t.Errorf("installer script missing %q", want)
		}
	}

	// Authenticated: token embedded.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+hub.InstallerPath, nil)
	req.Header.Set("Authorization", "Bearer owner")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "sekrit-token") {
		t.Error("authenticated installer did not embed the agent token")
	}
}

func TestValidName(t *testing.T) {
	valid := []string{"a", "foobar", "foo-bar", "f00-bar-2", strings.Repeat("a", 63)}
	invalid := []string{"", "-foo", "foo-", "Foo", "foo_bar", "foo.bar", strings.Repeat("a", 64)}
	for _, s := range valid {
		if !hub.ValidName(s) {
			t.Errorf("ValidName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if hub.ValidName(s) {
			t.Errorf("ValidName(%q) = true, want false", s)
		}
	}
}
