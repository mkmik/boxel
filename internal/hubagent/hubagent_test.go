package hubagent

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// freeAddr returns a host:port that nothing is listening on (a listener opened
// then immediately closed), for exercising the connection-refused path.
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestProxyForwardsToTarget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hi from target")
	}))
	defer backend.Close()

	h := newProxyHandler(Config{Name: "t", Version: "vX"}, mustURL(t, backend.URL), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "hi from target" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestProxyForwardFailureIsInformative(t *testing.T) {
	target := "http://" + freeAddr(t) // nothing listening -> connection refused
	h := newProxyHandler(Config{Name: "able-sky", Logf: func(string, ...any) {}}, mustURL(t, target), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v (%q)", err, rec.Body.String())
	}
	if body["error"] != "agent_forward_failed" {
		t.Fatalf("error = %v, want agent_forward_failed", body["error"])
	}
	if body["agent"] != "able-sky" {
		t.Fatalf("agent = %v, want able-sky", body["agent"])
	}
	if body["target"] != target {
		t.Fatalf("target = %v, want %s", body["target"], target)
	}
}

func TestDiagEndpointServedByAgentWhenTargetDown(t *testing.T) {
	target := "http://" + freeAddr(t)
	h := newProxyHandler(Config{Name: "able-sky", Version: "v0.2.0"}, mustURL(t, target), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, DiagPath, nil))

	// The agent answers the diag path itself, so it succeeds even though the
	// forward target is down.
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["agent"] != "able-sky" || body["agent_ok"] != true {
		t.Fatalf("diag = %v, want agent able-sky agent_ok true", body)
	}
	tc, ok := body["target_check"].(map[string]any)
	if !ok {
		t.Fatalf("no target_check: %v", body)
	}
	if tc["reachable"] != false {
		t.Fatalf("target_check.reachable = %v, want false", tc["reachable"])
	}
}

func TestDiagEndpointReportsReachableTarget(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	h := newProxyHandler(Config{Name: "t"}, mustURL(t, backend.URL), "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, DiagPath, nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	tc := body["target_check"].(map[string]any)
	if tc["reachable"] != true {
		t.Fatalf("reachable = %v, want true", tc["reachable"])
	}
	if got := tc["http_status"]; got != float64(http.StatusNoContent) {
		t.Fatalf("http_status = %v, want 204", got)
	}
}
