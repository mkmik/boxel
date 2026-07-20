package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func do(t *testing.T, h http.Handler, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestAuthMiddlewareRefusesUnauthenticated(t *testing.T) {
	if _, _, err := authMiddleware("", "", okHandler()); err == nil {
		t.Fatal("expected error when no auth is configured")
	}
}

func TestAuthMiddlewareBearerOnly(t *testing.T) {
	h, desc, err := authMiddleware("sekret", "", okHandler())
	if err != nil {
		t.Fatal(err)
	}
	if desc != "bearer" {
		t.Errorf("desc = %q, want bearer", desc)
	}
	if code := do(t, h, map[string]string{"Authorization": "Bearer sekret"}); code != http.StatusOK {
		t.Errorf("valid bearer: code %d", code)
	}
	if code := do(t, h, map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusUnauthorized {
		t.Errorf("bad bearer: code %d, want 401", code)
	}
	if code := do(t, h, nil); code != http.StatusUnauthorized {
		t.Errorf("no bearer: code %d, want 401", code)
	}
}

func TestAuthMiddlewareExeIdentityOnly(t *testing.T) {
	h, desc, err := authMiddleware("", "owner@example.com", okHandler())
	if err != nil {
		t.Fatal(err)
	}
	if desc != "exe-identity(owner@example.com)" {
		t.Errorf("desc = %q", desc)
	}
	// Correct owner (case/space-insensitive) passes.
	if code := do(t, h, map[string]string{exeEmailHeader: "  Owner@Example.com "}); code != http.StatusOK {
		t.Errorf("owner: code %d, want 200", code)
	}
	// Missing header → 401 (request did not traverse the authenticating edge).
	if code := do(t, h, nil); code != http.StatusUnauthorized {
		t.Errorf("missing header: code %d, want 401", code)
	}
	// Different authenticated user → 403.
	if code := do(t, h, map[string]string{exeEmailHeader: "intruder@example.com"}); code != http.StatusForbidden {
		t.Errorf("non-owner: code %d, want 403", code)
	}
}

func TestAuthMiddlewareBothLayers(t *testing.T) {
	h, desc, err := authMiddleware("sekret", "owner@example.com", okHandler())
	if err != nil {
		t.Fatal(err)
	}
	if desc != "bearer+exe-identity(owner@example.com)" {
		t.Errorf("desc = %q", desc)
	}
	// Both satisfied → OK.
	if code := do(t, h, map[string]string{
		"Authorization": "Bearer sekret",
		exeEmailHeader:  "owner@example.com",
	}); code != http.StatusOK {
		t.Errorf("both: code %d, want 200", code)
	}
	// Valid bearer but wrong owner → 403 (bearer layer passes, identity fails).
	if code := do(t, h, map[string]string{
		"Authorization": "Bearer sekret",
		exeEmailHeader:  "intruder@example.com",
	}); code != http.StatusForbidden {
		t.Errorf("wrong owner: code %d, want 403", code)
	}
	// Right owner but no bearer → 401 (bearer layer is outermost).
	if code := do(t, h, map[string]string{exeEmailHeader: "owner@example.com"}); code != http.StatusUnauthorized {
		t.Errorf("no bearer: code %d, want 401", code)
	}
}
