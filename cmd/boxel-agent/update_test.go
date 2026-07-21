package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveGoProxy(t *testing.T) {
	for _, tc := range []struct {
		flag, env string
		want      string
		wantErr   bool
	}{
		{"", "", defaultGoProxy, false},
		{"", "direct", defaultGoProxy, false},
		{"", "https://proxy.corp.example/", "https://proxy.corp.example", false},
		{"", "direct,https://proxy.corp.example", "https://proxy.corp.example", false},
		{"", "https://a.example|https://b.example", "https://a.example", false},
		{"", "off", "", true},
		{"https://flag.example/", "https://env.example", "https://flag.example", false},
	} {
		got, err := resolveGoProxy(tc.flag, tc.env)
		if (err != nil) != tc.wantErr {
			t.Errorf("resolveGoProxy(%q, %q) error = %v, wantErr %v", tc.flag, tc.env, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveGoProxy(%q, %q) = %q, want %q", tc.flag, tc.env, got, tc.want)
		}
	}
}

func TestLatestModuleVersion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Uppercase letters must reach the proxy in !-escaped form.
		if r.URL.Path != "/github.com/mk!mik/boxel/@latest" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"Version":"v0.3.1","Time":"2026-07-21T00:00:00Z"}`))
	}))
	defer ts.Close()

	got, err := latestModuleVersion(context.Background(), ts.URL, "github.com/mkMik/boxel")
	if err != nil {
		t.Fatal(err)
	}
	if got != "v0.3.1" {
		t.Errorf("latest = %q, want v0.3.1", got)
	}

	if _, err := latestModuleVersion(context.Background(), ts.URL, "github.com/other/mod"); err == nil {
		t.Error("expected error for unknown module (404), got nil")
	}
}

func TestLatestModuleVersionRejectsGarbage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Version":"not-a-version"}`))
	}))
	defer ts.Close()

	if _, err := latestModuleVersion(context.Background(), ts.URL, "github.com/mkmik/boxel"); err == nil {
		t.Error("expected error for non-semver version, got nil")
	}
}
