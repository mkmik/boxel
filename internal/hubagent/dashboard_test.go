package hubagent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// innerMux is the shape of the wrapped handler in in-process mode: /mcp and
// /healthz, nothing on /.
func innerMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mcp " + r.Method))
	})
	return mux
}

func TestDashboardServedOnRoot(t *testing.T) {
	d := newDashboard(Config{Name: "able-sky", Version: "v0.3.0", HubURL: "http://hub.example"}, innerMux())
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"able-sky",                  // agent name
		"v0.3.0",                    // version
		`href="http://hub.example"`, // link back to the hub URL
		`href="../.."`,              // relative hub-dashboard link (works through /vm/<name>/)
		"/vm/able-sky/mcp",          // MCP endpoint hint
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q; body:\n%s", want, body)
		}
	}
}

func TestDashboardShowsDiscoveredHubURL(t *testing.T) {
	// No configured hub URL: the dashboard says so until a connect cycle
	// resolves one via autodiscovery.
	d := newDashboard(Config{Name: "t", Version: "v1"}, innerMux())
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if body := rec.Body.String(); !strings.Contains(body, "autodiscovering") {
		t.Errorf("dashboard without hub URL missing autodiscovery note; body:\n%s", body)
	}

	d.setHubURL("http://boxel.int.exe.xyz")
	rec = httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if body := rec.Body.String(); !strings.Contains(body, `href="http://boxel.int.exe.xyz"`) {
		t.Errorf("dashboard missing discovered hub URL; body:\n%s", body)
	}
}

func TestDashboardPassesEverythingElseThrough(t *testing.T) {
	d := newDashboard(Config{Name: "t", Version: "v1"}, innerMux())

	// Non-root paths reach the wrapped handler.
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "mcp POST" {
		t.Errorf("POST /mcp: code %d, body %q, want inner handler", rec.Code, rec.Body.String())
	}

	// Non-GET on / reaches the wrapped handler too (a 404 from the mux here,
	// not a dashboard page).
	rec = httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if ct := rec.Header().Get("Content-Type"); strings.HasPrefix(ct, "text/html") && strings.Contains(rec.Body.String(), "boxel agent") {
		t.Errorf("POST / rendered the dashboard; want passthrough (code %d, body %q)", rec.Code, rec.Body.String())
	}
}
