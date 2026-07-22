package hubagent

import (
	"html/template"
	"net/http"
	"sync/atomic"
)

// dashboard wraps the in-process handler and answers GET / itself with a
// small HTML status page: which agent this is, the version it runs, and a
// link back to the hub it is connected to. Through the hub it renders at
// /vm/<name>/ — the page a browser lands on when following an agent link
// from the hub dashboard. Every other path (and method) falls through to
// the wrapped handler.
type dashboard struct {
	name    string
	version string
	inner   http.Handler
	// hubURL is the hub base URL of the current connect cycle. It starts as
	// the configured URL and is updated on every cycle, so an autodiscovered
	// hub shows up once discovery succeeds.
	hubURL atomic.Value // string
}

func newDashboard(cfg Config, inner http.Handler) *dashboard {
	d := &dashboard{name: cfg.Name, version: cfg.Version, inner: inner}
	d.hubURL.Store(cfg.HubURL)
	return d
}

// setHubURL records the hub URL the agent is dialing this cycle.
func (d *dashboard) setHubURL(u string) { d.hubURL.Store(u) }

func (d *dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		d.inner.ServeHTTP(w, r)
		return
	}
	hubURL, _ := d.hubURL.Load().(string)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = agentDashboardTmpl.Execute(w, struct {
		Name, Version, HubURL string
	}{d.name, d.version, hubURL})
}

// The "← hub dashboard" link is relative (../.. from /vm/<name>/ resolves to
// the hub root) so it works through whatever hostname the browser reached the
// hub on; the Hub row shows the URL the agent itself dials, which on exe.dev
// is the internal peer-integration address.
var agentDashboardTmpl = template.Must(template.New("agent-dashboard").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>boxel agent — {{.Name}}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 40rem; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  .back { margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  th { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; opacity: .7; width: 10rem; }
  footer { margin-top: 1.5rem; font-size: .8rem; opacity: .6; }
  a { color: inherit; }
</style>
</head>
<body>
<h1>boxel agent — {{.Name}}</h1>
<p class="back"><a href="../..">← hub dashboard</a></p>
<table>
  <tr><th>Agent</th><td>{{.Name}}</td></tr>
  <tr><th>Version</th><td>{{if .Version}}{{.Version}}{{else}}(unknown){{end}}</td></tr>
  <tr><th>Hub</th><td>{{if .HubURL}}<a href="{{.HubURL}}">{{.HubURL}}</a>{{else}}autodiscovering…{{end}}</td></tr>
  <tr><th>MCP endpoint</th><td><code>/vm/{{.Name}}/mcp</code> on the hub</td></tr>
</table>
<footer>boxel {{if .Version}}{{.Version}}{{end}}</footer>
</body>
</html>
`))
