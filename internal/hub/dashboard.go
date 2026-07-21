package hub

import (
	"html/template"
	"net/http"
	"time"
)

// dashboardRow is one agent in the dashboard view: the public info plus
// pre-rendered timestamps (templates shouldn't do time math).
type dashboardRow struct {
	AgentInfo
	// Since describes the current status: how long the agent has been
	// connected, or how long ago it disconnected.
	Since string
}

type dashboardData struct {
	Version   string
	Rows      []dashboardRow
	Connected int
	Messages  int64
}

// handleDashboard renders the agent status dashboard: every agent that has
// registered since the hub started, whether it is currently connected, and how
// many messages the mux proxied to it.
func (h *Hub) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := dashboardData{Version: h.cfg.Version}
	now := time.Now()
	for _, a := range h.Agents() {
		row := dashboardRow{AgentInfo: a}
		if a.Connected {
			row.Since = "for " + roundDuration(now.Sub(a.ConnectedAt))
			data.Connected++
		} else {
			row.Since = roundDuration(now.Sub(a.DisconnectedAt)) + " ago"
		}
		data.Messages += a.Messages
		data.Rows = append(data.Rows, row)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = dashboardTmpl.Execute(w, data)
}

// roundDuration renders d at a resolution a human dashboard needs: seconds
// under a minute, otherwise minutes.
func roundDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>boxel hub</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 60rem; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  .summary { color: color-mix(in srgb, currentColor 65%, transparent); margin-bottom: 1rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: .45rem .7rem; border-bottom: 1px solid color-mix(in srgb, currentColor 20%, transparent); }
  th { font-size: .8rem; text-transform: uppercase; letter-spacing: .05em; opacity: .7; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .dot { display: inline-block; width: .6rem; height: .6rem; border-radius: 50%; margin-right: .4rem; }
  .up .dot { background: #2da44e; }
  .down .dot { background: #cf222e; }
  .down td { opacity: .6; }
  .empty { padding: 2rem 0; opacity: .7; }
  footer { margin-top: 1.5rem; font-size: .8rem; opacity: .6; }
  a { color: inherit; }
</style>
</head>
<body>
<h1>boxel hub — agents</h1>
<p class="summary">{{.Connected}} of {{len .Rows}} agent{{if ne (len .Rows) 1}}s{{end}} connected · {{.Messages}} message{{if ne .Messages 1}}s{{end}} proxied · refreshes every 5s</p>
{{if .Rows}}
<table>
  <tr><th>Agent</th><th>Status</th><th>Since</th><th>Remote address</th><th>Version</th><th>Messages</th></tr>
  {{range .Rows}}
  <tr class="{{if .Connected}}up{{else}}down{{end}}">
    <td><a href="/vm/{{.Name}}/">{{.Name}}</a></td>
    <td><span class="dot"></span>{{if .Connected}}connected{{else}}disconnected{{end}}</td>
    <td>{{.Since}}</td>
    <td>{{.RemoteAddr}}</td>
    <td>{{.Version}}</td>
    <td class="num">{{.Messages}}</td>
  </tr>
  {{end}}
</table>
{{else}}
<p class="empty">No agents have registered yet. Install one with <code>curl -fsSL &lt;hub&gt;/install-agent | sudo bash</code>.</p>
{{end}}
<footer>boxel {{.Version}}</footer>
</body>
</html>
`))
