// Package hub implements the pull-mode MCP multiplexer.
//
// Agents running on non-routable VMs dial *out* to the hub, authenticate with
// a shared registration token, and upgrade the TCP connection to a reverse
// HTTP/2 channel: after the 101 handshake the roles flip, the hub becomes the
// HTTP/2 client and the agent the server. Each agent registers under its short
// hostname; requests to /vm/<name>/... on the hub are proxied over the
// agent's channel (prefix-stripped), which forwards them to the boxel
// instance — or any HTTP server — listening locally on the agent's VM.
//
// Because a single hub hostname fronts every VM, a Claude MCP connector needs
// only one origin (and one auth cookie / bearer token): the MCP endpoint for
// VM "foobar" is https://<hub>/vm/foobar/mcp. The whole /vm/<name>/ base path
// is proxied, leaving room for more per-VM APIs later.
package hub

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Wire-protocol constants shared by the hub and the agent.
const (
	// ConnectPath is the registration endpoint agents dial.
	ConnectPath = "/hub/connect"
	// InstallerPath serves the curl|bash agent installer script.
	InstallerPath = "/install-agent"
	// UpgradeProtocol is the value of the Upgrade header for the reverse
	// HTTP/2 handshake.
	UpgradeProtocol = "boxel-h2c"
	// HeaderAgentName carries the handle the agent registers under.
	HeaderAgentName = "X-Boxel-Agent-Name"
	// HeaderAgentVersion carries the agent's version (informational).
	HeaderAgentVersion = "X-Boxel-Agent-Version"
	// HeaderExeEmail is injected by the exe.dev edge on authenticated
	// requests (overwriting any client-supplied copy).
	HeaderExeEmail = "X-ExeDev-Email"
	// HeaderSourceVM is set (not appended) by the exe.dev platform on
	// requests that flow through a peer integration: the name of the calling
	// VM, unforgeable by that VM.
	HeaderSourceVM = "X-Exedev-Source-Vm"
)

// Config configures a Hub. At least one of AgentToken / OwnerEmail must be
// set — a hub never accepts unauthenticated registrations. When both are set
// they are alternatives: a registration is accepted if either authenticates
// (mixed fleets: exe.dev VMs register via identity, others via token).
type Config struct {
	// AgentToken is a bearer token agents may present to register.
	AgentToken string
	// OwnerEmail enables identity-based registration for exe.dev
	// deployments: a registration is accepted when the exe.dev edge identity
	// header (X-ExeDev-Email) equals this address. Agent VMs have no direct
	// network path to the hub on exe.dev — they reach it through a peer
	// integration, whose injected API key authenticates the request at the
	// hub's edge as the owner. When the platform's X-Exedev-Source-Vm header
	// is present it overrides the self-asserted agent name, binding the
	// handle to the verified calling VM. Like tunnel-mcp's --owner-email,
	// this is trustworthy only when the hub is reachable exclusively through
	// the exe.dev edge (bind the listener to localhost).
	OwnerEmail string
	// AdvertiseURL is the base URL agents should dial to reach this hub
	// (typically an internal VM-to-VM address). It is embedded in the
	// installer script; when empty the installer falls back to the URL the
	// script was fetched from.
	AdvertiseURL string
	// InstallerAuth reports whether an installer request is authenticated as
	// the hub owner. The agent token is embedded in the emitted script only
	// when this returns true; unauthenticated requests still get a working
	// script that requires BOXEL_AGENT_TOKEN at install time.
	InstallerAuth func(*http.Request) bool
	// Version is reported in the installer script (informational).
	Version string
	// PingInterval is how often each agent channel is health-checked with an
	// HTTP/2 PING; a failed ping unregisters the agent. Default 30s.
	PingInterval time.Duration
	// Logf is the logging sink. Default log.Printf.
	Logf func(format string, args ...any)
}

// Hub is the multiplexer: a registry of connected agents plus the HTTP
// handlers that register agents and proxy /vm/<name>/ traffic to them.
type Hub struct {
	cfg   Config
	tr    *http2.Transport
	proxy *httputil.ReverseProxy

	mu     sync.Mutex
	agents map[string]*agentConn
	// registry remembers every agent that has registered since the hub
	// started, including ones that later disconnected, so the dashboard can
	// show them as offline instead of forgetting them.
	registry map[string]*agentRecord
}

// agentConn is one registered agent: a live reverse HTTP/2 channel.
type agentConn struct {
	name        string
	remoteAddr  string
	version     string
	auth        string // how the registration authenticated, for logs
	connectedAt time.Time
	cc          *http2.ClientConn
	conn        net.Conn
	cancel      context.CancelFunc
	closeOnce   sync.Once
}

func (a *agentConn) close() {
	a.closeOnce.Do(func() {
		a.cancel()
		_ = a.cc.Close()
		_ = a.conn.Close()
	})
}

// agentRecord is the durable view of an agent: it survives the agent's
// channel so status ("connected"/"disconnected") and traffic counters outlive
// reconnects. Guarded by Hub.mu.
type agentRecord struct {
	remoteAddr     string // last known
	version        string
	connected      bool
	connectedAt    time.Time // last (re-)registration
	disconnectedAt time.Time // zero while connected
	messages       int64     // requests proxied through the mux to this agent
}

// AgentInfo is the public view of a registered agent.
type AgentInfo struct {
	Name           string    `json:"name"`
	RemoteAddr     string    `json:"remote_addr"`
	Version        string    `json:"version,omitempty"`
	Connected      bool      `json:"connected"`
	ConnectedAt    time.Time `json:"connected_at"`
	DisconnectedAt time.Time `json:"disconnected_at,omitzero"`
	// Messages counts the requests the mux proxied to this agent.
	Messages int64 `json:"messages"`
}

// errNotConnected reports a /vm/<name>/ request for an agent that is not
// currently registered.
type errNotConnected struct{ name string }

func (e errNotConnected) Error() string {
	return fmt.Sprintf("no agent registered as %q (is boxel-agent running on that VM?)", e.name)
}

// New builds a Hub.
func New(cfg Config) *Hub {
	if cfg.PingInterval <= 0 {
		cfg.PingInterval = 30 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	h := &Hub{
		cfg:      cfg,
		agents:   map[string]*agentConn{},
		registry: map[string]*agentRecord{},
		// AllowHTTP lets RoundTrip accept the http scheme; the channel itself
		// is the already-established (possibly TLS) agent connection.
		tr: &http2.Transport{AllowHTTP: true},
	}
	h.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			name := pr.In.PathValue("name")
			prefix := "/vm/" + name
			// The agent name doubles as the routing key: the round tripper
			// resolves URL.Host against the registry.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = name
			pr.Out.URL.Path = strings.TrimPrefix(pr.In.URL.Path, prefix)
			if pr.Out.URL.Path == "" {
				pr.Out.URL.Path = "/"
			}
			if pr.In.URL.RawPath != "" {
				pr.Out.URL.RawPath = strings.TrimPrefix(pr.In.URL.RawPath, prefix)
			}
			// Preserve Authorization and identity headers (already on Out via
			// clone); add standard forwarding metadata.
			pr.SetXForwarded()
		},
		Transport: agentRoundTripper{h},
		// Flush every write through immediately: MCP streamable HTTP uses SSE.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			code := "bad_gateway"
			var nc errNotConnected
			if errors.As(err, &nc) {
				code = "vm_not_connected"
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   code,
				"vm":      r.PathValue("name"),
				"message": err.Error(),
			})
		},
	}
	return h
}

// agentRoundTripper routes proxied requests over the target agent's reverse
// HTTP/2 channel. The agent name travels in req.URL.Host (set by Rewrite).
type agentRoundTripper struct{ h *Hub }

func (rt agentRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	name := req.URL.Host
	a := rt.h.lookup(name)
	if a == nil {
		return nil, errNotConnected{name}
	}
	rt.h.countMessage(name)
	res, err := a.cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("vm %q tunnel: %w", name, err)
	}
	return res, nil
}

// AttachRoutes registers the hub's handlers on mux. guard (optional) wraps the
// caller-facing endpoints — the / dashboard, the /vm/<name>/ proxy and
// /agents — with the hub's client auth (bearer / edge identity). The
// registration endpoint authenticates itself with the agent token, and the
// installer endpoint is deliberately unauthenticated (it embeds the agent
// token only for requests that pass Config.InstallerAuth).
func (h *Hub) AttachRoutes(mux *http.ServeMux, guard func(http.Handler) http.Handler) {
	if guard == nil {
		guard = func(hh http.Handler) http.Handler { return hh }
	}
	mux.Handle("GET /{$}", guard(http.HandlerFunc(h.handleDashboard)))
	mux.Handle("GET "+ConnectPath, h.ConnectHandler())
	mux.Handle("/vm/{name}", guard(http.HandlerFunc(h.redirectVM)))
	mux.Handle("/vm/{name}/", guard(h.proxy))
	mux.Handle("GET /agents", guard(http.HandlerFunc(h.handleAgents)))
	mux.Handle("GET "+InstallerPath, http.HandlerFunc(h.handleInstaller))
}

// ConnectHandler returns the agent registration endpoint, for mounting on an
// additional (internal) listener.
func (h *Hub) ConnectHandler() http.Handler { return http.HandlerFunc(h.handleConnect) }

// authenticateAgent checks a registration request against the configured
// methods, returning the name of the method that authenticated it ("" = none).
func (h *Hub) authenticateAgent(r *http.Request) string {
	if h.cfg.AgentToken != "" {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if strings.HasPrefix(auth, prefix) &&
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(h.cfg.AgentToken)) == 1 {
			return "token"
		}
	}
	if h.cfg.OwnerEmail != "" {
		want := strings.ToLower(strings.TrimSpace(h.cfg.OwnerEmail))
		got := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderExeEmail)))
		if got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return "exe-identity"
		}
	}
	return ""
}

// handleConnect authenticates an agent, hijacks the connection, completes the
// 101 upgrade, and registers the reverse HTTP/2 channel.
func (h *Hub) handleConnect(w http.ResponseWriter, r *http.Request) {
	if h.cfg.AgentToken == "" && h.cfg.OwnerEmail == "" {
		http.Error(w, "agent registration disabled", http.StatusServiceUnavailable)
		return
	}
	method := h.authenticateAgent(r)
	if method == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="boxel-hub"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), UpgradeProtocol) ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, fmt.Sprintf("expected Upgrade: %s", UpgradeProtocol), http.StatusBadRequest)
		return
	}
	// The platform-verified caller VM name (present on requests through an
	// exe.dev peer integration) always beats the self-asserted one: a
	// workload can then only ever register as the VM it runs on.
	name := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderSourceVM)))
	nameSource := "verified"
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderAgentName)))
		nameSource = "self-reported"
	}
	if !ValidName(name) {
		http.Error(w, fmt.Sprintf("invalid agent name %q: want 1-63 chars of [a-z0-9-], not starting/ending with -", name), http.StatusBadRequest)
		return
	}
	if r.ProtoMajor != 1 {
		http.Error(w, "registration requires HTTP/1.1 (connection upgrade)", http.StatusHTTPVersionNotSupported)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported on this listener", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed", http.StatusInternalServerError)
		return
	}
	_ = conn.SetDeadline(time.Time{}) // the channel is long-lived
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + UpgradeProtocol + "\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		_ = conn.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return
	}
	// Roles flip: the hub speaks the HTTP/2 client preface over the accepted
	// connection; the agent serves it.
	cc, err := h.tr.NewClientConn(WrapConn(conn, brw.Reader))
	if err != nil {
		h.cfg.Logf("hub: HTTP/2 setup for agent %q failed: %v", name, err)
		_ = conn.Close()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &agentConn{
		name:        name,
		remoteAddr:  conn.RemoteAddr().String(),
		version:     r.Header.Get(HeaderAgentVersion),
		auth:        method + "," + nameSource + "-name",
		connectedAt: time.Now(),
		cc:          cc,
		conn:        conn,
		cancel:      cancel,
	}
	h.register(a)
	go h.pingLoop(ctx, a)
}

// register installs a, replacing (and closing) any previous channel with the
// same name — an agent restart re-registers while the hub may still hold the
// stale connection.
func (h *Hub) register(a *agentConn) {
	h.mu.Lock()
	old := h.agents[a.name]
	h.agents[a.name] = a
	rec := h.registry[a.name]
	if rec == nil {
		rec = &agentRecord{}
		h.registry[a.name] = rec
	}
	rec.remoteAddr = a.remoteAddr
	rec.version = a.version
	rec.connected = true
	rec.connectedAt = a.connectedAt
	rec.disconnectedAt = time.Time{}
	h.mu.Unlock()
	if old != nil {
		h.cfg.Logf("hub: agent %q reconnected from %s (%s; replacing channel from %s)", a.name, a.remoteAddr, a.auth, old.remoteAddr)
		old.close()
	} else {
		h.cfg.Logf("hub: agent %q connected from %s (%s)", a.name, a.remoteAddr, a.auth)
	}
}

// drop unregisters a (if it is still the current channel for its name) and
// closes it.
func (h *Hub) drop(a *agentConn, reason error) {
	h.mu.Lock()
	if h.agents[a.name] == a {
		delete(h.agents, a.name)
		if rec := h.registry[a.name]; rec != nil {
			rec.connected = false
			rec.disconnectedAt = time.Now()
		}
	}
	h.mu.Unlock()
	a.close()
	h.cfg.Logf("hub: agent %q disconnected: %v", a.name, reason)
}

// pingLoop health-checks the channel; a failed HTTP/2 PING unregisters the
// agent (it will re-register when its reconnect loop comes back).
func (h *Hub) pingLoop(ctx context.Context, a *agentConn) {
	t := time.NewTicker(h.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := a.cc.Ping(pctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					h.drop(a, fmt.Errorf("ping: %w", err))
				}
				return
			}
		}
	}
}

func (h *Hub) lookup(name string) *agentConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.agents[name]
}

// countMessage records one request proxied through the mux to name.
func (h *Hub) countMessage(name string) {
	h.mu.Lock()
	if rec := h.registry[name]; rec != nil {
		rec.messages++
	}
	h.mu.Unlock()
}

// Agents lists every agent that has registered since the hub started —
// connected or not — sorted by name.
func (h *Hub) Agents() []AgentInfo {
	h.mu.Lock()
	out := make([]AgentInfo, 0, len(h.registry))
	for name, rec := range h.registry {
		out = append(out, AgentInfo{
			Name:           name,
			RemoteAddr:     rec.remoteAddr,
			Version:        rec.version,
			Connected:      rec.connected,
			ConnectedAt:    rec.connectedAt,
			DisconnectedAt: rec.disconnectedAt,
			Messages:       rec.messages,
		})
	}
	h.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// redirectVM sends /vm/<name> to /vm/<name>/ so relative links inside proxied
// UIs resolve.
func (h *Hub) redirectVM(w http.ResponseWriter, r *http.Request) {
	u := "/vm/" + r.PathValue("name") + "/"
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, u, http.StatusPermanentRedirect)
}

// handleAgents reports the registry as JSON.
func (h *Hub) handleAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"agents": h.Agents()})
}

// ValidName reports whether s is a valid agent handle: 1-63 characters of
// [a-z0-9-], not starting or ending with a hyphen (short-hostname shaped).
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(s)-1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
