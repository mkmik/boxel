// Package hubagent implements the pull-mode boxel agent: it dials out to a
// boxel hub, registers under this VM's handle, and serves the hub's proxied
// requests over a reverse HTTP/2 channel, forwarding them to a local HTTP
// server (normally the tunnel-mcp instance on 127.0.0.1). Because the agent
// only makes outbound connections, the VM needs no routable inbound port —
// its HTTP port stays free for other workloads.
package hubagent

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/mkmik/boxel/internal/hub"
)

// Config configures the agent.
type Config struct {
	// HubURL is the base URL of the hub (http:// or https://); the
	// registration endpoint is HubURL + /hub/connect. On exe.dev this is the
	// hub's peer integration URL (http://<integration>.int.exe.xyz). When
	// empty, the agent autodiscovers it through the exe.dev reflection
	// integration: it looks for an attached http-proxy integration named
	// HubIntegration and dials that.
	HubURL string
	// ReflectionURL is the base URL of the exe.dev reflection integration
	// used for autodiscovery when HubURL is empty.
	// Default https://reflection.int.exe.xyz.
	ReflectionURL string
	// HubIntegration is the name of the hub's peer integration to discover
	// via reflection. Default "boxel".
	HubIntegration string
	// Token is the hub's agent registration bearer token. Optional: on
	// exe.dev the peer integration authenticates the agent as the owner, and
	// a hub configured with identity-based registration needs no token.
	Token string
	// Name is the handle to register under (normally the VM short hostname).
	Name string
	// Target is the local base URL proxied requests are forwarded to.
	Target string
	// TargetToken, when set, replaces the Authorization header on forwarded
	// requests with "Bearer <TargetToken>" so they authenticate to the local
	// boxel instance regardless of what the hub's caller presented.
	TargetToken string
	// Version is reported to the hub (informational).
	Version string
	// Logf is the logging sink. Default log.Printf.
	Logf func(format string, args ...any)

	// MinBackoff/MaxBackoff bound the reconnect backoff. Defaults 1s/30s.
	MinBackoff time.Duration
	MaxBackoff time.Duration
	// DialTimeout bounds the dial + registration handshake. Default 15s.
	DialTimeout time.Duration
}

// Run connects to the hub and serves its channel, reconnecting with
// exponential backoff, until ctx is canceled.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = time.Second
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	if cfg.ReflectionURL == "" {
		cfg.ReflectionURL = "https://reflection.int.exe.xyz"
	}
	if cfg.HubIntegration == "" {
		cfg.HubIntegration = "boxel"
	}
	if !hub.ValidName(cfg.Name) {
		return fmt.Errorf("invalid agent name %q: want 1-63 chars of [a-z0-9-], not starting/ending with -", cfg.Name)
	}
	if cfg.HubURL != "" {
		if err := validateBaseURL(cfg.HubURL); err != nil {
			return fmt.Errorf("invalid hub URL: %w", err)
		}
	}
	target, err := url.Parse(cfg.Target)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return fmt.Errorf("invalid target URL %q: want http(s)://host[:port][/base]", cfg.Target)
	}
	handler := newProxyHandler(cfg, target, cfg.TargetToken)

	backoff := cfg.MinBackoff
	var lastErr string
	var lastLogged time.Time
	for {
		start := time.Now()
		err := connectCycle(ctx, cfg, handler)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A session that lasted a while was healthy; restart the backoff.
		if time.Since(start) > time.Minute {
			backoff = cfg.MinBackoff
		}
		// A steady-state failure (e.g. waiting for the hub integration to be
		// attached) would otherwise log every backoff cycle; repeat the same
		// message at most every 5 minutes.
		if msg := err.Error(); msg != lastErr || time.Since(lastLogged) > 5*time.Minute {
			cfg.Logf("boxel-agent: hub connection: %v; retrying (backoff %s, repeats suppressed)", err, backoff)
			lastErr, lastLogged = msg, time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > cfg.MaxBackoff {
			backoff = cfg.MaxBackoff
		}
	}
}

func validateBaseURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q: want http(s)://host[:port][/base]", s)
	}
	return nil
}

// connectCycle resolves the hub URL (discovering it via reflection when not
// configured) and runs one dial → register → serve cycle. Discovery happens
// every cycle so a hub integration attached after the agent boots is picked
// up on the next retry.
func connectCycle(ctx context.Context, cfg Config, handler http.Handler) error {
	hubURL := cfg.HubURL
	if hubURL == "" {
		discovered, err := DiscoverHubURL(ctx, cfg.ReflectionURL, cfg.HubIntegration)
		if err != nil {
			return fmt.Errorf("hub autodiscovery: %w (pass --hub / BOXEL_HUB_URL to skip discovery)", err)
		}
		cfg.Logf("boxel-agent: discovered hub %s via reflection integration %q", discovered, cfg.HubIntegration)
		hubURL = discovered
	}
	u, err := url.Parse(hubURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid hub URL %q", hubURL)
	}
	return runOnce(ctx, cfg, u, handler)
}

// reflectionIntegrations mirrors the reflection integration's /integrations
// response.
type reflectionIntegrations struct {
	Integrations []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Help string `json:"help"`
	} `json:"integrations"`
}

var helpURLRe = regexp.MustCompile(`https?://[^\s"']+`)

// DiscoverHubURL finds the hub's peer integration through the exe.dev
// reflection integration and returns its base URL. It prefers the URL in the
// integration's help text (exe.dev's canonical usage hint), falling back to
// <name>.<int-domain> derived from the reflection host. A not-found error
// explains how to attach the integration: it is the expected state when the
// agent is installed before the fleet integration is set up.
func DiscoverHubURL(ctx context.Context, reflectionURL, integration string) (string, error) {
	if reflectionURL == "" {
		reflectionURL = "https://reflection.int.exe.xyz"
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, strings.TrimSuffix(reflectionURL, "/")+"/integrations", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("query reflection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("reflection returned %s", resp.Status)
	}
	var list reflectionIntegrations
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return "", fmt.Errorf("parse reflection response: %w", err)
	}
	for _, in := range list.Integrations {
		if in.Type != "http-proxy" || in.Name != integration {
			continue
		}
		if m := helpURLRe.FindString(in.Help); m != "" {
			return strings.TrimSuffix(m, "/"), nil
		}
		// No URL in the help text: derive <name>.<domain> from the
		// reflection host (reflection.int.exe.xyz → int.exe.xyz).
		if ru, err := url.Parse(reflectionURL); err == nil {
			if _, domain, ok := strings.Cut(ru.Host, "."); ok {
				return "http://" + integration + "." + domain, nil
			}
		}
		break
	}
	return "", fmt.Errorf("the hub's peer integration %q is not attached to this VM yet (checked %s) — create it (ssh exe.dev integrations add http-proxy --name %s --target https://<hub-vm>.exe.xyz/ --peer --attach tag:boxel) and tag this VM (ssh exe.dev tag <vm> boxel); the agent will connect automatically once attached", integration, reflectionURL, integration)
}

// runOnce performs one dial → register → serve cycle, returning when the
// channel dies.
func runOnce(ctx context.Context, cfg Config, u *url.URL, handler http.Handler) error {
	addr := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	d := &net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 15 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	conn := net.Conn(rawConn)
	if u.Scheme == "https" {
		tc := tls.Client(rawConn, &tls.Config{ServerName: u.Hostname()})
		hctx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = rawConn.Close()
			return fmt.Errorf("tls handshake with %s: %w", addr, err)
		}
		conn = tc
	}
	// Unblock ServeConn when ctx is canceled.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer conn.Close()

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Path: strings.TrimSuffix(u.Path, "/") + hub.ConnectPath},
		Host:   u.Host,
		Header: http.Header{
			"Upgrade":              {hub.UpgradeProtocol},
			"Connection":           {"Upgrade"},
			hub.HeaderAgentName:    {cfg.Name},
			hub.HeaderAgentVersion: {cfg.Version},
		},
	}
	// No token is fine on exe.dev: the peer integration authenticates the
	// request as the owner at the hub's edge.
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	_ = conn.SetDeadline(time.Now().Add(cfg.DialTimeout))
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("send registration: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return fmt.Errorf("read registration response: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		return fmt.Errorf("hub refused registration: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	_ = conn.SetDeadline(time.Time{})
	cfg.Logf("boxel-agent: registered with hub %s as %q, forwarding to %s", cfg.HubURL, cfg.Name, cfg.Target)

	// Roles flip: the hub is now the HTTP/2 client; serve its requests. The
	// hub pings every ~30s, so an idle read beyond 90s means a dead peer.
	h2s := &http2.Server{ReadIdleTimeout: 90 * time.Second, PingTimeout: 15 * time.Second}
	h2s.ServeConn(hub.WrapConn(conn, br), &http2.ServeConnOpts{
		Context: ctx,
		Handler: handler,
	})
	return errors.New("channel closed by hub")
}

// DiagPath is the reserved path the agent answers itself instead of forwarding
// to the local target. Reachable through the hub at /vm/<name>/__boxel-agent,
// it works even when the local target is down — the one signal a forwarded
// request can't give you.
const DiagPath = "/__boxel-agent"

// newProxyHandler forwards proxied requests to the local target, optionally
// swapping in the local bearer token. It answers DiagPath itself, and turns a
// failed forward into an informative JSON 502 instead of Go's default
// empty-bodied one, so an agent that is connected but can't reach its local
// target says so out loud.
func newProxyHandler(cfg Config, target *url.URL, token string) http.Handler {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			if token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}
		},
		// Flush every write through immediately: MCP streamable HTTP uses SSE.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cfg.Logf("boxel-agent: forward to %s failed: %v", target, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "agent_forward_failed",
				"agent":   cfg.Name,
				"target":  target.String(),
				"message": err.Error(),
				"hint":    "boxel-agent is connected but could not reach its local forward target; check that a server is listening there and that --target matches its address",
			})
		},
	}
	diag := &agentDiag{name: cfg.Name, version: cfg.Version, target: target}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == DiagPath || strings.HasPrefix(r.URL.Path, DiagPath+"/") {
			diag.serve(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// agentDiag answers DiagPath directly, reporting agent identity and a live
// reachability probe of the local forward target.
type agentDiag struct {
	name    string
	version string
	target  *url.URL
}

func (d *agentDiag) serve(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"agent":   d.name,
		"version": d.version,
		"target":  d.target.String(),
		// The agent is answering, so its channel to the hub is up by definition.
		"agent_ok": true,
	}
	out["target_check"] = d.probeTarget(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// probeTarget dials the local target and, if reachable, does a quick HTTP GET
// of its base URL — enough to tell "nothing listening" from "listening but
// erroring".
func (d *agentDiag) probeTarget(ctx context.Context) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	port := d.target.Port()
	if port == "" {
		port = "80"
		if d.target.Scheme == "https" {
			port = "443"
		}
	}
	addr := net.JoinHostPort(d.target.Hostname(), port)

	res := map[string]any{"addr": addr}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		res["reachable"] = false
		res["error"] = err.Error()
		return res
	}
	_ = conn.Close()
	res["reachable"] = true

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.target.String(), nil)
	if err == nil {
		if resp, herr := http.DefaultClient.Do(req); herr == nil {
			res["http_status"] = resp.StatusCode
			_ = resp.Body.Close()
		} else {
			res["http_error"] = herr.Error()
		}
	}
	return res
}
