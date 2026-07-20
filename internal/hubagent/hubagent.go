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
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/mkmik/boxel/internal/hub"
)

// Config configures the agent.
type Config struct {
	// HubURL is the base URL of the hub (http:// or https://), typically an
	// internal VM-to-VM address; the registration endpoint is HubURL +
	// /hub/connect.
	HubURL string
	// Token is the hub's agent registration bearer token.
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
	if cfg.Token == "" {
		return errors.New("agent registration token is required")
	}
	if !hub.ValidName(cfg.Name) {
		return fmt.Errorf("invalid agent name %q: want 1-63 chars of [a-z0-9-], not starting/ending with -", cfg.Name)
	}
	hubURL, err := url.Parse(cfg.HubURL)
	if err != nil || (hubURL.Scheme != "http" && hubURL.Scheme != "https") || hubURL.Host == "" {
		return fmt.Errorf("invalid hub URL %q: want http(s)://host[:port][/base]", cfg.HubURL)
	}
	target, err := url.Parse(cfg.Target)
	if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Host == "" {
		return fmt.Errorf("invalid target URL %q: want http(s)://host[:port][/base]", cfg.Target)
	}
	handler := newProxyHandler(target, cfg.TargetToken)

	backoff := cfg.MinBackoff
	for {
		start := time.Now()
		err := runOnce(ctx, cfg, hubURL, handler)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// A session that lasted a while was healthy; restart the backoff.
		if time.Since(start) > time.Minute {
			backoff = cfg.MinBackoff
		}
		cfg.Logf("boxel-agent: hub connection: %v; retrying in %s", err, backoff)
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
			"Authorization":        {"Bearer " + cfg.Token},
			hub.HeaderAgentName:    {cfg.Name},
			hub.HeaderAgentVersion: {cfg.Version},
		},
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

// newProxyHandler forwards proxied requests to the local target, optionally
// swapping in the local bearer token.
func newProxyHandler(target *url.URL, token string) http.Handler {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			if token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}
		},
		// Flush every write through immediately: MCP streamable HTTP uses SSE.
		FlushInterval: -1,
	}
}
