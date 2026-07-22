// Command tunnel-mcp runs the Tunnel MCP server: a generic-operation MCP
// server that tunnels the Claude Code tool-call protocol to the sandbox it
// runs on. See docs/prd-tunnel-mcp.md.
//
// Transports:
//   - stdio (default, for local testing):  tunnel-mcp --workspace /work
//   - streamable HTTP (for remote/phone):  tunnel-mcp --http :8080 --token-file t.txt
//
// On the HTTP transport, --idp-issuer additionally serves a built-in OIDC
// identity provider (see internal/idp) in the same process, and /mcp accepts
// its OAuth tokens — real OAuth for programmatic MCP connectors.
//
// The HTTP transport is meant to sit behind a TLS-terminating tunnel
// (Cloudflare Tunnel, Tailscale Funnel, the exe.dev edge). Production auth is
// OAuth via the built-in IDP or the fronting layer's SSO; the static bearer
// token is a defense-in-depth check and a local-testing convenience.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mkmik/boxel/internal/audit"
	"github.com/mkmik/boxel/internal/hub"
	"github.com/mkmik/boxel/internal/hubagent"
	"github.com/mkmik/boxel/internal/idp"
	"github.com/mkmik/boxel/internal/metrics"
	"github.com/mkmik/boxel/internal/policy"
	"github.com/mkmik/boxel/internal/session"
	"github.com/mkmik/boxel/internal/tunnel"
)

// opts holds the parsed command-line configuration.
type opts struct {
	httpAddr    string
	workspace   string
	permsFile   string
	mode        string
	auditPath   string
	metricsAddr string
	token       string
	tokenFile   string
	ownerEmail  string
	sessionTTL  time.Duration

	hubAgentToken      string
	hubAgentTokenFile  string
	hubAgentOwnerEmail string
	hubAgentListen     string
	hubAdvertiseURL    string

	// Pull-mode agent (dial OUT to a hub, serve MCP in-process; no local port).
	hubConnect     bool
	hubURL         string
	hubName        string
	hubToken       string
	hubTokenFile   string
	hubIntegration string
	reflectionURL  string

	// Built-in OIDC IDP.
	idpIssuer  string
	idpUsers   string
	idpKeyFile string
}

func main() {
	var o opts
	flag.StringVar(&o.httpAddr, "http", "", "serve streamable HTTP MCP on this address (e.g. :8080); empty = stdio transport")
	flag.StringVar(&o.workspace, "workspace", "", "workspace jail root; file operations outside it are denied (default: current directory)")
	flag.StringVar(&o.permsFile, "permissions", "", "path to permissions.json (Claude Code-compatible allow/ask/deny rules)")
	flag.StringVar(&o.mode, "permission-mode", string(policy.ModeDefault), "permission mode: default | acceptEdits | bypassPermissions (bypassPermissions is a server-side decision, never client-selectable)")
	flag.StringVar(&o.auditPath, "audit-log", "", "append-only JSONL audit log path (empty = disabled)")
	flag.StringVar(&o.metricsAddr, "metrics-addr", "", "serve Prometheus /metrics on this address (e.g. :9090); empty = disabled")
	flag.StringVar(&o.token, "token", "", "static bearer token required on HTTP requests (or set BOXEL_TOKEN); testing only — front with OAuth for production")
	flag.StringVar(&o.tokenFile, "token-file", "", "read the bearer token from this file")
	flag.StringVar(&o.ownerEmail, "owner-email", "", "pin to a single owner via the exe.dev edge: require the X-ExeDev-Email header (injected by the exe.dev proxy) to equal this address. Bind --http to localhost so the edge is the only path in. Composes with --token.")
	flag.DurationVar(&o.sessionTTL, "session-ttl", 24*time.Hour, "idle session garbage-collection TTL (0 disables GC)")
	flag.StringVar(&o.hubAgentToken, "hub-agent-token", "", "enable the pull-mode hub: bearer token agents may present to register (or set BOXEL_HUB_AGENT_TOKEN); requires --http")
	flag.StringVar(&o.hubAgentTokenFile, "hub-agent-token-file", "", "read the hub agent registration token from this file")
	flag.StringVar(&o.hubAgentOwnerEmail, "hub-agent-owner-email", "", "enable the pull-mode hub with exe.dev identity registration: accept a registration when the X-ExeDev-Email header (injected by the exe.dev edge for peer-integration traffic) equals this address; the platform-verified X-Exedev-Source-Vm header then names the agent. Composes with --hub-agent-token as an alternative method. Bind --http to localhost so the edge is the only path in.")
	flag.StringVar(&o.hubAgentListen, "hub-agent-listen", "", "additionally serve the agent registration endpoint ("+hub.ConnectPath+") on this address, reachable by agent VMs over the internal network (e.g. :8081)")
	flag.StringVar(&o.hubAdvertiseURL, "hub-advertise-url", "", "base URL agents should dial to reach this hub (internal VM-to-VM address, e.g. http://boxel.internal:8081); embedded in the "+hub.InstallerPath+" script")
	flag.BoolVar(&o.hubConnect, "hub-connect", false, "act as a pull-mode agent: dial OUT to a hub and serve THIS instance's MCP over the reverse channel, in-process. No --http listener or local port is needed; the hub reaches it at /vm/<name>/mcp. Composes with --http if a direct listener is also wanted.")
	flag.StringVar(&o.hubURL, "hub-url", os.Getenv("BOXEL_HUB_URL"), "with --hub-connect: base URL of the hub to dial (or BOXEL_HUB_URL); empty = autodiscover the hub's peer integration via exe.dev reflection")
	flag.StringVar(&o.hubName, "hub-name", os.Getenv("BOXEL_AGENT_NAME"), "with --hub-connect: handle to register under, becomes the /vm/<name>/ path (default: this VM's short hostname)")
	flag.StringVar(&o.hubToken, "hub-token", "", "with --hub-connect: registration bearer token to present to the hub (or BOXEL_AGENT_TOKEN); not needed on exe.dev identity hubs")
	flag.StringVar(&o.hubTokenFile, "hub-token-file", os.Getenv("BOXEL_AGENT_TOKEN_FILE"), "with --hub-connect: read the registration token from this file")
	flag.StringVar(&o.hubIntegration, "hub-integration", os.Getenv("BOXEL_HUB_INTEGRATION"), "with --hub-connect: hub peer-integration name to autodiscover via reflection (default boxel)")
	flag.StringVar(&o.reflectionURL, "hub-reflection-url", os.Getenv("BOXEL_REFLECTION_URL"), "with --hub-connect: exe.dev reflection base URL for autodiscovery (default https://reflection.int.exe.xyz)")
	flag.StringVar(&o.idpIssuer, "idp-issuer", "", "enable the built-in OIDC IDP and accept its OAuth bearer tokens on /mcp (an alternative to --token/--owner-email): the external base URL of this deployment as OAuth clients see it (e.g. https://myvm.exe.xyz). Serves the OAuth/OIDC well-knowns plus "+idp.AuthorizePath+", "+idp.TokenPath+", "+idp.RegisterPath+"; the authorize endpoint trusts the exe.dev edge identity header. See docs/deployment.md §4b.")
	flag.StringVar(&o.idpUsers, "idp-users", "", "comma-separated emails allowed to authenticate at the built-in IDP (default: --owner-email)")
	flag.StringVar(&o.idpKeyFile, "idp-key-file", "", "path to the IDP's P-256 signing key PEM, created on first run if missing; empty = ephemeral key (a restart invalidates every token and registered client — testing only)")
	flag.Parse()

	if err := run(o); err != nil {
		log.Fatal(err)
	}
}

func run(o opts) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !policy.ValidMode(o.mode) {
		return fmt.Errorf("invalid --permission-mode %q", o.mode)
	}
	workspace := o.workspace
	if workspace == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		workspace = wd
	}
	workspace, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	if info, err := os.Stat(workspace); err != nil || !info.IsDir() {
		return fmt.Errorf("workspace %q is not a directory", workspace)
	}

	var cfg policy.Config
	if o.permsFile != "" {
		cfg, err = policy.LoadConfig(o.permsFile)
		if err != nil {
			return err
		}
	}
	engine, err := policy.NewEngine(cfg, policy.Mode(o.mode), workspace)
	if err != nil {
		return err
	}

	auditLog, err := audit.NewLogger(o.auditPath)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	sessions := session.NewManager(workspace, o.sessionTTL)
	sessions.StartGC(ctx, 10*time.Minute)

	reg := prometheus.NewRegistry()
	mets := metrics.New(reg,
		func() float64 { return float64(sessions.ActiveShells()) },
		func() float64 { return float64(sessions.Count()) },
	)

	srv := tunnel.New(tunnel.Config{
		Engine:   engine,
		Sessions: sessions,
		Audit:    auditLog,
		Metrics:  mets,
	})

	if o.metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", mets.Handler())
		go func() {
			if err := http.ListenAndServe(o.metricsAddr, mux); err != nil && err != http.ErrServerClosed {
				log.Printf("metrics server: %v", err)
			}
		}()
	}

	hubToken, err := resolveHubToken(o)
	if err != nil {
		return err
	}
	hubEnabled := hubToken != "" || o.hubAgentOwnerEmail != ""
	if o.idpIssuer != "" && o.httpAddr == "" {
		return fmt.Errorf("the built-in IDP requires the HTTP transport: pass --http")
	}

	// The streamable MCP handler is shared by every transport below (the direct
	// --http listener and the in-process pull-mode agent), so sessions are
	// consistent regardless of how a request arrives.
	handler := newStreamableHandler(srv)

	// Portless pull-mode agent: no --http listener, so serve MCP in-process
	// straight over the reverse channel to the hub. No local port, no second
	// process, no loopback.
	if o.hubConnect && o.httpAddr == "" {
		if hubEnabled {
			return fmt.Errorf("--hub-connect is the agent side; hub-server mode (--hub-agent-*) needs --http — don't combine them without a listener")
		}
		return runHubAgent(ctx, o, handler, workspace)
	}

	if o.httpAddr == "" {
		if hubEnabled {
			return fmt.Errorf("the pull-mode hub requires the HTTP transport: pass --http")
		}
		log.SetOutput(os.Stderr) // keep stdout clean for the stdio transport
		log.Printf("tunnel-mcp %s: stdio transport, workspace %s, mode %s", tunnel.Version, workspace, o.mode)
		return srv.Run(ctx, &mcp.StdioTransport{})
	}

	bearer, err := resolveToken(o.token, o.tokenFile)
	if err != nil {
		return err
	}
	// The same process is both the OIDC issuer and the protected MCP
	// resource: enabling the IDP makes /mcp accept its tokens.
	var idpSrv *idp.Server
	var verifier *idp.Verifier
	if o.idpIssuer != "" {
		idpSrv, err = buildIDP(o)
		if err != nil {
			return err
		}
		verifier = idpSrv.Verifier()
	}
	guard, authOK, authDesc, err := authLayers(bearer, o.ownerEmail, verifier)
	if err != nil {
		return err
	}

	// Routes are registered unguarded here; the server handler below applies
	// the auth guard to EVERYTHING except the explicit public allowlist
	// (withGuard), so a forgotten wrap can never expose a new route.
	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	if idpSrv != nil {
		idpSrv.AttachRoutes(mux)
		attachResourceMetadata(mux, idpSrv.Issuer())
		log.Printf("idp: OIDC identity provider enabled, issuer %s", idpSrv.Issuer())
	}

	if hubEnabled {
		hb := hub.New(hub.Config{
			AgentToken:    hubToken,
			OwnerEmail:    o.hubAgentOwnerEmail,
			AdvertiseURL:  o.hubAdvertiseURL,
			InstallerAuth: authOK,
			Version:       tunnel.Version,
		})
		// No per-route guard: withGuard already covers the dashboard,
		// /vm/<name>/ proxy, and /agents; the registration and installer
		// endpoints are on the public allowlist (they authenticate
		// themselves — see isPublicPath).
		hb.AttachRoutes(mux, nil)
		log.Printf("hub: pull-mode multiplexer enabled: /vm/{name}/ proxy, %s registration, %s installer", hub.ConnectPath, hub.InstallerPath)
		if o.hubAgentListen != "" {
			amux := http.NewServeMux()
			amux.Handle("GET "+hub.ConnectPath, hb.ConnectHandler())
			amux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "ok")
			})
			go func() {
				log.Printf("hub: agent registration listener on %s%s", o.hubAgentListen, hub.ConnectPath)
				if err := http.ListenAndServe(o.hubAgentListen, amux); err != nil && err != http.ErrServerClosed {
					log.Printf("hub agent listener: %v", err)
				}
			}()
		}
	}

	// Optionally ALSO dial out to a hub while serving the direct listener.
	if o.hubConnect {
		go func() {
			if err := runHubAgent(ctx, o, handler, workspace); err != nil && ctx.Err() == nil {
				log.Printf("hub-connect: %v", err)
			}
		}()
	}

	hs := &http.Server{Addr: o.httpAddr, Handler: withGuard(guard, mux)}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}()
	log.Printf("tunnel-mcp %s: HTTP transport on %s/mcp, workspace %s, mode %s, auth %s", tunnel.Version, o.httpAddr, workspace, o.mode, authDesc)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// runHubAgent dials the hub and serves this instance's MCP mux in-process over
// the reverse channel — no local listener. The hub is the auth boundary (it
// guards /vm/<name>/ with its own client auth), so the in-process /mcp is
// served without the direct-listener guard, mirroring how a forward-mode local
// instance trusts requests arriving from its co-located agent.
func runHubAgent(ctx context.Context, o opts, mcpHandler http.Handler, workspace string) error {
	name := o.hubName
	if name == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("cannot derive agent name from hostname (%w); pass --hub-name", err)
		}
		name, _, _ = strings.Cut(h, ".")
		name = strings.ToLower(name)
	}
	token, err := resolveAgentToken(o.hubToken, o.hubTokenFile)
	if err != nil {
		return err
	}

	am := http.NewServeMux()
	am.Handle("/mcp", mcpHandler)
	am.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	log.Printf("tunnel-mcp %s: pull-mode agent — dialing hub, serving MCP in-process as %q (no local port), workspace %s, mode %s",
		tunnel.Version, name, workspace, o.mode)
	return hubagent.Run(ctx, hubagent.Config{
		HubURL:         o.hubURL,
		HubIntegration: o.hubIntegration,
		ReflectionURL:  o.reflectionURL,
		Token:          token,
		Name:           name,
		Handler:        am,
		Version:        tunnel.Version,
	})
}

// resolveAgentToken picks the hub registration token from, in order: the flag,
// a file, then BOXEL_AGENT_TOKEN.
func resolveAgentToken(token, tokenFile string) (string, error) {
	if token != "" {
		return token, nil
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read hub token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("BOXEL_AGENT_TOKEN"), nil
}

// newStreamableHandler builds the streamable HTTP MCP handler.
//
// The SDK's automatic DNS-rebinding protection 403s any request whose Host
// header is not loopback when the listener is bound to loopback — which is
// precisely the recommended deployment (bind 127.0.0.1 behind a
// TLS-terminating proxy that forwards the public Host). A rebinding attack is
// already dead on arrival here: the HTTP transport refuses to start without
// auth, and a browser cannot attach the bearer token or the edge identity
// header cross-origin without a CORS preflight we never approve.
func newStreamableHandler(srv *mcp.Server) http.Handler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		DisableLocalhostProtection: true,
	})
}

func resolveToken(token, tokenFile string) (string, error) {
	if token != "" {
		return token, nil
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv("BOXEL_TOKEN"), nil
}

// exeEmailHeader is injected by the exe.dev edge proxy for authenticated
// requests. The edge overwrites any client-supplied value, so it is
// trustworthy ONLY when tunnel-mcp is reachable exclusively through that edge
// (bind --http to localhost). See docs/deployment.md.
const exeEmailHeader = "X-ExeDev-Email"

// authLayers builds the configured HTTP auth: a middleware that wraps a
// handler with the enforcing layers, and a boolean predicate over a request
// (used to decide whether the hub installer may embed the agent token).
//
// Two alternative methods can satisfy a request:
//   - static: bearer (if set) requires a matching Authorization: Bearer
//     token; ownerEmail (if set) requires the exe.dev edge identity header to
//     equal that address. Both may be enabled, in which case a request must
//     satisfy both.
//   - oauth: a valid access token from the built-in IDP (whose --idp-users
//     allowlist already gates who can obtain one).
//
// At least one method must be configured — the invoke tool is authenticated
// RCE, so listening unauthenticated is refused. Returns a short description
// for logging.
func authLayers(bearer, ownerEmail string, oauth *idp.Verifier) (wrap func(http.Handler) http.Handler, ok func(*http.Request) bool, desc string, err error) {
	var static []string
	if bearer != "" {
		static = append(static, "bearer")
	}
	if ownerEmail != "" {
		static = append(static, "exe-identity("+ownerEmail+")")
	}
	var methods []string
	if len(static) > 0 {
		methods = append(methods, strings.Join(static, "+"))
	}
	if oauth != nil {
		methods = append(methods, "oauth("+oauth.Issuer()+")")
	}
	if len(methods) == 0 {
		return nil, nil, "", fmt.Errorf("HTTP transport requires authentication: pass --token/--token-file/$BOXEL_TOKEN, --owner-email, and/or --idp-issuer (the invoke tool is authenticated RCE; refusing to listen unauthenticated)")
	}
	staticOK := func(r *http.Request) bool {
		if len(static) == 0 {
			return false
		}
		if bearer != "" && !bearerOK(r, bearer) {
			return false
		}
		if ownerEmail != "" && !exeIdentityOK(r, ownerEmail) {
			return false
		}
		return true
	}
	oauthOK := func(r *http.Request) bool {
		if oauth == nil {
			return false
		}
		_, err := oauth.VerifyRequest(r)
		return err == nil
	}
	ok = func(r *http.Request) bool {
		return staticOK(r) || oauthOK(r)
	}
	wrap = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok(r) {
				next.ServeHTTP(w, r)
				return
			}
			// RFC 9728: point OAuth-capable clients at the protected-resource
			// metadata so they can discover the authorization server.
			challenge := `Bearer realm="tunnel-mcp"`
			if oauth != nil {
				challenge = fmt.Sprintf(`Bearer realm="tunnel-mcp", resource_metadata=%q`,
					requestOrigin(r)+"/.well-known/oauth-protected-resource"+r.URL.Path)
			}
			w.Header().Set("WWW-Authenticate", challenge)
			switch {
			case bearer != "" && !bearerOK(r, bearer):
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			case ownerEmail != "" && strings.TrimSpace(r.Header.Get(exeEmailHeader)) == "":
				http.Error(w, "unauthorized: missing exe.dev identity", http.StatusUnauthorized)
			case ownerEmail != "":
				http.Error(w, "forbidden: not the authorized owner", http.StatusForbidden)
			default:
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
		})
	}
	return wrap, ok, strings.Join(methods, " or "), nil
}

func bearerOK(r *http.Request, token string) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	return strings.HasPrefix(auth, prefix) &&
		subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(token)) == 1
}

func exeIdentityOK(r *http.Request, ownerEmail string) bool {
	want := strings.ToLower(strings.TrimSpace(ownerEmail))
	got := strings.ToLower(strings.TrimSpace(r.Header.Get(exeEmailHeader)))
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// buildIDP constructs the built-in IDP from the flags. The allowlist falls
// back to --owner-email so the common single-owner deployment needs no extra
// flag.
func buildIDP(o opts) (*idp.Server, error) {
	if o.idpIssuer == "" {
		return nil, fmt.Errorf("the built-in IDP requires --idp-issuer (the external base URL, e.g. https://myvm.exe.xyz)")
	}
	users := splitEmails(o.idpUsers)
	if len(users) == 0 && o.ownerEmail != "" {
		users = []string{o.ownerEmail}
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("the built-in IDP requires an allowlist: pass --idp-users (or --owner-email)")
	}
	key, err := idp.LoadOrCreateKey(o.idpKeyFile)
	if err != nil {
		return nil, err
	}
	if o.idpKeyFile == "" {
		log.Printf("idp: WARNING: no --idp-key-file; using an ephemeral signing key — a restart invalidates every token and registered client")
	}
	return idp.New(idp.Config{Issuer: o.idpIssuer, Users: users, Key: key})
}

// splitEmails parses a comma-separated email list, dropping empties.
func splitEmails(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// isPublicPath reports whether a path must remain reachable without client
// auth. The list is deliberately closed:
//   - /healthz: liveness probe.
//   - /.well-known/*: OAuth/OIDC discovery documents (RFC 8414/9728) — the
//     spec requires clients to fetch these before they have any credential.
//   - /idp/*: the OAuth flow endpoints. Each is self-authorizing: /authorize
//     requires the exe.dev edge identity, /token requires a valid single-use
//     code or refresh token, /userinfo requires an access token, /register
//     hands out only a client_id (which grants nothing), /jwks is public key
//     material.
//   - the hub agent registration endpoint (authenticates agents itself) and
//     the installer script (deliberately tokenless unless the fetch is
//     authenticated — see hub.Config.InstallerAuth).
//
// Everything else — /mcp, the dashboard, /vm/<name>/, /agents, and any route
// added in the future — is guarded by default.
func isPublicPath(path string) bool {
	switch path {
	case "/healthz", hub.ConnectPath, hub.InstallerPath:
		return true
	}
	return strings.HasPrefix(path, "/.well-known/") || strings.HasPrefix(path, "/idp/")
}

// withGuard applies the auth guard to every request except the public
// allowlist. Default-deny: routes are guarded unless isPublicPath says
// otherwise.
func withGuard(guard func(http.Handler) http.Handler, mux http.Handler) http.Handler {
	guarded := guard(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			mux.ServeHTTP(w, r)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}

// requestOrigin reconstructs the external origin of a request arriving
// through the TLS-terminating edge (X-Forwarded-*), falling back to the
// direct connection's view.
func requestOrigin(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// attachResourceMetadata serves the RFC 9728 OAuth protected-resource
// metadata: it tells OAuth clients (via the 401 WWW-Authenticate challenge)
// which authorization server guards this MCP resource. The well-known suffix
// names the resource path, so /.well-known/oauth-protected-resource/mcp
// describes /mcp and .../vm/<name>/mcp describes a hub-proxied VM.
func attachResourceMetadata(mux *http.ServeMux, issuer string) {
	h := func(w http.ResponseWriter, r *http.Request) {
		suffix := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource")
		if suffix == "" || suffix == "/" {
			suffix = "/mcp"
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":                 requestOrigin(r) + suffix,
			"authorization_servers":    []string{issuer},
			"bearer_methods_supported": []string{"header"},
		})
	}
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", h)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/", h)
}

// resolveHubToken resolves the hub agent registration token from the flags or
// $BOXEL_HUB_AGENT_TOKEN, and validates that hub-dependent flags are not set
// without a registration method. An empty result with no
// --hub-agent-owner-email means the hub is disabled.
func resolveHubToken(o opts) (string, error) {
	token := o.hubAgentToken
	if token == "" && o.hubAgentTokenFile != "" {
		b, err := os.ReadFile(o.hubAgentTokenFile)
		if err != nil {
			return "", fmt.Errorf("read hub agent token file: %w", err)
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		token = os.Getenv("BOXEL_HUB_AGENT_TOKEN")
	}
	if token == "" && o.hubAgentOwnerEmail == "" && (o.hubAgentListen != "" || o.hubAdvertiseURL != "") {
		return "", fmt.Errorf("--hub-agent-listen/--hub-advertise-url require a registration method: pass --hub-agent-token/--hub-agent-token-file/$BOXEL_HUB_AGENT_TOKEN and/or --hub-agent-owner-email")
	}
	return token, nil
}
