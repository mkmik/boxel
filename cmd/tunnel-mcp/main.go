// Command tunnel-mcp runs the Tunnel MCP server: a generic-operation MCP
// server that tunnels the Claude Code tool-call protocol to the sandbox it
// runs on. See docs/prd-tunnel-mcp.md.
//
// Transports:
//   - stdio (default, for local testing):  tunnel-mcp --workspace /work
//   - streamable HTTP (for remote/phone):  tunnel-mcp --http :8080 --token-file t.txt
//
// The HTTP transport is meant to sit behind a TLS-terminating tunnel
// (Cloudflare Tunnel, Tailscale Funnel) with OAuth handled by the fronting
// layer; the built-in static bearer token is a defense-in-depth check and a
// local-testing convenience, not the production auth story.
package main

import (
	"context"
	"crypto/subtle"
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
	handler := newStreamableHandler(srv)
	guard, authOK, authDesc, err := authLayers(bearer, o.ownerEmail)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", guard(handler))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	if hubEnabled {
		hb := hub.New(hub.Config{
			AgentToken:    hubToken,
			OwnerEmail:    o.hubAgentOwnerEmail,
			AdvertiseURL:  o.hubAdvertiseURL,
			InstallerAuth: authOK,
			Version:       tunnel.Version,
		})
		hb.AttachRoutes(mux, guard)
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

	hs := &http.Server{Addr: o.httpAddr, Handler: mux}
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
// (used to decide whether the hub installer may embed the agent token). bearer
// (if set) requires a matching Authorization: Bearer token; ownerEmail (if
// set) requires the exe.dev edge identity header to equal that address. Both
// may be enabled, in which case a request must satisfy both. At least one must
// be configured — the invoke tool is authenticated RCE, so listening
// unauthenticated is refused. Returns a short description for logging.
func authLayers(bearer, ownerEmail string) (wrap func(http.Handler) http.Handler, ok func(*http.Request) bool, desc string, err error) {
	var layers []string
	if bearer != "" {
		layers = append(layers, "bearer")
	}
	if ownerEmail != "" {
		layers = append(layers, "exe-identity("+ownerEmail+")")
	}
	if len(layers) == 0 {
		return nil, nil, "", fmt.Errorf("HTTP transport requires authentication: pass --token/--token-file/$BOXEL_TOKEN and/or --owner-email (the invoke tool is authenticated RCE; refusing to listen unauthenticated)")
	}
	wrap = func(next http.Handler) http.Handler {
		// Wrapped inner-to-outer so the bearer is checked first.
		h := next
		if ownerEmail != "" {
			h = requireExeIdentity(ownerEmail, h)
		}
		if bearer != "" {
			h = requireBearer(bearer, h)
		}
		return h
	}
	ok = func(r *http.Request) bool {
		if bearer != "" && !bearerOK(r, bearer) {
			return false
		}
		if ownerEmail != "" && !exeIdentityOK(r, ownerEmail) {
			return false
		}
		return true
	}
	return wrap, ok, strings.Join(layers, "+"), nil
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

func requireBearer(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !bearerOK(r, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="tunnel-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireExeIdentity enforces that the exe.dev edge authenticated the request
// as the owner. A missing header means the request did not come through the
// authenticating edge (or the VM is public without identity injection) and is
// rejected; a present-but-different email is a forbidden non-owner.
func requireExeIdentity(ownerEmail string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSpace(r.Header.Get(exeEmailHeader)) == "" {
			http.Error(w, "unauthorized: missing exe.dev identity", http.StatusUnauthorized)
			return
		}
		if !exeIdentityOK(r, ownerEmail) {
			http.Error(w, "forbidden: not the authorized owner", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
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
