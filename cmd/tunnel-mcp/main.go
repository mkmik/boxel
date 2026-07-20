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

	if o.httpAddr == "" {
		log.SetOutput(os.Stderr) // keep stdout clean for the stdio transport
		log.Printf("tunnel-mcp %s: stdio transport, workspace %s, mode %s", tunnel.Version, workspace, o.mode)
		return srv.Run(ctx, &mcp.StdioTransport{})
	}

	bearer, err := resolveToken(o.token, o.tokenFile)
	if err != nil {
		return err
	}
	handler := newStreamableHandler(srv)
	guarded, authDesc, err := authMiddleware(bearer, o.ownerEmail, handler)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/mcp", guarded)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

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

// authMiddleware wraps next with the configured HTTP auth layers. bearer (if
// set) requires a matching Authorization: Bearer token; ownerEmail (if set)
// requires the exe.dev edge identity header to equal that address. Both may be
// enabled, in which case a request must satisfy both. At least one must be
// configured — the invoke tool is authenticated RCE, so listening
// unauthenticated is refused. Returns a short description for logging.
func authMiddleware(bearer, ownerEmail string, next http.Handler) (http.Handler, string, error) {
	// h is wrapped inner-to-outer; layers is built outermost-first (the order
	// requests are checked) for a readable log line.
	var layers []string
	h := next
	if ownerEmail != "" {
		h = requireExeIdentity(ownerEmail, h)
		layers = append(layers, "exe-identity("+ownerEmail+")")
	}
	if bearer != "" {
		h = requireBearer(bearer, h)
		layers = append([]string{"bearer"}, layers...)
	}
	if len(layers) == 0 {
		return nil, "", fmt.Errorf("HTTP transport requires authentication: pass --token/--token-file/$BOXEL_TOKEN and/or --owner-email (the invoke tool is authenticated RCE; refusing to listen unauthenticated)")
	}
	return h, strings.Join(layers, "+"), nil
}

func requireBearer(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(token)) != 1 {
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
	want := strings.ToLower(strings.TrimSpace(ownerEmail))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.ToLower(strings.TrimSpace(r.Header.Get(exeEmailHeader)))
		if got == "" {
			http.Error(w, "unauthorized: missing exe.dev identity", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "forbidden: not the authorized owner", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
