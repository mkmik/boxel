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

func main() {
	var (
		httpAddr    = flag.String("http", "", "serve streamable HTTP MCP on this address (e.g. :8080); empty = stdio transport")
		workspace   = flag.String("workspace", "", "workspace jail root; file operations outside it are denied (default: current directory)")
		permsFile   = flag.String("permissions", "", "path to permissions.json (Claude Code-compatible allow/ask/deny rules)")
		modeFlag    = flag.String("permission-mode", string(policy.ModeDefault), "permission mode: default | acceptEdits | bypassPermissions (bypassPermissions is a server-side decision, never client-selectable)")
		auditPath   = flag.String("audit-log", "", "append-only JSONL audit log path (empty = disabled)")
		metricsAddr = flag.String("metrics-addr", "", "serve Prometheus /metrics on this address (e.g. :9090); empty = disabled")
		token       = flag.String("token", "", "static bearer token required on HTTP requests (or set BOXEL_TOKEN); testing only — front with OAuth for production")
		tokenFile   = flag.String("token-file", "", "read the bearer token from this file")
		sessionTTL  = flag.Duration("session-ttl", 24*time.Hour, "idle session garbage-collection TTL (0 disables GC)")
	)
	flag.Parse()

	if err := run(*httpAddr, *workspace, *permsFile, *modeFlag, *auditPath, *metricsAddr, *token, *tokenFile, *sessionTTL); err != nil {
		log.Fatal(err)
	}
}

func run(httpAddr, workspace, permsFile, modeFlag, auditPath, metricsAddr, token, tokenFile string, sessionTTL time.Duration) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !policy.ValidMode(modeFlag) {
		return fmt.Errorf("invalid --permission-mode %q", modeFlag)
	}
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
	if permsFile != "" {
		cfg, err = policy.LoadConfig(permsFile)
		if err != nil {
			return err
		}
	}
	engine, err := policy.NewEngine(cfg, policy.Mode(modeFlag), workspace)
	if err != nil {
		return err
	}

	auditLog, err := audit.NewLogger(auditPath)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	sessions := session.NewManager(workspace, sessionTTL)
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

	if metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", mets.Handler())
		go func() {
			if err := http.ListenAndServe(metricsAddr, mux); err != nil && err != http.ErrServerClosed {
				log.Printf("metrics server: %v", err)
			}
		}()
	}

	if httpAddr == "" {
		log.SetOutput(os.Stderr) // keep stdout clean for the stdio transport
		log.Printf("tunnel-mcp %s: stdio transport, workspace %s, mode %s", tunnel.Version, workspace, modeFlag)
		return srv.Run(ctx, &mcp.StdioTransport{})
	}

	bearer, err := resolveToken(token, tokenFile)
	if err != nil {
		return err
	}
	if bearer == "" {
		return fmt.Errorf("HTTP transport requires a bearer token: pass --token, --token-file, or set BOXEL_TOKEN (the invoke tool is authenticated RCE; refusing to listen unauthenticated)")
	}

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	mux := http.NewServeMux()
	mux.Handle("/mcp", requireBearer(bearer, handler))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	hs := &http.Server{Addr: httpAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutdownCtx)
	}()
	log.Printf("tunnel-mcp %s: HTTP transport on %s/mcp, workspace %s, mode %s", tunnel.Version, httpAddr, workspace, modeFlag)
	if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
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
