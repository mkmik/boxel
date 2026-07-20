// Command boxel-agent connects a non-routable VM to a boxel hub (a tunnel-mcp
// instance started with a --hub-agent-token). It dials out to the hub,
// registers under this VM's short hostname, and forwards the hub's proxied
// requests to a local HTTP server — normally the boxel/tunnel-mcp instance on
// 127.0.0.1 — over a reverse HTTP/2 channel. The VM then appears at
// https://<hub>/vm/<hostname>/ (MCP endpoint /vm/<hostname>/mcp) without
// exposing any inbound port.
//
// Every flag falls back to an environment variable so the systemd unit can be
// configured entirely from /etc/boxel-agent/env (see the hub's /install-agent
// script).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mkmik/boxel/internal/hubagent"
)

// Version is reported to the hub on registration.
const Version = "0.1.0"

func main() {
	var (
		hubURL          string
		token           string
		tokenFile       string
		name            string
		target          string
		targetToken     string
		targetTokenFile string
	)
	flag.StringVar(&hubURL, "hub", os.Getenv("BOXEL_HUB_URL"), "base URL of the boxel hub to register with, e.g. http://boxel.internal:8081 (or BOXEL_HUB_URL)")
	flag.StringVar(&token, "token", "", "agent registration bearer token (or BOXEL_AGENT_TOKEN)")
	flag.StringVar(&tokenFile, "token-file", os.Getenv("BOXEL_AGENT_TOKEN_FILE"), "read the registration token from this file")
	flag.StringVar(&name, "name", "", "handle to register under; becomes the /vm/<name>/ path on the hub (default: BOXEL_AGENT_NAME or this VM's short hostname)")
	flag.StringVar(&target, "target", "", "local base URL proxied requests are forwarded to (default: BOXEL_AGENT_TARGET or http://127.0.0.1:8080)")
	flag.StringVar(&targetToken, "target-token", "", "bearer token injected on forwarded requests so they authenticate to the local boxel instance (or BOXEL_AGENT_TARGET_TOKEN)")
	flag.StringVar(&targetTokenFile, "target-token-file", os.Getenv("BOXEL_AGENT_TARGET_TOKEN_FILE"), "read the target bearer token from this file")
	flag.Parse()

	if err := run(hubURL, token, tokenFile, name, target, targetToken, targetTokenFile); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func run(hubURL, token, tokenFile, name, target, targetToken, targetTokenFile string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if hubURL == "" {
		return errors.New("hub URL is required: pass --hub or set BOXEL_HUB_URL")
	}
	token, err := resolve(token, tokenFile, "BOXEL_AGENT_TOKEN")
	if err != nil {
		return err
	}
	if token == "" {
		return errors.New("registration token is required: pass --token/--token-file or set BOXEL_AGENT_TOKEN")
	}
	if name == "" {
		name = os.Getenv("BOXEL_AGENT_NAME")
	}
	if name == "" {
		if name, err = shortHostname(); err != nil {
			return fmt.Errorf("cannot derive agent name from hostname (%w); pass --name", err)
		}
	}
	if target == "" {
		target = os.Getenv("BOXEL_AGENT_TARGET")
	}
	if target == "" {
		target = "http://127.0.0.1:8080"
	}
	targetToken, err = resolve(targetToken, targetTokenFile, "BOXEL_AGENT_TARGET_TOKEN")
	if err != nil {
		return err
	}

	return hubagent.Run(ctx, hubagent.Config{
		HubURL:      hubURL,
		Token:       token,
		Name:        name,
		Target:      target,
		TargetToken: targetToken,
		Version:     Version,
	})
}

// resolve picks a credential from, in order: the flag value, a file, an
// environment variable.
func resolve(value, file, envVar string) (string, error) {
	if value != "" {
		return value, nil
	}
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(envVar), nil
}

// shortHostname returns the lowercased hostname up to the first dot.
func shortHostname() (string, error) {
	h, err := os.Hostname()
	if err != nil {
		return "", err
	}
	h, _, _ = strings.Cut(h, ".")
	return strings.ToLower(h), nil
}
