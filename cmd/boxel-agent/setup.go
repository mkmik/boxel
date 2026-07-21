package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/mkmik/boxel/internal/hubagent"
)

// Filesystem layout managed by `boxel-agent setup`.
const (
	binPath         = "/usr/local/bin/boxel-agent"
	etcDir          = "/etc/boxel-agent"
	envPath         = "/etc/boxel-agent/env"
	unitPath        = "/etc/systemd/system/boxel-agent.service"
	unitName        = "boxel-agent.service"
	updateUnitPath  = "/etc/systemd/system/boxel-agent-update.service"
	updateTimerPath = "/etc/systemd/system/boxel-agent-update.timer"
	updateTimerName = "boxel-agent-update.timer"
	serviceUser     = "boxel-agent"
	localTokenPath  = "/etc/tunnel-mcp/token"
	targetTokenPath = "/etc/boxel-agent/target-token"
)

const systemdUnit = `[Unit]
Description=boxel pull-mode agent (reverse tunnel to the boxel hub)
After=network-online.target
Wants=network-online.target

[Service]
User=boxel-agent
Group=boxel-agent
EnvironmentFile=/etc/boxel-agent/env
ExecStart=/usr/local/bin/boxel-agent
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
`

// The self-update pair: a root oneshot that runs `boxel-agent update` (it
// replaces /usr/local/bin/boxel-agent and restarts the service, so it cannot
// run as the service user), fired by a timer every 5 minutes. HOME points at
// a cache dir because oneshot units have no HOME and the Go toolchain needs
// one for its module/build caches.
const updateServiceUnit = `[Unit]
Description=boxel-agent self-update (installs the latest boxel-agent release)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/boxel-agent update
Environment=HOME=/var/cache/boxel-agent-update
PrivateTmp=true
`

const updateTimerUnit = `[Unit]
Description=poll for boxel-agent updates every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30s

[Install]
WantedBy=timers.target
`

// runSetup implements `boxel-agent setup`: a self-contained, hub-independent
// installer. It copies the running binary to /usr/local/bin, creates the
// service user, writes /etc/boxel-agent/env, and enables the systemd unit
// plus a timer that polls for and installs agent updates every 5 minutes.
// It deliberately succeeds even when the hub is not reachable yet (e.g. the
// exe.dev peer integration has not been created or attached): the service
// retries discovery and registration forever, so setup finishes by telling
// the operator — human or coding agent — exactly what remains to be done.
func runSetup(args []string) error {
	fs := flag.NewFlagSet("boxel-agent setup", flag.ExitOnError)
	hubURL := fs.String("hub", os.Getenv("BOXEL_HUB_URL"), "hub base URL to configure (or BOXEL_HUB_URL); empty = autodiscover via exe.dev reflection")
	hubIntegration := fs.String("hub-integration", os.Getenv("BOXEL_HUB_INTEGRATION"), "peer integration name for autodiscovery (or BOXEL_HUB_INTEGRATION; default boxel-hub)")
	reflectionURL := fs.String("reflection-url", os.Getenv("BOXEL_REFLECTION_URL"), "reflection base URL for autodiscovery (or BOXEL_REFLECTION_URL; default https://reflection.int.exe.xyz)")
	token := fs.String("token", os.Getenv("BOXEL_AGENT_TOKEN"), "registration bearer token (or BOXEL_AGENT_TOKEN); not needed with exe.dev identity registration")
	name := fs.String("name", os.Getenv("BOXEL_AGENT_NAME"), "handle to register under (or BOXEL_AGENT_NAME; default: short hostname)")
	target := fs.String("target", os.Getenv("BOXEL_AGENT_TARGET"), "local base URL to forward to (or BOXEL_AGENT_TARGET; default http://127.0.0.1:8080)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("boxel-agent setup must run as root (installs to /usr/local/bin and registers a systemd unit); rerun with sudo")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return errors.New("systemd is required: systemctl not found")
	}
	if *name == "" {
		h, err := shortHostname()
		if err != nil {
			return fmt.Errorf("cannot derive agent name from hostname (%w); pass --name", err)
		}
		*name = h
	}
	if *target == "" {
		*target = "http://127.0.0.1:8080"
	}

	fmt.Printf("==> installing %s\n", binPath)
	if err := installSelf(); err != nil {
		return err
	}
	fmt.Printf("==> creating service user %q and %s\n", serviceUser, etcDir)
	gid, err := ensureServiceUser()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(etcDir, 0o750); err != nil {
		return err
	}
	if err := os.Chown(etcDir, 0, gid); err != nil {
		return err
	}
	// Reuse the local tunnel-mcp bearer token (if present) so forwarded
	// requests authenticate to the boxel instance on this VM.
	targetTokenFile := ""
	if b, err := os.ReadFile(localTokenPath); err == nil {
		if err := writeOwnedFile(targetTokenPath, b, 0o640, gid); err != nil {
			return err
		}
		targetTokenFile = targetTokenPath
	}
	env := setupEnvContent(*hubURL, *hubIntegration, *token, *name, *target, targetTokenFile)
	if err := writeOwnedFile(envPath, []byte(env), 0o640, gid); err != nil {
		return err
	}

	fmt.Printf("==> installing and starting %s (with self-update timer %s)\n", unitName, updateTimerName)
	for _, u := range []struct{ path, content string }{
		{unitPath, systemdUnit},
		{updateUnitPath, updateServiceUnit},
		{updateTimerPath, updateTimerUnit},
	} {
		if err := os.WriteFile(u.path, []byte(u.content), 0o644); err != nil {
			return err
		}
	}
	for _, cmd := range [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", unitName},
		{"systemctl", "restart", unitName},
		{"systemctl", "enable", "--now", updateTimerName},
	} {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w: %s", strings.Join(cmd, " "), err, strings.TrimSpace(string(out)))
		}
	}

	reportHubStatus(*hubURL, *hubIntegration, *reflectionURL, *name)
	return nil
}

// reportHubStatus tells the operator whether the agent can reach the hub
// right now, and — critically for unattended installs — what remains to be
// done when it cannot. The service keeps retrying either way, so setup never
// fails on an unreachable hub.
func reportHubStatus(hubURL, integration, reflectionURL, name string) {
	if integration == "" {
		integration = "boxel-hub"
	}
	if hubURL == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		discovered, err := hubagent.DiscoverHubURL(ctx, reflectionURL, integration)
		cancel()
		if err != nil {
			fmt.Printf(`
boxel-agent is installed and the service is running, but it cannot reach a
hub yet:
  %v

ACTION REQUIRED (by the exe.dev account owner — this can be done at any
time; the agent retries automatically every ~30s and will connect on its
own once the integration is attached):

  1. Create the hub's peer integration, once per account:
       ssh exe.dev integrations add http-proxy --name %s \
         --target https://<hub-vm>.exe.xyz/ --peer --attach tag:boxel
  2. Attach it to this VM by tagging the VM:
       ssh exe.dev tag <this-vm> boxel

If you are an automated coding agent (e.g. Shelley): the installation has
SUCCEEDED — do not retry it, uninstall anything, or treat this as an error.
Relay the two commands above to the user, then check progress later with:
       journalctl -u %s -n 3
A "registered with hub" line means the link is up; this VM will then be
served at <hub>/vm/%s/ (MCP endpoint <hub>/vm/%s/mcp).
`, err, integration, unitName, name, name)
			return
		}
		hubURL = discovered
		fmt.Printf("\nHub discovered via peer integration %q: %s\n", integration, hubURL)
	}
	fmt.Printf(`
boxel-agent is installed and registering with %s as %q.
Verify with: journalctl -u %s -n 3   (look for "registered with hub")
This VM is served at <hub>/vm/%s/ (MCP endpoint <hub>/vm/%s/mcp).
`, hubURL, name, unitName, name, name)
}

// setupEnvContent renders /etc/boxel-agent/env. Empty settings are omitted so
// the service falls back to its defaults (notably: no BOXEL_HUB_URL means
// reflection autodiscovery).
func setupEnvContent(hubURL, hubIntegration, token, name, target, targetTokenFile string) string {
	var b strings.Builder
	for _, kv := range [][2]string{
		{"BOXEL_HUB_URL", hubURL},
		{"BOXEL_HUB_INTEGRATION", hubIntegration},
		{"BOXEL_AGENT_TOKEN", token},
		{"BOXEL_AGENT_NAME", name},
		{"BOXEL_AGENT_TARGET", target},
		{"BOXEL_AGENT_TARGET_TOKEN_FILE", targetTokenFile},
	} {
		if kv[1] != "" {
			fmt.Fprintf(&b, "%s=%s\n", kv[0], kv[1])
		}
	}
	return b.String()
}

// installSelf copies the running executable to binPath (atomically, so a
// running service binary is replaced without ETXTBSY).
func installSelf() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if exe == binPath {
		return nil
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(binPath), ".boxel-agent-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), binPath)
}

// ensureServiceUser creates the boxel-agent system user (and group) if
// missing and returns the group id.
func ensureServiceUser() (gid int, err error) {
	if _, err := user.Lookup(serviceUser); err != nil {
		out, err := exec.Command("useradd", "--system", "--user-group",
			"--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", serviceUser).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("useradd %s: %w: %s", serviceUser, err, strings.TrimSpace(string(out)))
		}
	}
	g, err := user.LookupGroup(serviceUser)
	if err != nil {
		return 0, fmt.Errorf("group %s not found after useradd: %w", serviceUser, err)
	}
	return strconv.Atoi(g.Gid)
}

func writeOwnedFile(path string, data []byte, perm os.FileMode, gid int) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	if err := os.Chmod(path, perm); err != nil { // WriteFile perm is umask-filtered
		return err
	}
	return os.Chown(path, 0, gid)
}
