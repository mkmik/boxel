package main

import (
	"context"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/mkmik/boxel/internal/version"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Self-update settings. The systemd timer installed by `boxel-agent setup`
// runs `boxel-agent update` every 5 minutes; the cache dir keeps the Go
// toolchain's module/build caches out of root's home (which systemd oneshot
// units don't even set).
const (
	updateCacheDir = "/var/cache/boxel-agent-update"
	defaultGoProxy = "https://proxy.golang.org"
	defaultModule  = "github.com/mkmik/boxel"
)

// runUpdate implements `boxel-agent update`: resolve the latest released
// version of the agent's module from the Go module proxy, and when it is
// newer than the running (= installed, since the timer executes
// /usr/local/bin/boxel-agent) binary, build it with `go install`, atomically
// replace the binary, and restart the service. Doing nothing is the normal
// outcome, so every no-op path exits 0 with a one-line explanation.
func runUpdate(args []string) error {
	fs := flag.NewFlagSet("boxel-agent update", flag.ExitOnError)
	checkOnly := fs.Bool("check", false, "report whether a newer version is available without installing it")
	goProxy := fs.String("goproxy", "", "Go module proxy used to resolve the latest version (default: first proxy URL in $GOPROXY, else "+defaultGoProxy+")")
	if err := fs.Parse(args); err != nil {
		return err
	}

	current := version.String()
	if !semver.IsValid(current) {
		fmt.Printf("installed version %q is not a released module version (source build?); not self-updating\n", current)
		return nil
	}
	proxy, err := resolveGoProxy(*goProxy, os.Getenv("GOPROXY"))
	if err != nil {
		fmt.Println(err)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	latest, err := latestModuleVersion(ctx, proxy, agentModule())
	if err != nil {
		return fmt.Errorf("resolve latest %s version: %w", agentModule(), err)
	}
	if semver.Compare(latest, current) <= 0 {
		fmt.Printf("up to date (installed %s, latest %s)\n", current, latest)
		return nil
	}
	fmt.Printf("update available: %s -> %s\n", current, latest)
	if *checkOnly {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("boxel-agent update must run as root (replaces " + binPath + " and restarts the service); rerun with sudo")
	}
	if err := installVersion(ctx, latest); err != nil {
		return err
	}
	// try-restart: pick up the new binary only if the service is running, so
	// an operator who stopped it deliberately doesn't get it back.
	fmt.Printf("==> restarting %s\n", unitName)
	if out, err := exec.Command("systemctl", "try-restart", unitName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl try-restart %s: %w: %s", unitName, err, strings.TrimSpace(string(out)))
	}
	fmt.Printf("updated to %s\n", latest)
	return nil
}

// agentModule returns the module path to update from, taken from the build
// info embedded in this binary so forks self-update from their own module.
func agentModule() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Path != "" {
		return bi.Main.Path
	}
	return defaultModule
}

// resolveGoProxy picks the proxy to query: the explicit flag value, else the
// first proxy URL in the (comma/pipe-separated) GOPROXY list, else the public
// default. GOPROXY=off returns an error meaning "don't update".
func resolveGoProxy(flagValue, env string) (string, error) {
	if flagValue != "" {
		return strings.TrimRight(flagValue, "/"), nil
	}
	for _, p := range strings.FieldsFunc(env, func(r rune) bool { return r == ',' || r == '|' }) {
		switch p = strings.TrimSpace(p); {
		case p == "off":
			return "", errors.New("GOPROXY=off: not self-updating")
		case strings.HasPrefix(p, "http://"), strings.HasPrefix(p, "https://"):
			return strings.TrimRight(p, "/"), nil
		}
	}
	return defaultGoProxy, nil
}

// latestModuleVersion asks the module proxy for modPath's latest version
// (GOPROXY protocol: GET <proxy>/<escaped module>/@latest).
func latestModuleVersion(ctx context.Context, proxy, modPath string) (string, error) {
	escaped, err := module.EscapePath(modPath)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxy+"/"+escaped+"/@latest", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s: %s", req.URL, resp.Status, strings.TrimSpace(string(body)))
	}
	var info struct{ Version string }
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("%s: %w", req.URL, err)
	}
	if !semver.IsValid(info.Version) {
		return "", fmt.Errorf("%s: invalid version %q", req.URL, info.Version)
	}
	return info.Version, nil
}

// installVersion builds <module>/cmd/boxel-agent@v with the local Go
// toolchain into a staging directory next to binPath (so the final rename is
// atomic and never crosses filesystems), verifies the staged binary really
// embeds the requested version, and swaps it in.
func installVersion(ctx context.Context, v string) error {
	goTool, err := lookGo()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(updateCacheDir, 0o755); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(binPath), ".boxel-agent-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	target := agentModule() + "/cmd/boxel-agent@" + v
	fmt.Printf("==> go install %s\n", target)
	cmd := exec.CommandContext(ctx, goTool, "install", target)
	cmd.Env = append(os.Environ(), "GOBIN="+staging)
	if os.Getenv("HOME") == "" {
		cmd.Env = append(cmd.Env, "HOME="+updateCacheDir)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go install %s: %w: %s", target, err, strings.TrimSpace(string(out)))
	}

	staged := filepath.Join(staging, "boxel-agent")
	bi, err := buildinfo.ReadFile(staged)
	if err != nil {
		return fmt.Errorf("verify staged binary: %w", err)
	}
	if bi.Main.Version != v {
		return fmt.Errorf("staged binary reports version %q, want %s", bi.Main.Version, v)
	}
	return os.Rename(staged, binPath)
}

// lookGo finds the go tool: PATH first, then the usual install locations
// (systemd units run with a minimal PATH that misses /usr/local/go/bin).
func lookGo() (string, error) {
	if p, err := exec.LookPath("go"); err == nil {
		return p, nil
	}
	for _, p := range []string{"/usr/local/go/bin/go", "/usr/local/bin/go", "/usr/bin/go"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("go toolchain not found (needed to build the update); install Go or add it to PATH")
}
