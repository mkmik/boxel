# AGENTS.md

Instructions for coding agents working on this repo. These capture decisions
made in earlier sessions — follow them instead of re-deriving them.

## Keep this file current

**Update AGENTS.md in the same PR whenever you learn something worth passing
on** — typically anything you didn't get right on the first try: a build/test
quirk, a non-obvious invariant, a wrong assumption this file (or its absence)
led you into, a deployment gotcha. If a session involved re-discovering
something, that's the signal it belongs here. Keep entries short, imperative,
and in the most relevant existing section (add one if none fits); prune
entries that code changes have made obsolete.

## What this project is

boxel is a **generic-operation MCP server** (`tunnel-mcp`) that tunnels the
Claude Code tool-call protocol to a remote sandbox VM, plus a **pull-mode hub**
that multiplexes MCP for a fleet of non-routable VMs, plus a **built-in OIDC
IDP** (`internal/idp`, enabled in-process with `--idp-issuer`) that turns
exe.dev edge identity into OAuth tokens for programmatic MCP connectors. The full design lives in
`docs/prd-tunnel-mcp.md`; the README is the user-facing source of truth and is
kept meticulously up to date — **update the README (and `docs/`) in the same PR
as any behavior change**.

Naming: the project/binary namespace is **boxel** (module
`github.com/mkmik/boxel`). Binaries: `cmd/tunnel-mcp` (server, both hub and
leaf), `cmd/boxel-agent` (forward-mode fleet agent). The exe.dev peer
integration is named **`boxel`** (it was renamed from `boxel-hub`; don't
reintroduce the old name).

## Build, test, lint

```sh
go build ./...
go test -race ./...   # CI runs with -race; do the same locally
go vet ./...
gofmt -l .            # CI fails on any unformatted file
```

- Go version is pinned in `go.mod` (currently 1.26.5) and CI uses
  `go-version-file: go.mod`. Use modern Go idioms; the codebase was
  deliberately modernized (e.g. `any`, `slices`/`maps`, `min`/`max`).
- The `Grep` harness tool shells out to **ripgrep**; its tests need the `rg`
  binary installed (CI apt-installs it).
- Tests include end-to-end tunnel tests using an in-memory MCP client — prefer
  extending those over mocking when touching the tunnel/harness path.

## Releases — merging = releasing

Every push to `main` (i.e. every merged PR) automatically tags the **next
minor version** and runs GoReleaser (`.github/workflows/auto-release.yml` →
`release.yml`). There is no manual release step and no version to bump in the
source: the binary version is **derived from embedded build info**
(`internal/version`), never hardcoded. Consequences:

- Anything merged to `main` ships immediately; fleet VMs auto-update within
  ~5 minutes (a systemd timer polls the Go module proxy). Don't merge
  half-finished behavior.
- Tags pushed with `GITHUB_TOKEN` don't trigger tag-push workflows, which is
  why `auto-release.yml` calls `release.yml` via `workflow_call` — keep that
  wiring if you touch the workflows.

## Frozen contracts and invariants

- **Byte-exact Claude Code tool semantics.** The harness tools (`Read`,
  `Write`, `Edit`, `Glob`, `Grep`, `Bash`, `BashOutput`, `KillShell`) must
  match Claude Code's native output formats **and failure-mode strings**
  exactly — the model's recovery behavior depends on them. Do not "improve"
  output or error text. Tools are implemented natively (no shelling out for
  Read/Edit).
- **Cross-package contracts are frozen** (envelope schemas, policy engine
  interface, audit JSON tag names — see `internal/policy/engine.go` and the
  audit tests). Changing them is a breaking change to be avoided, not a
  refactor.
- **Permission engine:** precedence is deny > ask > allow, then mode defaults.
  Hard denies (workspace jail escapes, credential paths) apply **always, even
  in `bypassPermissions`**. `bypassPermissions` is server-flag-only and must
  never become client-selectable. "Allow always" from an elicitation writes to
  a session-scoped overlay, never the persistent permissions file.
- **Security stance:** `invoke` is authenticated RCE by construction.
  Authentication is the primary boundary; the permission engine is
  defense-in-depth/UX. The HTTP transport **refuses to start without auth**
  (`--token` and/or `--owner-email`) — never weaken that. `Bash` is
  deliberately not jail-checked (a command carries no path); containment is
  OS-level sandboxing + egress deny, documented in `docs/deployment.md`.
- **Audit log:** every mutation is logged with an input digest and decision;
  **file contents are never logged**; sensitive Bash command lines are
  redacted.

## exe.dev deployment specifics (hard-won)

- The server binds `--http` to `127.0.0.1` behind a TLS-terminating edge that
  forwards the public hostname. The MCP Go SDK's DNS-rebinding Host-header
  check (auto-enabled on loopback since v1.4.0) is **intentionally disabled**
  via `StreamableHTTPOptions` — re-enabling it breaks the documented
  deployment with 403 "invalid Host header". Rebinding is mitigated by
  mandatory auth + no CORS approval.
- Edge identity: the exe.dev edge injects `X-ExeDev-Email` (checked against
  `--owner-email` / `--hub-agent-owner-email`) and, through the peer
  integration, the unforgeable `X-Exedev-Source-Vm` — that's why hub agent
  registration is tokenless on exe.dev. `--token` and `--owner-email` compose
  (both must pass when both are set); `--idp-issuer` OAuth tokens are an
  *alternative* method, OR'd with the static pair in `authLayers`.
- The edge injects identity on **public** VMs too (for logged-in visitors;
  anonymous requests just lack the headers), and `/__exe.dev/login?redirect=`
  forces a browser login — earlier docs wrongly claimed set-public disabled
  injection. exe.dev hosts **no user-facing OAuth/OIDC server** (its
  openid-configuration is a workload-identity stub; `exe-oidc-proxy` has no
  PKCE/DCR) — that's why the built-in IDP exists.
- The HTTP guard is **default-deny at the server level** (`withGuard` in
  cmd/tunnel-mcp): register routes unguarded on the mux; only the closed
  `isPublicPath` allowlist (OAuth well-knowns, self-authorizing `/idp/*`,
  `/healthz`, hub connect/installer) bypasses auth. Never re-introduce
  per-route guard wrapping — a forgotten wrap is an exposed route.
- Guard rejections are content-negotiated: browser navigations (GET/HEAD with
  `Accept: text/html`) that fail the exe.dev identity check get an HTML
  sign-in page bouncing through `/__exe.dev/login?redirect=` (or a sign-out
  button when the wrong account is signed in); everything else keeps the
  plain-text 401/403 so API clients see unambiguous errors.
- The IDP **auto-enables** when `--owner-email` is the sole configured auth
  (issuer `https://<short-hostname>.exe.xyz`, key at
  `~/.config/boxel/idp-key.pem`) so fleet auto-updates light it up without
  flag changes. It deliberately does NOT auto-enable when a `--token` is set:
  OAuth is an alternative method, and auto-adding it would weaken a
  token+identity deployment to identity alone. `--idp-issuer none` opts out.
- The IDP runs **in-process only** (it shares the signing key with the
  resource-side `Verifier`; there is deliberately no remote-issuer mode). Its
  non-authorize endpoints (`/idp/token`, `/idp/register`, well-knowns, JWKS)
  are **public by design** and must never be wrapped in the resource auth
  guard; the VM must be `share set-public` or OAuth clients' backends can't
  redeem codes. `/idp/authorize` is the only identity-bearing endpoint.
  Everything issued is stateless off `--idp-key-file` — losing that key
  strands every connector registration.
- Agents autodiscover the hub by querying the default `reflection` integration
  for an http-proxy integration named `boxel`. There is no VM-to-VM network on
  exe.dev; everything goes through `http://boxel.int.exe.xyz/`.
- The hub↔agent reverse channel is HTTP/2 over an `Upgrade: boxel-h2c`
  handshake; intermediaries that strip it break the channel right after
  the 101.

## Fleet agent / installer contract

- The default, installer-provisioned agent is a **single process**:
  `tunnel-mcp --hub-connect`, serving its MCP in-process over the reverse
  channel (no local port, no separate forwarder). The standalone `boxel-agent`
  forwarder exists for fronting an arbitrary local HTTP server or hub-less
  bootstrap — don't reintroduce the two-process default.
- **Unattended-install contract:** `install-agent` (served by the hub) must
  succeed even while the hub/integration is unreachable — the service retries
  discovery forever; the installer must **not retry or roll back**, and prints
  the exact remaining `integrations add` / `tag` commands for the owner.
- Diagnostics decided in past sessions and worth preserving: 502s from
  `/vm/<name>/` carry JSON bodies (`vm_not_connected` vs
  `agent_forward_failed`), and `GET /vm/<name>/__boxel-agent` is answered by
  the agent itself (never forwarded) with a live `target_check` probe.

## Working conventions

- CI must be green: gofmt-clean, `go vet`, build, `go test -race`.
- Security-sensitive changes (policy engine, jail, auth) get regression tests;
  past sessions added tests for every jail bypass and the Host-header fix —
  keep that bar.
- Keep the README's troubleshooting table and flag table in sync with code
  changes; they are part of the product.
