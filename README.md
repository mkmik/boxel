# boxel — Tunnel MCP

**A generic-operation MCP server that tunnels the Claude Code tool-call protocol to a remote sandbox VM.**

Instead of re-declaring every sandbox capability as a typed MCP tool, boxel advertises **one generic `invoke` operation** whose body *is* a Claude Code tool call. Any Claude surface — CLI, desktop, or the phone app via a remote MCP connector — becomes a thin controller for a sandbox VM you own. The MCP layer is a transport tunnel; the tool semantics live at the far end.

See [`docs/prd-tunnel-mcp.md`](docs/prd-tunnel-mcp.md) for the full product design.

```
Claude (phone / desktop / CLI)
        │  MCP (stdio, or streamable HTTP + bearer, behind a TLS tunnel)
        ▼
┌──────────────────────────────┐
│  tunnel-mcp server           │
│  ├─ MCP transport layer      │
│  ├─ Envelope parser/validator│
│  ├─ Permission engine ───────┼──► MCP elicitation → user approval
│  ├─ Harness (tool impls)     │
│  └─ Session manager          │
└───────────┬──────────────────┘
            ▼
      Sandbox VM filesystem + processes (workspace jail)
```

## Quick start: join a VM to the fleet

On a VM that should join an existing boxel hub (once the hub's peer
integration is attached to the VM — `ssh exe.dev tag SOME_VM boxel`):

```sh
curl -fsSL http://boxel.int.exe.xyz/install-agent | sudo bash
```

This installs a **single agent process**: a systemd unit running
`tunnel-mcp --hub-connect`, which dials out to the hub and serves this VM's
MCP in-process over the reverse channel — no local port, no separate
forwarder. The service autodiscovers the hub and retries until it connects,
so only the script *fetch* itself needs the integration attached. To front an
arbitrary local HTTP server instead (or to bootstrap before the integration
exists), use forward mode — see
[`docs/pull-mode.md`](docs/pull-mode.md#forward-mode-boxel-agent-setup):

```sh
GOBIN=/usr/local/bin go install github.com/mkmik/boxel/cmd/boxel-agent@latest
sudo /usr/local/bin/boxel-agent setup
```

To set up the hub itself, see the
[setup runbook](#setup-runbook-exedev) under
[Pull mode](#pull-mode-one-hub-many-non-routable-vms).

## Advertised MCP surface

| Tool | Purpose |
|---|---|
| `invoke` | Generic op. Body: `{"tool": string, "input": object, "session": string?}`, interpreted as a Claude Code tool call. |
| `describe` | Supported tool names + input schemas, active permission mode + redacted policy, sandbox metadata (hostname, OS, workspace root), sessions, limits. |
| `session` | Create / list / reset logical sessions (cwd, env, background shells, permission overlay). |

On a pull-mode hub the same three tools are served by the **fleet
dispatcher**, which adds an optional `"vm"` argument to each (target VM;
`"local"` = the hub's own sandbox, and the default) — see
[Pull mode](#pull-mode-one-hub-many-non-routable-vms).

### Tunneled tools (v1)

`Read`, `Write`, `Edit`, `Glob`, `Grep`, `Bash`, `BashOutput`, `KillShell` — implemented natively with **byte-exact Claude Code semantics** (identical output formats and failure-mode strings), so the model's recovery behavior transfers unchanged. Use the exact input schemas you use natively; call `describe` if unsure. Unknown tool names return `{"error": "unknown_tool", "supported": [...]}`.

## Running the server

Build:

```sh
go build ./cmd/tunnel-mcp
```

Run locally over **stdio** (for `claude mcp add` or local testing):

```sh
./tunnel-mcp --workspace /home/agent/work --permissions examples/permissions.json
```

Run over **streamable HTTP** (for a remote/phone connector; front with a TLS tunnel):

```sh
BOXEL_TOKEN=$(openssl rand -hex 32) \
  ./tunnel-mcp --http 127.0.0.1:8080 \
    --workspace /home/agent/work \
    --permissions examples/permissions.json \
    --audit-log /var/log/tunnel-mcp/audit.jsonl \
    --metrics-addr 127.0.0.1:9090
```

The MCP endpoint is `POST /mcp` (requires `Authorization: Bearer <token>`); `GET /healthz` is unauthenticated. Prometheus metrics are served separately on `--metrics-addr` at `/metrics`.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--http` | *(empty → stdio)* | Serve streamable HTTP on this address. |
| `--workspace` | current dir | Workspace jail root; file ops outside it are hard-denied. |
| `--permissions` | *(none)* | Path to `permissions.json` (Claude Code-compatible rules). |
| `--permission-mode` | `default` (`bypassPermissions` with `--hub-connect`) | `default` \| `acceptEdits` \| `bypassPermissions`. Pull-mode agents default to `bypassPermissions` — the agent VM is the sandbox, and the ask path needs elicitation support common MCP clients (e.g. Claude Code) lack. An explicit flag always wins. |
| `--audit-log` | *(disabled)* | Append-only JSONL audit log path. |
| `--metrics-addr` | *(disabled)* | Serve Prometheus `/metrics` on this address. |
| `--token` / `--token-file` | `$BOXEL_TOKEN` | Static bearer token for HTTP (testing; front with OAuth for production). |
| `--owner-email` | *(none)* | Pin to one owner via the exe.dev edge: require the `X-ExeDev-Email` header to equal this address. Composes with `--token`. See [`docs/deployment.md`](docs/deployment.md). |
| `--session-ttl` | `24h` | Idle-session GC TTL (`0` disables). |
| `--idp-issuer` | *(auto)* | Enable the **built-in OIDC IDP** (see below) and accept its OAuth tokens on `/mcp`: the external base URL clients see. **Auto-enabled** as `https://<hostname>.exe.xyz` when `--owner-email` is the sole configured auth; `none` disables. |
| `--idp-users` | `--owner-email` | Comma-separated emails allowed to authenticate at the IDP. |
| `--idp-key-file` | `~/.config/boxel/idp-key.pem` | P-256 signing key PEM, created on first run. |
| `--hub-agent-owner-email` | *(none)* | Enable the **pull-mode hub** (see below) with exe.dev identity registration: tokenless, names bound to the platform-verified caller VM. |
| `--hub-agent-token` / `--hub-agent-token-file` | `$BOXEL_HUB_AGENT_TOKEN` | Enable the pull-mode hub with token registration (non-exe.dev deployments; composes with the above). |
| `--hub-agent-listen` | *(disabled)* | Extra listener serving only the agent registration endpoint. |
| `--hub-advertise-url` | *(reflection discovery / fetch URL)* | Base URL agents dial; embedded in the `/install-agent` script. |

For HTTP, at least one of `--token` / `--owner-email` / `--idp-issuer` must be set — the server refuses to listen unauthenticated. The guard is **default-deny**: every route (`/mcp`, the hub dashboard, `/vm/…`, `/agents`, even unknown paths) requires auth, except a closed allowlist of endpoints the OAuth spec needs open (`/.well-known/*`, the self-authorizing `/idp/*` flow endpoints) plus `/healthz` and the hub's self-authenticating registration/installer endpoints. When a browser hits a guarded page without an exe.dev identity (e.g. right after signing out of the dashboard), the guard serves a sign-in page that bounces through the platform login and returns to the same URL; API clients get the plain 401/403.

## OAuth for external tools: the built-in OIDC IDP

Browser-based Claude surfaces can ride the exe.dev edge SSO, but programmatic
MCP clients — Claude's remote-MCP connectors, the phone app — speak **OAuth**:
they discover an authorization server, register a client, send the user
through an authorize page, and then call `/mcp` with a bearer access token.
exe.dev itself does not offer a user-facing OAuth/OIDC authorization server,
so boxel ships one: an intentionally small OAuth 2.1 / OIDC provider that
runs **in the same process** as the MCP server (and hub, if enabled), whose
source of user truth is the **exe.dev edge** (`X-ExeDev-Email`). It supports
dynamic client registration (RFC 7591), PKCE (S256, required), refresh
tokens, and RFC 9728 protected-resource discovery — the pieces the MCP
spec's auth flow needs. It never sees a password: the authorize endpoint
bounces anonymous browsers through `/__exe.dev/login`, then gates on an
email allowlist and a consent page.

**Zero flags for the common case:** on a deployment whose only auth is
`--owner-email` (the recommended exe.dev shape, including the hub runbook
below), the IDP **auto-enables** with issuer `https://<hostname>.exe.xyz`,
allowlist `--owner-email`, and a signing key persisted at
`~/.config/boxel/idp-key.pem` — so updating the binary and running
`ssh exe.dev share set-public <vm>` is all it takes to accept OAuth
connectors. Auto-enable is deliberately skipped when a `--token` is also
configured (there the static pair means token *and* identity, and OAuth
would weaken it to identity alone); pass `--idp-issuer` explicitly to opt
in, or `--idp-issuer none` to opt out. One public VM, one process:

```sh
tunnel-mcp --http 127.0.0.1:8080 \
  --workspace /home/agent/work --permissions /etc/tunnel-mcp/permissions.json \
  --owner-email you@example.com          # IDP auto-enables from this
ssh exe.dev share port myvm 8080
ssh exe.dev share set-public myvm
```

`/mcp` now answers `401` with an RFC 9728 `resource_metadata` challenge, and
an OAuth-capable client (e.g. a Claude custom connector pointed at
`https://myvm.exe.xyz/mcp`) discovers the IDP, registers itself, and walks
you through exe.dev login + consent in the browser. Everything the IDP issues
is stateless (signed by the `--idp-key-file` key), so restarts don't break
connectors — persist that key.

The VM must be **`set-public`**: token, registration, and metadata endpoints
are called server-side by the OAuth client without an exe.dev session, and a
private VM's edge would swallow them with a login redirect. Identity is still
rooted in exe.dev because `/idp/authorize` is the only place codes come from,
and it requires the edge-injected identity header (still injected on public
VMs for logged-in visitors). This composes with the pull-mode hub: enable
`--idp-issuer` on the hub and one OAuth connector credential covers the
fleet dispatcher at `/mcp` and every `/vm/<name>/mcp`. Pair it with `--owner-email` so
browser surfaces (the dashboard, `/agents`) keep working through exe.dev
edge identity while connectors use OAuth — the two methods are alternatives,
either satisfies the guard. See
[`docs/deployment.md`](docs/deployment.md) §4b for the threat model.

## Pull mode: one hub, many non-routable VMs

### The model

One routable boxel instance — the **hub** — multiplexes MCP for boxel
instances on VMs that expose no inbound HTTP port (their forwarded port stays
free for the workload you're actually developing). On each such VM an agent
dials *out* to the hub and registers under the VM's short hostname over a
reverse HTTP/2 channel. The default, installer-provisioned agent is a
**single process** — `tunnel-mcp --hub-connect` — that serves its own MCP
in-process over that channel; alternatively the standalone `boxel-agent`
forwarder fronts an arbitrary local HTTP server (default
`http://127.0.0.1:8080`). The hub proxies the whole `/vm/<name>/` base path
over that channel, so for VM `foobar`:

- MCP endpoint: `https://<hub-vm>.exe.xyz/vm/foobar/mcp`
- any other path under `/vm/foobar/` also reaches `foobar` (e.g.
  `/vm/foobar/healthz` hits the local instance's health check)

The hub's own `/mcp` additionally serves the **fleet dispatcher**: the same
`invoke`/`describe`/`session` surface with an optional `"vm"` argument, so a
*single* connector endpoint covers every VM — `describe` lists the fleet,
`session {"action":"create","session":<id>,"vm":<name>}` binds a session to a
VM, and invokes carrying that session route there over the same reverse
channel. The default target `"local"` is the hub's own sandbox, so clients
that never pass `vm` behave as before; the per-VM `/vm/<name>/mcp` endpoints
remain as the direct-addressing fallback. See
[`docs/pull-mode.md`](docs/pull-mode.md#fleet-dispatcher-one-endpoint-vm-chosen-at-the-tool-layer).

One connector origin and one credential cover the whole fleet: `/mcp`,
`/vm/…` and `/agents` (the JSON registry) all sit behind the hub's normal
client auth (`--token` / `--owner-email`).

On exe.dev there is no VM-to-VM network; agents reach the hub through a
**peer integration** — an exe.dev-managed proxy at
`http://boxel.int.exe.xyz/` that authenticates the calling VM to the
hub's edge and stamps the unforgeable caller VM name in `X-Exedev-Source-Vm`.
Registration is therefore **tokenless**: the hub accepts a registration when
the edge-injected `X-ExeDev-Email` equals `--hub-agent-owner-email`, and the
agent's handle is taken from the verified source-VM header. Agents
autodiscover the hub by querying the default `reflection` integration for an
attached http-proxy integration named `boxel`. (Non-exe.dev deployments
use `--hub-agent-token` instead; both methods can be enabled at once.)

### Setup runbook (exe.dev)

Placeholders: `HUB_VM` = the hub's VM name, `YOU@EXAMPLE.COM` = your exe.dev
account email (an agent can read it on any VM from
`curl -s https://reflection.int.exe.xyz/email`).

**Step 1 — on the hub VM**: run tunnel-mcp with the hub enabled. `--http`
requires client auth; with the VM kept private, edge SSO + `--owner-email` is
enough. Bind to `127.0.0.1` so the edge is the only path in, and make sure
the edge forwards to that port (`ssh exe.dev share port HUB_VM 8080`).

```sh
go build -o /usr/local/bin/tunnel-mcp ./cmd/tunnel-mcp   # or: GOBIN=/usr/local/bin go install github.com/mkmik/boxel/cmd/tunnel-mcp@latest
tunnel-mcp --http 127.0.0.1:8080 --workspace /home/agent/work \
  --owner-email YOU@EXAMPLE.COM \
  --hub-agent-owner-email YOU@EXAMPLE.COM
```

(For a production systemd unit and hardening, see
[`docs/deployment.md`](docs/deployment.md); add the `--hub-agent-owner-email`
flag to its `ExecStart`.)

**Step 2 — once, from any shell with your exe.dev SSH key** (laptop or the
exe.dev web UI at `/integrations`; VMs themselves normally can't run
`ssh exe.dev` account commands): create the fleet's peer integration,
attached by tag:

```sh
ssh exe.dev integrations add http-proxy --name boxel \
  --target https://HUB_VM.exe.xyz/ --peer --attach tag:boxel
```

**Step 3 — per fleet VM**: attach the integration by tagging the VM (same
place as step 2), and install the agent on the VM (needs a Go toolchain
≥ 1.25 and systemd). **Steps 2/3a and 3b can happen in either order** — the
installer succeeds even while the integration is missing, and the agent
service retries discovery every backoff cycle until it appears.

From your shell (or the web UI):

```sh
ssh exe.dev tag SOME_VM boxel
```

Then on `SOME_VM`, once the integration is attached:

```sh
curl -fsSL http://boxel.int.exe.xyz/install-agent | sudo bash
```

The script installs a **single-process** agent: it builds `tunnel-mcp`,
creates a `boxel-agent` system user with a jailed workspace
(`/var/lib/boxel-agent/work` by default, override with `BOXEL_WORKSPACE`),
and enables a `boxel-agent.service` running
`tunnel-mcp --hub-connect` — one process that dials the hub and serves this
VM's MCP in-process, with no local port and no separate forwarder. The unit
deliberately carries **no systemd sandboxing** and the agent runs in
**`bypassPermissions`** mode by default: the VM itself is the sandbox, and
permission prompts would stall anyway on MCP clients without elicitation
support (add `--permission-mode` to the unit's `ExecStart` to opt back into
prompting). The script also installs a
`boxel-agent-update.timer` that polls the Go module proxy every 5 minutes
and automatically installs newer releases. The install succeeds even while
the hub is unreachable: the service autodiscovers and retries until the
integration appears (an unattended agent must not retry or roll back), and
the script prints the exact `integrations add` / `tag` commands that remain
for the account owner.

To front an arbitrary local HTTP server instead — or for a hub-independent
bootstrap that works before the integration exists — use the forward-mode
`boxel-agent` (see
[`docs/pull-mode.md`](docs/pull-mode.md#forward-mode-boxel-agent-setup)):

```sh
GOBIN=/usr/local/bin go install github.com/mkmik/boxel/cmd/boxel-agent@latest
sudo /usr/local/bin/boxel-agent setup
```

**VM-description snippet** — paste this into a VM's description so a coding
agent (e.g. Shelley) performs the install autonomously:

> Set up the boxel fleet agent: ensure a Go toolchain is installed, then run
> `curl -fsSL http://boxel.int.exe.xyz/install-agent | sudo bash` and follow
> the script's output. If the URL is unreachable, the hub's peer integration
> isn't attached to this VM yet: relay `ssh exe.dev tag <this-vm> boxel` to
> the user and retry the same command after it's attached — the fetch is the
> only step that needs it. If the script's output says the hub is not
> reachable yet, the install still succeeded: relay the printed commands to
> the user, do not retry or uninstall, and check
> `journalctl -u boxel-agent -n 3` later until it logs "registered with hub".

**Step 4 — verify**:

```sh
# on the fleet VM: the agent should log "registered with hub"
systemctl status boxel-agent && journalctl -u boxel-agent -n 5
# from an authorized client (e.g. your browser via edge SSO):
#   https://HUB_VM.exe.xyz/agents            → lists the VM
#   https://HUB_VM.exe.xyz/vm/SOME_VM/healthz → "ok" from the VM's local boxel
```

**Step 5 — connect Claude**: point the MCP connector at the fleet
dispatcher, `https://HUB_VM.exe.xyz/mcp`, with the hub's credentials (see
[`docs/deployment.md`](docs/deployment.md) for the connector auth options) —
one connector covers the whole fleet. Call `describe` to list VMs, then bind
a session (`session {"action":"create","session":"job","vm":"SOME_VM"}`) so
invokes route to the VM without registering anything per-VM. Alternatively,
register per-VM connectors against
`https://HUB_VM.exe.xyz/vm/SOME_VM/mcp` — the direct-addressing fallback.
The VM's own public hostname stays free: `ssh exe.dev share port SOME_VM
<your-app-port>` gives it entirely to the app you're developing.

### Troubleshooting

| Symptom | Cause / fix |
|---|---|
| agent logs `hub autodiscovery: no http-proxy integration named "boxel"` | VM not tagged (step 3) or integration missing (step 2). Discovery retries every backoff cycle, so fixing the tag is enough. |
| agent logs `hub refused registration: 401` | Hub not started with `--hub-agent-owner-email`, or its value doesn't match the account that owns the VMs. |
| agent registers, then the channel drops immediately after the 101 | An intermediary isn't passing the `Upgrade: boxel-h2c` handshake through — report it. |
| `/vm/<name>/…` returns 502 `vm_not_connected` (JSON body) | Agent not running/registered on that VM — check step 4. |
| dispatcher `invoke`/`session` returns a `vm_not_connected` tool error | Same cause as the proxy's 502: no agent registered under that name — check step 4, or `describe` to list what is connected. |
| `/vm/<name>/…` returns 502 `agent_forward_failed` (JSON body) | Forward-mode (`boxel-agent`) only — a `--hub-connect` agent serves MCP in-process and has no forward target. The agent is connected but can't reach its **local** forward target: nothing is listening on `--target` (default `127.0.0.1:8080`), or it's on a different port. Start the local server, or fix `--target`. |
| `/vm/<name>/…` returns 502 with an **empty** body | An older agent (before the diagnostic endpoint) failing to forward — same cause as `agent_forward_failed`. Upgrade `boxel-agent` to get the explanatory body. |
| unsure whether it's the channel or the local target | Hit `GET /vm/<name>/__boxel-agent` — the agent answers this path **itself** (never forwarded), returning its name/version/`--target` and a live `target_check` reachability probe. A 200 here with `target_check.reachable: false` means the channel is up and the local target is down. |
| proxied requests get 401 from the *local* boxel (forward mode) | The agent isn't injecting the local token: ensure `/etc/boxel-agent/target-token` exists (rerun `boxel-agent setup` after creating `/etc/tunnel-mcp/token`) or set `BOXEL_AGENT_TARGET_TOKEN_FILE` in `/etc/boxel-agent/env` and restart `boxel-agent`. |

Full details (generic token-based deployments, security model, design notes):
[`docs/pull-mode.md`](docs/pull-mode.md).

## Permissions

Rules use Claude Code's `settings.json` format. Precedence is **deny > ask > allow**, then mode defaults. See [`examples/permissions.json`](examples/permissions.json).

- `Bash(git status:*)` — prefix form: commands starting `git status`.
- `Bash(rm *)` — glob form: `*` spans any characters including spaces.
- `Edit(/home/agent/work/**)` — doublestar glob over the resolved absolute path.
- `Read(**)` — any path (still subject to the jail + credential hard denies).

**Modes:** `default` asks on any unmatched mutating call; `acceptEdits` auto-approves `Write`/`Edit` inside the jail; `bypassPermissions` is audit-only and **server-flag only, never client-selectable**. A pull-mode agent (`--hub-connect`) defaults to `bypassPermissions` — the agent VM is the sandbox — unless `--permission-mode` is set explicitly.

**Ask path:** an "ask" decision issues an [MCP elicitation](https://modelcontextprotocol.io/) — `allow once` / `allow always` / `deny`. "Allow always" appends a rule to a **session-scoped overlay**, never the persistent file. Elicitation requires client support; clients without it (the Claude Code MCP client, currently) cannot answer an ask, which is why pull-mode agents default to `bypassPermissions`.

**Hard denies (always, even in `bypassPermissions`):**
- Paths outside the workspace jail.
- Credential files — `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`, `~/.gnupg/**`, `~/.kube/**`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `/etc/shadow`, `/etc/sudoers`, and anything under a `.ssh/` directory — unless an explicit (non-catch-all) allow rule matches.

## Security model

The generic `invoke` op is, by construction, an **authenticated RCE endpoint** — treat the whole design as "authenticated RCE with policy," not a typed API. **Authentication is the primary boundary; the permission engine is defense-in-depth and UX.** Deploy accordingly:

- Front the HTTP transport with a TLS-terminating tunnel, and authenticate clients with OAuth — the built-in OIDC IDP (`--idp-issuer`) or the fronting layer's SSO. The built-in bearer token is a second factor and a local-testing convenience, not the production auth story.
- Run the server as a dedicated **unprivileged** user, with the workspace on its own path and OS-level isolation (systemd sandboxing / bubblewrap / landlock) — *when the host machine is worth protecting*. Fleet agents installed via `/install-agent` deliberately skip systemd sandboxing and run `bypassPermissions`: there the entire disposable VM is the isolation boundary.
- Deny-by-default egress from the sandbox user (e.g. nftables per-UID) with a registry/GitHub allowlist, to bound exfiltration if a prompt-injected session goes rogue.
- Every mutation is recorded in the audit log with an input digest and the permission decision; **file contents are never logged**, and Bash command lines flagged sensitive are redacted.

### Known limitations of the policy layer

The permission engine is defense in depth, not the perimeter — deploy the OS-level isolation in [`docs/deployment.md`](docs/deployment.md). Specifically:

- **`Bash` is unrestricted RCE by design.** A Bash command carries no filesystem path for the engine to jail-check, so `cat /etc/shadow` is reachable subject only to Bash rule/mode gating (in `default` mode it prompts). The jail and credential hard-denies apply to the *file tools* (Read/Write/Edit/Glob/Grep), not to what a shell command can do. Egress deny + OS sandboxing are what actually contain a shell.
- **Symlink resolution is best-effort.** File-tool paths are resolved (symlinks followed) before the jail/credential check, so a symlinked parent inside the workspace can't disguise an outside target. This is not TOCTOU-proof against a path swapped between check and use; a landlock/bind-mount jail is.

See [`docs/deployment.md`](docs/deployment.md) for a systemd unit and Cloudflare Tunnel walkthrough.

## Development

```sh
go build ./...
go test ./...       # unit tests + end-to-end tunnel tests (in-memory MCP client)
go vet ./...
```

Package layout:

| Package | Responsibility |
|---|---|
| `internal/envelope` | `invoke` envelope + typed Claude Code tool input schemas. |
| `internal/policy` | Permission engine: rule parsing, precedence, modes, jail + credential hard denies, session overlays. |
| `internal/harness` | Native tool implementations (Read/Write/Edit/Glob/Grep/Bash/BashOutput/KillShell). |
| `internal/shellmgr` | Bash execution: foreground with cwd persistence, background shell table. |
| `internal/session` | Session manager (cwd, env, shells, overlay) with TTL GC. |
| `internal/audit` | Append-only JSONL audit log. |
| `internal/metrics` | Prometheus instrumentation. |
| `internal/tunnel` | MCP server wiring: envelope → policy → elicitation → harness → audit/metrics. |
| `internal/idp` | Built-in OIDC IDP: OAuth 2.1 code+PKCE flow, dynamic client registration, stateless ES256 tokens rooted in exe.dev edge identity; plus the resource-side token `Verifier`. |
| `internal/hub` | Pull-mode multiplexer: agent registry, reverse HTTP/2 registration, `/vm/<name>/` proxy, installer script. |
| `internal/hubagent` | Pull-mode agent runtime: dial-out, reconnect, forwarding to the local instance. |
| `cmd/tunnel-mcp` | Binary: stdio + streamable HTTP transports, bearer auth, hub mode, flags. |
| `cmd/boxel-agent` | Pull-mode agent binary for non-routable VMs. |
