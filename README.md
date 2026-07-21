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

## Advertised MCP surface

| Tool | Purpose |
|---|---|
| `invoke` | Generic op. Body: `{"tool": string, "input": object, "session": string?}`, interpreted as a Claude Code tool call. |
| `describe` | Supported tool names + input schemas, active permission mode + redacted policy, sandbox metadata (hostname, OS, workspace root), sessions, limits. |
| `session` | Create / list / reset logical sessions (cwd, env, background shells, permission overlay). |

### Tunneled tools (v1)

`Read`, `Write`, `Edit`, `Glob`, `Grep`, `Bash`, `BashOutput`, `KillShell` — implemented natively with **byte-exact Claude Code semantics** (identical output formats and failure-mode strings), so the model's recovery behavior transfers unchanged. Use the exact input schemas you use natively; call `describe` if unsure. Unknown tool names return `{"error": "unknown_tool", "supported": [...]}`.

## Quick start

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
| `--permission-mode` | `default` | `default` \| `acceptEdits` \| `bypassPermissions`. |
| `--audit-log` | *(disabled)* | Append-only JSONL audit log path. |
| `--metrics-addr` | *(disabled)* | Serve Prometheus `/metrics` on this address. |
| `--token` / `--token-file` | `$BOXEL_TOKEN` | Static bearer token for HTTP (testing; front with OAuth for production). |
| `--owner-email` | *(none)* | Pin to one owner via the exe.dev edge: require the `X-ExeDev-Email` header to equal this address. Composes with `--token`. See [`docs/deployment.md`](docs/deployment.md). |
| `--session-ttl` | `24h` | Idle-session GC TTL (`0` disables). |
| `--hub-agent-owner-email` | *(none)* | Enable the **pull-mode hub** (see below) with exe.dev identity registration: tokenless, names bound to the platform-verified caller VM. |
| `--hub-agent-token` / `--hub-agent-token-file` | `$BOXEL_HUB_AGENT_TOKEN` | Enable the pull-mode hub with token registration (non-exe.dev deployments; composes with the above). |
| `--hub-agent-listen` | *(disabled)* | Extra listener serving only the agent registration endpoint. |
| `--hub-advertise-url` | *(reflection discovery / fetch URL)* | Base URL agents dial; embedded in the `/install-agent` script. |

For HTTP, at least one of `--token` / `--owner-email` must be set — the server refuses to listen unauthenticated.

## Pull mode: one hub, many non-routable VMs

A routable boxel instance can act as a **multiplexer** for boxel instances on
VMs with no reachable inbound port. A small agent on each VM dials *out* to
the hub, registers under its short hostname over a reverse HTTP/2 channel, and
the hub proxies the whole `/vm/<name>/` base path to it — so the MCP endpoint
for VM `foobar` becomes `https://<hub>/vm/foobar/mcp`, behind the hub's own
auth (one connector origin, one credential, whole fleet).

On exe.dev this is fully tokenless: agents reach the hub through a **peer
integration** (`boxel-hub.int.exe.xyz`), the hub authorizes registrations by
the edge-injected owner identity, agent names are bound to the
platform-verified `X-Exedev-Source-Vm` header, and agents autodiscover the
hub via the `reflection` integration.

```sh
# hub VM: add to an existing HTTP deployment
tunnel-mcp --http 127.0.0.1:8080 ... --hub-agent-owner-email you@example.com

# once: create the fleet's peer integration, attached by tag
ssh exe.dev integrations add http-proxy --name boxel-hub \
  --target https://<hub-vm>.exe.xyz/ --peer --attach tag:boxel

# each fleet VM: tag it, then install the agent
ssh exe.dev tag <vm> boxel
curl -fsSL http://boxel-hub.int.exe.xyz/install-agent | sudo bash
```

The installer builds `cmd/boxel-agent` with `go install` and registers a
systemd unit. Non-exe.dev deployments use `--hub-agent-token` instead. See
[`docs/pull-mode.md`](docs/pull-mode.md).

## Permissions

Rules use Claude Code's `settings.json` format. Precedence is **deny > ask > allow**, then mode defaults. See [`examples/permissions.json`](examples/permissions.json).

- `Bash(git status:*)` — prefix form: commands starting `git status`.
- `Bash(rm *)` — glob form: `*` spans any characters including spaces.
- `Edit(/home/agent/work/**)` — doublestar glob over the resolved absolute path.
- `Read(**)` — any path (still subject to the jail + credential hard denies).

**Modes:** `default` asks on any unmatched mutating call; `acceptEdits` auto-approves `Write`/`Edit` inside the jail; `bypassPermissions` is audit-only and **server-flag only, never client-selectable**.

**Ask path:** an "ask" decision issues an [MCP elicitation](https://modelcontextprotocol.io/) — `allow once` / `allow always` / `deny`. "Allow always" appends a rule to a **session-scoped overlay**, never the persistent file.

**Hard denies (always, even in `bypassPermissions`):**
- Paths outside the workspace jail.
- Credential files — `~/.ssh/**`, `~/.aws/**`, `~/.config/gcloud/**`, `~/.gnupg/**`, `~/.kube/**`, `~/.docker/config.json`, `~/.netrc`, `~/.git-credentials`, `/etc/shadow`, `/etc/sudoers`, and anything under a `.ssh/` directory — unless an explicit (non-catch-all) allow rule matches.

## Security model

The generic `invoke` op is, by construction, an **authenticated RCE endpoint** — treat the whole design as "authenticated RCE with policy," not a typed API. **Authentication is the primary boundary; the permission engine is defense-in-depth and UX.** Deploy accordingly:

- Front the HTTP transport with a TLS-terminating tunnel and OAuth. The built-in bearer token is a second factor and a local-testing convenience, not the production auth story.
- Run the server as a dedicated **unprivileged** user, with the workspace on its own path and OS-level isolation (systemd sandboxing / bubblewrap / landlock).
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
| `internal/hub` | Pull-mode multiplexer: agent registry, reverse HTTP/2 registration, `/vm/<name>/` proxy, installer script. |
| `internal/hubagent` | Pull-mode agent runtime: dial-out, reconnect, forwarding to the local instance. |
| `cmd/tunnel-mcp` | Binary: stdio + streamable HTTP transports, bearer auth, hub mode, flags. |
| `cmd/boxel-agent` | Pull-mode agent binary for non-routable VMs. |
