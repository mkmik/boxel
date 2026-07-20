# PRD — Tunnel MCP

**A generic-operation MCP server that tunnels the Claude Code tool-call protocol to a remote sandbox VM.**

Status: Draft v0.1 · Owner: Marko · Last updated: 2026-07-19

---

## 1. Problem statement

Claude Code (CLI, desktop, and especially the phone app) can only act on the machine it runs on, or through MCP servers that advertise a fixed, typed tool surface. Exposing a sandbox VM through conventional MCP means either:

- a single `run_bash` tool — coarse, hard to filter, loses edit semantics; or
- re-declaring every tool (read, write, edit, glob, grep, bash…) as typed MCP tools — verbose, drifts from Claude Code's native schemas, and bloats the client's tool listing.

The model already knows the Claude Code tool protocol natively. We can exploit that: advertise **one generic operation** whose body *is* a Claude Code tool call, and interpret it server-side as if a Claude Code harness were running on the sandbox. The MCP layer becomes a transport tunnel; the semantics live at the far end.

## 2. Goals

1. Let any Claude surface (Claude Code CLI, desktop, **phone app via remote MCP connector**) execute the full Claude Code tool repertoire against a sandbox VM the user owns.
2. Keep the advertised MCP surface minimal: one generic `invoke` tool (plus small helpers).
3. Enforce server-side policy: permission rules compatible with Claude Code's `settings.json` format, permission modes (default / acceptEdits / bypassPermissions), and audit logging.
4. Surface permission prompts to the human through **MCP elicitation**, mirroring the local Claude Code approval UX.
5. Support the full async tool lifecycle: background bash, output polling, kill.

## 3. Non-goals (v1)

- Multi-tenant use by people other than the owner.
- Tunneling MCP-within-MCP (the sandbox harness does not itself call out to further MCP servers).
- Interactive TTY sessions / PTY streaming (bash is non-interactive, as in Claude Code).
- Windows sandbox targets.

## 4. Users & primary scenarios

- **Owner-operator (Marko).** Kicks off work from the phone: "clone repo X on the sandbox, run the tests, fix the failure." Claude drives Read/Edit/Bash on the VM through the tunnel; risky calls trigger an approval prompt on the phone.
- **Desktop Claude Code offloading.** A local session delegates heavy or dirty work (builds, package installs, throwaway experiments) to the sandbox without polluting the laptop.
- **Pairing with shelly VMs (exe-clone).** A freshly created agent VM registers with the tunnel gateway; any Claude surface becomes a thin controller for it.

## 5. Product requirements

### 5.1 Advertised MCP surface

| Tool | Purpose |
|---|---|
| `invoke` | Generic op. Body: `{ "tool": string, "input": object, "session": string? }`. Interpreted as a Claude Code tool call. |
| `describe` | Returns the supported tool names, their expected input schemas, current permission mode, and sandbox metadata (hostname, cwd, OS). Lets the model self-correct instead of guessing. |
| `session` | Create/list/reset logical sessions (working directory, env, background shells). Optional in v1 — a single default session is acceptable. |

The `invoke` description must teach the envelope in one paragraph, e.g.: *"Body is a Claude Code tool call. Supported tools: Bash, BashOutput, KillShell, Read, Write, Edit, Glob, Grep. Use the exact input schemas you use natively. Call `describe` if unsure."*

### 5.2 Supported tunneled tools (v1)

- **Read** — with offset/limit, line-numbered output, image passthrough optional (v2).
- **Write** — full-file write.
- **Edit** — `old_string`/`new_string` exact-match replace, `replace_all` flag; identical failure modes to Claude Code (not found / not unique) so the model's recovery behavior transfers.
- **Glob**, **Grep** — ripgrep-backed, same parameter names.
- **Bash** — cwd persistence per session, timeout param (default 120 s, max 600 s), `run_in_background`.
- **BashOutput** — incremental output by shell ID, includes exit status when finished.
- **KillShell**.

Unknown tool names return a structured error: `{ "error": "unknown_tool", "supported": [...] }`.

### 5.3 Permission engine

- Rule format: Claude Code-compatible — `Bash(git *)`, `Edit(/home/agent/work/**)`, `Read(**)` — loaded from a server-side `permissions.json`; deny > ask > allow precedence.
- Modes: `default` (ask on unmatched), `acceptEdits` (auto-approve Write/Edit within workspace), `bypassPermissions` (audit-only; requires explicit server flag, never client-selectable).
- **Ask path:** on an "ask" decision the server issues an MCP elicitation to the client ("Allow `Bash: rm -rf build/`? [allow once / allow always / deny]"). "Allow always" appends a rule to a session-scoped overlay, not the persistent file.
- Hard denies regardless of rules: paths outside the sandbox jail, credential files (`~/.ssh`, `~/.config/gcloud`, …) unless explicitly allowlisted.

### 5.4 Sessions & state

- A session owns: cwd, env overrides, background shell table (ID → process), permission overlay.
- Sessions are keyed by an opaque ID the client passes; absent → `"default"`.
- Idle sessions GC after a configurable TTL (default 24 h); background shells killed on GC.

### 5.5 Audit & observability

- Append-only JSONL audit log: timestamp, session, tool, input digest, permission decision, exit status, duration.
- Prometheus metrics: invocations by tool/decision, active shells, elicitation latency.
- `describe` exposes a redacted view of the active policy so the model can plan within it.

## 6. Architecture

```
Claude (phone / desktop / CLI)
        │  MCP (streamable HTTP + OAuth)
        ▼
┌──────────────────────────────┐
│  tunnel-mcp server           │
│  ├─ MCP transport layer      │
│  ├─ Envelope parser/validator│
│  ├─ Permission engine ───────┼──► elicitation → user approval
│  ├─ Harness (tool impls)     │
│  └─ Session manager          │
└───────────┬──────────────────┘
            │ local syscalls / exec (co-located)
            │ or gRPC to per-VM agent (gateway topology)
            ▼
      Sandbox VM filesystem + processes
      (unprivileged user, jailed workspace)
```

**Components**

- **Transport:** streamable HTTP (required for the phone app's remote connector path); stdio mode for local testing.
- **Envelope parser:** validates `{tool, input}` against per-tool JSON schemas; schema errors echo the expected shape back to the model.
- **Harness:** direct implementations of the tools (do not shell out for Read/Edit — implement natively for byte-exact semantics).
- **Execution isolation:** tools run as a dedicated unprivileged user; workspace jail via bind-mount + landlock/bubblewrap (or a systemd unit with `ProtectSystem=strict`, `ReadWritePaths=` on the workspace); no capability to escalate.

**Topologies**

1. **Co-located (v1):** server runs on the sandbox VM itself. Simplest; one binary, one systemd unit.
2. **Gateway (v2, shelly integration):** a central gateway terminates MCP/OAuth and forwards envelopes over gRPC/SSH to a thin agent on each VM; `session` gains a `vm` field. This is the natural fit for exe-clone, where VMs are created and destroyed dynamically.

## 7. Where to run it

**v1 recommendation: on the sandbox VM, exposed via a tunnel, no inbound ports.**

- **Host:** the existing sandbox VM (GCE works fine given the current GCP footprint; any Linux box does).
- **Exposure:** the phone app requires a publicly reachable HTTPS endpoint for custom connectors. Two good options:
  - **Cloudflare Tunnel** (`cloudflared`) — stable public hostname, TLS handled, optionally fronted by Cloudflare Access as a second auth layer.
  - **Tailscale Funnel** — if the tailnet already exists; slightly less control over the public hostname.
  - Avoid opening a raw inbound port + self-managed reverse proxy unless there's a reason; the tunnel options remove the attack surface of a listening public IP.
- **Auth:** OAuth 2.1 as required by remote MCP (the server acts as an OAuth provider or delegates to one); additionally pin to a single authorized subject (owner's identity). Static bearer tokens only for local/desktop testing.
- **Why not Cloud Run / serverless:** the server is stateful (background shells, sessions) and needs to *be* the sandbox or hold persistent connections to it; a VM is the right shape.

**v2:** gateway on a small always-on instance (or the shelly host), agents baked into the VM image so every new shelly VM is tunnel-ready at boot.

## 8. Security considerations

- The generic op is by construction an RCE endpoint — treat the whole design as "authenticated RCE with policy," not as a typed API. Auth is the primary boundary; the permission engine is defense in depth and UX, not the security perimeter.
- Deny-by-default egress from the sandbox user (nftables per-UID rules) with an allowlist (package registries, GitHub) to limit exfiltration if a prompt-injected session goes rogue.
- Elicitation responses must be verified server-side as coming from the authenticated user session, not inferred from model output.
- Rate limits: max concurrent bash processes, max output bytes per call (truncate like Claude Code does), max elicitations per minute.
- Secrets hygiene: audit log stores input digests for Bash command lines flagged sensitive; never log file contents.

## 9. Build plan

| Milestone | Scope | Exit criteria |
|---|---|---|
| **M0 — skeleton** | MCP server (stdio + HTTP), `invoke` + `describe`, Read/Glob/Grep read-only | Phone app connector lists the tools; Claude reads a file on the VM end-to-end |
| **M1 — mutation + policy** | Write/Edit, permission engine with rules file, audit log | Edit round-trip with exact Claude Code failure semantics; denied call returns structured refusal |
| **M2 — bash lifecycle** | Bash with cwd/timeout, background shells, BashOutput, KillShell, session manager | Claude runs a build in background from the phone and polls it to completion |
| **M3 — human in the loop** | Elicitation-based approval, session permission overlays, modes | "ask" rule triggers a phone prompt; allow-once vs allow-always behave correctly |
| **M4 — shelly integration** | Gateway topology, per-VM agents, `session.vm`, VM lifecycle hooks | New shelly VM usable through the tunnel within seconds of boot |

**Stack suggestion:** Go with the official `modelcontextprotocol/go-sdk` — single static binary, easy systemd deployment, good fit for the harness/exec work; ripgrep vendored or required as a dependency for Grep.

## 10. Open questions

1. **Schema fidelity vs freezing:** track Claude Code's tool schemas as they evolve, or freeze a v1 envelope and translate? (Leaning: freeze + `describe` as the source of truth.)
2. **Elicitation support on all surfaces:** verify current elicitation behavior in the phone app connector path before making M3 the only approval mechanism; fallback could be a companion approval web page.
3. **File transfer:** should Read/Write support binary/base64 for artifact exchange, or is that out of scope for a code sandbox?
4. **Multi-model callers:** the design leans on Claude knowing its own harness; if other models call it, `describe` + schema errors must carry the full teaching load. Acceptable?
5. **Auto-mode heuristics:** replicate Claude Code's auto-approval heuristics beyond the rule file, or keep the server strictly rule-driven? (Leaning: rule-driven; heuristics belong to the client model.)

## 11. Success metrics

- ≥ 95 % of tunneled tool calls parse and dispatch without a schema-error retry after the first `describe`.
- Median added latency ≤ 150 ms over direct execution (excluding elicitation waits).
- Zero policy-bypass incidents in audit review; every mutation attributable to a session and decision.
- Phone-initiated "clone → test → fix → verify" loop completes without touching a laptop.
