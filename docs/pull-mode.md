# Pull mode: multiplexing many VMs behind one hub

Pull mode turns one routable boxel instance — the **hub** — into a multiplexer
for boxel instances on VMs that expose **no inbound HTTP port** (e.g. the VM's
forwarded port is taken by the workload you're actually developing). Agents
dial *out* to the hub and register under their short hostname; the hub then
proxies `/vm/<name>/…` to them:

```
Claude connector ── https://boxel.exe.xyz/mcp          (fleet dispatcher)
                 ── https://boxel.exe.xyz/vm/foobar/mcp (per-VM proxy)
                          │
                 ┌────────▼─────────┐    exe.dev edge (TLS + SSO) → hub VM
                 │  tunnel-mcp hub  │
                 │  /mcp            ── fleet dispatcher: pick a VM per call or
                 │                     session; default "local" = own sandbox
                 │  /                ── dashboard (agents, status, traffic)
                 │  /vm/{name}/…    ── proxied to agent "name"
                 │  /agents         ── registry (JSON)
                 │  /install-agent  ── curl|bash installer
                 │  /hub/connect    ── agent registration (reverse channel)
                 └────────▲─────────┘
                          │ exe.dev peer integration (boxel.int.exe.xyz)
                          │ — authenticated, outbound-only
                 ┌────────┴─────────┐
                 │    tunnel-mcp    │  VM "foobar" (no exposed port needed)
                 │  --hub-connect   │  single process: serves its own MCP
                 │                  │  in-process over the reverse channel
                 └──────────────────┘
```

Because a single hub hostname fronts every VM, one Claude MCP connector origin
— and one auth cookie / bearer token, since both are bound to the hostname —
covers the whole fleet. The **entire base path** `/vm/<name>/` is proxied, not
just `/mcp`, leaving room to expose more per-VM APIs later.

The hub root (`/`) serves a small auto-refreshing HTML dashboard listing every
agent that has registered since the hub started — whether it is currently
connected, since when, and how many messages the mux proxied to it. The same
data is available as JSON at `/agents`. Both endpoints sit behind the hub's
client auth.

Each in-process agent serves a dashboard of its own on `GET /`, rendered at
`/vm/<name>/` through the hub: the agent's name and version, a link back to
the hub it is connected to (kept current across autodiscovery), and its MCP
endpoint. Forward mode deliberately does **not** claim `/` — it may front an
arbitrary app — so its self-served diagnostic lives at
`/vm/<name>/__boxel-agent` instead.

## Two ways to serve the agent side

The diagram shows the default shape — the one the hub's `/install-agent`
script sets up: a **single** `tunnel-mcp --hub-connect` process dials the hub
and serves its **own MCP mux in-process** over the reverse channel. No local
port, no separate `boxel-agent` process, no local-token injection, and no
"nothing listening on 8080 → 502" failure mode:

```sh
tunnel-mcp \
  --workspace /home/agent/work \
  --hub-connect                 # dial out; no --http, no local listener
  # --hub-url / --hub-name / --hub-token optional; defaults = autodiscover + hostname
```

The alternative is the **forward** mode: a standalone `boxel-agent` process
dials the hub and forwards proxied requests over loopback to a *separate*
local HTTP server (`127.0.0.1:8080`). That server can be a `tunnel-mcp`
instance **or any HTTP app** — the agent is content-agnostic, so the same
binary can expose a web app, a notebook, whatever is on that port.

`--hub-connect` also composes with `--http` if a VM wants *both* a direct
listener and a hub registration. Pick `--hub-connect` for the common "expose
this VM's MCP through the hub" case; pick forward mode (`boxel-agent`) to
front an arbitrary local app. Either way the hub is the auth boundary — it
guards `/vm/<name>/` with its client auth, so the in-process `/mcp` needs no
second credential.

## How the reverse channel works

The agent sends `GET /hub/connect` with `Upgrade: boxel-h2c`, gets back a
`101 Switching Protocols`, and the roles flip: the hub becomes an HTTP/2
*client* on the agent-initiated connection and the agent an HTTP/2 *server*.
Proxied requests are multiplexed as h2 streams (so concurrent requests,
request bodies, and SSE responses all work), the hub health-checks the channel
with h2 PINGs every 30s, and the agent reconnects with exponential backoff. A
re-registration under the same name atomically replaces the previous channel,
so an agent restart never needs hub-side cleanup.

Selecting the VM at the MCP *transport* layer was considered and rejected:
the streamable-HTTP session id is server-assigned and `initialize` carries no
client-choosable configuration, so a connector's only degree of freedom is
the URL — which is exactly the `/vm/<name>/mcp` scheme, and it keeps URL
routing, auth, and future non-MCP APIs for free. The single-endpoint
experience lives one layer up instead: the **fleet dispatcher** (next
section) terminates MCP on the hub's own `/mcp` and makes the VM part of the
*tool* semantics, which works because every VM advertises the identical
generic surface.

## Fleet dispatcher: one endpoint, VM chosen at the tool layer

With the hub enabled, the hub's `/mcp` serves the **fleet dispatcher**
instead of the plain local server: the same generic surface (`invoke` /
`describe` / `session`), extended with an optional `"vm"` argument naming
the target sandbox. One connector registration — one URL, one credential —
covers the whole fleet, and the model picks the VM at runtime:

- `describe` (no arguments) reports the fleet: every registered VM with its
  connection state, plus `"local"` — the hub's own sandbox and the default
  target, so a client that never mentions `vm` gets exactly the
  pre-dispatcher behavior.
- `session {"action": "create", "session": "job", "vm": "foobar"}` binds the
  logical session to a VM; subsequent `invoke` calls carrying
  `"session": "job"` route there with no per-call `vm`. Creating again with
  a different `vm` rebinds, and `session` list (no `vm`) includes the
  binding table. Bindings are pruned on the same idle TTL as tunnel
  sessions (`--session-ttl`).
- An explicit `"vm"` on `invoke` overrides the binding for that call only.
- Forwarding rides the same reverse HTTP/2 channels as the `/vm/<name>/`
  proxy: the dispatcher keeps one MCP client session per agent, dialed
  lazily against the agent's in-process `/mcp`, and re-dials automatically
  when the agent's channel is replaced (restart / reconnect).
- Failures surface as structured tool errors mirroring the proxy's 502
  bodies — `vm_not_connected` (no such agent registered) and
  `vm_unreachable` (channel or call failure) — so the model can react.

`invoke` results pass through byte-exact; the dispatcher never annotates
tool output (only `describe`/`session` responses gain `vm`/`fleet`/
`bindings` keys). One caveat: elicitation ("ask" permission prompts) does
not relay through the dispatcher — moot in practice, since fleet agents
default to `bypassPermissions`. The `/vm/<name>/mcp` proxy remains available
unchanged as the direct-addressing fallback, behind the same credential.

## exe.dev setup (recommended): zero tokens

On exe.dev, VMs are isolated — there is no private network between them. The
supported VM-to-VM mechanism is a **peer integration**: an exe.dev-managed
proxy at `http://<name>.int.exe.xyz/` that authenticates the calling VM to
the target VM's edge with a platform-injected API key, and stamps the
**verified caller VM name** in `X-Exedev-Source-Vm` (set, not appended, by
the platform — a source VM cannot forge it).

That gives pull mode everything it needs with no shared secret at all:

**1. On the hub VM**, enable identity-based registration:

```sh
tunnel-mcp \
  --http 127.0.0.1:8080 \
  --workspace /home/agent/work \
  --owner-email you@example.com \
  --hub-agent-owner-email you@example.com
```

A registration is accepted when the exe.dev edge authenticated the request as
you (`X-ExeDev-Email`), which for agents happens automatically via the peer
integration's injected key. The agent's handle is taken from
`X-Exedev-Source-Vm`, so a workload can only ever register as the VM it runs
on — no self-asserted names, no token to leak or rotate.

**2. Create the peer integration** pointing at the hub, attached by tag (this
is the fleet-membership switch):

```sh
ssh exe.dev integrations add http-proxy --name boxel \
  --target https://<hub-vm>.exe.xyz/ --peer --attach tag:boxel
```

**3. On each VM you want in the fleet:**

```sh
ssh exe.dev tag <vm> boxel        # attaches the boxel integration
# then, on the VM:
curl -fsSL http://boxel.int.exe.xyz/install-agent | sudo bash
```

The agent **autodiscovers the hub**: every exe.dev VM has the default
`reflection` integration, and the agent queries
`https://reflection.int.exe.xyz/integrations` for an attached http-proxy
integration named `boxel` (override with `--hub-integration` /
`BOXEL_HUB_INTEGRATION`) and dials it. Discovery re-runs on every reconnect
attempt, so tagging a VM after the agent is installed also works.

The VM is then live at `https://<hub-vm>.exe.xyz/vm/<name>/mcp`, behind the
hub's own client auth.

> The reverse channel rides an HTTP/1.1 `Upgrade` through two exe.dev proxy
> hops (the source-side peer integration and the hub's edge). If registration
> fails with the channel dropping right after the 101, an intermediary is not
> passing the upgrade through — that would be a bug worth reporting to the
> exe.dev folks.

## Generic setup: registration token

Outside exe.dev (or composing with it — both methods can be enabled, either
accepts a registration), use a shared registration token:

```sh
openssl rand -hex 32 | sudo tee /etc/tunnel-mcp/agent-token >/dev/null
tunnel-mcp --http 127.0.0.1:8080 ... \
  --hub-agent-token-file /etc/tunnel-mcp/agent-token \
  --hub-agent-listen :8081 \
  --hub-advertise-url http://<hub-internal-dns>:8081
```

| Flag | Meaning |
|---|---|
| `--hub-agent-owner-email` | Enables the hub with exe.dev identity registration (see above). |
| `--hub-agent-token(-file)` / `$BOXEL_HUB_AGENT_TOKEN` | Enables the hub with token registration. |
| `--hub-agent-listen` | Extra listener serving *only* `/hub/connect` (+`/healthz`), for networks where agents can reach the hub directly off-edge. `/hub/connect` is also on the main mux. |
| `--hub-advertise-url` | URL agents should dial, embedded in the installer. Unset with identity registration = agents autodiscover via reflection. |

With token registration, any token holder can register under any name —
including an existing one, receiving that VM's proxied traffic (and the
client's hub credentials). Treat the token like the hub bearer token. Identity
registration doesn't have this problem: names are platform-verified.

## Installing an agent

```sh
# on a fleet VM (needs a Go toolchain ≥ 1.25 and systemd):
curl -fsSL http://boxel.int.exe.xyz/install-agent | sudo bash       # exe.dev
curl -fsSL https://<hub>/install-agent | sudo bash                  # generic
```

The hub-served script installs the **single-process** agent:

1. builds `tunnel-mcp` with `go install` into `/usr/local/bin`;
2. creates a `boxel-agent` system user, `/etc/boxel-agent/env`, and a jailed
   workspace (default `/var/lib/boxel-agent/work`, override with
   `BOXEL_WORKSPACE`);
3. installs and starts a systemd unit (`boxel-agent.service`) running
   `tunnel-mcp --hub-connect --workspace <workspace>`: **one** process that
   dials the hub and serves this VM's MCP in-process — no local port, no
   separate forwarder. The unit deliberately has **no systemd sandboxing**
   and the agent defaults to **`bypassPermissions`**: the VM itself is the
   sandbox, and permission asks would stall on MCP clients without
   elicitation support (pass `--permission-mode` explicitly to opt back
   into prompting);
4. installs a self-update pair (`boxel-agent-update.service` +
   `boxel-agent-update.timer`): every 5 minutes the timer rebuilds
   `tunnel-mcp@latest` and, when the binary actually changes, atomically
   replaces `/usr/local/bin/tunnel-mcp` and restarts the service (source
   builds — non-release versions — are never clobbered, and a deliberately
   stopped service is not restarted);
5. succeeds even when the hub is not reachable yet: the service
   autodiscovers and retries forever, and the script prints the exact
   `integrations add` / `tag` commands that remain for the account owner.

Secrets policy: the hub embeds the registration token in the script **only**
when the installer request itself carried the hub's client credentials; in
identity mode there is no token at all, so any copy of the script is safe.
Everything is overridable at install time via `BOXEL_HUB_URL`,
`BOXEL_HUB_INTEGRATION`, `BOXEL_AGENT_TOKEN`, `BOXEL_AGENT_NAME`,
`BOXEL_WORKSPACE`.

### Forward mode: `boxel-agent setup`

To front an arbitrary local HTTP server instead, install the standalone
forwarder — a hub-independent bootstrap that works even before the peer
integration exists:

```sh
GOBIN=/usr/local/bin go install github.com/mkmik/boxel/cmd/boxel-agent@latest
sudo /usr/local/bin/boxel-agent setup
```

`boxel-agent setup`:

1. copies the binary to `/usr/local/bin/boxel-agent`;
2. creates a `boxel-agent` system user and `/etc/boxel-agent/env`;
3. if `/etc/tunnel-mcp/token` exists, copies it so forwarded requests
   authenticate to the local boxel instance automatically;
4. installs and starts a systemd unit (`boxel-agent.service`; like the
   hub-served installer, deliberately not systemd-sandboxed — the VM is the
   sandbox);
5. installs a self-update pair (`boxel-agent-update.service` +
   `boxel-agent-update.timer`): every 5 minutes the timer runs
   `boxel-agent update`, which asks the Go module proxy for the latest
   release and, when it is newer than the installed binary, rebuilds with
   `go install`, atomically replaces `/usr/local/bin/boxel-agent`, and
   restarts the service (source builds — non-semver versions — are never
   clobbered, and a deliberately stopped service is not restarted);
6. reports hub reachability — and here is the unattended-install contract:
   if the hub cannot be reached yet (peer integration not created or the VM
   not tagged), setup still **exits 0** and prints an `ACTION REQUIRED`
   block with the exact `integrations add` / `tag` commands for the account
   owner, plus explicit guidance for coding agents (the install succeeded;
   don't retry or roll back; poll `journalctl -u boxel-agent` for
   "registered with hub"). The service retries discovery every backoff
   cycle — with repeated identical log lines suppressed to one per ~5
   minutes — and connects on its own the moment the integration is
   attached.

Note the two installers share the `boxel-agent.service` /
`boxel-agent-update.*` unit names and `/etc/boxel-agent/env`, so running one
after the other cleanly replaces the previous shape.

Forward-mode install-time overrides: `BOXEL_AGENT_TARGET` (the local URL to
forward to, default `http://127.0.0.1:8080`) plus the same hub/token/name
variables as above.

## Running the agent by hand

```sh
boxel-agent                      # exe.dev: discovers the boxel integration via reflection
boxel-agent --hub http://boxel.int.exe.xyz              # explicit hub URL
boxel-agent --hub https://hub.example.com --token-file /etc/boxel-agent/token \
  --name foobar --target http://127.0.0.1:8080 \
  --target-token-file /etc/tunnel-mcp/token             # generic deployment
```

Every flag has an env fallback (`BOXEL_HUB_URL`, `BOXEL_HUB_INTEGRATION`,
`BOXEL_REFLECTION_URL`, `BOXEL_AGENT_TOKEN[_FILE]`, `BOXEL_AGENT_NAME`,
`BOXEL_AGENT_TARGET`, `BOXEL_AGENT_TARGET_TOKEN[_FILE]`), which is how the
systemd unit configures it.

`--target-token` deserves a note: the hub forwards the *client's* headers
(including `Authorization` for the hub and `X-ExeDev-Email` injected by the
edge), but the boxel instance on the agent VM has its own bearer token. When
set, the agent swaps in that local token, so the remote instance needs **no
auth changes at all** — its token never leaves the VM, and the client never
learns it.

## Auth model, summarized

| Hop | Guarded by |
|---|---|
| Claude → hub `/vm/<name>/…` | hub's `--token` / `--owner-email` (same as `/mcp`) |
| agent → hub `/hub/connect` | exe.dev identity (`--hub-agent-owner-email`, name bound to `X-Exedev-Source-Vm`) and/or `--hub-agent-token` |
| agent → local boxel | local `BOXEL_TOKEN`, injected by the agent |

As with `--owner-email`, identity headers are trustworthy only because the
exe.dev edge overwrites them — bind the hub's `--http` to `127.0.0.1` so the
edge is the only path in.

## Use case walkthrough

The motivating scenario: you develop an HTTP service on VM `foobar`, and want
exe.dev's edge to forward `foobar.exe.xyz` to *that service* — while still
driving the VM through boxel from a Claude connector.

1. `ssh exe.dev tag foobar boxel`, then on the VM:
   `curl -fsSL http://boxel.int.exe.xyz/install-agent | sudo bash` — this
   starts a single `tunnel-mcp --hub-connect` process serving boxel's MCP
   over the reverse channel (no local port at all).
2. Point the Claude connector at `https://<hub-vm>.exe.xyz/vm/foobar/mcp` with
   the hub's credentials.
3. `ssh exe.dev share port foobar <your-app-port>` — the VM's public hostname
   now belongs entirely to your app; boxel traffic rides the hub.

## Limitations

- WebSocket upgrades do not traverse the h2 channel (SSE — which MCP
  streamable HTTP uses — works fine).
- The registry is in-memory: a hub restart drops registrations, and agents
  re-register on their next reconnect attempt (≤30s backoff).
- `/hub/connect` requires a hijackable HTTP/1.1 listener and intermediaries
  that pass the `Upgrade` through.
