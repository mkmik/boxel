# Deploying tunnel-mcp

The v1 recommendation (PRD §7) is to run the server **on the sandbox VM itself**, exposed through a TLS tunnel with **no inbound ports**. This document walks through a co-located deployment on a Linux VM using systemd + Cloudflare Tunnel.

## 1. User and workspace

Run the server as a dedicated **unprivileged** user whose home *is* the jailed workspace. The permission engine denies filesystem access outside `--workspace`, but OS-level isolation is the real boundary.

```sh
sudo useradd --create-home --home-dir /home/agent --shell /usr/sbin/nologin agent
sudo -u agent mkdir -p /home/agent/work
```

Install ripgrep (required for `Grep`) and the binary:

```sh
sudo apt-get install -y ripgrep          # or: dnf install ripgrep
go build -o /usr/local/bin/tunnel-mcp ./cmd/tunnel-mcp
```

## 2. Configuration

Place a permission policy and a bearer token where only `agent` can read them:

```sh
sudo install -d -o agent -g agent -m 750 /etc/tunnel-mcp
sudo install -o agent -g agent -m 640 examples/permissions.json /etc/tunnel-mcp/permissions.json
openssl rand -hex 32 | sudo -u agent tee /etc/tunnel-mcp/token >/dev/null
sudo chmod 600 /etc/tunnel-mcp/token
sudo install -d -o agent -g agent -m 750 /var/log/tunnel-mcp
```

## 3. systemd unit

`/etc/systemd/system/tunnel-mcp.service`:

```ini
[Unit]
Description=Tunnel MCP sandbox server
After=network-online.target
Wants=network-online.target

[Service]
User=agent
Group=agent
ExecStart=/usr/local/bin/tunnel-mcp \
  --http 127.0.0.1:8080 \
  --workspace /home/agent/work \
  --permissions /etc/tunnel-mcp/permissions.json \
  --permission-mode default \
  --token-file /etc/tunnel-mcp/token \
  --audit-log /var/log/tunnel-mcp/audit.jsonl \
  --metrics-addr 127.0.0.1:9090
Restart=on-failure
RestartSec=2

# OS-level sandboxing (defense in depth beyond the permission engine).
ProtectSystem=strict
ReadWritePaths=/home/agent/work /var/log/tunnel-mcp
ProtectHome=tmpfs
BindReadOnlyPaths=/etc/tunnel-mcp
PrivateTmp=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

Note the server binds `127.0.0.1` only — it is never directly reachable from the network. The tunnel (next step) is the sole public entry point.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now tunnel-mcp
curl -s http://127.0.0.1:8080/healthz    # → ok
```

## 4. Public exposure via Cloudflare Tunnel

The phone app's custom connector needs a publicly reachable HTTPS endpoint. Cloudflare Tunnel (`cloudflared`) gives a stable hostname with TLS handled and no inbound ports.

```sh
cloudflared tunnel login
cloudflared tunnel create tunnel-mcp
```

`~/.cloudflared/config.yml`:

```yaml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
ingress:
  - hostname: sandbox.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

```sh
cloudflared tunnel route dns tunnel-mcp sandbox.example.com
sudo cloudflared service install
```

Optionally front it with **Cloudflare Access** for a second, identity-aware auth layer, and/or **Tailscale Funnel** if a tailnet already exists.

### Connecting a Claude surface

- **Phone / desktop connector:** add a custom MCP connector pointing at `https://sandbox.example.com/mcp`, sending `Authorization: Bearer <token>`. For production, put OAuth in front (Cloudflare Access, or an OAuth 2.1 provider) — the static token is a defense-in-depth second factor, not the primary boundary.
- **Local CLI over stdio:** skip the tunnel entirely and run the binary directly:
  ```sh
  claude mcp add tunnel -- /usr/local/bin/tunnel-mcp --workspace /home/agent/work --permissions /etc/tunnel-mcp/permissions.json
  ```

## 4b. Deploying on an exe.dev VM

An [exe.dev](https://exe.dev) box already provides the "VM behind a TLS tunnel" shape, so you can skip Cloudflare entirely. The exe.dev edge at `https://<vm>.exe.xyz/` terminates TLS and forwards to a port on the VM, and — critically — it is an **identity gate**:

- **Private by default:** only users with access to the VM can reach the proxy; a first request is redirected to log into exe.dev (OIDC). `ssh exe.dev share set-public <vm>` opens it to the internet; `set-private` reverts.
- On authenticated requests, the edge injects `X-ExeDev-UserID` and `X-ExeDev-Email` headers (overwriting any client-supplied copy). This holds on **public** VMs too: logged-in visitors still get the headers; anonymous requests simply arrive without them, and an app can bounce a browser through `/__exe.dev/login?redirect=<path>` to force a login.
- The forwarded port defaults to the lowest `EXPOSE`d TCP port; set it explicitly with `ssh exe.dev share port <vm> 8080`.

### Model A — edge identity is the auth boundary (best for desktop / browser MCP)

Keep the VM **private** and let exe.dev SSO gate the edge; tunnel-mcp pins to your address via the injected header. No bearer token to manage.

```sh
tunnel-mcp \
  --http 127.0.0.1:8080 \
  --workspace /home/agent/work \
  --permissions /etc/tunnel-mcp/permissions.json \
  --owner-email you@example.com          # require X-ExeDev-Email == this
ssh exe.dev share port <vm> 8080
```

`--owner-email` makes `/mcp` require the exe.dev identity header to equal your address: a missing header is `401` (the request didn't come through the authenticating edge), a different authenticated user is `403`. API clients get those as plain-text errors; a browser navigation (e.g. revisiting the hub dashboard after signing out) instead gets an HTML page with a **Sign in** button through the platform login bounce (`/__exe.dev/login?redirect=…`), which returns to the same URL with identity attached — or, when signed in as the wrong account, a sign-out button to switch.

**Safety rule:** bind `--http` to `127.0.0.1` so the exe.dev edge is the *only* path to tunnel-mcp. The header is trustworthy only because the edge overwrites it; if the process were reachable directly, a client could spoof `X-ExeDev-Email`. On a `set-public` VM the edge still injects identity for logged-in users (and strips it from anonymous requests), so `--owner-email` fails closed there too — but keeping the VM private, or adding `--token`, stays the safer posture for a browser-only deployment.

### Model B — bearer token is the boundary (needed for the phone app)

The phone app's remote-MCP connector is a programmatic client sending `Authorization: Bearer …`; it can't complete the edge's interactive browser login. Two options:

1. Keep the VM private and put exe's programmatic OIDC proxy, [`exe-oidc-proxy`](https://pkg.go.dev/github.com/boldsoftware/exe-oidc-proxy), in front of tunnel-mcp.
2. `ssh exe.dev share set-public <vm>` and let tunnel-mcp's `--token` be the gate:

```sh
tunnel-mcp --http 127.0.0.1:8080 --workspace /home/agent/work \
  --permissions /etc/tunnel-mcp/permissions.json --token-file /etc/tunnel-mcp/token
```

### Model C — the built-in OIDC IDP is the boundary (real OAuth for MCP connectors)

Claude's remote-MCP connectors do full OAuth: authorization-server discovery (RFC 9728/8414), dynamic client registration (RFC 7591), the code flow with PKCE, refresh tokens. Nothing hosted by exe.dev provides that today — the platform's `https://exe.dev/.well-known/openid-configuration` is a workload-identity token stub (no authorize/token endpoints), and Bold's [`exe-oidc-proxy`](https://github.com/boldsoftware/exe-oidc-proxy) is a single-static-client OIDC shim without PKCE or dynamic registration. So tunnel-mcp ships the missing piece in-process: a minimal OAuth 2.1 / OIDC provider that converts the edge's `X-ExeDev-Email` into signed tokens, and `/mcp` accepts them. It **auto-enables** whenever `--owner-email` is the sole configured auth (issuer `https://<hostname>.exe.xyz`, allowlist `--owner-email`, key persisted at `~/.config/boxel/idp-key.pem`), so an existing Model A deployment needs **no flag changes** — update the binary, then make the VM public. `--idp-issuer` overrides the derived issuer (or `none` disables); auto-enable is skipped when a `--token` is configured, because OAuth-as-alternative would weaken the token+identity pair to identity alone. One process, one **public** VM:

```sh
tunnel-mcp --http 127.0.0.1:8080 \
  --workspace /home/agent/work --permissions /etc/tunnel-mcp/permissions.json \
  --owner-email you@example.com          # IDP auto-enables from this
ssh exe.dev share port <vm> 8080
ssh exe.dev share set-public <vm>
```

This composes with the pull-mode hub (add the `--hub-agent-*` flags to the same process): the auth guard covers `/vm/<name>/mcp` too, so one OAuth connector credential reaches the whole fleet through the hub origin. The guard is default-deny — only the OAuth discovery/flow endpoints, `/healthz`, and the hub's self-authenticating registration/installer endpoints bypass it — so the dashboard and `/agents` stay behind auth on the public VM; keeping `--owner-email` (as above) lets your logged-in browser reach them via the still-injected edge identity while connectors use OAuth tokens.

Why **public**? The OAuth client's *backend* (e.g. Claude's servers) fetches the metadata, registers, and redeems codes at `/idp/token` with no exe.dev session — a private VM's edge would answer those with a login redirect. The design stays safe because those endpoints hand out nothing by themselves: every authorization code is minted only by `/idp/authorize`, which requires the edge-injected identity header (anonymous browsers are bounced through `/__exe.dev/login`), enforces the `--idp-users` allowlist, and shows a consent page. Codes are single-use and PKCE-bound; access tokens are short-lived ES256 JWTs carrying the resource audience; refresh tokens and client registrations are stateless signatures under `--idp-key-file`, so restarts don't strand connectors.

### Recommended: compose layers

`--token` and `--owner-email` compose — supply both and a request must satisfy *both* the bearer check and the owner-identity check (bearer is checked first). Keeping the VM private (edge SSO) *and* requiring the bearer *and* pinning the owner means two independent failures are needed before any tool runs. `--idp-issuer` OAuth tokens are an *alternative* satisfying method alongside the static pair, for clients that authenticate with OAuth instead.

> Pick by client: a browser/desktop surface that can complete edge SSO → Model A (keep the VM private). A programmatic client with a pre-shared secret → Model B. An OAuth-capable MCP connector (Claude phone/web custom connectors) → Model C.

## 5. Egress hardening (recommended)

Bound exfiltration if a prompt-injected session goes rogue: deny-by-default egress for the `agent` UID, allowlisting only package registries and GitHub.

```sh
# nftables sketch — allow DNS + HTTPS to specific CIDRs, drop the rest, per-UID.
sudo nft add table inet tunnel
sudo nft add chain inet tunnel out '{ type filter hook output priority 0; }'
sudo nft add rule inet tunnel out meta skuid agent tcp dport 443 ip daddr @allowlist accept
sudo nft add rule inet tunnel out meta skuid agent udp dport 53 accept
sudo nft add rule inet tunnel out meta skuid agent drop
```

## 6. Observability

- **Audit log** — `/var/log/tunnel-mcp/audit.jsonl`, one JSON object per invocation: timestamp, session, tool, input digest, permission decision + rule, mode, exit status, duration. File contents are never logged; sensitive Bash command lines are redacted.
  ```sh
  tail -f /var/log/tunnel-mcp/audit.jsonl | jq .
  ```
- **Metrics** — `http://127.0.0.1:9090/metrics`: `boxel_invocations_total{tool,decision}`, `boxel_tool_duration_seconds`, `boxel_active_shells`, `boxel_active_sessions`, `boxel_elicitation_duration_seconds`. Scrape locally or over the tunnel; keep it off the public ingress.

## Topology note (v2)

For dynamic fleets, a central hub can now front VMs that expose no inbound port at all: **pull mode**. A per-VM agent dials out to the hub and registers under its hostname, and the hub proxies `https://<hub>/vm/<name>/mcp` to it over a reverse HTTP/2 channel — one connector origin and one credential for the whole fleet. See [`pull-mode.md`](pull-mode.md).
