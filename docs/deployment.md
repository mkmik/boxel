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
- On authenticated requests, the edge injects `X-ExeDev-UserID` and `X-ExeDev-Email` headers (overwriting any client-supplied copy).
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

`--owner-email` makes `/mcp` require the exe.dev identity header to equal your address: a missing header is `401` (the request didn't come through the authenticating edge), a different authenticated user is `403`.

**Safety rule:** bind `--http` to `127.0.0.1` so the exe.dev edge is the *only* path to tunnel-mcp. The header is trustworthy only because the edge overwrites it; if the process were reachable directly, a client could spoof `X-ExeDev-Email`. Do **not** rely on `--owner-email` alone once the VM is `set-public` (the edge no longer injects identity there) — add `--token` for that case.

### Model B — bearer token is the boundary (needed for the phone app)

The phone app's remote-MCP connector is a programmatic client sending `Authorization: Bearer …`; it can't complete the edge's interactive browser login. Two options:

1. Keep the VM private and put exe's programmatic OIDC proxy, [`exe-oidc-proxy`](https://pkg.go.dev/github.com/boldsoftware/exe-oidc-proxy), in front of tunnel-mcp.
2. `ssh exe.dev share set-public <vm>` and let tunnel-mcp's `--token` be the gate:

```sh
tunnel-mcp --http 127.0.0.1:8080 --workspace /home/agent/work \
  --permissions /etc/tunnel-mcp/permissions.json --token-file /etc/tunnel-mcp/token
```

### Recommended: both layers

`--token` and `--owner-email` compose — supply both and a request must satisfy *both* the bearer check and the owner-identity check (bearer is checked first). Keeping the VM private (edge SSO) *and* requiring the bearer *and* pinning the owner means two independent failures are needed before any tool runs.

> Verify first whether your Claude surface's MCP connector can authenticate to a **private** exe.dev box (via `exe-oidc-proxy` or an OAuth flow it supports). If yes, keep it private (Model A). If no — as with the phone app today — use `set-public` + bearer (Model B).

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
