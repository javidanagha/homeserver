# homeserver

A security-focused home server built on a repurposed HP ProDesk 400 G2 (i5-4590S, 8 GB RAM, Ubuntu 26.04 LTS).
Everything runs natively under systemd, no containers, so every layer is visible, debuggable and hardened by hand.

It provides network-wide ad/tracker blocking with encrypted upstream DNS, a WAF-protected HTTPS reverse proxy,
file sharing, a database, uptime monitoring, and host-based intrusion detection with Telegram alerting.

## Architecture

```
                  LAN / Tailscale clients
                           │
          ┌────────────────┴────────────────┐
          │ :53 DNS                         │ :443 HTTPS
          ▼                                 ▼
   Pi-hole (blocklists)          Caddy — TLS + Coraza WAF (OWASP CRS)
          │                                 │ 127.0.0.1:8090
          ▼                                 ▼
   dnscrypt-proxy                 nginx (internal router, loopback only)
   127.0.0.1:5053                   ├─ /            lobby page + JSON feeds
          │                         ├─ /admin       Pi-hole UI
          ▼                         ├─ /files/      Filebrowser
   Quad9 (DNSCrypt)                 ├─ /db/         Adminer (PostgreSQL)
                                    ├─ /waf/        WAF dashboard
                                    └─ uptime.*     Uptime Kuma
```

**Detection & alerting**

```
Caddy JSON access log ─► waf-sync.py (30 s) ─► waf.json (dashboard) + PostgreSQL archive
System logs ─► Wazuh manager (analysisd) ─► alerts.json ─► wazuh-telegram.py ─► Telegram (level ≥ 10)
```

## Stack

| Layer | Component | Notes |
|---|---|---|
| DNS filtering | Pi-hole v6 | Network-wide via router DHCP; StevenBlack, HaGeZi Pro/Ultimate/TIF, OISD Big |
| DNS privacy | dnscrypt-proxy → Quad9 | ISP no longer sees plaintext DNS queries |
| Edge / TLS | Caddy 2 (custom build) | Coraza WAF compiled in via `xcaddy`, OWASP CRS embedded |
| Web backend | nginx | Bound to `127.0.0.1` only; real client IP via `X-Forwarded-For` |
| WAF telemetry | `waf-sync.py` | Parses Caddy logs, classifies attacks, archives to PostgreSQL with dedup |
| HIDS | Wazuh manager (no indexer/dashboard) | Rule matching only; alerts pushed to Telegram |
| Files | Samba + Filebrowser | Same share over SMB and HTTPS |
| Database | PostgreSQL + Adminer | `scram-sha-256` auth, least-privilege roles per service |
| Monitoring | Uptime Kuma | Status mirrored to the lobby via a custom sqlite → JSON sync |
| Remote access | Tailscale | No ports exposed to the internet |

## Security posture

- **No inbound internet exposure**: ufw default-deny, services reachable only from the LAN or the tailnet.
- **SSH**: key-only (ed25519, passphrase-protected), fail2ban on `sshd`.
- **TLS everywhere** internally (mkcert CA), terminated at Caddy.
- **WAF in blocking mode**: in a 15-payload test (SQLi, XSS, path traversal, command injection, scanner probes), 11 were blocked, and the rest were 404s or deliberately benign payloads.
- **Least privilege**: dedicated DB role (`INSERT, SELECT` on one table) for the WAF archiver; the Telegram forwarder runs as a system user with read-only group access to alerts.
- **Secrets never in code**: credentials are loaded from `EnvironmentFile=` (mode 600, root-owned) and excluded from this repo.
- **Wazuh API** bound to `127.0.0.1` (the default is all interfaces, with default credentials).
- **Encrypted upstream DNS**; config backups pushed daily to a separate private repo via a repo-scoped deploy key.

## Engineering notes (problems hit and how they were solved)

**ModSecurity → Coraza migration.** The first WAF was ModSecurity 3 built as a dynamic nginx module. Under sustained browser traffic, nginx workers stopped closing client sockets, and `ss -tn` showed 700+ connections stuck in `CLOSE-WAIT` within hours, which caused intermittent site-wide hangs. One-off `curl` tests never reproduced it. Setting `keepalive_timeout 0` did not help. This matches the unresolved upstream issue owasp-modsecurity/ModSecurity#3031. I replaced it the same day with Coraza compiled directly into Caddy, which gives the same CRS ruleset with no C/FFI connector. Under the same traffic there were 0 `CLOSE-WAIT` sockets.

**Telling WAF blocks from upstream 403s.** A failed app login also returns 403. Caddy's `handle_errors 403` only fires for errors raised by Coraza itself, so it tags them with an `X-Waf-Block: true` header, and the telemetry script counts only those.

**Coraza breaks WebSockets.** With Coraza active, Uptime Kuma's socket.io connection cycled between `101 Switching Protocols` and a disconnect every few minutes (corazawaf/coraza-caddy#78). Scoping the WAF with a `not header Upgrade *` matcher was not enough, so the Kuma subdomain is fully excluded from inspection.

**dnscrypt-proxy vs systemd socket activation.** The packaged `.socket` unit hardcodes `127.0.2.1:53`, and the implicit service↔socket link cannot be removed from the service side. The fix was a socket drop-in that clears and resets `ListenStream`/`ListenDatagram` (see `dns/`). Also, `cloudflared proxy-dns` was removed upstream in 2026.2.0, so it is no longer an option.

**Rootcheck false positives on Ubuntu 26.04.** Wazuh flagged `ls`, `cat`, `chmod` and other coreutils as trojaned. Ubuntu now ships Rust `uutils` coreutils, whose binaries contain strings that match Wazuh's legacy generic signatures. I verified the binaries against package checksums (`dpkg --verify rust-coreutils`), then suppressed only those paths with a local rule. Rootcheck stays enabled for everything else.

## Repository layout

```
caddy/      Caddyfile (TLS + Coraza WAF)
nginx/      nginx.conf and site configs (loopback-only backend)
systemd/    service and timer units
scripts/    waf-sync.py, status-sync.sh
web/        lobby page and WAF dashboard (vanilla JS, no innerHTML for untrusted data)
wazuh/      ossec.conf, local_rules.xml, api.yaml
dns/        dnscrypt-proxy config and socket override
```

Configs are sanitized: credentials, keys, certificates and network-specific secrets are intentionally not included.

## Roadmap

- [x] Pi-hole + encrypted upstream DNS
- [x] Caddy + Coraza WAF, dashboard, PostgreSQL archive
- [x] Wazuh manager


