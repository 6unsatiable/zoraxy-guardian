# Guardian

A [Zoraxy](https://github.com/tobychui/zoraxy) plugin that adds an L7 security layer to your reverse-proxy rules: IP allow/block lists, User-Agent blocklists, WAF-style payload pattern matching, and per-IP rate limiting — with per-host scopes so each rule can apply globally or only to specific vhosts.

[![build-and-release](https://github.com/articrevised/zoraxy-guardian/actions/workflows/release.yml/badge.svg)](https://github.com/articrevised/zoraxy-guardian/actions/workflows/release.yml)
[![latest release](https://img.shields.io/github/v/release/articrevised/zoraxy-guardian?include_prereleases&label=rolling)](https://github.com/articrevised/zoraxy-guardian/releases/tag/latest)

---

## Why

Zoraxy ships with a built-in blacklist tied to access rules. Guardian extends that with the pieces a typical reverse proxy in front of public-facing apps needs:

- Per-IP rate limiting with token-bucket bursts
- Regex User-Agent blocking (default-ships scanner UAs: `sqlmap`, `nikto`, `nmap`, `masscan`, `acunetix`, `nessus`)
- WAF-style request inspection (default rules for SQLi, XSS, path traversal, null bytes)
- Allowlist + blocklist with CIDR (IPv4 and IPv6) support
- All four can be scoped to individual hosts via glob patterns

It plugs into Zoraxy's **dynamic capture** API — your proxy rules carry on as normal, and Guardian only intercepts requests it actively wants to block.

---

## Features

| | |
|---|---|
| **IP rules** | Allowlist + blocklist. CIDR (IPv4 + IPv6) and single IPs. |
| **User-Agent blocklist** | Go regex (use `(?i)` for case-insensitive). |
| **WAF rules** | Go regex over URI, full URL, Cookie, Referer. 7 default rules. |
| **Rate limit** | Per-IP token bucket with automatic idle bucket eviction. |
| **Honeypot paths** | Any request to a tripwire URL (e.g. `/.env`, `/wp-login.php`) installs a temp ban on the source IP. |
| **Host-header blocklist** | Block by regex against the request's `Host` header — useful for rejecting probes that arrive with `Host: localhost` etc. |
| **UA path exceptions** | UA rules can carry an `except_paths` list — e.g. block Googlebot except on `/robots.txt`. |
| **Cloudflare rule import** | Paste a Cloudflare WAF / Custom Rule expression and Guardian translates it into the right primitives. Handles path/query/UA/host predicates with AND/OR/NOT, multi-clause expressions, and the `path ne X and (...)` exemption pattern. |
| **Auto-ban escalation** | After N strikes in a sliding window, the IP gets a temp ban — escalates noisy scanners from per-rule blocks to a wholesale ban. |
| **Per-host scopes** | Each rule has an optional host glob filter — `*.api.test`, `**.example.com`, `*`, or exact. |
| **Live block log** | Last 500 events kept in memory; mirrored to JSONL on disk with fsync; restored on restart; auto-rotates at 5 MiB. Paginated UI with live SSE updates. |
| **Zoraxy event subscription** | Mirrors Zoraxy's own `blacklistedIpBlocked` events into Guardian's log. |
| **XFF awareness** | Respects `X-Forwarded-For`/`X-Real-IP` from Zoraxy by default. Toggle in UI. |
| **Dark mode** | Light / dark theme toggle, persisted in localStorage; defaults to system preference. |
| **No external services** | Single ~6 MB Go binary. Embedded UI. No DB, no Redis. |

---

## Install (Docker bind-mount Zoraxy)

### One-click install through Zoraxy's plugin directory

Add this URL as a custom plugin directory in Zoraxy, then install **Guardian**
from the Plugins page. Zoraxy selects and downloads the correct binary for its
platform automatically:

```
https://raw.githubusercontent.com/6unsatiable/zoraxy-guardian/main/directories/index.json
```

The directory tracks the rolling `latest` release. Restart Zoraxy after an
update if your deployment does not automatically restart plugins.

### Manual / Docker install

The same `update.sh` script also installs from scratch. On the Zoraxy host:

```bash
# One-time: pull the installer
curl -fsSL https://raw.githubusercontent.com/articrevised/zoraxy-guardian/main/update.sh \
  -o /usr/local/bin/guardian-update
chmod +x /usr/local/bin/guardian-update

# Install (replace with the host path bind-mounted to the container's plugins dir)
guardian-update --dir /opt/zoraxy/plugins

# Restart the Zoraxy container
docker restart <zoraxy-container-name>
```

Then in Zoraxy's web UI:

1. **Plugins** → find **Guardian** → click **Enable**.
2. Click the **(i)** info icon to confirm the assigned port + UI path.
3. **HTTP Proxy** → on a rule you want protected, add a tag (e.g. `guardian`).
4. Back to **Plugins** → assign Guardian to that tag.
5. Open Guardian's UI and configure rules.

### Updating

```bash
guardian-update --dir /opt/zoraxy/plugins
docker restart <zoraxy-container-name>
```

`guardian-update` defaults to the rolling `latest` release. Pin to a specific version with `--version v0.2.0`.

### Manual install (non-Docker)

```bash
mkdir -p /path/to/zoraxy/plugins/guardian
curl -fsSL -o /path/to/zoraxy/plugins/guardian/guardian \
  https://github.com/articrevised/zoraxy-guardian/releases/download/latest/linux_amd64_guardian
chmod +x /path/to/zoraxy/plugins/guardian/guardian
sudo systemctl restart zoraxy
```

Choose the asset matching your platform: `linux_amd64`, `linux_arm64`, `linux_arm`, `darwin_amd64`, `darwin_arm64`, `windows_amd64`.

---

## Configuration

Guardian is configured entirely through its web UI (reverse-proxied by Zoraxy at `/plugin.ui/com.guardian.zoraxy/ui/`). State is held in memory and persisted to `config.json` next to the binary on every save.

### Tabs

**IP rules** — Two tables, allowlist and blocklist. Each row is a value (IP or CIDR) plus optional comma-separated host patterns.

- *Allowlist semantics*: If at least one allow rule applies to the current host, **only** IPs matching one of the applicable rules pass through that host. Hosts where no allow rule applies are unaffected.
- *Blocklist semantics*: Any IP/CIDR match denies the request.

**User agents** — Regex blocklist. Default ships common scanner UAs.

**WAF rules** — Toggleable regex rules. Patterns match against `request_uri + " " + url + cookie + referer`. Default rules cover:

| Name | Catches |
|---|---|
| `sqli-union` | `UNION SELECT` injection variants |
| `sqli-comment` | Comment-based SQLi (`--`, `#`, `/*`) combined with `OR`/`AND` |
| `xss-script` | `<script>` tags |
| `xss-javascript-uri` | `javascript:` URIs |
| `xss-onevent` | `onerror=`, `onclick=`, etc. |
| `path-traversal` | `../` and `..\` |
| `null-byte` | `%00` |

**Rate limit** — Per-IP token bucket. Configure requests/minute and burst. Buckets idle for >10 min are swept automatically; the map is hard-capped at 50k entries.

**Honeypot** — A list of "tripwire" URL paths. Any request matching one of them adds the source IP to the temp-ban list for the configured duration. Ships with sensible defaults (`/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin/`, etc.) and is OFF by default — turn it on once you've reviewed the path list.

**Auto-ban** — After an IP triggers any block rule `Threshold` times within `Window` seconds, it gets promoted to the temp-ban list for `Ban duration`. Honeypot hits install temp bans directly without strikes.

**Temp bans** — Live list of IPs currently temp-banned, with their expiry timestamps. Per-row "Clear" button to manually revoke.

**Host block** — Regex blocklist matched against the request's `Host` header. Patterns are evaluated after the IP blocklist and before honeypots. Common use: block scans probing your origin IP with `Host: localhost`, `Host: example.invalid`, etc.

**Import CF** — Paste a Cloudflare expression (e.g. from the CF dashboard) and translate it to Guardian primitives. Click **Preview** to see what would be added; click **Apply & merge** to commit. Supported predicates:

| Cloudflare field | Operator | Translates to |
|---|---|---|
| `http.request.uri.path` | `contains` | Honeypot path |
| `http.request.uri.path` | `matches` | WAF rule |
| `http.request.uri.path` | `ne` *(inside AND)* | UA rule `except_paths` |
| `http.request.uri.query` | `contains` | WAF rule (case-insensitive) |
| `http.user_agent` | `contains`, `matches` | UA blocklist entry |
| `http.host` | `contains`, `eq` | Host blocklist |
| `ip.src` | `in {…}` | IP blocklist |

Anything else (e.g. `cf.threat_score`, `ip.geoip.country`, `ssl`, method/header subfields) is reported as a warning rather than translated.

**General** — Trust-XFF toggle and host pattern reference.

**Block log** — Recent block events with source (`guardian` vs `zoraxy`), reason, status code. Paginated 50 at a time with a free-text filter. New blocks appear live via Server-Sent Events (the green/red dot in the header reflects connection status).

### Host pattern syntax

Used in every rule's `Hosts` column. Empty (or `*`) means apply to all hosts.

| Pattern | Matches |
|---|---|
| `example.com` | exact match only |
| `*.example.com` | one subdomain level (`foo.example.com`, not `a.b.example.com`) |
| `**.example.com` | any subdomain depth |
| `*` | any host |

Matching is case-insensitive; port suffixes (`:8443`) are stripped before matching.

### Rule evaluation order

For each incoming request:

1. **Temp ban** — IP currently in the auto-expiring ban list
2. **IP blocklist** — static CIDR/IP block
3. **Host blocklist** — regex on the `Host` header
4. **Honeypot** — URI matches a tripwire path → installs a temp ban as a side-effect
5. **IP allowlist** — only enforced on hosts where an allow rule applies
6. **User-Agent blocklist** (with optional path exceptions)
7. **WAF rules**
8. **Rate limit**

First match wins. The decision is recorded under the request's UUID; when Zoraxy follows up to deliver the actual request body to Guardian's capture endpoint, Guardian responds with `403` (or `429` for rate-limit) and an `X-Guardian-Reason` header.

Blocks from rules 2 and 5-8 also record a *strike* against the source IP. If the IP accumulates `AutoBan.Threshold` strikes within `AutoBan.WindowSeconds`, it gets promoted to a temp ban.

---

## How it integrates with Zoraxy

```
client ───▶ Zoraxy ───▶ HTTP proxy rule
                │
                │ for each request matching a rule
                │ that has Guardian assigned via a tag:
                ▼
            ┌────────────────────────┐
            │ POST /d_sniff          │  Zoraxy sends request metadata
            │   to Guardian          │  (no body), Guardian responds
            └────────────────────────┘  200 to accept, 501 to skip
                │
                ▼  if accepted:
            ┌────────────────────────┐
            │ POST /d_capture        │  Zoraxy sends the real request;
            │   to Guardian          │  Guardian writes the block
            └────────────────────────┘  response (403/429).
```

Guardian also subscribes to `/zoraxy_event/<event-name>` so Zoraxy can push native blacklist hits into Guardian's log.

---

## Development

Requires Go 1.23+.

```bash
git clone https://github.com/articrevised/zoraxy-guardian
cd zoraxy-guardian

# Run the test suite
go test ./...

# Build and run a quick check
./build.sh

# Build without pushing
SKIP_PUSH=1 ./build.sh
```

`build.sh` runs `go test ./...` → `go build` → `./<binary> -introspect` → `git add -A && git commit && git push`. Any failing step short-circuits before the push, so broken commits never reach `main`.

### Project layout

```
.
├── main.go                   ← entrypoint: Introspect spec + handler wiring
├── guardian/
│   ├── state.go              ← Config, Store, persistence, temp bans, strike tracker
│   ├── sniff.go              ← rule evaluation pipeline
│   ├── ingress.go            ← block-response writer
│   ├── ratelimit.go          ← token bucket per IP, background sweep
│   ├── host.go               ← glob host matching
│   ├── blocklog.go           ← bounded JSONL log w/ rotation + fsync
│   ├── broadcast.go          ← log fan-out for SSE subscribers
│   ├── cfparse.go            ← Cloudflare expression parser + translator
│   ├── events.go             ← Zoraxy event subscription handler
│   ├── api.go                ← UI-facing HTTP endpoints (config, log, SSE, tempbans)
│   └── *_test.go             ← test suite
├── mod/zoraxy_plugin/        ← vendored SDK from upstream Zoraxy
├── www/                      ← embedded UI (no build step; vanilla HTML/CSS/JS)
├── build.sh                  ← local build + push wrapper
├── update.sh                 ← installer/updater for the Zoraxy host
└── .github/workflows/        ← CI: matrix build + rolling release
```

### Releases

Two release types, both produced by `.github/workflows/release.yml`:

- **Rolling `latest`** — Refreshed on every push to `main`. Marked as a pre-release on GitHub. `guardian-update` uses this by default.
- **Tagged `vX.Y.Z`** — Triggered by pushing a `v*` tag. Full release with auto-generated notes.

To cut a stable release:

```bash
git tag v0.3.0
git push --tags
```

### Building for a different platform

The CI cross-compiles for `linux/amd64`, `linux/arm64`, `linux/arm`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`. To build locally for a different target:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o linux_arm64_guardian .
```

---

## Troubleshooting

### "Save failed: 403"

Caused by sending the CSRF token in the wrong header. Guardian sends it as `X-CSRF-Token` (gorilla/csrf default); older builds used `X-Zoraxy-Csrf` which is incorrect. Update to the latest release.

### Block log empty after restart, but `blocklog.jsonl` has lines

Check that `blocklog.jsonl` lives next to the binary in `<plugins-dir>/guardian/`. Permissions need to allow the Zoraxy process to read it.

### Plugin shows enabled but no traffic is captured

Confirm Guardian is assigned to the **same tag** as the HTTP Proxy Rule you want it on. The plugin only sees traffic for rules carrying its tag. Visit Plugins → click (i) on Guardian → check "developer insight" for the registered capture paths.

### Rate limit doesn't block aggressive scanners

Static IP block rules are evaluated first; rate-limit is last. If a scanner is matching one of the earlier rules (e.g. UA blocklist), you'll see `ua-blocklist` in the log instead of `rate-limit`. This is intentional — the more specific reason is more useful.

### Guardian sees my IP as Zoraxy's loopback

Make sure **Trust X-Forwarded-For** is on in the General tab. Disable only if you have an untrusted hop between the client and Zoraxy.

---

## Configuration files

Located next to the binary at `<plugins-dir>/guardian/`:

| File | Purpose | Safe to delete? |
|---|---|---|
| `config.json` | Live config, written on every save. | Yes — Guardian regenerates defaults on next start. |
| `blocklog.jsonl` | Append-only block log. Auto-rotates at 5 MiB. | Yes — but you lose history. |

---

## License

MIT — see [LICENSE](LICENSE).

The vendored `mod/zoraxy_plugin/` SDK is LGPL (from upstream Zoraxy).
