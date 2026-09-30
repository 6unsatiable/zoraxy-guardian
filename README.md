# Guardian

A [Zoraxy](https://github.com/tobychui/zoraxy) plugin that adds an L7 security layer to your reverse-proxy rules: IP allow/block lists, User-Agent blocklists, WAF-style payload pattern matching, and per-IP rate limiting — with per-host scopes so each rule can apply globally or only to specific vhosts.

[![build-and-release](https://github.com/6unsatiable/zoraxy-guardian/actions/workflows/release.yml/badge.svg)](https://github.com/6unsatiable/zoraxy-guardian/actions/workflows/release.yml)
[![latest release](https://img.shields.io/github/v/release/6unsatiable/zoraxy-guardian?include_prereleases&label=rolling)](https://github.com/6unsatiable/zoraxy-guardian/releases/tag/latest)

---

## Why

Zoraxy ships with a built-in blacklist tied to access rules. Guardian extends that with the pieces a typical reverse proxy in front of public-facing apps needs:

- Per-IP rate limiting with token-bucket bursts
- Regex User-Agent blocking (grouped defaults for network, web-vulnerability, and content-discovery scanners)
- WAF-style request inspection (defaults for SQLi, XSS, command injection, Log4Shell, SSRF metadata probes, and path traversal)
- Allowlist + blocklist with CIDR (IPv4 and IPv6) support
- All four can be scoped to individual hosts via glob patterns

It plugs into Zoraxy's **dynamic capture** API — your proxy rules carry on as normal, and Guardian only intercepts requests it actively wants to block.

---

## Features

| | |
|---|---|
| **IP rules** | Allowlist + blocklist. CIDR (IPv4 + IPv6) and single IPs. |
| **User-Agent blocklist** | Go regex (use `(?i)` for case-insensitive). |
| **WAF rules** | Go regex over URI, full URL, Cookie, Referer, checked both as sent and percent-decoded (twice, for double encoding). 10 consolidated default rules. |
| **Rate limit** | Per-IP token bucket with automatic idle bucket eviction. |
| **Honeypot paths** | Any request to a tripwire URL (e.g. `/.env`, `/wp-login.php`) installs a temp ban on the source IP. |
| **Host-header blocklist** | Block by regex against the request's `Host` header — useful for rejecting probes that arrive with `Host: localhost` etc. |
| **UA path exceptions** | UA rules can carry an `except_paths` list — e.g. block Googlebot except on `/robots.txt`. |
| **Cloudflare rule import** | Paste a Cloudflare WAF / Custom Rule expression and Guardian translates it into the right primitives. Handles path/query/UA/host predicates with AND/OR/NOT, multi-clause expressions, and the `path ne X and (...)` exemption pattern. |
| **Auto-ban escalation** | After N strikes in a sliding window, the IP gets a temp ban — escalates noisy scanners from per-rule blocks to a wholesale ban. |
| **Per-host scopes** | Each rule has an optional host glob filter — `*.api.test`, `**.example.com`, `*`, or exact. |
| **Live block log** | Last 2000 events kept in memory; mirrored to JSONL on disk (fsync'd every second); restored on restart; auto-rotates at 5 MiB. Repeat hits from an already-banned client are logged once a minute. Sensitive query values are redacted; the UI includes live updates, a source filter, top counts, and JSON/CSV exports (CSV cells are formula-safe). |
| **Zoraxy event subscription** | Mirrors Zoraxy's own `blacklistedIpBlocked` events into Guardian's log. |
| **Trusted proxies** | Honors `X-Forwarded-For`/`X-Real-IP` only when Zoraxy's direct peer is in a configured trusted-proxy CIDR. Uses Zoraxy's own resolved `client_ip` (v3.3.5+) when Zoraxy trusted the headers. |
| **Cloudflare aware** | One switch trusts Cloudflare's built-in edge ranges and reads `CF-Connecting-IP` (only from real Cloudflare addresses). A proxy address is never banned, struck or rate limited, and the UI warns when traffic arrives through a proxy Guardian doesn't trust. |
| **Persistent bans** | Temp and fingerprint bans are saved to `bans.json` and survive a restart. IPv6 clients are banned and rate limited per /64. |
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
curl -fsSL https://raw.githubusercontent.com/6unsatiable/zoraxy-guardian/main/update.sh \
  -o /usr/local/bin/guardian-update
chmod +x /usr/local/bin/guardian-update

# Install (replace with the host path bind-mounted to the container's
# /opt/zoraxy/plugin dir). An existing install is found and updated in place.
guardian-update --dir /path/to/zoraxy/plugin

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
guardian-update --dir /path/to/zoraxy/plugin
docker restart <zoraxy-container-name>
```

`guardian-update` defaults to the rolling `latest` release. Pin to a specific version with `--version v0.3.0`. The previous binary is kept as `<binary>.bak`.
Zoraxy v3.3.5+ can also update the plugin from its Plugins page when it was installed from the plugin directory.

### Manual install (non-Docker)

```bash
# Zoraxy runs the file named like its folder: <plugin dir>/Guardian/Guardian
mkdir -p /path/to/zoraxy/plugin/Guardian
curl -fsSL -o /path/to/zoraxy/plugin/Guardian/Guardian \
  https://github.com/6unsatiable/zoraxy-guardian/releases/download/latest/linux_amd64_guardian
chmod +x /path/to/zoraxy/plugin/Guardian/Guardian
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

**User agents** — Regex blocklist. The three defaults group common network scanners, web-vulnerability scanners, and content-discovery tools so the list remains easy to review.

**WAF rules** — Toggleable regex rules. v0.4.0 replaced the v0.2/v0.3 `xss-pattern`, `sqli-boolean-comment` and `command-injection` defaults, which blocked ordinary traffic (`?only=`, an `onboarding` cookie, slugs like `tom-and-jerry--movie`, JWT cookies). Existing installs get the new ones via **General → Merge recommended rules**, which only replaces unedited old defaults. Patterns match against `request_uri + " " + url + cookie + referer`. The defaults consolidate related signatures into a smaller, reviewable set:

| Name | Catches |
|---|---|
| `sqli-union` | `UNION SELECT` injection variants |
| `sqli-boolean-comment` | A quote followed by a comment (`admin'--`), quote-then-`OR`/`AND` (`' or '1'='1`), and numeric tautologies (`or 1=1`) |
| `sqli-time-based` | Time-delay SQLi (`sleep`, `benchmark`, `pg_sleep`) |
| `xss-pattern` | `<script>`/`<iframe>`/`<object>`/`<embed>` tags, `javascript:` URIs, and real DOM event handlers such as `onerror=` (not every parameter starting with "on") |
| `path-traversal` | `../` and `..\` |
| `null-byte` | `%00`, including double-encoded (`%2500`) |
| `command-injection` | Shell separators or `$(…)`/backticks followed by a download/shell tool used as a command |
| `log4shell` | `${jndi:...}` payloads |
| `dangerous-uri-scheme` | `php://`, `file://`, and `expect://` wrappers |
| `ssrf-metadata` | Requests targeting common cloud metadata services |

**Rate limit** — Per-IP token bucket (IPv6: per /64). Configure requests/minute and burst; the defaults (600/min, burst 200) leave room for dashboards that load 100+ thumbnails at once. 429 responses carry `Retry-After`. Buckets idle for >10 min are swept automatically; the map is hard-capped at 50k entries.

**Honeypot** — A list of "tripwire" URL paths. Any request matching one of them adds the source IP to the temp-ban list for the configured duration. Matching ignores case and the query string. A literal path matches anywhere in the path (`/.env` also catches `/api/.env`); a path with wildcards must match the whole path, where `*`/`?` stay inside one segment and `**` spans segments (`/backup*.zip`, `/**/phpinfo.php`). Defaults cover exposed secrets, CMS/database probes, framework diagnostics, and known appliance paths. It is OFF by default — turn it on once you've reviewed the path list.

**Auto-ban** — After an IP triggers any block rule `Threshold` times within `Window` seconds, it gets promoted to the temp-ban list for `Ban duration`. Honeypot hits install temp bans directly without strikes.

**Temp bans** — Live list of IPs currently temp-banned, with their expiry timestamps. Per-row "Clear" button to manually revoke.

**Host block** — Regex blocklist matched against the request's `Host` header. Patterns are evaluated after the IP blocklist and before honeypots. Common use: block scans probing your origin IP with `Host: localhost`, `Host: example.invalid`, etc.

**Import CF** — Paste a Cloudflare expression (e.g. from the CF dashboard) and translate it to Guardian primitives. Click **Preview** to see what would be added; click **Apply & merge** to commit. Supported predicates:

| Cloudflare field | Operator | Translates to |
|---|---|---|
| `http.request.uri.path` | `contains` | Honeypot path (matches anywhere in the path) |
| `http.request.uri.path` | `eq`, `in {…}` | Exact honeypot path (`=/path`) |
| `http.request.uri.path` | `matches` | WAF rule confined to the path |
| `http.request.uri.path` | `ne` *(inside AND)* | UA rule `except_paths` |
| `http.request.uri.query`, `http.request.uri`, `http.request.full_uri` | `contains`, `matches` | WAF rule |
| `http.user_agent` | `contains`, `matches`, `eq`, `in {…}` | UA blocklist entry |
| `http.host` | `contains`, `eq`, `in {…}`, `matches` | Host blocklist |
| `ip.src` | `eq`, `in {…}` (IPv4/IPv6, CIDR) | IP blocklist |

Both operator styles work (`eq`/`==`, `and`/`&&`, `matches`/`~`, …), as do `lower()`/`upper()` wrappers and raw strings (`r"…"`). Rules a translation would make broader are not imported: honeypots ban the client, so an exact Cloudflare path stays exact. Anything Guardian can't evaluate (`cf.*` bot/threat scores, `ip.geoip.*`, `ssl`, methods, `$lists`, NOT, and most AND combinations) is reported as a warning, and regexes Go can't compile show up in the preview instead of failing on apply. Cloudflare's `contains` is case-sensitive; Guardian's imported UA, host and honeypot rules ignore case.

**Exempt clients** (General) — IPs/CIDRs Guardian never blocks, bans or rate limits, e.g. your home network or VPN, so a false positive can't lock you out.

**General** — Turn on **Trust Cloudflare** if any site is proxied through Cloudflare (orange cloud); otherwise Guardian sees Cloudflare's servers instead of your visitors. Configure the CIDRs of any other proxies directly in front of Zoraxy. Forwarding headers are ignored for all other peers, preventing client-IP spoofing. This tab also previews or merges the current recommended UA, WAF, and honeypot rules without replacing custom or host-scoped rules.

**Block log** — Recent block events with source (`guardian` vs `zoraxy`), reason, and status code. Paginated 50 at a time with a free-text filter, top IP/rule counts, and JSON/CSV exports. New blocks appear live via Server-Sent Events (the green/red dot in the header reflects connection status). Values for common credential query keys are redacted before logging.

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
git clone https://github.com/6unsatiable/zoraxy-guardian
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
│   ├── clientip.go           ← client IP resolution, Cloudflare ranges, ban keys
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

### The block log shows Cloudflare addresses (104.16.x, 172.64–71.x, 162.158.x …)

Your site is proxied through Cloudflare and Guardian isn't trusting it, so every visitor looks like a Cloudflare server. Turn on **General → Trust Cloudflare**. Before v0.3.0 this could ban a Cloudflare edge and lock out everyone routed through it; since v0.3.0 proxy addresses are never banned or rate limited, and the UI shows a warning banner until it's fixed.

### Guardian sees my IP as Zoraxy's loopback

In **General**, add the CIDR of the proxy or Docker network directly connected to Zoraxy, such as `172.17.0.0/16`. Guardian then trusts forwarding headers only from that peer range and picks the rightmost untrusted address from `X-Forwarded-For`. Never add a public client range just to make this work.

---

## Configuration files

Located next to the binary at `<plugins-dir>/guardian/`:

| File | Purpose | Safe to delete? |
|---|---|---|
| `config.json` | Live config, written on every save. | Yes — Guardian regenerates defaults on next start. |
| `blocklog.jsonl` | Append-only block log. Auto-rotates at 5 MiB. | Yes — but you lose history. |
| `bans.json` | Active temp and fingerprint bans, saved every minute and on shutdown. | Yes — this lifts all current bans. |

---

## License

MIT — see [LICENSE](LICENSE).

The vendored `mod/zoraxy_plugin/` SDK is LGPL (from upstream Zoraxy).
