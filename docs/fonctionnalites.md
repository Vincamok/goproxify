# GoProxify Features

## 1. Overview

GoProxify is a **distributed, secure reverse proxy** compiled as a **single Go binary** with zero runtime dependency. The instance personality is determined at startup by the CLI subcommand or the `GOPROXIFY_MODE` environment variable.

The product comes in **three complementary personalities**:

| Component | Role | Persistence | Exposed ports |
|---|---|---|---|
| **Edge** | Data Plane — high-performance routing engine + WS hub (+ optional Access) | RAM + encrypted cache | `:80`, `:443` TCP+UDP, `:8000` internal + WS; Access `:2222` / `:8444` if enabled |
| **Admin** | Control Plane — UI, API, MCP, alerting, Access | SQLite | `:9443` |
| **Agent** | Discovery & Telemetry — Docker sidecar | Volatile | `:9191` Prometheus, `:51820` WireGuard (no inbound port for control plane) |

---

## 2. Edge — Data Plane

### Supported protocols

| Protocol | Details |
|---|---|
| HTTP/1.1 | Full reverse proxy with header management |
| HTTP/2 | Stream multiplexing, ALPN negotiation |
| HTTP/3 QUIC | UDP transport, `Alt-Svc` negotiation |
| WebSocket | HTTP → WS upgrade handled natively; when the route defines `cors.allowed_origins`, an upgrade whose `Origin` is not listed (or is `null`) gets `403` (anti cross-site WebSocket hijacking); requests without `Origin` pass |
| gRPC | Transparent proxy over HTTP/2 |
| TCP L4 | Pure stream: local port → remote host:port, native SSL passthrough, L4 load balancing |
| UDP L4 | Pure tunnel, bytes in/out metrics |

### TLS

- **TLS termination**: certificates pushed into RAM only via `GetCertificate` — never written to disk
- **SNI Passthrough**: passive detection by reading the first 5 bytes of the Client Hello (no decryption)
- **ALPN negotiation**: `h2` and `http/1.1`
- **mTLS client**: client certificate validation (Milestone 5)
- **Inter-Edge delegation**: an entry Edge can forward a domain to another Edge — **Passthrough** (raw TLS tunnel) or **Terminate** (TLS at entry + HTTP(S) proxy + `X-Forwarded-For`) modes. See [docs/delegation.md](delegation.md).

### Path locations — case sensitivity

`locations` (`path_type` `prefix` | `exact` | `regex`) are matched on the decoded, normalised path (`//`, `/./`, `..`, `;a=b`, `%2f`, `%00`, `%5c` are rejected upstream). Matching is **case-insensitive by default for any prefix/exact location carrying `auth`, `ip_filter` or `rate_limit`**, and case-sensitive otherwise. Per-location option `case_insensitive` (`true`/`false`) overrides the default. `regex` locations are never folded (use `(?i)` explicitly). `strip_prefix` follows the same rule. Why: a case-insensitive backend (IIS, ASP.NET) serves `/API/ADMIN` as `/api/admin`, so a case-sensitive protected location would be bypassed. Forcing `case_insensitive: false` on a protected location re-opens that bypass against such backends.

### Autonomous operation without Admin

The Edge can operate **autonomously** if the Admin is temporarily unreachable:

- Automatic backup of the routing table and certificates in an **encrypted local cache** (`/etc/goproxify/edge-cache.gpx`)
- Triggered on each push received from Admin + configurable interval
- On startup without reachable Admin: automatic load from cache
- **Automatic reconnect** as soon as Admin becomes available again → cache update
- Explicit log indicating startup mode (live / local cache)

### Performance

- `sync.Map` for routing table: atomic updates **with no connection interruption**
- Network buffer `sync.Pool`: stable P99 under load, reduced GC pressure
- Response compression negotiated per proxy (`compression`): **zstd**, **Brotli** and **gzip**, chosen from `Accept-Encoding`; configurable algorithms, minimum size, level and MIME types; skips already-encoded, SSE and WebSocket responses
- **TLS fingerprinting JA3 / JA4 wired to Sentinel** (Edge `0.36.0`): the gateway reads each client's raw TLS ClientHello (GREASE ignored) and computes its **JA3** (MD5) and **JA4** fingerprints, whatever the HTTP client claims in its User-Agent. Sentinel `custom_lists.tls_fingerprints` lists signatures to ban (signal `tls_fp`, critical score, normal ban flow: duration, escalation, HA propagation, `detect` mode logs without banning, whitelisted IPs exempt). Every access-log line carries `tls_ja3` / `tls_ja4` so a scanner's signature can be found then listed; the Sentinel drawer has an "Empreintes TLS bloquées" field. TLS only — plain HTTP and HTTP/3 have no fingerprint. Local computation, works without the Admin
- **TLS fingerprints in the Admin logs** (Admin `0.115.0`, Edge `0.44.0`): the gateway ships `tls_ja3` / `tls_ja4` with each access-log line to the Admin, which stores them (indexed). Logs page: a JA4 column, JA3 and JA4 in the entry drawer, click-to-filter, `tls_ja3` / `tls_ja4` filters in the API (`GET /logs`, `/logs/facets`), CLI (`logs list -tls-ja4`) and MCP (`list_logs`). Entries from before the upgrade, plain HTTP and HTTP/3 carry no fingerprint. Not in Prism yet.
- **Bot challenge settings in the proxy dialog** (Admin `0.115.0`): in Protection › Bot protection, mode "JS challenge" shows provider (proof of work, Turnstile, hCaptcha), difficulty (1–24 bits), proof lifetime, site/secret keys and exempt paths (one per line).
- **Browser challenge against bots and AI scrapers** (Edge `0.35.0`, proxy `bot` option in `challenge` mode): the previous page only set a cookie that any scraper could copy from the HTML. It is now a real **proof-of-work** (default `challenge_provider: "pow"`): the page makes the browser find a nonce so that SHA-256 of a signed, stateless challenge has `challenge_difficulty` leading zero bits (default 16 ≈ 1 s, max 24; each bit doubles the work); solving it costs the client CPU, scraping at scale becomes expensive. Optional **Cloudflare Turnstile** (`turnstile`) or **hCaptcha** (`hcaptcha`) with `challenge_site_key` and `challenge_provider_secret` (token verified server-side, refused if the provider cannot be reached). The proof is an `HttpOnly` cookie bound to the client's IP and User-Agent (a copied cookie is useless elsewhere), valid `challenge_ttl` (default 24h), and removed before the request reaches the backend. `challenge_exempt_paths` lists prefixes never challenged (APIs, webhooks); non-GET requests without proof get a plain `403`. Set `challenge_secret` to share the signing key across HA members (otherwise each gateway has its own and re-challenges after a restart). No Admin needed at runtime
- **PROXY protocol v1/v2** (Edge `0.34.0`): inbound on `:80` / `:443` (Edge config `network.proxy_protocol: { enabled, trusted_cidrs }`) so the real client IP survives a Layer-4 load balancer — only sources listed in `trusted_cidrs` are believed (no spoofing), `enabled` without `trusted_cidrs` is refused at startup, and a trusted source sending no header (LB health probe) is served with its own address. Outbound per proxy (`proxy_protocol: "v1" | "v2"`) towards HTTP backends and TLS passthrough routes; on an HTTP route each request uses its own backend connection (a PROXY header describes a single client, so no keep-alive reuse). Local config only — works without the Admin
  - **Health probes carry the PROXY header too** (Edge `0.45.0`): when a route sets `proxy_protocol`, its active health checks (HTTP and the TCP fallback) write a header with no client address (`LOCAL` in v2, `UNKNOWN` in v1), so backends that require PROXY no longer see them as invalid connections or flap down.
- Disk proxy cache (`cache`, Edge `0.33.0`): TTL per status code, `Vary`, bypass rules, **stale-while-revalidate**, **stale-if-error**, **request coalescing** and **purge by tag or URL** (`Cache-Tag` / `Surrogate-Key` response headers; API, CLI `proxy cache-purge`, MCP `purge_proxy_cache`)

### Security

| Feature | Details |
|---|---|
| IP/CIDR filtering | Gateway-wide profiles (all proxies, before routing; `allow` beats `deny`; per-proxy filtering stays in the `ip_filter` snippet): built-in feed profiles (Cloudflare, Tor, FireHOL…), templates for more feeds (Bogons, blocklist.de, CINS Army) and manually entered IP/CIDR lists (validated, deduplicated, exclusive with a feed); feeds aggregated (dedup + merged prefixes), private ranges excluded from deny lists, conditional downloads (ETag/304), exponential retry backoff with visible failure state, and a shrink guard against emptied/truncated feeds and an `ip_profile_refresh_failed` alert after N consecutive failures |
| Geo-IP | Allow or block by country (MaxMind GeoLite2; auto-download at startup) |
| Rate limiting | Token bucket per IP or authenticated user — `key_by` field: `ip` (default), `jwt_sub`, `jwt_email`, `jwt_claim:<name>` |
| Backpressure | Per-route cap on concurrent requests (`backpressure`: `max_inflight`, `queue`, `queue_timeout_ms`); extra requests wait in a bounded queue, then get `503` + `Retry-After`. WebSocket upgrades are exempt. Metrics `gpx_backpressure_*` — see [docs/security.md](security.md#backpressure-par-route) |
| HTTP security headers | HSTS, X-Frame-Options, Content-Security-Policy, etc. |
| CORS | Configurable origins, methods and headers |
| Server fingerprint masking | Removal of revealing headers (`Server`, `X-Powered-By`) |
| WAF | Own section in the proxy modal (mode, application-platform picker with search and auto-detection, advanced settings). Native Go engine, 13 OWASP CRS-4 rule sets, request **and** response inspection, detect/block mode, custom rules hot-reload — see [docs/security.md](security.md#waf) |
| Sentinel | Per-IP behavioral detection: sliding window, immediate ban on signal, global anti-DDoS RPS, optional bounded **tarpit** (holds the response to blocked IPs), optional **per-IP cumulative score with decay** (a ban only when signals add up faster than they fade), optional **weighted 4xx errors** (per status code and per path prefix) fed into that score, optional **graduated bans** (repeat offenders are banned longer, an unban resets the count) — see [docs/security.md](security.md#sentinel). Runs without the Admin: the Edge keeps an encrypted copy of its Sentinel config and stores Sentinel bans locally, so both survive an Edge restart while the Admin is unreachable. The Sentinel page has three tabs (overview, detections, lists and exceptions) and a side settings drawer, with a **dry-run simulation** on recent access logs before saving |
| Native Go Fail2Ban | Automatic banning after N failures, no external dependency. 403s served to an already banned IP don't count. IPv4 and IPv6; an IPv6 client is counted and banned per /64 (the ban shows the prefix), unless the allowlist overlaps that /64. With IP anonymisation or pseudonymisation, the Admin ignores the truncated IPs of its logs and each Edge keeps banning on the real IP — see [docs/security.md](security.md#fail2ban-natif-go) |
| Self-hosted vector basemap | Optional: drop an OpenStreetMap PMTiles file on the Admin server (`<storage>/basemap/basemap.pmtiles` or `GPX_BASEMAP_PATH`, cut with `pmtiles extract`) and the Prism / Security / Proxy-view maps zoom down to street level with no external tile service. Served with HTTP `Range` requests so the browser only reads visible tiles; drawn under the country outlines in the area it covers, follows the light/dark theme, 2 levels of overzoom. Without the file the maps keep the embedded country outlines. Setup: `docs/deployment.md`. |
| Terraform provider | `integrations/terraform-provider-goproxify`: manage proxies (`goproxify_proxy`), manual bans with optional gateway/group scope (`goproxify_ban`), the ban whitelist (`goproxify_ban_whitelist_entry`) and IP profiles (`goproxify_ip_profile`) as code, with import and drift detection (defaults added by the Admin are not drift). Built on the Admin REST API with a personal access token. Not yet published on the Terraform Registry. |
| ASN bans | Ban a whole operator (hosting provider, ISP) by banning every range it announces: search by number (`AS16276`), IP address (the ASN announcing it) or name; preview before banning (ranges created / skipped / rejected, last 24 h of traffic including successful requests that would be cut, warnings); one operation and one push to the gateways, with gateway/group scope, expiry and reason; lift all of an ASN's bans at once (Bans page "+ ASN" and "Bans par ASN" strip, API, CLI `security bans asn`, MCP `lookup_asn` / `preview_asn_ban` / `ban_asn` / `unban_asn`). Data: the public ip2asn dataset (iptoasn.com, public domain, no account), downloaded by the Admin on first use. Gateways need no ASN data: they get plain range bans and stay autonomous. A snapshot: run it again to add newly announced ranges. |
| Saved filters | Page Bans: the list filters (search, source, expiry, gateway, sort) can be saved under a name, recalled from a drop-down and deleted. Kept in the browser (`localStorage`), separately for the Admin and each gateway menu — they do not follow the account or another browser. UI only. |
| Gateway- or group-scoped bans | A ban (manual or imported) can apply on one gateway only or on the members of an HA group (`target_scope`: gateway name or `group:<name>`; UI « Applies to », CLI `-scope`, MCP `scope`). Each gateway receives only the global bans, the ones aimed at it and its group's; unknown scope refused; scope shown in the bans list and filterable (`?scope=`). |
| Ban whitelist | Page Bans › **Liste blanche**: addresses and CIDR ranges that no ban reaches (manual, Fail2Ban, CrowdSec, Sentinel, rules, peer bans) and that Sentinel does not evaluate, with a comment per entry. Existing bans are kept and simply stop applying (they show as "Exempt"); a ban fully inside the whitelist is refused. Stored as a managed `allow` IP profile that Edges keep on disk, so it works without the Admin — see [docs/security.md](security.md#liste-blanche-des-bans). API `/security/bans/whitelist`, CLI `security bans whitelist`, MCP `list_ban_whitelist` / `add_ban_whitelist` / `remove_ban_whitelist` |
| List import | Page Bans › **Importer**: create bans (or whitelist entries) from a pasted list or file in one go — plain text (one address or CIDR per line, `#` and `;` comments, as public lists like FireHOL, blocklist.de or Spamhaus DROP), CSV (the bans export re-imports as is) or JSON. Every entry is validated like a single ban; duplicates, already-covered targets and private ranges are skipped. **Analyse first** (dry run) shows what would be created, rejected and skipped, line by line; the real import is one transaction and one push to the Edges — see [docs/security.md](security.md#import-de-liste). API `POST /security/bans/import`, CLI `security bans import`, MCP `import_security_bans` |
| Manual bans on an IP or a CIDR range | A manual ban targets an address **or a CIDR range** (UI, API, CLI `security bans add`, MCP `create_security_ban` / `ban_ip`): the value is validated and normalised (`203.0.113.7/24` becomes `203.0.113.0/24`), ranges wider than /16 (IPv4) or /32 (IPv6) are refused, and so is a range containing the caller's own address. An **impact preview** (form button, `GET /security/bans/preview`, CLI `security bans preview`, MCP `preview_security_ban`) measures recent traffic — including successful requests the ban would cut — and the bans and IP profiles overlapping the target before anything is created — see [docs/security.md](security.md#bans-par-plage-cidr) |
| Unban & allowlists | Unbanning from the Admin lifts every ban of the IP on every Edge, including bans the Edge posted itself (Fail2Ban, Sentinel, rules, HA peer); kept across an Edge restart and replayed to an Edge that was offline. An IP in the Fail2Ban or Sentinel allowlist is no longer blocked by bans that engine already posted — see [docs/security.md](security.md#déban) |
| CrowdSec | LAPI stream bouncer → bans pushed to Edge (403), Docker compatible |
| Security menu | One "Security" entry with a shared Overview (score, active bans by source, recent threats, timeline) and a "Security engines" window with a switch per engine and per capability (Sentinel, Fail2Ban, CrowdSec, rules, CVE scanner), plus tabs (Overview, Vulnerabilities, Bans, Sentinel, Proxy scores — a per-proxy grade from 9 checks: TLS, HSTS, X-Frame-Options, hidden Server header, rate limiting, WAF, bot protection, IP filtering, authentication), the same on the Admin and on each Edge. Vulnerabilities: a **Fleet** view (one card per Edge on the Admin, per backend on an Edge, with a risk score and severity bar) or a filterable **List**, plus a detail drawer with actions (fixed, ignore, reopen). Each CVE carries **KEV** (actively exploited, CISA catalog), **EPSS** (0-1 exploitation probability, FIRST.org) and a **remediation SLA** (days after detection, per CVSS severity, editable in the Security engines window — Admin `0.52.3`); the risk score and the KEV filter chip account for KEV. Mobile-friendly (bottom sheet, stacked rows) |
| IP / CIDR trace | **With the ASN database installed**: the trace header shows the IP's operator (ASN, name, country) and the exact range it announces, with one-click scopes *this IP* / *announced range* / *whole ASN* (no CIDR to type; `scope=range|asn`, CLI `-scope`, MCP `scope`). **Security › IP trace** (also "Full trace" in a ban's IP history): follow one IP or CIDR step by step over a long period (24 h to everything kept, or custom dates). Access requests are grouped into **episodes** (a gap of 10 min starts a new one) with domains, paths, status classes, WAF categories and Sentinel signals; CrowdSec/Sentinel detections, bans and unbans (including bans set on a CIDR that contains the target) and system events are interleaved chronologically, newest or oldest first. Header: first/last seen, totals, daily activity, top IPs (CIDR) / domains / paths / WAF / countries, current bans and IP profiles that contain the target. Requests go back as far as the access-log retention (365 days by default); pseudonymised or truncated IPs (GDPR) are not found. `GET /api/v1/security/ip-trace`, `goproxify security trace`, MCP `trace_ip` (Admin `0.82.0`). A magnifier button ("Analyze IP") next to public IPs on the Bans page, CrowdSec threats, Sentinel detections, Prism and the log detail drawer opens the trace for the IP or its range (/24, /16 — /64, /48 in IPv6), offered in a small dialog (Admin `0.83.0`) |
| Access portal themes | The admin picks the look of the user-facing Access portal per gateway (**Access portal › Settings › Portal theme**; API `theme`, CLI `access config set -theme`, MCP `update_portal_config`): Automatic (follows the OS), Light, Dark, Ocean, Forest, Amethyst or High contrast. Pushed to the gateway, kept in its local copy, applied before first paint; the xterm terminal follows the theme colours. Portal users have no picker (Admin `0.85.0`, Edge `0.22.1`) |
| Access portal entries (views) | One gateway, several dedicated portals, each reachable at its own address: `domain.com/contractors`, `contractors.domain.com`, or any dedicated domain. Same directory and destinations, but each entry has its own theme, title/tagline, authentication provider, 2FA requirement, **allowed users and groups** and **destinations**. Groups are created per gateway (**Users Access › Groups**) and hold members by login (email or directory identifier). The user dialog shows and edits the user's groups, tags and — computed live — the entries and destinations they can reach. Configured in **Access portal › Settings › Dedicated entries** (API `views` + `/portal/groups`, CLI `access config set -views` / `access groups`, MCP `update_portal_config` / `*_portal_group`). A session is bound to the entry it was opened on. The pushed portal configuration is kept in an encrypted local copy, so the portal restarts without the Admin (Admin `0.87.0`, Edge `0.24.0`) |
| Access destination groups | Bundle catalog machines (SSH / Docker) into named groups per gateway (**Access Catalog › Groups**). A portal entry offers every destination of its groups on top of its own list. Groups are expanded when the Admin pushes the config, so the gateway keeps working from its encrypted local copy without the Admin. Deleting a destination removes it from its groups. REST API, CLI (`access destination-groups`) and MCP tools. User groups are managed from **Settings › Access › Users Access**. |
| Bans page | One page for the Admin (all Edges) and for each Edge menu (that Edge's bans plus global bans): KPIs, 48 h timeline, origin by country, breakdown by source / Edge (domain on an Edge) / reason, then an Active / History / CrowdSec list filterable by search, source, duration (expiring within 1 h, temporary, permanent, repeat offenders) and Edge. Row actions as icons (Prism, IP history, extend 24 h, make permanent, lift), bulk actions on a selection, CSV export, mobile card layout. Each ban records the Edge that reported it (`edge_name`, empty = global); `goproxify security bans list -edge …` and the MCP tool `list_security_bans` take the same `edge` filter |
| Automatic rules engine | Event-driven conditions (critical CVE, ban spike, silent engine, error rate, repeat offender IP, node offline, cert expiring) → actions (disable proxy, ban IP, alert, strict mode, webhook call, trigger backup); cooldown, dry-run, history — see [docs/security.md](security.md#automatic-rules-engine) |
| SSO | GitHub OAuth2, LDAP/Active Directory, SAML 2.0, OIDC (Google, Microsoft/Entra, Auth0, Okta, Keycloak, Zitadel, Casdoor, Dex, Authentik, Authelia) |
| JWT validation | JWKS : RSA (RS256/384/512), EC (ES256/384/512) and Ed25519 (EdDSA); `none` and HS* refused; `header_name: Authorization` accepts `Bearer <token>` |

### Request transformation pipeline

Each route can declare a `RequestTransform` block (Admin UI → proxy → **Transform** tab):

| Field | Description |
|---|---|
| `rewrite_from` / `rewrite_to` | URL prefix rewrite (e.g. `/api/v1` → `/v1`) |
| `add_request_headers` | Headers to inject into the upstream request |
| `remove_request_headers` | Headers to strip from the upstream request |
| `add_response_headers` | Headers to inject into the client response |
| `remove_response_headers` | Headers to strip from the client response |

The middleware applies first in the chain, before WAF and upstream routing. Hot-reload without Edge restart.

### L4 mTLS Edge↔Edge tunnel

The `internal/edge/tunnel` package provides a persistent encrypted TCP channel between two Edges (inter-datacenter L4 traffic, relay for backends unreachable from the entry Edge).

**Architecture:**
```
Edge A (client)          Edge B (server)
   │                          │
   ├─ mTLS TLS 1.3 ──────────▶│:9443
   │   CONNECT-like:           │
   │   "host:port\n"  ──────▶  │ dial TCP target
   │   ◀── "OK\n"              │ bidirectional pipe
   │   [L4 stream]   ◁────────▶│
```

- **Manager** (client side): peer pool `PeerConfig{Name, Addr, CACert, CertPEM, KeyPEM}`, automatic reconnect, failover to other registered peers
- **Serve** (server side): mTLS listener `RequireAndVerifyClientCert`, TLS 1.3 min, CONNECT-like protocol on one ASCII line
- Usage: `Manager.Dial(peerName, targetAddr)` returns a ready-to-use `net.Conn` for proxying or L4 access

### Resilience

- **Load balancing**: Round Robin, Weighted, **Adaptive** (CPU×0.5 + mem×0.3 + disk IO×0.2 via Agent WS metrics)
- **Configurable active health checks**: `HealthCheckConfig` per route — `path`, `interval`, `timeout`, `healthy_threshold`, `unhealthy_threshold`; probes follow the live route table (manual proxies, revisions, agent routes) and are restarted or stopped on change, including after a gateway restart without the Admin. Probes are **per route**: each route probes its backends with its own `health_check` and has its own verdict, even when a backend is shared with another route; a config edit applies live and the probes stop when the route is removed or disabled. Passive quarantine after a proxy error stays shared per backend URL
- **Failover**: short quarantine + try next backend on dial/proxy failure
- **Circuit Breaker**: per backend (a failing backend does not open the circuit of the others); counts transport failures (not 5xx responses). Open circuit = the backend is skipped (failover to the others); if every backend is open, immediate `503` with `Retry-After`. After `timeout`: half-open with a single probe request, success closes the circuit, failure reopens it
- **Retry policy** with configurable exponential backoff
- **Sticky sessions** via cookie
- **Slow-start** (`slow_start_sec`): a backend that is newly added or recovers from an outage ramps up from ~5 % to 100 % of its share over the configured window; sticky sessions keep their backend. Metric `gpx_backend_slowstart_shifted_total`
- **Configurable server timeouts**: `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout` HTTP/QUIC — configurable from Admin (Security > Server settings) and propagated to Edges via WebSocket

### Observability

- **Live topology** (Infrastructure → Topology): Admin → Edges → Agents map refreshed every 5 s in place, each node showing health, request rate (req/s over the last 60 s, with a 2-minute sparkline) and a **risk score 0-100** (highest of: offline, rejection rate 403/429, 5xx rate, CPU/RAM pressure; the dominant cause is shown). API `GET /api/v1/nodes/live`, CLI `goproxify nodes live`, MCP `get_topology_live` — see [docs/api_specs.md](api_specs.md#get-apiv1nodeslive)

- **Async JSON access log**: client IP, domain, method, HTTP code, duration, upstream, HTTP version
- **Structured JSON system log** for all components, with rotation
- **Prometheus metrics** exposed on `/metrics` — full instrumentation of all services: `gpx_edge_*`, `gpx_backend_*`, `gpx_backend_up`, `gpx_peer_sync_duration_seconds`, `gpx_waf_profiles_active`, `gpx_portal_sessions_active`, `gpx_pipeline_*`, `gpx_tls_*`, `gpx_auth_*`, `gpx_ratelimit_*`, `gpx_traffic_*`, `gpx_routing_*`, `gpx_f2b_*`, `gpx_crowdsec_*`, `gpx_rulesengine_*`, `gpx_vulnscan_*`, `gpx_admin_http_*` — see `docs/services.md`
- **OpenTelemetry tracing** (OTLP/HTTP, W3C Trace Context): one server span per request continuing an incoming `traceparent`, a client span per backend call (`traceparent` forwarded to the backend, so the trace spans caller → Edge → backend), Sentinel / ban decisions as span events (`sentinel.signal`, `ban.blocked`, no IP recorded) and route attributes (`gpx.route.id`, `gpx.route.host`). `X-Trace-Id` is returned to the client. Enable with `engine.tracing_endpoint` (`host:port` for plain HTTP, or a full `https://…` URL) or from Admin (`tracing_endpoint`, pushed to Edges; applied live); `engine.tracing_sample_ratio` (default `1`) samples new traces while honoring the caller's decision. Without an endpoint the Edge stays transparent: an incoming `traceparent` is still forwarded, nothing is exported. `/metrics` is not traced
- **JSON audit log**: full traceability of all operations

### GoProxify Access (SSH / shell portal)

Operator portal served by the **Edge** (not Admin):

- **Dual façade**: web terminal (xterm.js) + standard `ssh` client with UUID token (`ssh -p 2222 <uuid>@<edge>`)
- **Targets**: VM / bare-metal (`sshd`) or Docker containers (`docker exec` via Agent)
- **Vault**: SSH login + password or private key, encrypted on the Edge (never exposed to Admin)
- Optional **2FA** (TOTP / OTP email); TTL / one-shot sessions / revocation; metadata audit
- Config & catalogue pushed from Admin (see §3)

---

## 3. Admin — Control Plane

### First start

- Automatic detection of missing SQLite database on first launch
- **Guided initialization screen**: enter administrator email and password
- Generation of ECDSA P-256 key for JWT token signing

### REST API

Endpoints on `:9443` — two families:

- `/api/v1/` — session JWT authentication (human administrators) **or** PAT `gpx_pat_*`
- `/internal/v1/` — pairing token authentication (Edges and Agents, backward compat)

| Resource | Operations |
|---|---|
| Proxies (HTTP, TCP, UDP) | Full CRUD + immediate push to Edge(s) |
| Proxy duplication | "Duplicate" action in the proxy ⋯ menu: opens the creation modal pre-filled with the source config (domain and aliases cleared), created on save (Admin `0.72.0`) |
| Proxy dry run | YAML editor: "Test (dry run)" button validates the config without saving or pushing (structure, host/alias/port conflicts, optional backend probes) with an expandable detailed report — `POST /api/v1/proxies/dry-run` (Admin `0.72.0`) |
| Users | Create, edit, delete, password reset; roles `admin`, `user`, `dpo` (data protection officer: user rights + revealing pseudonymised IPs). Superadmin and accounts holding the reveal right can only be changed, reset or deleted by the superadmin (Admin `0.78.0`) |
| Teams | Access organization by scope; the superadmin can grant a team the right to reveal pseudonymised IPs (`gdpr:reveal`), its membership then being superadmin-only (Admin `0.78.0`) |
| Pairing (Infrastructure › Pairing) | Generate, list, revoke pairing tokens (`gpx_edge_*`, `gpx_join_*`) and see each Edge's details (status, endpoint, version, last contact, token); read-only view in Edge settings › Infrastructure › Pairing (Admin `0.79.0`) |
| User API tokens (PAT) | Self-service `/api/v1/me/tokens` — resource scopes, optional expiry; writes need the matching `:write` scope (`alerts:write`, `domains:write`, `certs:write`, `logs:write`, `security:write`…, admin roles only) |
| Snippets | Reusable profiles: IP, TLS, CORS, rate-limit, auth providers, DNS providers |
| Nodes | Registration, cluster state, accept/reject pending |
| Agents | List, approve / revoke (pending → approved workflow) |
| Declared / bootstrap | Wizard declared nodes; QR tickets `/i/{token}` + `curl|bash` |
| Domains | Apex / wildcards, entry Edge, ACME DNS, **delegation** Passthrough or Terminate to another Edge |
| Security | Bans, CrowdSec threats, CVE, Fail2Ban, overview |
| Access | Destination catalogue, SMTP user invite, HTML templates, portal options per Edge, audit |

**Write roles (UI session and PAT alike):** certificates (incl. deploy targets and pull tokens), domains, alert channels / rules / acknowledgements and IP profiles are readable by every account but writable by `admin`/`superadmin` only; snippets are writable by admins and by `user` accounts holding at least one `write` grant. The web UI hides those actions from accounts that cannot perform them (Admin `0.70.2`).

### MCP server

Endpoint `https://<admin>:9443/mcp` — MCP protocol `2025-03-26`, JSON-RPC 2.0 + SSE.

- **Auth:** PAT only (`Authorization: Bearer gpx_pat_…`) — UI session JWT is rejected
- **Scopes:** each tool requires the same scope as its REST equivalent (`proxies:read|write|delete`, `nodes:read|write`, `alerts:read|write`, `domains:read|write`, `certs:read|write` incl. internal CA, `audit:read` / `security:write` for security and automation — rules engine, scheduled tasks, playbooks, silences, auth providers, IP profiles —, `portal:read|write` for Access, …) ∩ current account rights. Tools whose REST route is admin-only (security, automation, internal CA, auth providers, agents, architecture, backups, Access…) also require the `admin`/`superadmin` role. Resources (`resources/read`) follow the rules of the tool they expose. Fail-closed: a tool without a declared scope is refused (Admin `0.70.0`)
- **Read:** proxies, nodes, agents, declared-nodes, alerts, metrics, backups, users, snippets, domains, certs, logs, teams, audit, bans / threats / CVE, alert channels/rules, auth providers, IP profiles, Access (config, catalogue, users, templates, audit)
- **Write:** `create_proxy`, `update_proxy`, `set_proxy_enabled`, `delete_proxy`, `approve_agent`, `revoke_agent`, `create_declared_node`, `create_bootstrap_ticket`, `accept_node` / `reject_node`, `create_security_ban`, `delete_security_ban`, `ban_ip`, `unban_ip`, `create_alert_channel`, `delete_alert_channel`, `create_alert_rule`, `delete_alert_rule`, `create_auth_provider`, `delete_auth_provider`, `create_ip_profile`, `delete_ip_profile`, `create_snippet`, `delete_snippet`, `create_domain`, `renew_domain`, `obtain_cert`, Access tools (`update_portal_*`, `invite_portal_user`, `push_portal`, templates…)
- **Sentinel dry-run:** `simulate_sentinel_config` (scope `logs:read`, admin role) replays recent access logs against a candidate Sentinel config and diffs it with the current one (blocked requests, bans, likely false positives) without applying anything
- Documentation: [docs/mcp.md](mcp.md)
- **Access control (`/mcp-access`, admin only):**
  - **Source IP allowlist:** admins restrict `/mcp` to a list of IP/CIDR entries (`GET`/`PUT /api/v1/mcp-access/allowed-ips`); enforced server-side before PAT auth even runs. Empty list (default) = no restriction.
  - **Backend destination allowlist:** `create_proxy` / `update_proxy` may only point to allowed destinations (`GET`/`PUT /api/v1/mcp-access/allowed-backends`; private networks and `*.internal`/`*.local`/`*.svc` by default), so a prompt-injected agent cannot redirect traffic to an external server.
  - **Active users:** table of every user holding an active PAT on the instance, with their scopes — "who can use the MCP" at a glance.
  - **Scope catalogue (reference):** each scope's covered MCP tools. Scope selection at issuance stays self-service on `/api-tokens` (a PAT is personal to its holder).

### Automation menu

`Automatisation` has four admin-only entries; the rest are tabs:

| Entry | Route | Content |
|-------|-------|---------|
| Overview | `automation` | KPIs, 24 h activity, latest executions, failure banner, shortcuts, GitOps **export/import as YAML** (`GET/POST /api/v1/rules-engine/export`\|`import` — rules, channels and silences, upserted by name on import), a banner listing **actions awaiting approval** with one-click Approve/Reject (see rule flag below) |
| Automations | `security-rules` | Tabs: **Rules** (`security-rules`, engine CRUD, dry-run, a **require approval** flag that queues the action for human Approve/Reject instead of running it — see [docs/security.md](security.md#approbation-avant-action)), **Flow editor** (`automation-flow`, a rule as Trigger → Safeguard → Action → Notification, inline edit, real dry-run simulation, **version history with one-click rollback** — 20 snapshots per rule), **Schedules** (`automation-schedules`, cron-triggered rules-engine actions independent of any condition — 5-field cron expressions, run-now, per-task run history, see [docs/security.md](security.md#planifications-cron)), **Playbooks** (`automation-playbooks`, chains action / wait / condition / approval steps, triggered as a rule/schedule action (`run_playbook`) or manually, each run tracked with a per-step log and, at an approval step, an Approve/Reject in its history — see [docs/security.md](security.md#playbooks)), **Templates** (`rules-store`, 15 templates via `GET /api/v1/rules-engine/templates`, install via `POST /api/v1/rules-engine/templates/{id}/install`) |
| Alerts | `alert-channels` | Tabs: **Channels** (email, webhook, ntfy, gotify, Slack, Microsoft Teams, Telegram, SMS via Twilio, plus the Jira/Linear/GitHub/GitLab/Zammad/GLPI ticketing channels), **Alert routing** (`alerts` — per-rule noise-reduction **grouping window**, `group_window_sec`, merges matching events into one notification; per-rule **escalation** steps, `escalation`, renotify unacknowledged events on their own channels, checked against acknowledgement at each step's due time), **Silences & maintenance** (`automation-silences`, time windows that suspend rule actions and alert notifications alike, for all or chosen rules of either engine — see [docs/security.md](security.md#silences--maintenance)) |
| Journal | `automation-history` | Every rule evaluation (`GET /api/v1/rules-engine/history`), filterable: executed / failed / condition met without action / not met; a failed entry can be **replayed** (`POST /rules-engine/history/{id}/replay`, reuses the original detail, condition not re-evaluated) |

### Infrastructure page and architecture edit mode

The **Infrastructure** page reads top to bottom:

- one **indicator strip**: traffic (with a session curve), nodes online, HA quorum, WebSocket connections (admin / agents), peer sync;
- a **To handle** bar, only when something needs attention: pending nodes (Accept / Reject), offline nodes (for how long, last heartbeat), hosts to redeploy (declared vs. deployed differences), excluded agents to confirm;
- the **architecture schema**, in three layouts:
  - **Flow**, read left to right: Internet → Edges (HA groups framed, leader and quorum) → Agents, the Admin above the Edges. Links are drawn from the real node positions: user traffic, agent WebSocket (dashed red when the agent is offline), Admin management. Each node is a card (role icon, status, host, throughput or containers, session availability strip);
  - **By host**: each host is a frame holding its roles;
  - **List**: inventory grouped by host (Matches deployed / To redeploy / Not connected, access to the host Configuration), one row per node with status, session availability, load, version and capabilities; filters All / Edges / Agents / Offline / Differences with counts, and a search by name, host or capability.
  Responsive: single column on mobile;
- a **detail panel** next to the schema for the selected node (no modal): status, host and exposure, req/s and **p95 latency** (Edge, from the Admin's last sample of the gateways) or containers and CPU (Agent), session availability, capabilities, 5xx rate, version, configuration state, HA peers or target Edge, operating actions (traffic, settings, configuration, update, rollback, rescan, delete…) and the node's latest events. By default it shows a node that is down, if any;
- the **infrastructure log** (scaling and health events), with **See all**: the 200 most recent node events, filtered by category (scaling, health, connections, other) and by node.

The schema model (host → role → capability) comes from **`architecture.json`** (`GET /api/v1/architecture`); live state (`GET /api/v1/nodes/live`, `GET /api/v1/metrics/summary`, `GET /api/v1/metrics/proxies`, refreshed every 5 s) is only an overlay.

**Infrastructure → Edit architecture** switches the page to **edit mode**:

- an edit bar shows the number of unsaved changes, with *History*, *Cancel* (asks before discarding) and *Review and save*;
- a palette (**Host, Edge, Agent, Admin**) whose items are dragged onto a host card, or clicked to add to the selected host; roles are moved between hosts by drag and drop. On a **touch screen**, tapping a palette item arms it and tapping a host places it; a role is moved with *Runs on* in the inspector. A **By host / By role** switch shows host cards or the Edges / Agents tiers;
- each change is flagged on the canvas — **New**, **Modified** (added / removed capabilities highlighted), **Removed** (with **Restore**) — and listed below the canvas with its impact: install, redeploy, restart, applied on save (Access on a connected Edge), declaration only;
- unsaved changes are kept as a **draft** in the browser (Portainer keys excluded) and restored when you come back, even after a reload; if the architecture changed in the meantime, you choose to resume the draft anyway or discard it. The Infrastructure page reminds you of a pending draft in its *To handle* bar;
- the **inspector** has *General* (name, host), *Capabilities* (Access, HA group, domains & TLS / ACME, Docker, Podman, Portainer, K8s) and *Network* (reachable address, delegations, target Edge) tabs, and shows the **Before** value of every changed setting. An agent's **target Edge** can be a single Edge or, when at least one HA group of 2+ Edges exists, the group itself — the agent is then linked to every member (`target_edge: "ha:<group id>"` in the declared config), so any Edge of the group can serve it, whether the pair runs active/active or active/passive;
- **Review and save** lists the changes, their impact, the exact **diff of `architecture.json`** (entries added, removed, keys changed) and warnings. For each connected node removed from the canvas, an option also **stops it** (the agent is revoked then excluded, the Edge deleted); without it, only its declaration is removed and the node shows up again while connected. Saving writes `architecture.json`; the confirmation offers the *Configuration* (Compose, install ticket) of hosts with new nodes and the command to stop revoked agents' containers. Nothing is created or approved on save.

A **host** is a machine that carries one or more elements: several gateways, several agents and the Admin. An agent carries one or more platforms (Docker or Podman, Portainer, K8s), or one agent per platform can be placed on the same host.

Each host has a **Configuration** panel (from the detail panel, the List view, the host inspector or the review confirmation). Its header identifies the host (zone, region, roles) with its compliance state — clicking it opens the differences. A side navigation groups the sections:

- **Deploy** — *Docker Compose*, *.env variables*, *Command line* (`docker run`): a code viewer with line numbers, syntax colouring, **secrets masked** by default (pairing secret, JWT, passwords, API keys; *Show secrets* reveals them), and *Copy* / *Download* of the complete file; *Install ticket*: explained in three steps, then generated on demand — install command (`curl|bash`), `/i/{token}` page, expiry and QR code. The ticket (24 h, one-shot) and the pre-approval of the host's agents are only created when you click **Generate a ticket**; nodes declared this way are **auto-accepted** on connection.
- **Check** — *Differences*: a verdict (everything matches / N differences to fix / nothing connected yet) then, per node, declared vs. deployed settings with their state; *Network flows*: table of the ports to open for this host; *Declaration*: the `architecture.json` entries of the host.
- **History** — *Versions*: timeline of the 50 kept versions of `architecture.json` (date, age, size); selecting one shows what changed since then (added / changed / removed) and its content, with *Restore this version*.

**History** in the Infrastructure top bar and in edit mode opens the same timeline on its own.

The canvas state lives in **`architecture.json`** (Admin `state/` folder), the reference file of the architecture: declared nodes, Edges, RBAC scopes. The Admin reconnects the Edges it describes at startup (address taken from `endpoint`, or from the node's `reachable_host`), aligns its database on the file, and keeps the previous **50 versions** of the file (`goproxify architecture versions|restore`, `GET /api/v1/architecture/versions`). Edges of an HA group announce their Raft peers in their heartbeat, so the Admin discovers the other members without extra configuration. **HA groups** (`config.cluster` + `config.cluster_group` in the canvas) share their security settings: Sentinel, IPS provider and HTTP timeouts are edited once and applied to every member (also replayed to a member that was offline), and the Sentinel reference lists (UA, paths, IPs) are synchronised between peer Edges. The **access portal** follows the group too: its options, destinations and invited users are those of the group (a member without the portal keeps a standby replica, ready to take over), and accounts, 2FA, vaults, personal targets, favourites and, optionally (`sticky` or `shared` HA sessions), web sessions are replicated between the members, encrypted with a group key. Bans decided locally are also passed between peer Edges when the Admin is unavailable.

### Multi-Edge delegation

A domain can be **delegated**: the entry Edge (DNS / public IP) forwards traffic to a target Edge.

| Mode | Behavior | Client IP on target Edge |
|---|---|---|
| **Passthrough** | Raw TLS tunnel (SNI) | Entry Edge's IP |
| **Terminate** | TLS terminated at entry + HTTP(S) proxy + `X-Forwarded-For` | Public IP (if seen by entry) |

Detailed documentation: [delegation.md](delegation.md).

### WebSocket control plane

Admin maintains a **persistent WS connection** to each registered Edge (Admin→Edge). This connection replaces HTTP push calls to `/internal/v1/*`:

- **Automatic reconnect**: exponential backoff 1s → 60s + jitter
- **Full-sync on reconnect**: complete state automatically resent
- **Message queue**: messages emitted during a disconnect are queued and delivered on reconnect
- **Immediate propagation**: any config change is sent in real time to the affected Edge

### Agent approval

Agents connecting for the first time via `JOIN_TOKEN` appear in `pending` status. The operator approves via UI or API (`POST /api/v1/agents/:id/approve`). The Edge immediately sends the first `agent_hmac` via WS.

### TLS / ACME management (DNS-01, HTTP-01, TLS-ALPN-01)

- **Domain entry Edge = HA group**: a domain's entry Edge can be a whole HA group (`ha:<group>`) so every member gets the domain scope, certificate and delegations
- **Wildcard Let's Encrypt certificates** via DNS-01 challenge
- **Validation per domain** (`cert_method`): **DNS-01** (wildcard, needs a DNS provider), **HTTP-01** (`acme-http`, port 80) or **TLS-ALPN-01** (`acme-tls-alpn`, port 443) — no DNS provider required, no wildcard. The Admin opens the ACME order and pushes the challenge answer to the Edges covering the domain (`acme_challenge` WS message); the Edge serves `/.well-known/acme-challenge/<token>` or presents the challenge certificate on ALPN `acme-tls/1` (RAM only, 15 min max, removed after validation). Used by automatic renewal too. Issuance still goes through the Admin and needs at least one connected Edge
- Supported DNS providers: **OVH, Cloudflare, Gandi, Route53, Hetzner**
- Automatic renewal 30 days before expiry
- Push decoded certificates to Edge in RAM only (never on disk on Edge side)
- **OCSP stapling** (Edge `0.20.0`): the Edge fetches the CA's OCSP response itself (certificate AIA URL) and staples it in the TLS handshake — refreshed hourly and at half the response validity, never stale, works without the Admin. Skipped for certificates without an OCSP URL (Let's Encrypt, internal CA). Metrics `gpx_tls_ocsp_staple_seconds`, `gpx_tls_ocsp_revoked`
- **Disk cache is user-safe by default** (Edge `0.21.2`): a route with `cache.enabled` never stores nor serves a response to a request carrying `Authorization` or any cookie, and never stores a response with `Cache-Control: private` or `no-store`, a `Set-Cookie`, or `Vary: *`; other `Vary` headers are honored (one variant per value). Opt-in per route: `cache.ignore_cookies` (cookies not part of the key) or `cache.vary_cookies` (named cookies join the key). `bypass_headers` / `bypass_cookies` unchanged. Static resources without cookies stay cached
- **Encrypted Client Hello (ECH)** (Admin `0.75.0` / Edge `0.21.0`): hides the site name (SNI) in the TLS handshake — an on-path observer only sees a configurable public name. The Admin generates X25519/HPKE keys, shows the `ech="…"` value to publish in each domain's HTTPS DNS record, and pushes the key set to the Edges, which keep it in their encrypted local cache (works without the Admin, across restarts), and replicate it between the members of an HA group without the Admin (encrypted by the group key, newest set wins; Edge `0.40.0`). Key rotation keeps the previous key accepting until DNS caches expire. Page Certificates → Settings, `goproxify ech`, MCP `get_ech_status`. TCP only (HTTP/1.1, h2), not for SNI-passthrough hosts

### Certificate Hub (v0.8)

Feature suite around the TLS certificate lifecycle.

**ACME monitoring — single entry point** (`/acme-monitor`, sidebar Access → Monitoring ACME)
- Unifies what used to be three separate menus ("Certificates", "Certificate deployment", "ACME Monitoring") into one page — the other two are removed
- Dashboard: status per cert (`ok` / `warning ≤30d` / `critical ≤7d` / `expired`), global KPIs, inline renewal button
- Per-row actions: **Deploy** (opens the Deploy Hub drawer below) and **Edit** (opens the source domain's modal — DNS provider, manual PEM, entry Edge, delegation — disabled when the cert has no linked domain, e.g. manual import); `domain_id` field in `GET /api/v1/certs/acme-monitor` links the emitted cert back to its `domains` row
- Automatic alerts: `cert_expiring_soon` (warning ≤30d, critical ≤7d) emitted to the existing alert engine
- **Multi-DNS providers**: manage multiple named providers (e.g. `cloudflare-prod`, `ovh-zone2`) via the "DNS Providers" section of the ACME Monitoring page; each provider has a type (`cloudflare`, `ovh`, `gandi`, `hetzner`, `route53`) and JSON credentials; full CRUD via `/api/v1/acme/providers`

**External certificate import**
- `POST /api/v1/certs/import`: PEM + private key upload — domain auto-extracted from SAN/CN, upserted in DB, real-time push to Edges
- Modal interface in the `acme-monitor` page

**Deploy Hub** (reachable via the "Deploy" button on each cert row in ACME Monitoring — no longer a standalone menu)
- **Deploy targets**: webhook (POST HMAC-SHA256 signed) or `ssh_exec` (script executed on target machine with `GPX_CERT_PEM / GPX_KEY_PEM / GPX_DOMAIN`)
- Automatic trigger on each ACME renewal + manual trigger
- Audit history per target (`cert_deploy_history`)
- `cert_deploy_failed` alert on failure

**Pull tokens**
- Secure tokens (HMAC-SHA256, TTL, max_uses) for pull download via `curl`
- 7 output formats: `pem`, `key`, `fullchain`, `der`, `der_key`, `pkcs12` (password), `json`
- Public endpoint `GET /api/v1/cert-bundle?token=…&format=…`

### Internal CA (internal certificate authority)

Self-signed root CA generation and issuance of internal server/client certificates, outside ACME — for internal services with no public exposure.

- **Root CA generation**: ECDSA P-256 self-signed root, configurable validity (default 10 years); private key persisted on disk under `certs/internal-ca/<ca_id>/`, never in the DB (only the cert PEM and metadata are stored)
- **Certificate issuance**: server (`ExtKeyUsageServerAuth`) or client (`ExtKeyUsageClientAuth`) leaf certificates signed by a chosen internal CA, with DNS/IP SANs, configurable validity (default 397 days)
- **Revocation**: certificates can be marked revoked (`internal_ca_certs.revoked`)
- `GET/POST /api/v1/internal-ca`, `GET/POST /api/v1/internal-ca/{id}/certs`, `DELETE /api/v1/internal-ca/{id}/certs/{certID}`
- CLI: `goproxify internal-ca create-ca|list-ca|issue|list-certs|revoke`
- MCP tools: `create_internal_ca`, `list_internal_cas`, `issue_internal_cert`, `list_internal_certs`, `revoke_internal_cert`
- Admin UI: "Internal CA" section embedded in the "Domains & certificates" page (`/acme-monitor`) — create a CA, list CAs, side panel to issue/revoke certificates per CA

### Domains & certificates page

Single list of public certificates (ACME, imported) and local ones (issued by an internal CA), with expiry counters, an All / Public / Local filter and search. Row actions on the right: renew (reissue for local, replace for imported), deploy (download root CA for local), details, edit, copy, download, delete (revoke for local). The Add button opens a wizard: Public, Local (issued by an internal CA, with a reminder to install the root CA) or Import. ACME settings (email, directory URL), DNS providers and internal CAs live in a Settings side drawer. `GET /api/v1/certs/{domain}/pem` returns the public certificate only.

### Granular alerting

Alertmanager-inspired model: each rule independently defines its scope, triggers and channels. The same event can notify multiple teams on different channels.

**Rule scope**:
- Target node(s)
- Domain pattern (glob: `infra.*.com`, `*.prod.*`)
- Team(s)
- Component (`edge` / `agent` / `admin`)
- Minimum severity (`info` / `warning` / `critical`)

**Configurable triggers**:
- Edge/Agent node offline
- Certificate expiring in < N days
- CVE detected on a backend
  - The HTTP scanner rejects private targets (RFC1918/ULA), localhost and cloud metadata by default (anti-SSRF). To scan Docker/LAN backends: `GPX_VULNSCAN_ALLOW_PRIVATE=true` on Admin, or via the toggle in the UI (Security > CVE Scanner, Edge view only — the manual scan trigger, the private-network toggle and the scanner status card all live on the Edge side; the Admin view shows only the aggregated CVE list across all Edges, with an Edge column identifying which Edge reported each CVE).
- New Fail2Ban ban (threshold: N bans/hour)
- Critical CrowdSec decision
- Sensitive configuration change
- Scheduled backup failure
- HTTP error rate > threshold on a proxy
- P95 latency > threshold on a proxy
- N failed admin login attempts

**Quality of service**: anti-spam rate limiting per trigger, grouping of similar alerts (configurable cooldown).

### Scheduled backups

- **Proxies**: per-proxy versioning, navigable history, per-proxy rollback
- **Admin**: JSON dump (users, token metadata without secrets, snippets, alert channels/rules, declared nodes, plus configuration tables: settings incl. MCP IP allowlist, automatic rules, teams/scopes, workspaces, domains, cert deploy targets, auth providers, IP profiles, tunnel configs, error/portal pages, fail2ban/CrowdSec config); secrets redacted (a redacted secret never overwrites an existing value on restore); optional AES-GCM encryption via `GPX_BACKUP_KEY`, which also adds an encrypted `secrets` section (password hashes, MFA, tokens, GDPR/ECH keys, internal CA, state files) restorable by the superadmin; the encryption key can be generated, rotated (old keys kept so past snapshots stay readable) and revealed by the superadmin from the UI; snapshots are checksummed and re-read on creation, and copied to off-site destinations (folder, WebDAV, S3-compatible); the encrypted `secrets` section also carries the effective HA config, each gateway's persisted state and its Agents' local files, and an optional encrypted `history` section holds logs, audit and past bans with per-destination retention and `backup_failed` alerts
- **Configurable cron** scheduling, configurable retention (number of snapshots)
- **Selective restore** of a snapshot: choose which entities to restore (proxies, users, tokens, PATs, snippets, alert channels/rules, configuration) and the conflict mode (overwrite/skip), with per-entity counts shown beforehand; a safety snapshot is taken before any overwrite
- CLI: `goproxify backup create/list/restore`

### Third-party config import

Automatic source format detection. Two modes: paste content or import one or more files. Preview before validation, partial import possible.

Supported formats: nginx, HAProxy, Traefik YAML, Traefik TOML, Traefik Labels, Caddy, Zoraxy, BunkerWeb, CSV, GoProxify native JSON.

### Coordinated cluster update

- Version inconsistency detection between nodes (via heartbeat)
- Alert if Edges or Agents run different versions
- Triggered from UI (per node or entire cluster) or via CLI
- Configurable rolling update (one node at a time, validation between each)
- Cluster rollback orchestrated from Admin

### Web interface

- Dashboard in three tabs sharing one dataset — Health (status verdict, to-do list, services), Cockpit (KPIs, 1 h traffic chart, edges, busiest hosts, certificate expiry), Map (traffic origin by country, blocks per layer, p95 per edge); the chosen tab is remembered
- Unified proxy list view (HTTP/HTTPS + TCP + UDP) — Docker labels greyed out read-only
- Adaptive create/edit form by proxy type
- Interactive Docker Compose label generator (HTTP, TCP, UDP)
- TLS certificate, snippet, token, user, team management
- Integrations: Prism (traffic analysis), Security dashboard, Backups, Import
- **Feature search** (Admin `0.73.0`): search button in the top bar (also Ctrl/Cmd+K or `/`) opens a command palette over every Admin and Edge page by title, section and FR/EN keywords (accent-insensitive, keyboard navigation, role-aware); also finds individual proxies (host, alias, backend), certificates, domains, gateways, snippets and users by name and opens the page listing them with its search field pre-filled; picking a gateway page from the Admin space asks which gateway to open. Keywords live in `searchKeywords` of `app.config.js`
- **Logs**: aggregated view (access + system + audit), filters, pagination, live mode via WebSocket; access logs add quick period and status-class chips, a requests/errors histogram (click a bar to zoom) and a request detail drawer (IP reputation, analyze in Prism, correlate, filter, copy as cURL, ban IP); system logs and the audit journal get the same period/level chips, histogram and detail drawer, and audit exports now honour the page filters
- **Access logs — unified view redesign** (Admin `0.55.0`): same code for the Admin page (all Edges) and the per-Edge menu (locked scope) — colored gateway chips replace the node dropdown in the Admin scope, hidden in the Edge scope where the scope banner already names it; columns reorganized into a merged "Host & path" cell, then **IP, Country** (new — flag + ISO code, resolved best-effort from the geo-IP cache already used by the dashboard/Prism/Bans, `country` field on `GET /api/v1/logs` entries), and log level shown as a colored left border on the row instead of a dedicated column (full message stays in the detail drawer)
- **Logs — GDPR** (Admin `0.71.0`): the Logs settings (gear icon, admins only) set how client IPs are kept — in full, **anonymised** (truncated, irreversible) or **pseudonymised** (truncated on gateways, real IP encrypted with AES-GCM on the Admin); both modes are exclusive, a gateway-local `ip_anonymize` in `edge.json` always wins, and gateways keep the setting across a restart without the Admin. A holder of the reveal right (superadmin, `dpo` role, or an account or team the superadmin delegated it to — Admin `0.78.0`) can **reveal** the real IP of a pseudonymised entry from its detail panel, with a mandatory legal reason recorded in the audit log (`POST /logs/reveal-ip`, `goproxify logs reveal-ip`). **Erasure** by IP or user (Art. 17, `DELETE /logs/by-ip|by-user`, `goproxify logs delete`) also removes pseudonymised entries and does not write the erased IP back in clear. A truncated IP (`x.x.x.0`, /48 prefix) is labelled in the entry detail and in Prism's top IPs, and the UI never offers to ban or scan it — it covers a whole network of clients (`ip_truncated` in `GET /logs`, Admin `0.71.2`). See [docs/rgpd.md](rgpd.md)
- **Observability overview**: one page for the Admin (all Edges, Edge selector) and each Edge menu (Edge locked): top anomalies, KPIs, traffic chart, HTTP codes, Edge table, proxies to watch, top countries, certificates to renew, availability SLO with error budget and burn rate (`/prism/slo`, MCP `get_prism_slo`, alert trigger `slo_burn` evaluated every 5 min per Edge and fleet-wide)
- **Prism**: command-center layout, KPIs with sparklines, Leaflet map with bundled country outlines (no external tiles; zones, cities or regions of every country, requests / error rate / banned IPs, live pulses at the source city), server-side anomaly detection (`/prism/anomalies`, MCP `get_prism_anomalies`, CLI `goproxify prism anomalies`), country and city drill-down, time series, HTTP codes, tabs Paths / IPs / Sources (components, bots, referrers) / Countries, period comparison, IP scan, CSV/JSON/HTML/PDF exports; private/loopback source IPs (no real country) stay in the same country ranking (Prism, dashboard, Bans) but always after real countries, with a "Local network" separator (Admin `0.52.7`)
- **Alerts and SLO page** (Admin and per Edge): SLO card with server-side target, SLO by Edge, coverage warning + one-click rule creation for the `slo_burn` trigger, recent fired alerts with histogram and detail drawer (`GET /alert-events`, MCP `list_alert_events`, CLI `goproxify alert events`), a **Silenced** badge on events an active silence window blocked from notifying, and an **Acknowledge** button (`POST /alert-events/{id}/ack`) that stops a rule's remaining escalation steps; alert cooldown is now per Edge/domain
- **Metrics page** (Admin): fleet Prometheus view (throughput, 5xx rate, bytes, control connections), Edge table, filterable proxy table with trend, TLS certificates, security pipeline counters
- **Live attacks map** on the Security overview: errors and banned IPs of the last 24 h plus a live feed of `error` / `banned` events, per Edge or for the whole fleet
- **Proxy view** (Admin/Edge `0.69.1`, Observability menu next to Prism, replaces the "Explorer" log explorer): a searchable list of every configured proxy (status dot, requests/s, p95) next to a live control panel for the selected proxy — the same "traffic by country" map as Prism (Requests/Error rate/Banned IPs modes, Zones/Cities/Regions styles) with a "Top countries" ranking (local-network entries grouped last, like Prism) and an embedded live connections feed with repeated-event grouping (`×N`, same as Prism's live feed), KPI tiles (requests/s, p95, error rate), server-side anomalies, and icon-only quick actions: purge cache, put into maintenance/reactivate, bans, full Prism view; same page for the Admin (all proxies) and each Edge menu (locked scope, `GET /proxies?edge=…`). The map, top countries and feed are built purely from the live stream (`/prism/live-ips`) while the page is open — no historical `/prism/geo` aggregate, by design: this is a real-time control panel, not an analysis tool (use the full Prism view for that). Purge cache and maintenance are real server actions: `POST /api/v1/proxies/{id}/cache/purge` (relayed to every Edge hosting the proxy; the disk cache is stored per-route so it purges cleanly one proxy at a time) and the existing `PATCH /api/v1/proxies/{id}` (`enabled`)

---

## 4. Agent — Discovery & Telemetry

### Docker discovery

- Listens to Docker events via Unix socket (`/var/run/docker.sock`, mounted read-only)
- Detects `goproxify.*` labels on containers at startup and in real time (start/stop/die)
- **Hot-connects** the Edge to the application's private Docker bridge network (apps expose no port on the host)
- Transmits network configuration to Admin (validated token)
- Discovered proxies marked `source: "label"` → read-only in UI

### Supported Docker labels

> Full reference: [docs/labels.md](labels.md)

Key examples:

```yaml
goproxify.enable: "true"
goproxify.host: "app.example.com"
goproxify.port: "3000"
goproxify.tls: "true"
goproxify.waf: "block"
goproxify.sentinel.whitelist: "10.0.0.0/8"
goproxify.canary: "true"
goproxify.canary.weight: "10"
```

### Kubernetes discovery

Symmetrically to Docker mode, the Agent can discover annotated Kubernetes resources:

- Watches `Ingress` and `Service` resources carrying the **label** `goproxify.enabled: "true"` (a Kubernetes label selector cannot match annotations, so this is a label, unlike Docker's `goproxify.enable`)
- Configuration comes from `goproxify.*` **annotations** with the same semantics as the Docker labels (see [docs/labels.md](labels.md)): `host` (CSV = aliases; on an Ingress the rule host wins), `port`, `backend`, `tls`, `waf`, `rate_limit`, `limit_conn`, `backpressure`, `slow_start`, `jwt`, `mtls`, `headers.add/remove`, `cache`, etc. The label prefix is configurable (`kubernetes.label_prefix`)
- Values deduced from the resource (host, backend, TLS from `spec.tls`) take precedence over the annotations
- Proxies created read-only in UI (source `k8s`)
- Requires a `ServiceAccount` with `get/watch/list` access on `ingresses` and `services`
- Compatible with multi-namespace Kubernetes deployments; target namespace configurable in `agent.json`

```json
{
  "kubernetes": {
    "enabled": true,
    "kubeconfig": "/etc/goproxify/kubeconfig",
    "namespaces": ["production", "staging"]
  }
}
```

### Horizontal auto-scaling

- Configurable triggers: container CPU (Agent telemetry) and/or request rate / P95 latency (Edge metrics)
- Coordinated decision by Admin (min/max instance rules)
- Instance creation/deletion via `docker compose up --scale` or `docker run`
- Hot-add to Edge routing table without interruption
- Compatible with resource-weighted adaptive load balancing
- Configurable cooldown between decisions (anti-flapping)

### Health escalation

Progressive recovery logic for `unhealthy` containers:

1. **Simple restart** (`docker restart`)
2. **Recreate** if still unhealthy after configurable delay (`docker rm` + `docker run`)
3. **Rollback** to previous image
4. **Quarantine**: removal from LB pool + operator alert

Delays and thresholds configurable per container via `goproxify.healthcheck.*` labels.

### Image lifecycle management

- Detection of available updates (local vs registry digest comparison)
- Per-container strategies: `auto`, `scheduled` (cron), `manual`
- Pull + recreate without interruption if multiple replicas
- Automatic rollback if container does not return `healthy` within configured delay
- Optional prune after successful update

### Log forwarding

- Collection of labelled container logs (`docker logs --follow`) opt-in (`goproxify.logs: "true"`)
- Real-time streaming to Admin
- Correlation with Edge/Agent/Admin logs in Logs view
- Configurable rotation and retention per container

### System telemetry

- Reads `/proc/stat` and `/proc/meminfo`
- Prometheus export on `:9191/metrics`
- Data used by Edge adaptive load balancing (host + containers via WS)

### Persistent WS connectivity

Agent maintains a **persistent WS connection** to the Edge (Agent→Edge). This connection:

- **Replaces the HTTP 30s heartbeat**: heartbeat sent via WS if connected, HTTP as fallback
- **Transmits discovered containers** in real time via `containers` message
- **Streams per-container metrics** (CPU, mem, latency) via `metrics` message every 10s
- **Sends lifecycle events** (start, stop, scale, die) via `event` message
- **Automatic reconnect**: exponential backoff 1s → 60s + jitter
- The Agent exposes **no inbound port** for the control plane

**Authentication:**
1. First start: `JOIN_TOKEN` (TTL 24h) → `pending` state
2. After Admin approval: rotating `agent_hmac` (automatic rotation every hour)

### Adaptive LB

Docker metrics (**CPU**, **memory**, **disk IO**) of `goproxify.enable` containers are streamed to the Edge every **10s** via WS (`metrics`). Score per IP:

`cpu×0.5 + mem×0.3 + disk_io×0.2` — lowest score backend receives the request.

- **Local pool**: multiple containers with the same `goproxify.host` → one `docker-host:…` multi-backend route.
- **Failover**: proxy failure → ~15s quarantine → try another pool backend (no 502 as long as one healthy remains).
- **Cross-Edge**: if the same host is discovered on Edge A and Edge B, peer sync + `gateway/tunnel` tunnel to the remote IP via the owner Edge (see [architecture.md](architecture.md#adaptive-load-balancing)).

P95 latency / error_rate: fields planned in payload, not used in v1 score.

### Canary and Shadow Mirror

**Manual** configuration on the proxy (UI / API): `CanaryConfig` (weight %, header, cookie) and `ShadowConfig` (fire-and-forget mirror). With `compare: true` (Edge `0.42.0`) the mirror response is compared to the primary one: status always, `compare_headers` (list of header names) and `compare_body` (size + SHA-256 of the first 8 MB, nothing stored) on request; differences are counted in `gpx_routing_shadow_diff_total{host,kind}` (`status`, `header`, `body`, `error` when the mirror is unreachable) next to `gpx_routing_shadow_compared_total`, and one sample per 10 s is logged.

Docker labels `goproxify.canary` / `goproxify.shadow`: automatic detection via Agent discovery — the Edge activates `CanaryConfig` / `ShadowConfig` on the `docker-host:` route without manual config. The canary/shadow container stays outside the LB pool (same `goproxify.host` as normal backends).

### Advanced routing and API protection (per proxy, JSON config)

All options run on the Edge alone — no Admin needed, even after an Edge restart.

| Option | Effect |
|---|---|
| `split` | `variants: [{name, backend, weight}]`, `sticky_cookie` (stable A/B assignment), `override` (header/cookie naming a variant, for tests) |
| `conditions[].type = "jwt_claim"` | Route on a claim of a JWT **validated by the route** (`jwt`); array claims such as `groups` match on any element; never true without JWT validation |
| `signed_url` | `secret`, `param_sig` (`sig`), `param_expires` (`expires`), `paths`; `sig = base64url(HMAC-SHA256(secret, path + "\n" + expires))` — 403 if missing, wrong or expired; params stripped before the backend |
| `rate_limit.quota` / `quota_period` | Fixed-window quota per key (`minute`, `hour`, `day`); `key_by` also accepts `header:<name>` (API key) and `cookie:<name>`. Per-Edge counters. A client-chosen header key is spoofable: combine with authentication |
| `bandwidth.bytes_per_sec` | Per-response throughput cap (nginx `limit_rate`) |
| `maintenance` | 503 + `Retry-After`, optional HTML; `bypass_cidrs`, `bypass_header` (`"Name: value"`) |
| `redact_json` | `fields` (key at any depth, or `a.b` path), `mask`; fails closed (502) on invalid, oversized (16 MB) or non-gzip-encoded bodies |
| `graphql` | `max_depth`, `max_aliases`, `block_introspection` (POST, batches, GET) |
| `hedge` | `delay_ms`, `max_extra`: a GET/HEAD without body not answered after the delay is also sent to the next backend; first response wins |
| `static` | `root`, `index`, `spa_fallback`, `cache_max_age`: the route serves a gateway folder instead of proxying (no backend needed); GET/HEAD only, no directory listing, dotfiles hidden; with `spa_fallback`, unknown page paths (no extension, or `Accept: text/html`) return the index, missing assets stay 404; ETag revalidation and Range; the index is always revalidated |
| `request_schema` | `rules[]` (`methods`, `path_prefix`, `schema`), `mode` (`block` default / `detect`), `max_body`: validates JSON request bodies against a JSON Schema (draft 2020-12 and earlier); first matching rule wins (default methods POST/PUT/PATCH); invalid → 422 with up to 5 `{path, message}` details, body over `max_body` (1 MB) → 413 in block mode; `detect` always forwards and only counts (`gpx_routing_request_schema_total{host,result}`); non-JSON bodies are not validated; schemas must be self-contained (external `$ref` refused); invalid schemas are rejected by the dry-run |
| `grpc_web` | Translates gRPC-Web (binary and `-text`) to gRPC for an HTTP/2 backend, trailers returned in the final frame |
| `rate_limit.shared` | HA group members add up each other's quota counts (~2 s lag, clocks must be in sync); local count if peers are unreachable |
| `sso.provider = "oauth2_proxy"` / `authelia` / `authentik` / `forward` | Forward-auth: any 2xx allows; `forward_auth_signin_url` redirects a 401 (`?rd=`); `forward_auth_timeout_ms`; `headers_to_forward` accepts a trailing `*`; client-supplied identity headers are stripped |

Set from the proxy dialog (Advanced tab › Advanced routing, plus key, quota and HA sharing under Protection › Rate limiting; Admin `0.115.0`), the CLI (`goproxify proxy option`) or MCP (`update_proxy` `options`). Saving the dialog now keeps these options (earlier versions dropped them). Not available yet: REST↔gRPC transcoding, HA-shared instantaneous rate (`rps`) and bandwidth cap.

### Network connectivity

- Optional **WireGuard** tunnels for inter-node communication (port `:51820` UDP)

---

## 5. Alert channels

All channels can be combined in the same rule.

| Channel | Description |
|---|---|
| **Email** | Configurable SMTP, direct notification to operators |
| **Webhook** | Generic webhook — compatible with Slack, Discord, Teams, n8n, etc. |
| **ntfy.sh** | Mobile push, self-hosted or public instance |
| **Gotify** | Mobile push, self-hosted |
| **Jira** | Automatic issue creation in a Jira project |
| **Linear** | Automatic issue creation in Linear |
| **GitHub Issues** | Issue opened in a GitHub repository |
| **GitLab Issues** | Issue opened in a GitLab project |
| **Zammad** | Ticket creation in the Zammad open-source ticketing system |
| **GLPI** | Ticket creation via the GLPI REST API |

Each channel has a "Test" button in the admin interface.

---

## 6. Config import

| Format | Notes |
|---|---|
| **nginx** | `server {}` blocks |
| **HAProxy** | `frontend` / `backend` sections |
| **Traefik YAML** | Routes, middlewares, TLS configuration |
| **Traefik TOML** | TOML equivalent |
| **Traefik Labels** | Interactive conversion guide to GoProxify config |
| **Caddy** | Caddyfile |
| **Zoraxy** | Native Zoraxy JSON |
| **BunkerWeb** | BunkerWeb configuration |
| **CSV** | Columns: domain, backend, options |
| **JSON** | GoProxify native format or generic JSON |

---

## 7. CLI

```
goproxify <command> [options]
```

| Command | Role |
|---|---|
| `admin` | Start Admin (Control Plane + Web UI) |
| `edge` | Start Edge (Data Plane — Reverse Proxy) |
| `agent` | Start Agent (Discovery & Telemetry) |
| `token create/list/revoke` | Edge/Agent pairing tokens (Admin API) |
| `backup create/list/restore` | Admin snapshots + routing export (Admin API) |
| `import` | Import nginx/Traefik/Caddy/HAProxy (parse local, apply remote) |
| `proxy list/get/enable/disable/delete` | Proxy route management |
| `cert list/obtain/delete` | TLS certificates |
| `user list/get/create/update/passwd/delete` | Admin user accounts |
| `audit list/export` | Action audit log |
| `logs list/export` | Access and system logs |
| `alert channels/rules/test` | Alert channels and rules |
| `snippet list/get/create/update/delete` | Reusable middleware snippets |
| `domain list/get/create/renew/delete` | Managed ACME domains |
| `agent-mgmt list/get/approve/revoke/delete` | Registered Docker agents (management) |
| `settings smtp/mfa` | Admin config: SMTP, MFA (SMS, WebAuthn) |
| `auth-provider list/get/create/update/enable/disable/delete` | External auth providers (OIDC, SAML…) |
| `teams list/get/create/update/delete + members + permissions` | RBAC teams, permissions granted to members (`gdpr:reveal`) |
| `workspaces list/get/create/update/delete + members + resources` | Workspaces (multi-tenant) |
| `ip-profile list/get/create/update/delete` | IP profiles (CIDR allowlist/blocklist, GeoIP) |
| `containers list` | Discovered Docker containers (read-only) |
| `me get/update/passwd + me tokens` | Current profile + personal API tokens (PAT) |
| `security threat/bans/waf` | Security: Sentinel (including `threat simulate`, a dry-run on recent logs), IP bans, WAF per proxy |
| `status` | Cluster state (nodes, versions, health) |
| `access` | GoProxify Access (config, catalogue, users, templates, audit) |
| `nodes` | List / live health-throughput-risk (`nodes live`) / accept / reject nodes (Infrastructure) |
| `declared` | Architecture wizard declared nodes |
| `bootstrap` | QR / curl\|bash host integration tickets |
| `edge cache show/refresh/export/clear` | Edge locale cache management |
| `update check/apply/rollback` | Docker image updates (via Agent) |
| `version` | Display binary version |
| `help` | Display help |

Common options: `-config <path>`, `-admin-url <url>`, `-token <token>` (or `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN`).

---

## 8. High Availability

### Edge — independent groups

- Edges organize into **groups** (by datacenter, region, customer…)
- Each group elects its **coordinator via the Raft algorithm** (majority required)
- Any config change is validated by the group majority before applying
- If the network partitions a group, only the majority half can elect a coordinator
- On loss of Admin access, each Edge falls back to its **encrypted local cache**

### Admin — rqlite

- **3 Admin instances** continuously synchronized via rqlite (distributed SQLite over Raft)
- Writes go through the **leader node**, reads on any node
- If one instance goes down, the other two continue without interruption
- Automatic leader failover in seconds

### Inter-node connectivity

- WireGuard tunnels managed by the Agent for secure communication between groups
- Adaptive load balancing based on metrics reported by Agents

---

## 9. Deployment

| Mode | Details |
|---|---|
| **Docker Compose** | `bash scripts/quickstart.sh` generates `docker-compose.yml` + `.env`, then `docker compose up -d` — recommended |
| **Bare-metal** | Interactive `setup.sh` script — module selection (Admin / Edge / Agent) |
| **systemd** | Hardened service (systemd units with sandboxing) |
| **setcap** | `setcap cap_net_bind_service` to listen on ports < 1024 without root |

Configuration: JSON files in `config/` (`admin.json`, `edge.json`, `agent.json`) + `GPX_*` prefixed environment variables (production priority).

---

## 10. Tech stack

| Domain | Choice |
|---|---|
| Language | Go — single binary, zero runtime dependency |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 QUIC (UDP), WebSocket, gRPC, TCP/UDP L4 |
| **Control plane** | **Persistent WebSocket (nhooyr.io/websocket) — Admin→Edge(WS), Agent→Edge(WS)** |
| TLS | `crypto/tls` + `GetCertificate` (RAM only), passive SNI passthrough, ACME DNS-01 wildcard |
| Routing table | `sync.Map` — atomic updates without interruption |
| Persistence | Embedded SQLite `modernc.org/sqlite` (CGO-free) — Admin only |
| Admin HA | rqlite (distributed SQLite, 3 nodes, Raft) |
| Edge HA | Raft algorithm per group, encrypted local cache |
| Configuration | Viper — JSON + `GPX_*` env var override |
| Discovery | Docker Engine API via Unix socket (`/var/run/docker.sock`) |
| Metrics | Prometheus (`/metrics`), OpenTelemetry |
| Auth | JWT ECDSA P-256, bcrypt passwords, HMAC-SHA256 WS control plane, JOIN_TOKEN lifecycle, PAT `gpx_pat_*` (API + MCP) |
| App security | Native Go Fail2Ban, CrowdSec LAPI bouncer, native Go WAF (OWASP CRS-4, 13 rules) |
| LLM integrations | MCP server JSON-RPC 2.0 + SSE (`/mcp`, PAT auth) |
| Deployment | Single binary · Docker Compose · systemd (hardening) · `setcap cap_net_bind_service` |
