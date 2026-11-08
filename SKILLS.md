# GoProxify — Skills Catalogue

Everything GoProxify can do, organised by what you want to *get done* rather than by component.
Each skill says **what it does**, **where you drive it** (UI, REST API, CLI, MCP, labels, Terraform) and
**whether it keeps working without the Admin**.

This file is a map, not the manual. Each section points to the document that holds the detail.
Product status: **preview (0.x)** — see [DISCLAIMER.md](DISCLAIMER.md).

- [How to read this file](#how-to-read-this-file)
- [1. Route and serve traffic](#1-route-and-serve-traffic)
- [2. Shape, transform and protect requests](#2-shape-transform-and-protect-requests)
- [3. Keep backends alive (resilience)](#3-keep-backends-alive-resilience)
- [4. Certificates and TLS](#4-certificates-and-tls)
- [5. Detect and stop attacks](#5-detect-and-stop-attacks)
- [6. Learn what normal looks like](#6-learn-what-normal-looks-like)
- [7. Automate and alert](#7-automate-and-alert)
- [8. Discover services automatically](#8-discover-services-automatically)
- [9. Reach machines safely (GoProxify Access)](#9-reach-machines-safely-goproxify-access)
- [10. Run a fleet: infrastructure, HA, deployment](#10-run-a-fleet-infrastructure-ha-deployment)
- [11. Logs, metrics, tracing and privacy](#11-logs-metrics-tracing-and-privacy)
- [12. Identity, teams and rights](#12-identity-teams-and-rights)
- [13. Backup, import and migration](#13-backup-import-and-migration)
- [14. Extend it (WASM plugins, modules)](#14-extend-it-wasm-plugins-modules)
- [15. Drive it from code and from AI](#15-drive-it-from-code-and-from-ai)
- [Recipes: things you can imagine doing](#recipes-things-you-can-imagine-doing)
- [What keeps working when the Admin is down](#what-keeps-working-when-the-admin-is-down)
- [Not there yet](#not-there-yet)
- [Where to read more](#where-to-read-more)

---

## How to read this file

GoProxify is **one Go binary with three roles**:

| Role | Plane | What it owns |
|------|-------|--------------|
| **Edge** (also called *gateway*) | Data plane | Routing, TLS in RAM, WAF, Ephor, L4, Access portal. Autonomous. |
| **Admin** | Control plane | Web UI, REST API, MCP server, ACME, alerting, automation, SQLite state. |
| **Agent** | Discovery | Reads Docker/Podman/Kubernetes/Consul/Nomad/etcd/ECS, reports metrics. No inbound port. |

Ways to drive any skill (not every skill has every door):

| Door | Use it for |
|------|------------|
| **Web UI** (Admin `:9443`, plus a menu per Edge) | Everyday operation, three skins, light/dark, Ctrl+K search |
| **REST API** (`/api/v1/…`) | Anything scriptable; session JWT or personal token `gpx_pat_*` |
| **CLI** (`goproxify <command>`) | Shell, CI, runbooks — [docs/cli.md](docs/cli.md) |
| **MCP** (`/mcp`) | AI assistants (Claude Desktop, Cursor…) — [docs/mcp.md](docs/mcp.md) |
| **Labels / annotations** (`goproxify.*`) | Declare a proxy on the container or Service itself — [docs/labels.md](docs/labels.md) |
| **Terraform provider** | Proxies, bans, ban whitelist, IP profiles as code (not yet on the Registry) |
| **`architecture.json`** | The reference description of hosts, Edges, Agents, HA groups |

Rights apply the same way through every door (see [skill 12](#12-identity-teams-and-rights)).

---

## 1. Route and serve traffic

| Skill | Details |
|-------|---------|
| **Reverse-proxy HTTP/1.1, HTTP/2, HTTP/3 (QUIC)** | One listener set (`:80`, `:443/tcp`, `:443/udp`), `Alt-Svc` negotiation, ALPN |
| **WebSocket and gRPC** | Native upgrade; transparent gRPC over HTTP/2; WebSocket upgrades refused cross-origin when the route lists `cors.allowed_origins` |
| **TCP and UDP (L4)** | Port → host:port streaming, SSL passthrough by passive SNI, per-client UDP sessions, round-robin or weighted backends, idle timeout, active TCP probes |
| **TLS termination or passthrough** | Certificates held in RAM only; SNI passthrough reads 5 bytes of the ClientHello, decrypts nothing |
| **Multi-host and aliases** | One proxy, many hostnames; wildcard routes |
| **Path locations** | `prefix` / `exact` / `regex`, per-location auth, rate limit, IP filter, `strip_prefix`; case-insensitive by default where it protects (avoids IIS-style bypasses) |
| **Static file server with SPA fallback** | `static`: serve a folder of the gateway with no backend, ETag, Range, `index` fallback |
| **Inter-Edge delegation** | An entry Edge hands a domain to another Edge — *Passthrough* (raw TLS) or *Terminate* (`X-Forwarded-For`) — [docs/delegation.md](docs/delegation.md) |
| **L4 mTLS tunnel between Edges** | Peer pool, automatic failover, CONNECT-like protocol over TLS 1.3 |
| **PROXY protocol v1/v2** | Inbound behind an L4 load balancer (only trusted CIDRs are believed); outbound to backends and passthrough; health probes carry the header too |
| **Trusted front proxies** | `X-Forwarded-For` / `CF-Connecting-IP` honoured only from `GPX_TRUSTED_PROXIES` — no forged-IP bypass |
| **Maintenance mode per route** | 503 + `Retry-After`, custom HTML, bypass by CIDR or header |
| **Duplicate, dry-run, diff and revert a proxy** | "Duplicate" action, YAML editor with *Test (dry run)*, field-by-field revision diff, revisions kept on the Edge |

Where: UI *Proxies* (seven-step proxy dialog: Entry → Security → Routing → Transformation → Backends → Resilience → Observability, simple mode with protection cards, expert mode, YAML toggle) · API `/proxies` · CLI `goproxify proxy …` · MCP `create_proxy`, `update_proxy`, `set_proxy_enabled`, `delete_proxy`, `list_proxies`, `get_proxy`.
Autonomy: **full** — proxies are YAML files on the Edge.

---

## 2. Shape, transform and protect requests

| Skill | Details |
|-------|---------|
| **Header and URL rewriting** | `rewrite_from/to`, add/remove request and response headers (`RequestTransform`) |
| **A/B and weighted split** | `split` variants with sticky cookie and test override; route on a validated JWT claim |
| **Canary and shadow mirroring** | Weighted canary by header/cookie; fire-and-forget mirror; `shadow.compare` diffs status, chosen headers and body hash and exports metrics |
| **Hedged requests** | A slow GET/HEAD is also sent to a second backend; first answer wins |
| **Response compression** | zstd, Brotli, gzip chosen from `Accept-Encoding`, per-proxy tuning |
| **Disk cache** | TTL by status, `Vary`, stale-while-revalidate, stale-if-error, request coalescing, purge by `Cache-Tag` / URL; safe by default (never caches authenticated or `private` responses) |
| **Rate limiting** | Token bucket per IP, JWT `sub`/`email`/claim, API-key header or cookie; fixed-window quotas; shareable across an HA group |
| **Bandwidth cap** | Per-response throughput limit |
| **Backpressure** | Max in-flight, bounded queue, then 503 + `Retry-After` |
| **Signed URLs** | HMAC + expiry, parameters stripped before the backend |
| **JSON field redaction** | Mask fields at any depth in responses; fails closed |
| **HTML injection** | Insert a snippet before `</head>` or `</body>` with a CSP nonce |
| **GraphQL guards** | Max depth, max aliases, block introspection |
| **JSON Schema and OpenAPI validation** | `request_schema` (per method/path rules) and full `openapi` (paths, methods, typed parameters, bodies) in `block` or `detect` mode |
| **gRPC-Web and REST↔gRPC transcoding** | Expose a gRPC backend as REST/JSON from `.proto` or a descriptor set, unary and streaming |
| **Authentication per route** | Basic, JWT (JWKS: RSA, EC, Ed25519; `none`/HS* refused), forward-auth (Authelia, Authentik, oauth2-proxy), OIDC, SAML, LDAP/AD, GitHub OAuth2, mTLS client certificates |
| **CORS and security headers** | Origins/methods/headers, HSTS, CSP, X-Frame-Options, server-fingerprint masking |
| **Reusable snippets** | IP, TLS, CORS, rate-limit, WAF, bot, auth profiles, edited through forms built from module manifests |

Where: proxy dialog (Advanced, Protection) · `goproxify proxy option` · MCP `update_proxy` with `options`, `purge_proxy_cache`, `create_snippet`.
Autonomy: **full**.

---

## 3. Keep backends alive (resilience)

| Skill | Details |
|-------|---------|
| **Load balancing** | Round robin, weighted, **adaptive** (CPU 50 % + memory 30 % + disk IO 20 %, from Agent metrics) |
| **Active health checks** | Per route: path, interval, timeout, healthy/unhealthy thresholds; follow the live route table |
| **Failover and passive quarantine** | Failing backend set aside, next one tried |
| **Circuit breaker** | Per backend, half-open probe, `503` + `Retry-After` when every backend is open |
| **Retry with exponential backoff** | Configurable |
| **Sticky sessions** | Cookie-based |
| **Slow-start** | A new or recovered backend ramps from ~5 % to 100 % over a window |
| **Server timeouts** | Read / write / idle / read-header for HTTP and QUIC, set from the Admin and pushed |
| **Container health escalation** | Restart → recreate → rollback image → quarantine, per container labels |
| **Horizontal auto-scaling** | Agent clones or stops containers on CPU, decided locally (works with the Admin off) |
| **Image lifecycle** | Detect new images, update `auto` / `scheduled` / `manual`, roll back if the container does not turn healthy |

---

## 4. Certificates and TLS

| Skill | Details |
|-------|---------|
| **ACME with three validation methods** | DNS-01 (wildcards), HTTP-01, TLS-ALPN-01; automatic renewal 30 days ahead |
| **33 DNS providers** | OVH, Cloudflare, Gandi, Route 53, Hetzner natively + 28 through libdns (Azure DNS, Google Cloud DNS, DigitalOcean, Scaleway, Namecheap, GoDaddy, Porkbun, deSEC, Infomaniak, IONOS…); several named providers side by side |
| **Certificate Hub** | Expiry dashboard (`ok` / `warning` / `critical` / `expired`), alerts at 30 and 7 days, external PEM import, deploy targets (signed webhook, `ssh_exec`), pull tokens in PEM/DER/PKCS#12/JSON |
| **Internal CA** | Self-signed root, server and client certificates for internal services, revocation |
| **OCSP stapling** | Fetched by each Edge itself, refreshed on schedule |
| **Encrypted Client Hello (ECH)** | Admin generates keys, Edges keep and replicate them, rotation keeps old keys valid until DNS caches expire |
| **TLS hardening at the door** | ClientHello read outside the accept loop with timeouts and caps, neutral `404` (or dropped connection) for unknown hosts, every refusal counted by reason |
| **Domain watch** (opt-in) | Certificate-transparency monitoring for unknown issuance, CAA checks, dangling CNAME takeover detection |
| **Certificate-to-proxy delegation** | Entry Edge or a whole HA group (`ha:<group>`) per domain |

Where: UI *Domains & certificates*, *ACME monitoring* · CLI `goproxify cert|acme|domain|internal-ca|ech` · MCP `obtain_cert`, `rotate_cert`, `list_certs`, `get_cert_status`, `import_cert`, `trigger_cert_deploy`, `create_internal_ca`, `issue_internal_cert`, `revoke_internal_cert`, `get_ech_status`, `list_dns_providers`.
Autonomy: certificates and keys survive an Admin outage in the Edge's encrypted cache; **issuance** needs the Admin and a connected Edge.

---

## 5. Detect and stop attacks

### Built-in engines

| Engine | What it does |
|--------|--------------|
| **WAF** | Native Go engine, **OWASP CRS-4**, 13 rule sets (SQLi, XSS, LFI, RCE, PHP, SSRF, scanners, Java/Log4Shell, RFI, NodeJS prototype pollution, HTTP smuggling, sensitive files, response leaks), inspects requests *and* responses, `detect` or `block`, custom rules hot-reloaded, **per-path rule exclusions** so one misfiring rule never opens the whole proxy, a per-gateway master switch |
| **Ephor** | Behavioural, per-IP: sliding windows, a **cumulative risk score with decay**, weighted 4xx, graduated bans for repeat offenders, tarpit, allow/deny lists, global anti-DDoS rate, **dry-run simulation on recent logs** before saving; survives Edge restarts, works without the Admin |
| **One risk note per IP** | Ephor, WAF and CrowdSec feed the same note; every automatic ban says **why** (signals with points and observed values) |
| **Behaviour signals** | UA↔TLS mismatch, missing assets, regular cadence, scan breadth, whole-ASN failures, rate deviation vs. learned norm — each born in `detect`, promoted to `block` after a replay |
| **Thresholds** | "N events in T → action" on served responses (`auth-fail`, `waf-repeat` + your own); keyed variants count per account (credential stuffing without lockout), per JA4 fingerprint, per ASN |
| **Enumeration detection** | An IP walking many values of `/api/users/{int}` |
| **Decoy paths** | `/.git/`, `/backup.sql`… whoever asks is almost surely a scanner |
| **Unknown-host signal** | Access by raw IP or unserved name adds moderate points; regular probes recognised and exemptable |
| **Seasonal traffic reference** | Learned per route × weekday × hour; volume gap = warning, volume + nature gap = probable attack; `block` hardens the route with a challenge and adaptive rate cap for IPs without history |
| **Challenge before the ban** | Proof-of-work page for borderline IPs instead of a refusal — humans barely notice, shared NATs are not banned |
| **Bot / AI-scraper challenge** | Proof-of-work (SHA-256 difficulty 1–24 bits), Cloudflare Turnstile or hCaptcha, cookie bound to IP + UA |
| **TLS fingerprinting (JA3 / JA4)** | Ban by signature; Prism tab of top fingerprints; **reputation** learns bad fingerprints and *proposes* them with proof |
| **CrowdSec** | LAPI stream bouncer → bans pushed to Edges |
| **Multi-gateway thresholds** | The Admin adds client errors counted by each gateway and bans spread-out offenders |
| **Geo-IP and IP profiles** | Country allow/block (MaxMind), feed profiles (Cloudflare, Tor, FireHOL, Bogons, blocklist.de, CINS), manual lists, `allow` beats `deny`, ETag refresh, shrink guard |
| **CVE scanner** | Reads the *real* application inventory (container image, response headers) and queries NVD by CPE with **KEV** and **EPSS** enrichment and a remediation SLA; no backend probing needed; CPE overrides |

### Banning

| Skill | Details |
|-------|---------|
| **Manual bans on IP or CIDR** | Validated, normalised, never wider than /16 (IPv4) or /32 (IPv6), refuses a range that includes you; **impact preview** before creating |
| **ASN bans** | Search by number, IP or name; preview with the last 24 h of traffic; one push; lift all at once |
| **Scoped bans** | One gateway, or an HA group |
| **Ban whitelist** | Addresses no ban reaches, kept on the Edge |
| **List import** | Plain text / CSV / JSON, analyse first (dry-run), one transaction |
| **Bans page** | KPIs, 48 h timeline, country map, source breakdown, bulk actions, CSV export, saved filters |
| **IP / CIDR trace** | Step-by-step history of an IP over up to a year: episodes, WAF/Ephor signals, bans, operator (ASN) |
| **Security overview and proxy scores** | A–F grade per proxy from 9 checks (TLS, HSTS, X-Frame-Options, hidden Server header, rate limit, WAF, bot protection, IP filter, authentication) |
| **Calibration** | `security threat calibrate` replays your own traffic against grids of settings and proposes the most sensitive one that would not have raised false alarms |
| **Terraform / GitOps bans** | Bans and whitelist as code |

Where: UI *Security* (Overview, Vulnerabilities, Bans, Ephor, Proxy scores, IP trace), *Prism* · CLI `goproxify security …` (`threat`, `bans`, `waf`, `surface`, `cve`, `trace`, `tls-reputation`, `rejections`), `goproxify ip-profile` · MCP `ban_ip`, `unban_ip`, `create_security_ban`, `preview_security_ban`, `import_security_bans`, `lookup_asn`, `ban_asn`, `trace_ip`, `list_security_threats`, `list_security_cves`, `simulate_ephor_config`, `calibrate_ephor`, `get_waf_activity`.
Autonomy: WAF, Ephor, thresholds, bans and challenges **all run on the Edge without the Admin**; bans keep flowing between HA peers.

---

## 6. Learn what normal looks like

**Surface learning** ([ADR 0016](docs/adr/0016-apprentissage-de-la-surface-d-un-proxy.md)) — switch a proxy to `learn` and the gateway builds a profile of what its *legitimate* traffic really uses, then walks you up the ladder one step at a time, always with a way back:

1. **Observe** — methods, path templates (`/api/users/{int}`), content types, body sizes, parameters, clients. Nothing is blocked; scanners teach it nothing; no value or IP is stored; a convergence check says when to trust it.
2. **Propose** — justified `max_body_size`, `rate_limit`, `geo_ip`, `ip_filter` (client /24 and /48 networks), `cors`, and path-scoped WAF exclusions, each with the command that applies it. Nothing applied automatically.
3. **Generate** an OpenAPI 3.1 policy for the existing `openapi` control, in `detect`.
4. **Enforce**, violation type by violation type (unknown path, unknown method, invalid parameter…), with guard rails, `dry_run` and one-click relax.
5. **Suggest additions** from clean clients coming back; accepting only ever *adds*.

Also learned: normal request rate per route and hour (Ephor), seasonal traffic references, bad TLS fingerprints, the application inventory.
Where: proxy dialog › Advanced, `goproxify security surface`, MCP `get_proxy_surface*`, `enforce_proxy_surface`, `relax_proxy_surface`, `accept_proxy_surface_suggestions`.

---

## 7. Automate and alert

| Skill | Details |
|-------|---------|
| **Automation flows** | One object for rules, schedules and playbooks: a *trigger* (condition tree on CVEs, bans, silent engines, error rate, offline nodes, expiring certificates, any sampled metric; an alert event; cron; manual with parameters) → *steps* (disable proxy, ban IP, notify, strict-mode hardening, signed webhook, PagerDuty, backup, wait, if/else, **human approval**, call a playbook, stop) |
| **Editor with simulation** | Visual flow editor, draft simulation with animated path, 20 versions with diffs and rollback, 18 parameterised templates, run journal with replay |
| **Flows on the gateways** | Simple condition flows run on the Edge, even with the Admin down |
| **Muting / maintenance windows** | Suspend flows and notifications together or selectively |
| **GitOps export/import** | Flows, channels and mutings as one YAML document |
| **Alert rules** | Per node / domain / team, grouping window against noise, **escalation** with acknowledgement, routing by trigger |
| **14 alert channels** | Email, Webhook (Slack/Discord/Teams/n8n compatible), Slack, Microsoft Teams, Telegram, SMS (Twilio), ntfy.sh, Gotify, Jira, Linear, GitHub Issues, GitLab Issues, Zammad, GLPI — each with a Test button |
| **Event triggers** | `cert_expiring_soon`, `cert_deploy_failed`, `ephor_ban`, `backend_down`, `traffic_deviation`, `surface_suggestion`, `domain_watch`, `ip_profile_refresh_failed`, SIEM lag, backup failure… |

Where: UI *Automation* (Overview, Automations, Alerts, Journal) · CLI `goproxify automation`, `goproxify alert` · MCP automation tools (flow catalogue, runs), `create_alert_channel`, `create_alert_rule`, `ack_alert_event`, `list_alert_events`.

---

## 8. Discover services automatically

| Source | How it declares a route |
|--------|-------------------------|
| **Docker / Podman** | `goproxify.*` labels on containers, real time; the Edge hot-joins the app's private bridge network (no published host port needed) |
| **Portainer** | Stack and container discovery |
| **Kubernetes** | `Ingress` / `Service` with label `goproxify.enabled` and `goproxify.*` annotations |
| **Consul, Nomad, etcd, Amazon ECS** | Service tags / meta / keys / task labels; polled; an unreachable directory never removes a route |

Around discovery:

- **Convert to proxy** — a discovered container becomes a regular, editable proxy in one click; a configured proxy always wins over the label route of the same host, which takes it back when the proxy is disabled or deleted.
- **Enable/disable a container route** per host without touching the container.
- **Inactive containers** stay visible, greyed out, never routed.
- **Container details and security template** — config, backend health, score, last requests, and the labels that would add the missing TLS / WAF / rate limit (as Compose, Portainer, `docker run` or Kubernetes).
- **Labels of any existing proxy** — export a proxy as Compose / Portainer / `docker run` / Kubernetes labels, secrets turned into variables.
- **Orphan proxies** flagged when their source container is gone.
- **Log forwarding** from labelled containers to the Admin.

Where: UI *Traffic › Discovered containers* · CLI `goproxify containers` (`list`, `show`, `orphans`, `convert`, `enable`, `disable`), `agent-mgmt` · MCP `get_discovered_container`, `convert_discovered_container`, `set_container_route_enabled`, `list_orphan_proxies`, `get_proxy_labels`, `list_discovery_sources`, `approve_agent`, `revoke_agent`.

---

## 9. Reach machines safely (GoProxify Access)

An operator portal served by the **Edge** (not the Admin):

| Skill | Details |
|-------|---------|
| **Web terminal and real `ssh`** | xterm.js in the browser, or `ssh -p 2222 <uuid>@<edge>` |
| **Targets** | VMs / bare metal (`sshd`) and Docker containers (`docker exec` through the Agent) |
| **Vault** | SSH login + password or private key, encrypted on the Edge, never visible to the Admin |
| **2FA and sessions** | TOTP / email OTP, TTL and one-shot sessions, revocation |
| **Catalogue and groups** | Destinations (global or per Edge), destination groups, user groups, tags |
| **Dedicated portal entries** | `domain.com/contractors`, `contractors.domain.com`: own theme, title, auth provider, 2FA, users, groups and destinations |
| **Access policies** | Time windows, allowed IPs, idle logout |
| **Temporary access with approval** | Request from the portal, approval tab, automatic expiry |
| **Live sessions** | List, observe in real time, terminate |
| **Session recording and replay** | Encrypted on the Edge, adjustable retention, player in the Admin |
| **User invitations** | By email (SMTP), notification of access requests |
| **Themes and templates** | Seven themes, HTML templates, per-Edge options |
| **Shared state in HA** | Accounts, 2FA, vaults, optional shared web sessions replicated between group members |

Where: UI *Access portal* (Summary, Destinations, Users, Templates, Audit, Settings) · CLI `goproxify access` · MCP `*_portal_*` tools (config, destinations, users, groups, sessions, requests, policy, recordings, templates, audit).
Autonomy: the portal restarts from its encrypted local copy without the Admin.

---

## 10. Run a fleet: infrastructure, HA, deployment

| Skill | Details |
|-------|---------|
| **One-command install** | `launcher` image: generates secrets, admin account, TLS certificate, backup key; deploys Admin + Edge + Agent, rolls back on failure, removes itself |
| **Add hosts with a QR code** | 15-minute ticket, confirmation page showing the Admin certificate fingerprint; or `curl \| bash`; `launcher join <url>` |
| **Design page** | Declare machines and roles, dry-run, watch the diagram (drawing or Mermaid) |
| **Update in place** | `launcher update` re-pulls images keeping volumes, with automatic return to the old image if the new one is not healthy; coordinated `goproxify update check/apply/rollback` |
| **Rebuild a lost Admin** | `launcher --restore` from a backup (same root secret and certificate so survivors recognise it) |
| **Infrastructure view** | Live flow schema Internet → Edges → Agents, node detail panel, risk score 0–100, "to handle" bar, infrastructure event log |
| **Architecture editor** | Drag-and-drop hosts / Edges / Agents / Admin, impact per change, exact `architecture.json` diff, 50 restorable versions, browser draft |
| **Host configuration generator** | Docker Compose, `.env`, `docker run`, network flows to open, drift check (declared vs deployed) |
| **Edge HA groups** | Leaderless: any member can take over; settings (Ephor, WAF switch, timeouts, portal, domains) configured once per group and replayed to members that were offline |
| **Admin HA** | rqlite (Raft) option, three Admin instances |
| **Pairing** | Shared secret (`GPX_PAIRING_SECRET`) or explicit tokens; Agent `pending → approved` with hourly HMAC rotation |
| **Deployment targets** | Docker Compose, Portainer stack, Helm chart (Admin, Edge and Agent DaemonSets), bare metal `setup.sh`, hardened systemd units, `setcap` for low ports |

Where: UI *Infrastructure* · CLI `goproxify nodes|declared|bootstrap|hosts|architecture|launcher|token|status|update|migrate-yaml` · MCP `get_architecture`, `get_topology_live`, `create_bootstrap_ticket`, `create_host_join_ticket`, `accept_node`, `reject_node`, `set_group_attributes`, `list_hosts`.

---

## 11. Logs, metrics, tracing and privacy

| Skill | Details |
|-------|---------|
| **Access logs** | Async JSON per request (client IP, domain, method, code, duration, upstream, HTTP version, JA3/JA4, request id); exact correlation by `request_id`; live view; the Edge owns its raw lines |
| **Prism** | Command centre: zoomable map (optional self-hosted vector basemap), top paths / IPs / sources / countries / TLS fingerprints, anomalies computed server-side, SLO, geo, direct-traffic view |
| **Proxy view** | Multi-select proxies for tiles, KPIs, map, anomalies, curves |
| **Dashboard in three views** | Health (verdict and actions), Cockpit (indicators, gateways, certificates), Map |
| **Prometheus** | Full `gpx_*` instrumentation on the Edge internal API and the Agent `:9191` |
| **OpenTelemetry** | OTLP/HTTP traces with W3C `traceparent` carried caller → Edge → backend; ban decisions as span events |
| **Live topology** | req/s, health and risk score per node, refreshed every 5 s |
| **SIEM export** | From every gateway, even with the Admin off: syslog RFC 5424 (TCP/TLS), HTTP NDJSON or OTLP; own cursor, at-least-once, lag alert |
| **Signed log export and legal hold** | Real IPs decrypted, password-encrypted archive, manifest signed by the gateway, hash-chained local audit, legal hold freezes files against retention |
| **GDPR toolkit** | IPs kept full / anonymised / pseudonymised (AES-GCM, audited reveal), 90-day default retention, Art. 15/20 export, Art. 17 erasure by IP or user *including on the gateways*, no third-party geolocation unless opted in, compliance kit (register, impact assessment, privacy notice) |
| **Audit log** | Structured trace of every operation, exportable |

Where: UI *Logs*, *Prism*, *Observability* · CLI `goproxify logs` (`list`, `export`, `delete`, `subject-export`), `prism`, `audit`, `edge logs …` · MCP `list_logs`, `get_metrics`, `get_proxy_metrics`, `get_prism_*`, `get_siem_status`, `get_audit_log`.

---

## 12. Identity, teams and rights

| Skill | Details |
|-------|---------|
| **Sign-in** | Local accounts with bcrypt, MFA (TOTP, SMS, WebAuthn), GitHub OAuth2, LDAP/AD, SAML 2.0, OIDC (Google, Microsoft/Entra, Auth0, Okta, Keycloak, Zitadel, Casdoor, Dex, Authentik, Authelia) |
| **Personal API tokens** | `gpx_pat_*` self-service, resource scopes, optional expiry; a read scope never allows a write |
| **Teams hold the rights** | Roles `admin` (whole platform) and `user` (only what its teams grant); the built-in **DPO** team carries the four GDPR capabilities |
| **Level × perimeter** | Per-service levels (e.g. proxies: read → operate → manage; alerts: read → acknowledge → manage rules), on a perimeter combining domain glob, proxy name glob/regex, backend, gateway group (by name, `environment`, `region`, `tags`) and label (`env=prod`); ticked sensitive permissions (`certs:deploy`, `automation:approve`, `engines:enforce`…) |
| **Profiles and preview** | Start from operations / SOC / domain owner / PKI / on-call / auditor / portal support; "this perimeter covers N proxies" before saving |
| **Same rules everywhere** | UI, REST, CLI, MCP, logs, certificates, alerts, topology, network security, portal, surface learning, WAF/Ephor tuning |
| **Effective-access view** | What an account can do, and where each right comes from |
| **CI guard** | Every route, MCP tool and CLI command must declare service + permission or the tests fail |

Where: UI *Access* · CLI `goproxify teams access|catalog|preview`, `user access`, `me` · MCP `get_rights_catalog`, `list_team_accesses`, `set_team_access`, `delete_team_access`, `preview_perimeter`, `list_teams`.

---

## 13. Backup, import and migration

| Skill | Details |
|-------|---------|
| **Snapshots** | Scheduled or manual; destinations S3 / WebDAV / folder; integrity re-read and compared; alert on failure or missed run |
| **Encrypted secrets section** | With a backup key, snapshots carry passwords, MFA, tokens, GDPR/ECH keys, internal CA and state files for a full rebuild; key generated, rotated and revealed (superadmin) from the UI |
| **Complete backups** | HA config, state of each gateway and its Agents, history (journals, audit, bans) |
| **Selective restore** | Pick entities and conflict mode |
| **Import** | nginx, HAProxy, Traefik (YAML, TOML, labels), Caddy, Zoraxy, BunkerWeb, CSV, JSON — parse locally, apply remotely |
| **Edge cache tools** | `edge cache show/refresh/export/clear` |

Where: UI *Backups* · CLI `goproxify backup|import|edge cache` · MCP `list_backups`.

---

## 14. Extend it (WASM plugins, modules)

| Skill | Details |
|-------|---------|
| **WASM plugins (wazero)** | Sandboxed: no files, network or clock by default; memory and time capped; fresh instance per call; failing plugin denies. Hooks on request, response, bodies (buffered, replaceable), log (async), TCP/UDP connect. Declared capabilities: bounded `kv` state, allow-listed `http` |
| **Signed packages and repositories** | Ed25519 over manifest + digest, trusted keys, catalogue / install / update through the same checks |
| **Ready-made examples** | `path-guard`, `rate-guard`, `body-redact`, `tcp-allow` installable in one click, plus **Coraza (SecLang)** whose denials are logged and can ban the IP |
| **Per-route attachment** | Route form *Plugins* tab or labels `goproxify.plugins` |
| **Module registry** | Alert channels, importers, DNS providers, discovery sources, deploy targets, auth providers, detectors and flow actions share one manifest-driven model (forms, validation, secret masking come for free) — [docs/plugins.md](docs/plugins.md), ADR 0007 |

---

## 15. Drive it from code and from AI

| Skill | Details |
|-------|---------|
| **MCP server** | JSON-RPC 2.0 + SSE at `/mcp`, **PAT only**; `tools/list` shows only what the token may call; `?toolsets=…` trims the list for small local models; every tool and resource requires the scope of its REST twin; no scope declared → refused |
| **MCP guard rails** | Source-IP allowlist for `/mcp`, backend-destination allowlist so a prompt-injected agent cannot point a proxy at an outside server, table of who can use MCP |
| **What an assistant can do** | Read: proxies, nodes, agents, metrics, logs, certs, domains, bans, threats, CVEs, anomalies, SLO, topology, audit, rights. Write (with the right scope): create/update/disable/delete proxies, ban/unban, manage certs/domains/alerts/flows, approve agents, issue internal certificates, tune Ephor, enforce surface policies, run the Access portal |
| **CLI for scripts and CI** | Every resource has a command; common auth via `-admin-url` / `-token` or `GPX_CONTROLPLANE_*` |
| **Terraform provider** | `goproxify_proxy`, `goproxify_ban`, `goproxify_ban_whitelist_entry`, `goproxify_ip_profile`, import and drift detection |
| **Config schema** | [docs/config_schema.json](docs/config_schema.json) for editor validation |
| **REST contract** | [docs/api_specs.md](docs/api_specs.md) |

---

## Recipes: things you can imagine doing

Compositions of the skills above. Each one is reachable today unless marked otherwise.

**Publish an app in 60 seconds** — label a container `goproxify.host=app.example.com`, `goproxify.tls=true`, `goproxify.waf=block`. Agent discovers, Edge routes, Admin obtains the certificate.

**Home lab, one box** — launcher with `--admin --edge --agent`; HTTPS for every container, a wildcard certificate by DNS-01, SSH into a NAS from the browser through Access.

**Zero-downtime release** — canary at 10 %, shadow-compare against the new build, watch `gpx_routing_shadow_diff_total`, ramp the weight, keep the old backend as hedge.

**Harden an API without writing a rule** — put the proxy in `learn`, wait for convergence, read the proposals, generate the OpenAPI policy in `detect`, enforce unknown-path and invalid-parameter refusals, relax in one click if a client breaks.

**Credential-stuffing defence without lockouts** — keyed threshold on login accounts: attackers from many IPs get a proof-of-work or a trickle of attempts; the legitimate user keeps signing in.

**Ban a hosting provider that keeps scanning you** — look up the ASN from an offending IP, preview the 24 h impact including successful requests, ban all its ranges on one gateway only, with an expiry.

**Shrink a bot problem** — JS challenge with proof of work for AI scrapers, exempt `/api/` and webhooks, JA4 reputation proposes the scanner's signature, you accept it in one click.

**Calm a noisy night** — a muting window silences notifications and flows for a maintenance slot; escalation renotifies on-call only if nobody acknowledged.

**Auto-containment with a human in the loop** — flow: critical KEV CVE on a proxy → notify → wait for approval → disable the proxy → open a Jira issue → page via PagerDuty.

**Certificate expiry that never surprises** — alerts at 30 and 7 days, auto-renew, push to a legacy appliance through an `ssh_exec` deploy target, pull token for a box that can only fetch PKCS#12.

**Hide the site name from the wire** — publish the ECH key in the HTTPS DNS record; observers see only the public name.

**Multi-site with a regional entry** — HA group per datacenter, a domain delegated from the entry Edge to a regional one in Passthrough, client IP preserved via PROXY protocol.

**Audit-ready support access** — a contractors entry at `/contractors` with its own users, 2FA, office-hours policy, temporary access approved by a manager, every session recorded and replayable.

**Compliance on demand** — export all access of one person (Art. 15), erase an IP everywhere including gateways (Art. 17), freeze logs under legal hold, hand a signed archive to the auditor — with the Admin switched off.

**SOC with scoped analysts** — a team access "SOC" on perimeter `env=prod`: sees prod bans, logs and threats, cannot touch staging, cannot switch a signal to `block` without `engines:enforce`.

**Chat-ops** — ask an assistant over MCP "who hit `/wp-login.php` from AS16276 this week, ban them on edge-2 for a day"; it traces, previews, then bans within the token's scope.

**Infrastructure as code** — Terraform for proxies and bans, `architecture.json` in Git, automation export YAML in CI, `goproxify proxy option` in deploy scripts.

**Migrate off another proxy** — `goproxify import` an nginx/Traefik/Caddy/HAProxy config, dry-run the YAML, shadow-mirror live traffic, cut over host by host.

**Custom policy in WASM** — write a `path-guard` variant in TinyGo or Rust, sign it, push it from a plugin repository, attach it to one route.

---

## What keeps working when the Admin is down

Designed so the data plane never depends on the control plane (ADR 0006):

- Routing, TLS (certificates from the encrypted local cache), L4, caching, health checks, load balancing
- WAF, Ephor (config, scores, bans, thresholds, seasonal references), challenges, CrowdSec bans
- Ban propagation between HA peers
- Simple automation flows evaluated by gateways, with their muting windows
- Access portal (accounts, 2FA, vault, sessions, recording)
- Surface learning profiles, application inventory
- Local log storage, SIEM export, signed export and legal hold
- Service discovery by the Agent, auto-scaling, health escalation
- OCSP stapling, ECH keys

Needs the Admin: certificate issuance, pushing new configuration, alert delivery by channels, the UI, rights evaluation, backups.

---

## Not there yet

Honest list from the [public roadmap](suivi/roadmap-public.md) — do not rely on these:

- Community ban collector (shared bans across installations) — planned
- SBOM + cosign attestation of images — to be reintegrated in the release pipeline
- Terraform provider on the public Registry
- Permission perimeters for the remaining services of [ADR 0022](docs/adr/0022-modele-de-droits-niveaux-et-perimetres.md)
- Admin-managed log store ([ADR 0018](docs/adr/0018-logs-geres-par-l-admin.md)) and launcher polish ([ADR 0019](docs/adr/0019-launcher-bootstrap-multi-hotes.md)) — in progress
- Plugin SDKs for more languages; multi-gateway and long-run plugin measurements
- Interleaved bidirectional gRPC transcoding; HA-shared instantaneous `rps` for bandwidth cap
- Ephor calibration against real production logs is left to the operator before any switch to `block` — see [docs/security.md](docs/security.md)

---

## Where to read more

| Topic | Document |
|-------|----------|
| Product catalogue | [docs/fonctionnalites.md](docs/fonctionnalites.md) |
| CLI reference | [docs/cli.md](docs/cli.md) |
| MCP tools and clients | [docs/mcp.md](docs/mcp.md) |
| REST contract | [docs/api_specs.md](docs/api_specs.md) |
| Security engines in depth | [docs/security.md](docs/security.md) |
| Docker / Kubernetes labels | [docs/labels.md](docs/labels.md) |
| Architecture and delegation | [docs/architecture.md](docs/architecture.md), [docs/delegation.md](docs/delegation.md) |
| Deployment | [docs/deployment.md](docs/deployment.md) |
| Plugins | [docs/plugins.md](docs/plugins.md) |
| GDPR | [docs/rgpd.md](docs/rgpd.md), [docs/rgpd-conformite.md](docs/rgpd-conformite.md) |
| Backups | [docs/sauvegardes.md](docs/sauvegardes.md) |
| Decisions | [docs/adr/](docs/adr/) |
| Roadmap and changelog | [suivi/roadmap-public.md](suivi/roadmap-public.md), [suivi/changelog.md](suivi/changelog.md) |
