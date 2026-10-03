# GoProxify — RGPD / GDPR Compliance Guide

> This document applies to operators running GoProxify. GoProxify is a **self-hosted** tool: the operator is the data controller for all personal data processed through it.

---

## 1. Data collected and where it lives

| Data | Component | Storage | Default retention |
|---|---|---|---|
| Client IP address | Edge (access log) | Log file on Edge + forwarded to Admin SQLite | 365 days |
| HTTP method, path, host, status, latency | Edge (access log) | Log file on Edge + Admin SQLite | 365 days |
| User-Agent header | Edge (access log) | Log file on Edge + Admin SQLite | 365 days |
| Referrer header | Edge (access log) | Log file on Edge + Admin SQLite | 365 days |
| WAF rule matches (categories only, no payload) | Passerelle (access log) | Admin SQLite | 365 days |
| Banned IP + ban reason + expiry | Passerelle / Admin | Admin SQLite | 730 days |
| Admin user email + bcrypt password hash | Admin | Admin SQLite | Until deleted |
| Admin user session JWT | Admin | In-memory + cookie (browser session) | Until logout or expiry |
| Audit log (who did what, when) | Admin | Admin SQLite | 90 days |
| GeoIP lookups | Edge | In-memory only, MaxMind DB on Edge disk | Never stored per-request |
| SSH portal session metadata (target, duration) | Passerelle / Admin | Admin SQLite | Until deleted |
| SSH portal credentials (login/key) | Edge | AES-GCM encrypted on Edge disk, never sent to Admin | Until deleted |

**What GoProxify does NOT collect:**
- Request bodies (WAF inspects them in memory; they are never logged)
- Response bodies (same: in-memory inspection only)
- Cookie values
- Authorization headers or tokens
- Any data sent to Anthropic, Cloudflare, or any third party

---

## 2. Minimisation options

### IP anonymisation in access logs (recommended for GDPR)

Enable in `edge.json`:

```json
{
  "engine": {
    "ip_anonymize": true
  }
}
```

Or push from the Admin UI → **Logs** page → settings (gear icon, admins only) → **Client IP addresses (GDPR)** → *Anonymised*.

Effect:
- IPv4: last octet zeroed → `192.168.1.123` becomes `192.168.1.0`
- IPv6: last 80 bits zeroed → prefix `/48` is kept
- The Edge's Fail2Ban and Sentinel still receive the real IP before anonymisation and keep banning
- The Admin's Fail2Ban, which reads the stored logs, ignores truncated IPs: `x.x.x.0` or a `/48` prefix covers many clients, and banning it would hit none of them (IPv4) or innocent ones (IPv6). The Edge flags every truncated line (`ip_truncated`), including when anonymisation comes from its own `edge.json`. What is lost: the Admin no longer catches an IP whose errors are spread over several Edges — see [security.md](security.md#fail2ban-natif-go)
- The Admin UI does not offer to ban or analyse a truncated IP: the **Logs** page detail labels it *Truncated IP (anonymisation)* and hides **Ban** and the IP reputation scan; Prism's top IPs tags it *Truncated* and hides re-scan and **Ban**; Prism's "dominant IP" anomaly (which offers **Ban**) only considers attributable IPs. The flag is exposed as `ip_truncated` in `GET /api/v1/logs`, the live stream `/logs/live`, `GET /prism/ips`, `GET /prism/ip-scan` and the MCP tool `list_logs`. Lines stored before Admin `0.71.1`, or sent by an Edge older than `0.17.12`, carry no flag and are shown as regular IPs

### Log retention

Configure in the Admin UI → **Logs** page → settings (gear icon) or via API:

```http
PUT /api/v1/logs/settings
{
  "retention_access_days": 90,
  "retention_system_days": 30
}
```

| Setting | Default | GDPR recommendation |
|---|---|---|
| `retention_access_days` | 365 | ≤ 90 days (or 13 months max, CNIL) |
| `retention_system_days` | 90 | 90 days |
| Ban history | 730 days | Legitimate interest — adjust to policy |

Older entries are purged automatically every night.

### IP pseudonymisation (recommandé pour RGPD strict)

Mode plus fort que l'anonymisation : l'IP est **chiffrée** (AES-GCM 256 bits) en base SQLite côté Admin. Le fichier de log de la passerelle reçoit toujours une IP tronquée. L'IP réelle ne peut être obtenue que par un utilisateur possédant le scope `gdpr:reveal` (voir §3 bis).

Activer dans l'interface Admin → page **Logs** → réglages (icône engrenage, admins) → **Adresses IP des clients (RGPD)** → *Pseudonymisées*, ou via API :

```http
PUT /api/v1/logs/settings
{ "ip_pseudonymize": true }
```

Ou dans `edge.json` (non supporté — ce réglage est Admin-side).

| Comportement | Anonymisation | Pseudonymisation |
|---|---|---|
| IP dans fichier passerelle | tronquée (x.x.x.0) | tronquée (x.x.x.0) |
| IP dans SQLite Admin | tronquée | chiffrée AES-GCM |
| Fail2Ban/Sentinel de la passerelle | IP réelle ✓ | IP réelle ✓ |
| Fail2Ban de l'Admin (logs) | IP tronquée ignorée | IP pseudonymisée ignorée |
| Bannir / analyser l'IP depuis l'interface (Logs, Prism) | masqué (« IP tronquée ») | masqué (« Pseudonymisée ») |
| Révélation possible ? | ❌ irréversible | ✓ avec scope `gdpr:reveal` |

Les deux modes sont exclusifs : l'Admin refuse (`400`) un réglage qui les laisserait actifs ensemble. Sur la passerelle, l'anonymisation l'emporte toujours : si `ip_anonymize: true` est défini dans `edge.json`, l'IP réelle n'est jamais envoyée à l'Admin, même quand celui-ci active la pseudonymisation.

La clé AES-GCM est générée automatiquement au premier démarrage et stockée dans la table `gdpr_keys` de la base Admin. Elle ne quitte jamais le serveur Admin. Elle reste chargée quand la pseudonymisation est désactivée : les entrées déjà pseudonymisées restent révélables jusqu'à la fin de leur rétention.

Modifier ces réglages, comme effacer des logs (ci-dessous), est réservé aux rôles admin et superadmin (scope `logs:write` pour un token API). Chaque changement de mode est inscrit au journal d'audit (`logs_ip_anonymize`, `logs_ip_pseudonymize`).

Chaque passerelle garde une copie chiffrée des réglages reçus de l'Admin (`/etc/goproxify/edge-settings.gpx`) et la recharge au démarrage : une passerelle redémarrée pendant une coupure de l'Admin continue d'anonymiser ou de pseudonymiser les IP de son access log.

---

### Right to erasure (Article 17) — delete by IP

```http
DELETE /api/v1/logs/by-ip/{ip}
```

Removes all log entries of the given IP, **including pseudonymised entries**: each one carries a keyed fingerprint of the real IP (`ip_hmac`, HMAC-SHA256), so the Admin finds them without decrypting the logs. IPv6 is matched whatever its notation. Entries pseudonymised before Admin `0.70.5` get their fingerprint in the background at the next start.

`{ip}` must be a valid IP address (`400` otherwise). An audit entry (`rgpd_erasure_ip`) and a system log are created with the reason and the number of deleted entries; neither contains the erased IP in clear, only its fingerprint (`hmac:…`), or its truncated form if the pseudonymisation key is unavailable.

CLI equivalent:

```bash
goproxify logs delete --by-ip 203.0.113.42 --reason "GDPR Art.17 request"
```

### Right to erasure — delete by user

```http
DELETE /api/v1/logs/by-user/{user_id}
```

Removes all log entries attributed to an authenticated user (JWT subject).

---

## 3 bis. Droit de révélation IP (scope `gdpr:reveal`)

Les utilisateurs possédant le scope `gdpr:reveal` peuvent obtenir l'IP réelle d'une entrée pseudonymisée, avec traçabilité complète. C'est possible tant que l'entrée est conservée, même si la pseudonymisation a été désactivée depuis.

### Qui peut avoir ce droit ?

| Compte | `gdpr:reveal` |
|---|---|
| Super-admin | ✓ toujours |
| Rôle `dpo` (délégué à la protection des données) | ✓ — droits d'un compte `user`, plus la révélation |
| Compte auquel le super-admin a accordé le droit | ✓ — quel que soit son rôle (DPO externe, juriste, RSSI…) |
| Membre d'une équipe à laquelle le super-admin a accordé le droit | ✓ — tant qu'il en est membre |
| Admin, utilisateur sans délégation | ❌ |

Avec un token API, le scope `gdpr:reveal` doit en plus figurer sur le token ; un compte ne peut le placer sur ses tokens que s'il détient le droit.

**Seul le super-admin délègue** : lui seul attribue ou retire le rôle `dpo`, accorde ou retire le droit à un compte ou à une équipe, et change les membres d'une équipe qui le porte. Chaque attribution est inscrite au journal d'audit (`set_permissions`).

**Comptes protégés** : un compte super-admin ou détenteur du droit ne peut être modifié, voir son mot de passe changé ou être supprimé que par le super-admin. Sinon, un admin pourrait réinitialiser le mot de passe d'un DPO et révéler des IP sous son identité. De même, un import ou une restauration de sauvegarde lancé par un admin n'attribue jamais ce droit (rôle `dpo`, membres d'une équipe qui le porte).

Pour déléguer :

- **Interface** : page **Utilisateurs** → modifier le compte → rôle **dpo**, ou case **Révélation des IP pseudonymisées (RGPD)** ; pour une équipe → modifier l'équipe → case **Les membres peuvent révéler les IP pseudonymisées**. Ces contrôles ne sont actifs que pour le super-admin.
- **CLI** : `goproxify user create -email dpo@example.com -password … -role dpo`, `goproxify user update <id> -permissions gdpr:reveal` (`none` pour retirer), `goproxify teams permissions <id> -permissions gdpr:reveal`.
- **API** : `role: "dpo"` ou `permissions: ["gdpr:reveal"]` sur `POST/PUT /api/v1/users`, `PUT /api/v1/teams/{id}/permissions` (voir [api_specs.md](api_specs.md#utilisateurs-équipes-et-permissions--apiv1users-apiv1teams)).

Un admin ne peut toujours rien révéler, mais il peut désactiver la pseudonymisation : les nouvelles entrées sont alors conservées en clair. La séparation protège les entrées déjà pseudonymisées, pas la configuration future.

### Via l'interface

Page **Logs** → cliquer une entrée dont l'IP est « Pseudonymisée » → **Révéler l'IP** (bouton visible des seuls détenteurs du droit) → saisir le motif légal → **Révéler**. L'IP s'affiche dans le panneau de détail uniquement.

### Via API

```http
POST /api/v1/logs/reveal-ip
Content-Type: application/json
{
  "entry_id": 4821,
  "reason": "Réquisition judiciaire n°2026/1234"
}
```

Réponse :
```json
{
  "entry_id": 4821,
  "ip": "203.0.113.42",
  "requested_by": "dpo@example.com",
  "reason": "Réquisition judiciaire n°2026/1234",
  "ts": "2026-09-20T14:32:01Z"
}
```

### Via CLI

```bash
goproxify logs reveal-ip \
  --entry-id 4821 \
  --reason "Réquisition judiciaire n°2026/1234"
```

### Audit

Chaque révélation crée automatiquement une entrée dans le journal d'audit (`action = gdpr_reveal_ip`) avec l'acteur, l'ID de l'entrée et le motif. Un log système de niveau `warn` est également créé.

---

## 3. GeoIP (MaxMind GeoLite2)

The Edge downloads **GeoLite2-Country** at startup (if `geoip.auto_download: true`). This database is:
- Stored locally on the Edge volume (`/etc/goproxify/geoip/`)
- Never sent anywhere
- Used only for allow/block decisions and Prism dashboard enrichment (country of request)
- The IP itself is never sent to MaxMind at runtime

MaxMind's terms require attribution and accept that the database is used offline. No personal data is transmitted to MaxMind during normal operation.

To disable auto-download, set `geoip.auto_download: false` in `edge.json` and supply your own database.

### Admin: Prism map (city-level position)

The Admin geolocates client IPs to draw the Prism map (country, city, region). Two modes:

- **Local database (default when available)**: the Admin downloads **GeoLite2-City** in the background at startup (`geoip.auto_download: true`, path `geoip.city_db_path`, source `geoip.city_db_url`, default `/etc/goproxify/geoip/GeoLite2-City.mmdb`). IPs are resolved offline and never leave the Admin.
- **Fallback: ip-api.com**: while the database is absent (download in progress, disabled, or unreachable), the Admin queries the public service ip-api.com over plain HTTP, **which sends the client IPs to that third party**. Set `geoip.auto_download: true` (or place the file yourself) to avoid it, and block outbound access to `ip-api.com` if it must never be used.

Results (IP, country, city, region, latitude, longitude) are cached in the Admin database (`geoip_cache`). Positions are approximate (city level).

---

## 4. Third-party integrations (operator-configured)

These integrations are **opt-in** and configured by the operator. GoProxify sends data to them only when explicitly configured.

| Integration | Data sent | When |
|---|---|---|
| CrowdSec LAPI | Client IP (ban check) | On each request if bouncer enabled |
| Alert channels (email, Slack, ntfy…) | Event metadata (no client IP by default) | On alert trigger |
| ACME (Let's Encrypt) | Domain name only | On certificate issuance/renewal |
| DNS providers (OVH, Cloudflare…) | Domain/token for DNS-01 challenge | On certificate issuance/renewal |
| External auth providers (OIDC, SAML, LDAP) | Redirect URI, no credentials stored in GoProxify | On SSO flow |

---

## 5. Data processor checklist for operators

Before going to production, ensure:

- [ ] IP anonymisation enabled (`ip_anonymize: true`) if no legitimate need to store full IPs — or pseudonymisation if real IPs must remain obtainable for legal requests
- [ ] Only the accounts that need it are admins (they can change these settings and erase logs) or can reveal pseudonymised IPs (superadmin, `dpo` role, right granted to an account or a team — review the GDPR badges on the Users page)
- [ ] Log retention set to the shortest period that meets your legal obligations
- [ ] Admin user list reviewed — remove test accounts
- [ ] SSH portal vault entries reviewed — remove unused targets
- [ ] Alert channel configurations reviewed — confirm no personal data is included in alert payloads
- [ ] If using CrowdSec, check CrowdSec's own GDPR documentation
- [ ] Backup encryption enabled (`GPX_BACKUP_KEY`) if backups may contain personal data
- [ ] Privacy notice for end users updated to mention reverse proxy logging

---

## 6. Security measures protecting personal data

| Measure | Details |
|---|---|
| TLS in transit | All Admin↔Edge↔browser communication is TLS — certificates in RAM only on Edge |
| SSH vault encryption | AES-GCM, key never leaves passerelle |
| Admin authentication | JWT ECDSA P-256, bcrypt passwords, optional MFA (TOTP / WebAuthn) |
| Audit log | All admin operations are recorded with actor, timestamp, action |
| Role-based access | Teams + scopes limit who can read logs or security data |
| Backup encryption | AES-GCM via `GPX_BACKUP_KEY` |
