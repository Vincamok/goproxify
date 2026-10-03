# MCP Goproxify — Référence des outils et ressources

Le serveur MCP (Model Context Protocol) de Goproxify expose l'Administration à tout client compatible MCP (Claude Desktop, Claude Code, etc.). Il permet à un LLM de lire l'état de l'infrastructure et d'agir dessus sans passer par l'interface web.

**Endpoint :** `https://<admin-host>:9443/mcp`  
**Protocole :** MCP `2025-03-26`, JSON-RPC 2.0 over HTTP  
**Authentification :** `Authorization: Bearer <gpx_pat_…>` — token API utilisateur (PAT) créé depuis **Paramètres → Mes tokens API**. Le JWT de session UI n’est **pas** accepté sur `/mcp`.  
**SSE (streaming) :** `GET /mcp/sse` — keepalive toutes les 15 s

Les scopes du PAT (`proxies:read`, `nodes:read`, …) bornent les outils MCP ; l’autorisation effective est toujours l’intersection avec les droits actuels du compte.

**Allowlist IP :** la page **Accès → Accès MCP** (`/mcp-access`, admin uniquement) permet de restreindre `/mcp` à une liste d'IP/CIDR sources (`GET`/`PUT /api/v1/mcp-access/allowed-ips`). Liste vide (défaut) = pas de restriction. Le contrôle s'applique **avant** l'authentification PAT — une requête hors liste reçoit un 403 immédiat, PAT valide ou non.

**Vue d'ensemble admin :** la même page affiche la liste des utilisateurs porteurs d'un PAT actif sur l'instance (tous porteurs confondus) avec leurs scopes, ainsi que le catalogue de scopes et les outils MCP que chacun couvre, pour référence. C'est une vue en lecture seule côté scopes — la création et le choix des scopes d'un PAT restent self-service depuis **Paramètres → Mes tokens API**.

### Contrôle d'accès des outils

Chaque outil exige un scope, le même que sa route REST équivalente. Les outils marqués † s'appuient sur une route REST réservée aux administrateurs : ils exigent en plus le rôle `admin` ou `superadmin`, comme l'API. Une ressource (`resources/read`) applique les mêmes règles que l'outil qu'elle expose. Un outil sans scope déclaré est refusé : aucun outil n'est appelable sans contrôle (depuis Admin `0.70.0` ; 56 outils n'étaient auparavant soumis à aucun scope).

| Scope | Outils |
|-------|--------|
| `proxies:read` | `list_proxies`, `get_proxy` |
| `proxies:write` | `create_proxy`, `update_proxy`, `set_proxy_enabled` |
| `proxies:delete` | `delete_proxy` |
| `nodes:read` | `list_nodes`, `list_declared_nodes`, `get_topology_live`, `list_agents` †, `get_architecture` † |
| `nodes:write` | `create_declared_node`, `delete_declared_node`, `create_bootstrap_ticket`, `accept_node`, `reject_node`, `approve_agent` †, `revoke_agent` † |
| `alerts:read` | `list_alerts`, `list_alert_events`, `list_alert_channels`, `list_alert_rules` |
| `alerts:write` | `create_alert_channel`, `delete_alert_channel`, `create_alert_rule`, `delete_alert_rule`, `ack_alert_event` |
| `metrics:read` | `get_metrics`, `get_proxy_metrics` |
| `backups:read` | `list_backups` † |
| `users:read` | `list_users` † |
| `teams:read` | `list_teams` † |
| `snippets:read` | `list_snippets` |
| `snippets:write` | `create_snippet`, `delete_snippet` |
| `domains:read` | `list_domains` |
| `domains:write` | `create_domain`, `renew_domain`, `rotate_cert` |
| `certs:read` | `list_certs`, `get_cert_status`, `list_cert_deploy_targets`, `list_internal_cas` †, `list_internal_certs` †, `get_ech_status` † |
| `certs:write` | `obtain_cert`, `import_cert`, `trigger_cert_deploy`, `create_internal_ca` †, `issue_internal_cert` †, `revoke_internal_cert` † |
| `logs:read` | `list_logs`, `get_prism_anomalies`, `get_prism_geo`, `get_prism_slo`, `simulate_sentinel_config` † |
| `audit:read` | `get_audit_log`, `list_ip_profiles`, `get_security_overview` †, `list_security_bans` †, `list_security_threats` †, `list_security_cves` †, `list_auth_providers` †, `list_rules` †, `list_rule_history` †, `list_rule_versions` †, `list_pending_actions` †, `list_silences` †, `export_automation` †, `list_scheduled_tasks` †, `list_scheduled_task_runs` †, `list_playbooks` †, `list_playbook_runs` †, `get_playbook_run` † |
| `security:write` | `create_ip_profile`, `delete_ip_profile`, `create_security_ban` †, `delete_security_ban` †, `ban_ip` †, `unban_ip` †, `create_auth_provider` †, `delete_auth_provider` †, `run_rule` †, `replay_rule_history` †, `restore_rule_version` †, `approve_pending_action` †, `reject_pending_action` †, `create_silence` †, `import_automation` †, `create_scheduled_task` †, `update_scheduled_task` †, `delete_scheduled_task` †, `run_scheduled_task` †, `create_playbook` †, `update_playbook` †, `delete_playbook` †, `run_playbook_now` †, `approve_playbook_run` †, `reject_playbook_run` † |
| `portal:read` / `portal:write` | outils Access (`*_portal_*`, `push_portal`) † — voir [GoProxify Access](#goproxify-access-portail) |

Les scopes d'écriture (`proxies:delete`, `nodes:write`, `alerts:write`, `domains:write`, `certs:write`, `security:write`, `import:write`) ainsi que `users:read`, `teams:read` et `portal:*` sont réservés aux rôles admin et superadmin (`proxies:write` et `snippets:write` sont aussi ouverts à un compte `user` qui a un droit d'écriture). Un refus est renvoyé comme erreur d'outil (`isError: true`) :

- `Erreur: scope insuffisant: <scope>` : le PAT n'a pas ce scope, ou le compte ne peut plus le détenir ;
- `Erreur: accès réservé aux administrateurs` : outil † appelé par un compte `user` ;
- `Erreur: outil sans scope déclaré: <outil>` : outil exposé sans entrée dans la table outil → scope (bug serveur, refusé par sécurité).

---

## Connexion depuis Claude Desktop

1. Connectez-vous à l’Admin → **Paramètres → Mes tokens API** → créez un token avec les scopes nécessaires.
2. Copiez le secret `gpx_pat_…` (affiché une seule fois).
3. Ajoutez le bloc suivant dans `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "goproxify": {
      "url": "https://<admin-host>:9443/mcp",
      "headers": {
        "Authorization": "Bearer gpx_pat_<votre-token>"
      }
    }
  }
}
```

Depuis Claude Code (CLI) :

```bash
claude mcp add goproxify \
  --transport http \
  --url https://<admin-host>:9443/mcp \
  --header "Authorization: Bearer gpx_pat_<votre-token>"
```

---

## Outils (tools)

### `list_proxies`

Liste toutes les routes proxy configurées.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "px_01abc",
    "name": "app.example.com",
    "enabled": true,
    "host": "app.example.com",
    "type": "http",
    "tls": true
  }
]
```

---

### `get_proxy`

Retourne la configuration complète d'un proxy.

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|--------------------------------------|
| `id`      | string | ✓      | ID, nom ou domaine du proxy          |

**Réponse :** objet JSON complet du proxy (backends, LB, headers, snippets…)

---

### `create_proxy`

Crée une nouvelle route proxy (HTTP, TCP ou UDP). Le `backend` doit appartenir à l'allowlist de destinations MCP (`GET/PUT /api/v1/mcp-access/allowed-backends` ; défaut : réseaux privés et suffixes `*.internal`/`*.local`/`*.svc`) — même règle pour `update_proxy`.

| Paramètre     | Type    | Requis | Description                                           |
|---------------|---------|--------|-------------------------------------------------------|
| `host`        | string  | ✓      | Domaine cible (ex : `app.example.com`)                 |
| `backend`     | string  | ✓      | URL du backend (ex : `http://10.0.0.5:3000`)          |
| `tls_enabled` | boolean | —      | Active HTTPS (défaut : `false`)                        |
| `type`        | string  | —      | `http` (défaut), `tcp`, `udp`                          |
| `lb`          | string  | —      | `round_robin` (défaut), `weighted`, `adaptive`         |

**Réponse exemple :**
```json
{ "id": "px_02def", "host": "app.example.com", "backend": "http://10.0.0.5:3000", "type": "http", "lb": "round_robin" }
```

---

### `update_proxy`

Met à jour un proxy existant (champs partiels).

| Paramètre     | Type    | Requis | Description                                    |
|---------------|---------|--------|------------------------------------------------|
| `id`          | string  | ✓      | ID, nom ou domaine du proxy                    |
| `host`        | string  | —      | Nouveau domaine                                |
| `backend`     | string  | —      | Remplace la liste `backends` par une URL       |
| `tls_enabled` | boolean | —      | Active ou désactive HTTPS                      |
| `lb`          | string  | —      | `round_robin`, `weighted`, `adaptive`          |
| `enabled`     | boolean | —      | Active ou désactive la route                   |

**Réponse :** `{ "id", "name", "enabled", "config" }`

---

### `set_proxy_enabled`

Active ou désactive un proxy sans modifier sa configuration.

| Paramètre | Type    | Requis | Description                         |
|-----------|---------|--------|-------------------------------------|
| `id`      | string  | ✓      | ID, nom ou domaine                  |
| `enabled` | boolean | ✓      | `true` = activer, `false` = couper  |

---

### `delete_proxy`

Supprime un proxy par son ID.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `id`      | string | ✓      | ID du proxy à supprimer  |

**Réponse :** `{ "deleted": "px_01abc" }`

---

### `list_nodes`

Liste les nœuds passerelle et Agent avec leurs métriques en temps réel.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "nd_01",
    "node_name": "edge-eu-west",
    "role": "edge",
    "version": "1.4.2",
    "status": "online",
    "cpu_pct": 12.5,
    "mem_pct": 38.2,
    "last_seen_at": "2026-08-02T10:00:00Z"
  }
]
```

---

### `list_agents`

Liste les Agents vus via le plan de contrôle WebSocket (`pending`, `approved`, `revoked`).

**Paramètres :** aucun  
**Scope :** `nodes:read` + rôle admin

**Réponse exemple :**
```json
[
  { "id": "agent-1", "name": "agent-1", "version": "0.3.0", "status": "pending", "seen_at": "2026-08-08T10:00:00Z" }
]
```

---

### `approve_agent`

Approuve un Agent en attente (broadcast `approve_agent` aux passerelles).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID de l'Agent      |

**Scope :** `nodes:write` + rôle admin

---

### `revoke_agent`

Révoque un Agent (ferme la session WS et invalide le HMAC).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID de l'Agent      |

**Scope :** `nodes:write` + rôle admin

---

### `list_alert_events`

Alertes déclenchées (30 jours conservés), la plus récente d'abord. Scope : `alerts:read`.

| Paramètre | Type   | Requis | Description                                                  |
|-----------|--------|--------|--------------------------------------------------------------|
| `days`    | number | —      | Fenêtre en jours (défaut 30, max 30)                         |
| `trigger` | string | —      | Déclencheur, ex. `slo_burn`, `high_error_rate`, `node_offline` |
| `node`    | string | —      | Nom de passerelle (lu dans le détail de l'événement)         |
| `limit`   | number | —      | Événements max (défaut 100, max 500)                         |

Chaque événement : `id`, `rule_id`, `rule_name`, `trigger`, `detail`, `channels`, `title`, `body`, `priority`, `silenced`, `acked`, `acked_by`, `acked_at`, `fired_at`. `silenced: true` : bloqué par un silence actif (`list_silences`), `channels` vide. `acked: true` : accusé de réception (`ack_alert_event`), les paliers d'escalade restants ne renotifient plus.

---

### `list_alerts`

Liste les règles d'alerting avec leurs déclencheurs et canaux de notification.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "al_01",
    "name": "CPU critique",
    "enabled": true,
    "scope": {},
    "triggers": ["cpu_pct > 90"],
    "channels": ["email-ops"],
    "cooldown_sec": 300,
    "priority": 1
  }
]
```

---

### `get_metrics`

Retourne les KPIs de trafic des dernières 24 heures.

| Paramètre | Type   | Requis | Description                                             |
|-----------|--------|--------|---------------------------------------------------------|
| `proxy`   | string | —      | Domaine à filtrer (laisser vide = tout le trafic)       |

**Réponse exemple :**
```json
{
  "requests": 142800,
  "errors": 214,
  "error_rate": 0.15,
  "avg_latency_ms": 42,
  "unique_ips": 3812,
  "window": "24h"
}
```

---

### `get_proxy_metrics`

Retourne, par host, le débit, le taux d'erreurs 5xx et le p95 du dernier relevé, avec la série de
débit récente. L'Admin relève les passerelles toutes les 10 s et garde 1 h d'historique en mémoire
(vide juste après un démarrage de l'Admin). Scope requis : `metrics:read`.

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|----------------------------------------------------------|
| `host`    | string | —      | Host à filtrer (laisser vide = tous)                     |
| `points`  | number | —      | Points de la série, un toutes les 10 s (défaut 60, max 360) |

**Réponse exemple :**
```json
{
  "interval_s": 10,
  "sampled_at": "2026-09-26T13:11:37+02:00",
  "proxies": [
    { "host": "myapp.example.fr", "requests_per_second": 3.8, "error_rate": 0.002, "p95_ms": 9.3, "series": [3.7, 4.0, 3.8] }
  ]
}
```

---

### `list_backups`

Liste les 20 derniers snapshots de sauvegarde.

**Paramètres :** aucun  
**Scope :** `backups:read` + rôle admin

**Réponse exemple :**
```json
[
  {
    "id": "bk_01",
    "name": "backup-2026-08-02",
    "size_bytes": 2097152,
    "created_at": "2026-08-02T03:00:00Z"
  }
]
```

---

### `list_users`

Liste les comptes utilisateurs avec leur rôle. Les données sensibles (hash du mot de passe) ne sont jamais exposées.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  { "id": "usr_01", "email": "admin@example.fr", "role": "superadmin", "created_at": "2026-01-10T08:00:00Z" },
  { "id": "usr_02", "email": "ops@example.fr",   "role": "operator",   "created_at": "2026-02-15T09:30:00Z" }
]
```

**Rôles possibles :** `superadmin`, `admin`, `operator`, `viewer`

---

### `list_snippets`

Liste les snippets middleware réutilisables (rate-limit, en-têtes de sécurité, authentification…).

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "sn_01",
    "name": "rate-limit-api",
    "type": "rate_limit",
    "config": { "requests_per_second": 100, "burst": 200 },
    "created_at": "2026-03-01T10:00:00Z"
  }
]
```

---

### `list_domains`

Liste les domaines gérés avec leur fournisseur DNS et l'état du certificat.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "dm_01",
    "domain": "example.fr",
    "edge_id": "nd_01",
    "dns_provider": "cloudflare",
    "cert_method": "dns",
    "delegation_mode": "passthrough",
    "cert_expires_at": "2026-11-01T00:00:00Z",
    "created_at": "2026-01-01T00:00:00Z"
  }
]
```

`delegation_mode` : `passthrough` (tunnel TLS) ou `terminate` (TLS sur la passerelle d'entrée + proxy HTTP(S)). Voir [delegation.md](delegation.md).

---

### `list_certs`

Liste les certificats TLS gérés avec leur émetteur et leur durée de validité restante.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "ct_01",
    "domain": "app.example.fr",
    "issuer": "Let's Encrypt",
    "expires_at": "2026-11-01T00:00:00Z",
    "days_until_expiry": 91,
    "updated_at": "2026-08-01T04:00:00Z"
  }
]
```

Un `days_until_expiry` négatif indique un certificat expiré.

---

### `list_logs`

Retourne les 100 derniers logs d'accès, filtrables par domaine, niveau ou `request_id`.

| Paramètre    | Type   | Requis | Description                                                        |
|--------------|--------|--------|--------------------------------------------------------------------|
| `domain`     | string | —      | Filtrer par domaine proxy                                          |
| `level`      | string | —      | Filtrer par niveau : `info`, `warn`, `error`                       |
| `request_id` | string | —      | Corrélation exacte : retourne tous les logs portant cet identifiant|

**Réponse exemple :**
```json
[
  {
    "ts": "2026-09-12T10:01:05Z",
    "level": "info",
    "component": "edge",
    "domain": "app.example.fr",
    "method": "GET",
    "path": "/api/users",
    "status": 200,
    "ip": "1.2.3.4",
    "latency_ms": 38,
    "request_id": "req_01jx4z8k",
    "message": ""
  }
]
```

Le champ `request_id` est présent quand le proxy cible a l'option **Injection request_id** activée. Utilisez-le comme filtre pour récupérer l'ensemble des entrées (Admin + Passerelle) d'une même requête HTTP.

Depuis Admin `0.71.2`, `ip_truncated: true` signale une IP tronquée par la passerelle (anonymisation ou pseudonymisation RGPD : `x.x.x.0`, préfixe /48 `2a01:e0a:1::`). Cette valeur regroupe plusieurs clients : `ban_ip` dessus ne bannirait personne (IPv4) ou pas le bon client (IPv6). Le champ est absent pour une IP complète.

---

### `list_teams`

Liste les équipes avec leur nombre de membres.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  { "id": "tm_01", "name": "ops-eu", "member_count": 4, "created_at": "2026-02-01T00:00:00Z" }
]
```

---

### `get_audit_log`

Retourne le journal d'audit des actions administratives.

| Paramètre | Type   | Requis | Description                                     |
|-----------|--------|--------|-------------------------------------------------|
| `limit`   | number | —      | Nombre d'entrées (défaut : 50, max : 200)        |

**Réponse exemple :**
```json
[
  {
    "actor": "admin@example.fr",
    "action": "update",
    "resource": "proxy:px_01abc",
    "detail": "app.example.com",
    "severity": "info",
    "created_at": "2026-08-02T09:55:00Z"
  }
]
```

---

### `get_security_overview`

Compteurs sécurité : bans actifs, menaces CrowdSec, CVE ouvertes, certificats expirant sous 30 jours.

**Paramètres :** aucun  
**Scope :** `audit:read` + rôle admin (comme `GET /api/v1/security`)

---

### `list_security_bans`

Liste les bans IP (Fail2Ban, CrowdSec, natif).

| Paramètre      | Type    | Requis | Description                                      |
|----------------|---------|--------|--------------------------------------------------|
| `ip`           | string  | —      | Filtrer par IP (sous-chaîne)                     |
| `source`       | string  | —      | `native`, `fail2ban`, `crowdsec`                 |
| `active_only`  | boolean | —      | Uniquement les bans non expirés                  |
| `edge`         | string  | —      | Passerelle (nom du nœud ou id du token) : ses bans et les bans globaux |

Chaque ban renvoyé porte `edge_name` (passerelle d'origine, vide = ban global).

**Scope :** `audit:read` + rôle admin

---

### `create_security_ban`

Crée un ban IP natif (**permanent** si `expires_at` omis) et pousse les bans aux passerelles.

| Paramètre     | Type   | Requis | Description                         |
|---------------|--------|--------|-------------------------------------|
| `ip`          | string | ✓      | Adresse IP                          |
| `reason`      | string | —      | Motif                               |
| `domain`      | string | —      | Domaine ciblé (vide = global)       |
| `expires_at`  | string | —      | Expiration RFC3339, enregistrée en UTC ; omis = permanent ; date illisible → erreur |

**Scope :** `security:write`

---

### `delete_security_ban`

Supprime le ban et lève tous les bans de son IP sur chaque passerelle, y compris ceux posés localement (Fail2Ban, Sentinel, règles) — voir [Déban](security.md#déban).

| Paramètre | Type   | Requis | Description   |
|-----------|--------|--------|---------------|
| `id`      | string | ✓      | ID du ban     |

**Scope :** `security:write`

---

### `ban_ip`

Banne une IP directement depuis le MCP (insère dans `security_bans`, pousse aux passerelles). Un seul ban par IP, d'id `mcp-<ip>` : un nouvel appel pour la même IP remplace son motif et son expiration.

| Paramètre    | Type   | Requis | Description                               |
|--------------|--------|--------|-------------------------------------------|
| `ip`         | string | ✓      | Adresse IP à bannir                       |
| `reason`     | string | —      | Motif du ban                              |
| `expires_at` | string | —      | Expiration RFC3339, enregistrée en UTC ; omis = permanent ; date illisible → erreur |

**Scope :** `security:write` (depuis Admin `0.69.6` ; aucun scope n'était vérifié auparavant)  
**Réponse :** `{ "id": "mcp-<ip>", "ip": "<ip>", "reason": "…", "permanent": true|false }` (`reason` vaut `mcp_ban` si omis)

---

### `unban_ip`

Lève le ban d'une IP (supprime de `security_bans`) et tous ses bans sur chaque passerelle, y compris ceux posés localement (Fail2Ban, Sentinel, règles) même si l'Admin ne les connaît pas — voir [Déban](security.md#déban). La correspondance est exacte : un ban Fail2Ban IPv6 porte sur un /64, il se lève en passant le préfixe tel que le renvoie `list_security_bans` (`2a01:e0a:1:2::/64`), pas une adresse qu'il contient.

| Paramètre | Type   | Requis | Description         |
|-----------|--------|--------|---------------------|
| `ip`      | string | ✓      | Adresse IP à débannir |

**Scope :** `security:write` (depuis Admin `0.69.6` ; aucun scope n'était vérifié auparavant)  
**Réponse :** `{ "ip": "<ip>", "deleted": <n> }` (`deleted` : nombre de bans supprimés de `security_bans`, `0` si l'Admin n'en connaissait aucun — le déban est tout de même envoyé aux passerelles)

---

### `list_rules`

Liste les règles automatiques configurées dans le moteur de règles.

Tous les outils du moteur de règles, des planifications, des playbooks et des silences sont réservés au rôle admin, comme `/api/v1/rules-engine`, `/api/v1/scheduled-tasks` et `/api/v1/playbooks` : lecture `audit:read`, action ou modification `security:write`.

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau de règles `{ id, name, enabled, condition, action, cooldown_sec, fire_count, last_fired_at }`

---

### `run_rule`

Déclenche l'évaluation immédiate d'une règle. Par défaut en `dry_run` (aucune action exécutée). Si un silence actif couvre la règle, `detail.silenced` vaut `true` et l'action n'est pas exécutée même hors dry-run.

| Paramètre | Type    | Requis | Description                                  |
|-----------|---------|--------|-----------------------------------------------|
| `id`      | string  | Oui    | ID de la règle                                |
| `dry_run` | boolean | Non    | `false` pour exécuter réellement l'action (défaut `true`) |

**Scope :** `security:write` + rôle admin (même en `dry_run`, comme `POST /api/v1/rules-engine/rules/:id/run`)  
**Réponse :** `{ matched, dry_run, detail }`

---

### `list_rule_history`

Liste le journal d'exécution du moteur de règles (200 dernières entrées), y compris les non-déclenchements et les entrées silencées.

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, rule_id, rule_name, cond_result, action_taken, detail, error, fired_at }`

---

### `replay_rule_history`

Rejoue l'action d'une entrée d'historique en échec (`list_rule_history`), en réutilisant le `detail` capturé au déclenchement d'origine — la condition n'est pas réévaluée.

| Paramètre    | Type   | Requis | Description                          |
|--------------|--------|--------|----------------------------------------|
| `history_id` | number | Oui    | ID de l'entrée d'historique            |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `list_rule_versions`

Liste l'historique des versions d'une règle (20 dernières, la plus récente en premier) — un instantané par création/modification/restauration.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|---------------------|
| `rule_id` | string | Oui    | ID de la règle       |

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ version, name, description, enabled, condition, action, cooldown_sec, created_at }`

---

### `restore_rule_version`

Restaure une règle à une version antérieure (condition, action, cooldown, activation, nom, description). La restauration devient elle-même une nouvelle version.

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|----------------------------------------|
| `rule_id` | string | Oui    | ID de la règle                         |
| `version` | number | Oui    | Numéro de version (`list_rule_versions`) |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `list_scheduled_tasks`

Liste les planifications (cron) : exécutent une action du moteur de règles à heure fixe, indépendamment de toute condition.

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, name, cron_expr, action, enabled, last_run_at, created_at }`

---

### `create_scheduled_task`

Crée une planification.

| Paramètre   | Type    | Requis | Description                                          |
|-------------|---------|--------|--------------------------------------------------------|
| `name`      | string  | Oui    | Nom de la planification                                |
| `cron_expr` | string  | Oui    | Expression cron 5 champs (`minute heure jour-du-mois mois jour-de-semaine`), ex. `"0 3 * * *"` |
| `action`    | object  | Oui    | Action à exécuter : `{ type, ...paramètres }` (mêmes types que `create_rule`) |
| `enabled`   | boolean | —      | Activer immédiatement (défaut `true`)                  |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ id, name }`

---

### `update_scheduled_task`

Met à jour une planification existante. Mêmes paramètres que `create_scheduled_task`, plus `id` (requis).

**Scope :** `security:write` + rôle admin

---

### `delete_scheduled_task`

| Paramètre | Type   | Requis | Description                    |
|-----------|--------|--------|----------------------------------|
| `id`      | string | Oui    | ID de la planification à supprimer |

**Scope :** `security:write` + rôle admin

---

### `run_scheduled_task`

Exécute immédiatement l'action d'une planification, indépendamment de son expression cron.

| Paramètre | Type   | Requis | Description             |
|-----------|--------|--------|----------------------------|
| `id`      | string | Oui    | ID de la planification      |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `list_scheduled_task_runs`

Liste les 100 dernières exécutions d'une planification (30 jours conservés).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|------------------------|
| `id`      | string | Oui    | ID de la planification |

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, success, error, ran_at }`

---

### `list_pending_actions`

Liste les actions du moteur de règles mises en attente d'approbation humaine (règles avec `require_approval`).

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|-------------------------------------------------------------|
| `status`  | string | —      | `pending` (défaut), `approved`, `rejected`, ou `all`         |

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, rule_id, rule_name, action, detail, status, created_at, decided_at, decided_by }`

---

### `approve_pending_action`

Approuve une action en attente : elle est exécutée immédiatement (détail capturé au déclenchement, condition non réévaluée).

| Paramètre | Type   | Requis | Description                                |
|-----------|--------|--------|-----------------------------------------------|
| `id`      | string | Oui    | ID de l'action en attente (`list_pending_actions`) |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `reject_pending_action`

Refuse une action en attente : elle ne sera jamais exécutée.

| Paramètre | Type   | Requis | Description                                |
|-----------|--------|--------|-----------------------------------------------|
| `id`      | string | Oui    | ID de l'action en attente (`list_pending_actions`) |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `list_playbooks`

Liste les playbooks (séquences d'étapes déclenchables via une règle, une planification, ou manuellement).

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, name, description, steps, enabled, created_at, updated_at }`

---

### `create_playbook`

Crée un playbook.

| Paramètre     | Type    | Requis | Description                                                       |
|---------------|---------|--------|---------------------------------------------------------------------|
| `name`        | string  | Oui    | Nom du playbook                                                     |
| `steps`       | array   | Oui    | `[{"type":"action","action":{...}}, {"type":"wait","wait_sec":900}, {"type":"condition","condition":{...}}, {"type":"approval"}]` |
| `description` | string  | —      | Description                                                         |
| `enabled`     | boolean | —      | Activer immédiatement (défaut `true`)                               |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ id, name }`

---

### `update_playbook`

Met à jour un playbook existant. Mêmes paramètres que `create_playbook`, plus `id` (requis).

**Scope :** `security:write` + rôle admin

---

### `delete_playbook`

| Paramètre | Type   | Requis | Description                |
|-----------|--------|--------|-------------------------------|
| `id`      | string | Oui    | ID du playbook à supprimer     |

**Scope :** `security:write` + rôle admin

---

### `run_playbook_now`

Démarre l'exécution d'un playbook depuis sa première étape.

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|------------------------|
| `id`      | string | Oui    | ID du playbook         |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ run_id }` — à suivre avec `get_playbook_run`.

---

### `list_playbook_runs`

Liste les 50 dernières exécutions d'un playbook.

| Paramètre | Type   | Requis | Description    |
|-----------|--------|--------|-------------------|
| `id`      | string | Oui    | ID du playbook      |

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, current_step, status, log, started_at, updated_at, finished_at }`

---

### `get_playbook_run`

Détail d'une exécution : étape courante, statut, journal de chaque étape.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|----------------------|
| `run_id`  | string | Oui    | ID de l'exécution     |

**Scope :** `audit:read` + rôle admin  
**Réponse :** `{ id, playbook_id, playbook_name, steps, current_step, status, log, context, started_at, updated_at, finished_at }`

---

### `approve_playbook_run`

Approuve une exécution suspendue à une étape d'approbation : reprend à l'étape suivante.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|----------------------|
| `run_id`  | string | Oui    | ID de l'exécution     |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `reject_playbook_run`

Refuse une exécution suspendue à une étape d'approbation : l'exécution s'arrête.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|----------------------|
| `run_id`  | string | Oui    | ID de l'exécution     |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ ok: true }`

---

### `list_silences`

Liste les fenêtres de silence, communes au moteur de règles et au moteur d'alertes (suspendent l'exécution des actions / l'envoi des notifications ; la condition ou l'événement reste évalué et journalisé).

**Scope :** `audit:read` + rôle admin  
**Réponse :** tableau `{ id, name, rule_ids, starts_at, ends_at, created_at, active }`

---

### `create_silence`

Crée une fenêtre de silence, pour toutes les règles des deux moteurs (`rule_ids` omis) ou une liste choisie (IDs issus de `list_rules` et/ou `list_alerts`).

| Paramètre   | Type   | Requis | Description                              |
|-------------|--------|--------|-------------------------------------------|
| `name`      | string | Oui    | Nom de la fenêtre de silence               |
| `starts_at` | string | Oui    | Début, RFC3339 (tout décalage horaire, stocké en UTC) |
| `ends_at`   | string | Oui    | Fin, RFC3339 (doit être après `starts_at`) |
| `rule_ids`  | array  | Non    | IDs de règles (moteur de règles et/ou d'alertes) concernées, vide = toutes |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ id }`

---

### `export_automation`

Exporte en YAML toute la configuration d'automatisation (règles, canaux d'alerte, silences), réimportable telle quelle (GitOps). Les canaux exportent leur config en clair : à traiter comme un secret.

**Scope :** `audit:read` + rôle admin  
**Réponse :** `{ yaml: "<document>" }`

---

### `import_automation`

Importe un document YAML au format de `export_automation`. Règles et canaux sont upsertés par nom (créés ou mis à jour) ; les silences sont toujours créés, dates ramenées en UTC (RFC3339, quotées ou non, ou `AAAA-MM-JJ HH:MM:SS` en UTC) — un silence aux dates illisibles est ignoré.

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|----------------------------------------|
| `yaml`    | string | Oui    | Document YAML (voir `export_automation`) |

**Scope :** `security:write` + rôle admin  
**Réponse :** `{ rules_created, rules_updated, channels_created, channels_updated, silences_created }`

---

### `rotate_cert`

Force le renouvellement ACME d'un domaine en vidant la date d'expiration en base (le prochain cycle d'auto-renouvellement émettra un nouveau certificat) et pousse les routes aux passerelles.

| Paramètre | Type   | Requis | Description                              |
|-----------|--------|--------|------------------------------------------|
| `domain`  | string | ✓      | Domaine cible (ex : `app.example.fr`)    |

**Scope :** `domains:write` (comme `POST /api/v1/domains/:id/renew`)  
**Réponse :** `{ "domain": "<domain>", "status": "renew_requested" }` (le domaine est créé s'il n'était pas encore géré)

---

### `get_cert_status`

Retourne le statut d'expiration de tous les certificats avec KPIs globaux (ok / warning / critical / expired).

| Paramètre | Type   | Requis | Description                                    |
|-----------|--------|--------|------------------------------------------------|
| `domain`  | string | —      | Filtrer sur un domaine spécifique              |

**Scope :** `certs:read`  
**Réponse :** `{ "certs": [...], "total": N, "ok": N, "warning": N, "critical": N, "expired": N }`

---

### `list_cert_deploy_targets`

Liste les cibles de déploiement configurées pour un certificat (webhook, ssh_exec) avec leur dernier statut.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|-------------------|
| `cert_id` | string | ✓      | ID du certificat  |

**Scope :** `certs:read`

---

### `trigger_cert_deploy`

Déclenche immédiatement le déploiement d'un certificat vers une cible spécifique.

| Paramètre   | Type   | Requis | Description                     |
|-------------|--------|--------|---------------------------------|
| `target_id` | string | ✓      | ID de la cible de déploiement   |

**Scope :** `certs:write`  
**Réponse :** `{ "target_id": "...", "cert_id": "...", "type": "webhook|ssh_exec", "status": "triggered" }`

---

### `import_cert`

Importe un certificat externe (non-ACME) en fournissant le PEM et la clé privée. Le domaine est extrait automatiquement du CN ou des SAN.

| Paramètre  | Type   | Requis | Description                                          |
|------------|--------|--------|------------------------------------------------------|
| `cert_pem` | string | ✓      | Certificat PEM (`-----BEGIN CERTIFICATE-----`)       |
| `key_pem`  | string | ✓      | Clé privée PEM                                       |
| `issuer`   | string | —      | Émetteur (défaut : `custom`)                         |

**Scope :** `certs:write`  
**Réponse :** `{ "domain": "...", "issuer": "...", "expires_at": "...", "status": "imported" }`

---

### `create_internal_ca`

Crée une nouvelle autorité de certification interne (CA racine auto-signée ECDSA P-256), pour émettre des certificats serveur/client internes hors ACME.

| Paramètre        | Type   | Requis | Description                              |
|------------------|--------|--------|-------------------------------------------|
| `name`           | string | ✓      | Nom de la CA (identifiant lisible)         |
| `common_name`    | string | ✓      | Common Name du certificat racine           |
| `validity_years` | number | —      | Durée de validité en années (défaut : 10)  |

Tous les outils de CA interne sont réservés au rôle admin, comme `/api/v1/internal-ca`.

**Scope :** `certs:write` + rôle admin  
**Réponse :** objet CA (`id`, `name`, `subject`, `cert_pem`, `not_after`, `created_at`).

---

### `list_internal_cas`

Liste les autorités de certification internes.

_Aucun paramètre._

**Scope :** `certs:read` + rôle admin

---

### `get_ech_status`

État d'Encrypted Client Hello : activation, nom public, clés (jamais les clés privées) et valeur `ech=` à publier dans l'enregistrement DNS HTTPS.

_Aucun paramètre._

**Scope :** `certs:read` + rôle admin

---

### `issue_internal_cert`

Émet un certificat serveur ou client signé par une CA interne.

| Paramètre       | Type   | Requis | Description                                  |
|-----------------|--------|--------|------------------------------------------------|
| `ca_id`         | string | ✓      | ID de la CA interne émettrice                  |
| `common_name`   | string | ✓      | Common Name du certificat                      |
| `sans`          | array  | —      | Noms alternatifs (DNS ou IP)                   |
| `usage`         | string | —      | `server` ou `client` (défaut : `server`)       |
| `validity_days` | number | —      | Durée de validité en jours (défaut : 397)      |

**Scope :** `certs:write` + rôle admin  
**Réponse :** objet certificat (`id`, `ca_id`, `common_name`, `usage`, `sans`, `serial`, `cert_pem`, `not_after`, `revoked`, `created_at`).

---

### `list_internal_certs`

Liste les certificats émis par une CA interne.

| Paramètre | Type   | Requis | Description          |
|-----------|--------|--------|------------------------|
| `ca_id`   | string | ✓      | ID de la CA interne    |

**Scope :** `certs:read` + rôle admin

---

### `revoke_internal_cert`

Révoque un certificat émis par une CA interne.

| Paramètre | Type   | Requis | Description                |
|-----------|--------|--------|------------------------------|
| `cert_id` | string | ✓      | ID du certificat émis        |

**Scope :** `certs:write` + rôle admin  
**Réponse :** `{ "cert_id": "...", "status": "revoked" }`

---

### `list_security_threats`

Décisions CrowdSec synchronisées (`security_threats`).

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|--------------------------------------|
| `limit`   | number | —      | Défaut 100, max 500                  |

Trié par `last_seen_at` décroissant. Chaque résultat inclut `edge_name` (Passerelle d'origine) et `occurrences` (nombre de fois où cette menace ip+scenario a été observée ; `last_seen_at` reflète la plus récente).

**Scope :** `audit:read` + rôle admin

---

### `list_security_cves`

CVE détectées sur les backends.

| Paramètre         | Type    | Requis | Description                          |
|-------------------|---------|--------|--------------------------------------|
| `status`          | string  | —      | `open`, `ignored`, `resolved`        |
| `critical_only`   | boolean | —      | CVSS ≥ 7 uniquement                  |
| `kev_only`        | boolean | —      | Uniquement les CVE du catalogue CISA KEV (exploitation active) |

Chaque résultat inclut désormais `edge_name` — la passerelle d'origine ayant remonté la CVE (vide pour les entrées antérieures à cette colonne) — ainsi que `kev` (bool, exploitation activement observée, catalogue CISA) et `epss_score` (0-1, probabilité d'exploitation sous 30 jours, modèle EPSS de FIRST.org), rafraîchis en fin de scan (Admin `0.52.3`).

**Scope :** `audit:read` + rôle admin

---

### `get_prism_anomalies`

Anomalies détectées par Prism : pic d'erreurs, IP dominante, pays en erreur, backend en difficulté, part de bots élevée. Scope : `logs:read`.

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|----------------------------------------------------------|
| `hours`   | number | —      | Fenêtre analysée en heures (défaut 24, max 720)          |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes  |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                           |

Chaque résultat : `kind`, `level` (`critical` | `warning`), `subject`, `label`, `value`, `baseline`, `count`. Mêmes règles que `GET /api/v1/prism/anomalies` : l'IP dominante n'est jamais une IP tronquée par l'anonymisation RGPD ni `[pseudonymisé]`.

---

### `get_prism_slo`

SLO de disponibilité (réponses non-5xx) sur une fenêtre glissante : disponibilité, budget d'erreur restant, vitesse de consommation sur 1 h et 6 h, état (`ok`, `warning`, `critical`, `exhausted`). Scope : `logs:read`.

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|----------------------------------------------------------|
| `target`  | number | —      | Objectif en % (défaut : objectif enregistré, 99.9)       |
| `days`    | number | —      | Fenêtre en jours (défaut 30, max 90)                     |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes  |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                           |

---

### `get_prism_geo`

Trafic par pays (requêtes, erreurs, taux d'erreur, IPs bannies) ou par ville (position approximative issue de la géolocalisation IP). Scope : `logs:read`.

| Paramètre | Type   | Requis | Description                                                        |
|-----------|--------|--------|--------------------------------------------------------------------|
| `level`   | string | —      | `country` (défaut) ou `city`                                       |
| `hours`   | number | —      | Fenêtre analysée en heures (défaut 24, max 720)                    |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes            |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                                     |
| `limit`   | number | —      | Villes retournées (défaut 300, max 1000) ; ignoré au niveau pays   |

---

### `simulate_sentinel_config`

Dry-run Sentinel : rejoue les access logs récents contre une config candidate et la compare à la config actuelle, **sans rien modifier**. Permet de répondre à « si j'applique cette règle, combien de requêtes légitimes auraient été bloquées dans la dernière heure ? » avant de faire `PUT /security/threat-config`. Scope : `logs:read` + rôle admin (la route REST équivalente est réservée aux admins).

| Paramètre | Type    | Requis | Description |
|-----------|---------|--------|-------------|
| `config`  | object  | ✓      | Champs Sentinel à surcharger sur la config actuelle (mêmes noms que `threat-config`, config du groupe HA si la passerelle en fait partie : `rate_limit`, `rate_window`, `rate_ban_threshold`, `error_threshold`, `error_window`, `custom_lists`, `whitelist`, `score_threshold`, `ban_duration`) |
| `hours`   | number  | —      | Fenêtre rejouée (défaut `1`, max `24`) |
| `domain`  | string  | —      | Limiter le rejeu à un domaine |
| `edge`    | string  | —      | Passerelle dont la config actuelle sert de base (défaut : config globale) |

Réponse : `current` et `candidate` (`events`, `blocked`, `blocked_by_ban`, `legit_blocked`, `blocked_ips`, `by_reason`, `bans`, `top_ips`), `delta` (candidat − actuel), `events_replayed`, `truncated` (plafond 200 000 événements, les plus récents sont conservés), `skipped_unattributable_ip`.

- Le rejeu utilise le moteur Sentinel réel sur l'horloge des logs, en mode `block` ; une IP bannie pendant le rejeu reste bloquée pour la durée du ban.
- `legit_blocked` compte les requêtes bloquées qui avaient reçu un statut `< 400` : indicateur de faux positifs, pas une certitude.
- **Non simulé** : listes par défaut (UA/path/IP téléchargées), `global_rps`, règles User-Agent (l'UA n'est pas conservé dans les logs Admin) et WAF (ni en-têtes ni corps conservés). Les IP pseudonymisées ou tronquées par l'anonymisation (RGPD) sont ignorées et comptées dans `skipped_unattributable_ip`.
- Équivalent REST (bouton « Simuler » de la page Sentinel) : `POST /api/v1/security/threat-config/simulate`, voir `docs/api_specs.md`. Équivalent CLI : `goproxify security threat simulate`.

---

## Infrastructure / wizard architecture

Scopes PAT : `nodes:read` (lecture) / `nodes:write` (écriture). Alignés sur `/api/v1/declared-nodes`, `/api/v1/bootstrap-tickets`, `/api/v1/nodes/{id}/accept|reject`.

### `get_architecture`

Architecture déclarée (`architecture.json`, référentiel de la topologie) : nœuds passerelle / Agent avec leur hôte (`config.host`), région et capacités (HA, TLS, Docker, Portainer…), plus les domaines. Scope : `nodes:read` + rôle admin (comme `GET /api/v1/architecture`).

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `version` | string | —      | Nom d'une version conservée (`architecture-….json`, voir `goproxify architecture versions`) ; vide = version courante |

Retourne `{schema_version, nodes, domains}` (même format que `GET /api/v1/architecture`). Une version qui n'existe pas renvoie une erreur ; rien n'est restauré.

---

### `get_topology_live`

État temps réel de la topologie : pour chaque passerelle et Agent, santé, CPU/mémoire, débit (req/s sur 60 s), taux de refus (403/429) et d'erreurs 5xx, score de risque 0-100 avec son facteur dominant, plus le nombre de bans actifs. Même réponse que `GET /api/v1/nodes/live` (formule du score : voir [api_specs.md](api_specs.md)). Scope `nodes:read`.

**Paramètres :** aucun

---

### `list_declared_nodes`

Liste les nœuds déclarés (toile architecture) pas encore connectés.

**Paramètres :** aucun

---

### `create_declared_node`

Déclare (ou met à jour) un nœud passerelle/Agent pour le suivi wizard / auto-accept.

| Paramètre       | Type   | Requis | Description                |
|-----------------|--------|--------|----------------------------|
| `role`          | string | ✓      | `edge` ou `agent`          |
| `name`          | string | ✓      | Nom du nœud                |
| `region`        | string | —      | Région                     |
| `environment`   | string | —      | Environnement              |
| `config`        | object | —      | Config JSON libre          |

---

### `delete_declared_node`

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID (`dn_…`)        |

---

### `create_bootstrap_ticket`

Crée un ticket one-shot : URL `/i/{token}`, script `.sh`, QR PNG, commande `curl|bash`.

| Paramètre         | Type    | Requis | Description                          |
|-------------------|---------|--------|--------------------------------------|
| `host_name`       | string  | —      | Nom d’hôte affiché                   |
| `edge_endpoint`   | string  | —      | Endpoint passerelle cible                  |
| `payload`         | object  | —      | Payload JSON (compose / options)     |
| `ttl_hours`       | number  | —      | 1–168 (défaut 24)                    |
| `auto_accept`     | boolean | —      | Auto-accept des nœuds liés (défaut true) |
| `node_names`      | array   | —      | Noms de nœuds pour l’auto-accept     |

---

### `accept_node` / `reject_node`

Accepte ou rejette un nœud en attente (`pending_nodes`) après présentation du pairing secret.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `id`      | string | ✓      | ID du nœud pending       |

---

## Canaux et règles d'alerte

Scopes PAT : `alerts:read` (lecture) / `alerts:write` (création, suppression, accusé de réception), alignés sur `/api/v1/alert-channels`, `/api/v1/alert-rules` et `/api/v1/alert-events`.

### `list_alert_channels`

Liste les canaux de notification (email, webhook, ntfy, Gotify, Jira…).

**Paramètres :** aucun

---

### `create_alert_channel`

Crée un canal de notification.

| Paramètre | Type   | Requis | Description                                    |
|-----------|--------|--------|------------------------------------------------|
| `name`    | string | ✓      | Nom du canal                                   |
| `type`    | string | ✓      | `email`, `webhook`, `ntfy`, `gotify`, `jira`, `linear`, `github`, `gitlab`, `zammad`, `glpi`, `slack`, `teams`, `telegram`, `sms` |
| `config`  | object | ✓      | Configuration dépendant du type                |

**Réponse :** `{ "id": "ac_…", "name": "…", "type": "…" }`

---

### `delete_alert_channel`

| Paramètre | Type   | Requis | Description         |
|-----------|--------|--------|---------------------|
| `id`      | string | ✓      | ID du canal         |

---

### `list_alert_rules`

Liste les règles d'alerte avec leurs déclencheurs, scopes et canaux associés.

**Paramètres :** aucun

---

### `create_alert_rule`

Crée une règle d'alerte.

| Paramètre          | Type    | Requis | Description                                          |
|--------------------|---------|--------|------------------------------------------------------|
| `name`             | string  | ✓      | Nom de la règle                                      |
| `channels`         | array   | ✓      | IDs des canaux de notification                       |
| `triggers`         | array   | ✓      | Déclencheurs (`list_alert_triggers`)                 |
| `enabled`          | boolean | —      | Activée par défaut (`true`)                          |
| `cooldown_sec`     | number  | —      | Délai anti-spam en secondes (défaut : 300)           |
| `priority`         | number  | —      | Priorité (0 = normale, plus élevé = plus urgent)     |
| `group_window_sec` | number  | —      | Fenêtre de regroupement en secondes (défaut 0 = désactivé) — fusionne les événements correspondants en une seule notification |
| `escalation`       | array   | —      | Paliers `[{"after_sec":900,"channels":["id"]}]` : sans accusé de réception (`ack_alert_event`) avant `after_sec`, renotifie (`channels` vide = ceux de la règle) |
| `scope`            | object  | —      | Scope : `nodes`, `domain_glob`, `components`, `min_severity`, etc. |

**Réponse :** `{ "id": "ar_…", "name": "…", "enabled": true }`

---

### `ack_alert_event`

Accuse réception d'un événement d'alerte : les paliers d'escalade déjà programmés le revérifient à leur échéance et ne renotifient plus.

| Paramètre | Type   | Requis | Description                       |
|-----------|--------|--------|--------------------------------------|
| `id`      | string | Oui    | ID de l'événement (`list_alert_events`) |

**Réponse :** `{ ok: true }`

---

### `delete_alert_rule`

| Paramètre | Type   | Requis | Description         |
|-----------|--------|--------|---------------------|
| `id`      | string | ✓      | ID de la règle      |

---

## Fournisseurs d'authentification

Scopes PAT : `audit:read` (lecture) / `security:write` (écriture), plus le rôle admin, comme `/api/v1/auth-providers`.

### `list_auth_providers`

Liste les fournisseurs d'authentification externe (OIDC, SAML, LDAP…).

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  { "id": "ap_01", "name": "Google", "type": "oidc", "enabled": true }
]
```

---

### `create_auth_provider`

Crée un fournisseur d'authentification.

| Paramètre | Type    | Requis | Description                                  |
|-----------|---------|--------|----------------------------------------------|
| `name`    | string  | ✓      | Nom du fournisseur                            |
| `type`    | string  | ✓      | `oidc`, `saml`, `ldap`, `github`, `google`   |
| `config`  | object  | ✓      | Configuration dépendant du type              |
| `enabled` | boolean | —      | Activé par défaut (`true`)                   |

---

### `delete_auth_provider`

| Paramètre | Type   | Requis | Description                |
|-----------|--------|--------|----------------------------|
| `id`      | string | ✓      | ID du fournisseur          |

---

## Profils IP

Scopes PAT : `audit:read` (lecture) / `security:write` (écriture), comme `/api/v1/ip-profiles`.

### `list_ip_profiles`

Liste les profils IP (listes blanches/noires CIDR, GeoIP, réputation).

Chaque profil inclut l'état du rafraîchissement automatique : `last_updated_at` (dernier succès), `last_error`, `consecutive_failures` et `next_attempt_at` (vides / 0 quand le feed est à jour).

**Paramètres :** aucun

---

### `create_ip_profile`

Crée un profil IP.

| Paramètre     | Type   | Requis | Description                           |
|---------------|--------|--------|---------------------------------------|
| `name`        | string | ✓      | Nom du profil                         |
| `action`      | string | ✓      | `allow` ou `block`                    |
| `cidrs`       | array  | —      | Liste de CIDRs/IPs                    |
| `countries`   | array  | —      | Codes pays ISO 3166-1 alpha-2         |
| `description` | string | —      | Description libre                     |

---

### `delete_ip_profile`

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID du profil IP    |

---

## Snippets

Scopes PAT : `snippets:read` (lecture, `list_snippets`) / `snippets:write` (écriture), comme `/api/v1/snippets`.

### `create_snippet`

Crée un snippet middleware réutilisable (WAF, rate-limit, headers…).

| Paramètre | Type   | Requis | Description                                      |
|-----------|--------|--------|--------------------------------------------------|
| `name`    | string | ✓      | Nom du snippet                                   |
| `type`    | string | ✓      | `waf`, `rate_limit`, `headers`, `cors`, `auth`   |
| `config`  | object | ✓      | Configuration dépendant du type                  |

---

### `delete_snippet`

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|-------------------|
| `id`      | string | ✓      | ID du snippet     |

---

## Domaines

Scopes PAT : `domains:read` (lecture, `list_domains`) / `domains:write` (écriture, y compris `rotate_cert`), comme `/api/v1/domains`.

### `create_domain`

Déclare un nouveau domaine géré (ACME DNS-01).

| Paramètre | Type   | Requis | Description                            |
|-----------|--------|--------|----------------------------------------|
| `domain`  | string | ✓      | Domaine (ex : `app.example.fr`)        |
| `edge_id` | string | —      | ID de la passerelle d'entrée                    |

**Réponse :** `{ "id": "dm_…", "domain": "app.example.fr", "edge_id": "…" }`

---

### `renew_domain`

Force le renouvellement du certificat d'un domaine.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|-------------------|
| `id`      | string | ✓      | ID du domaine     |

---

## Certificats

### `obtain_cert`

Déclenche l'émission ACME d'un certificat pour un domaine.

| Paramètre | Type   | Requis | Description                     |
|-----------|--------|--------|---------------------------------|
| `domain`  | string | ✓      | Domaine cible                   |

**Scope :** `certs:write` (comme `POST /api/v1/certs`)

---

## GoProxify Access (portail)

Scopes PAT : `portal:read` (lecture) / `portal:write` (écriture + push). Réservés aux rôles admin.

### `get_portal_config` / `update_portal_config` / `push_portal`

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | ✓ | Nom du nœud passerelle |
| `enabled`, `ssh_port`, `http_port`, `public_host`, `allow_personal_targets`, `require_2fa`, `session_ttl_sec`, `session_mode`, `ha_session_mode` | — | — | Champs optionnels pour `update_portal_config` (`ha_session_mode` : `sticky` ou `shared`, groupe HA) |

### Catalogue — `list_portal_destinations`, `create_portal_destination`, `update_portal_destination`, `delete_portal_destination`, `preview_portal_destinations`

Création / mise à jour : `edge_name`, `name`, `kind` (`ssh`\|`docker`), `host`, `port`, `agent_name`, `container`, `tags`.

### Users — `list_portal_users`, `invite_portal_user`, `update_portal_user`, `delete_portal_user`, `resend_portal_invite`

Invitation : `email`, `home_edge`, `tags` (SMTP Admin requis).

### Sessions en direct — `list_portal_sessions`, `terminate_portal_session`

`list_portal_sessions` (`edge`, scope `portal:read`) liste les connexions en cours ; `terminate_portal_session` (`edge`, `id`, scope `portal:write`) en ferme une.

### Accès temporaires — `list_portal_access_requests`, `decide_portal_access_request`

`list_portal_access_requests` (`edge`, `status` optionnel, scope `portal:read`) liste les demandes ; `decide_portal_access_request` (`id`, `decision` = `approve`\|`deny`\|`revoke`, `duration_min` optionnel pour `approve`, scope `portal:write`) tranche une demande.

### Politique d'accès — `get_portal_policy`, `set_portal_policy`

`get_portal_policy` (`edge`, scope `portal:read`) lit la politique ; `set_portal_policy` (`edge` + `hours_enabled`, `days`, `start_time`, `end_time`, `timezone`, `ip_allow`, `idle_timeout_min`, `record_sessions`, `record_retention_days`, scope `portal:write`) la remplace en entier : un champ absent revient à « pas de restriction ».

### Enregistrements — `list_portal_recordings`, `delete_portal_recording`

`list_portal_recordings` (`edge`, scope `portal:read`) liste les métadonnées ; `delete_portal_recording` (`edge`, `id`, scope `portal:write`) supprime un enregistrement. Le contenu se rejoue dans l'interface ou s'exporte avec la CLI.

### `list_portal_audit`

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | — | Filtrer par passerelle |
| `limit` | number | — | Défaut 100, max 500 |

### Templates — `list_portal_templates`, `get_portal_template`, `upsert_portal_template`, `delete_portal_template`, `push_portal_templates`

Clés stables (`login`, `vault`, …). `upsert` : `key`, `body`, `name` optionnel.

---

## Ressources (resources)

Les ressources permettent à un client MCP d'accéder aux données sans construire d'appel d'outil explicite.

| URI                            | Description                              |
|--------------------------------|------------------------------------------|
| `goproxify://proxies`          | Liste de toutes les routes proxy         |
| `goproxify://nodes`            | Nœuds passerelle et Agent                      |
| `goproxify://agents`           | Agents WS (pending / approved)           |
| `goproxify://alerts`           | Règles d'alerting                        |
| `goproxify://users`            | Comptes utilisateurs et rôles            |
| `goproxify://snippets`         | Middlewares réutilisables                |
| `goproxify://domains`          | Domaines gérés et état TLS               |
| `goproxify://certs`            | Certificats TLS et expiration            |
| `goproxify://certs/monitor`    | Statut d'expiration avec KPIs (ok/warning/critical/expired) |
| `goproxify://logs`             | 100 derniers logs d'accès                |
| `goproxify://security/bans`    | Bans IP actifs                           |
| `goproxify://security/threats` | Décisions CrowdSec                       |
| `goproxify://security/cves`    | CVE ouvertes                             |
| `goproxify://portal/destinations` | Catalogue destinations Access         |
| `goproxify://portal/users`     | Utilisateurs Access                      |
| `goproxify://portal/templates` | Templates HTML Access                    |
| `goproxify://portal/audit`     | Journal d'audit Access                   |
| `goproxify://declared-nodes`   | Nœuds déclarés (wizard architecture)     |

Toutes les ressources retournent `mimeType: application/json`.

Lire une ressource exige les mêmes droits que l'outil qu'elle expose (`goproxify://users` → `list_users`, `goproxify://security/bans` → `list_security_bans`, `goproxify://certs/monitor` → `get_cert_status`, etc. ; voir [Contrôle d'accès des outils](#contrôle-daccès-des-outils)). Un refus renvoie une erreur JSON-RPC `-32603` dont le message est `scope insuffisant: <scope>` ou `accès réservé aux administrateurs` (depuis Admin `0.70.0` ; les ressources n'étaient auparavant soumises à aucun contrôle).

---

## Gestion des erreurs

Les erreurs suivent le standard JSON-RPC 2.0 :

| Code    | Signification            |
|---------|--------------------------|
| -32700  | Erreur de décodage JSON  |
| -32601  | Méthode ou outil inconnu |
| -32602  | Paramètres invalides     |
| -32603  | Erreur interne           |
| -32002  | Ressource introuvable    |

Les erreurs d'outil (proxy introuvable, backend SQL) sont retournées avec `isError: true` dans le contenu, sans code d'erreur JSON-RPC — le LLM reçoit le message et peut proposer une correction. Les refus d'autorisation (`scope insuffisant`, `accès réservé aux administrateurs`, `outil sans scope déclaré`) suivent le même format, voir [Contrôle d'accès des outils](#contrôle-daccès-des-outils).
