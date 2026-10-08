# Spécifications API — Goproxify Administration

Base URL : `https://<admin-host>:9443`

Toutes les réponses sont en JSON. Authentification par `Authorization: Bearer <token>` sauf les endpoints publics marqués `[PUBLIC]`.

---

## Authentification

### `POST /api/v1/auth/login` `[PUBLIC]`

Échange email/mot de passe contre un JWT de session.

**Corps :**
```json
{ "email": "admin@example.fr", "password": "..." }
```

**Réponse 200 :**
```json
{ "token": "eyJ...", "expires_at": "2026-07-16T09:00:00Z" }
```

---

### `POST /api/v1/auth/logout`

Invalide le token de session courant.

---

## Tokens API utilisateur (PAT)

Les PAT (`gpx_pat_*`) sont créés en self-service. Ils authentifient l’API REST (scopes) et sont **obligatoires** pour `/mcp`. Distincts des tokens d’appairage `/api/v1/tokens`.

### `GET /api/v1/me/tokens`

Liste les PAT de l’utilisateur connecté (métadonnées ; pas de secret). Session JWT uniquement.

### `GET /api/v1/me/tokens/scopes`

Catalogue des scopes avec indicateur `available` selon le rôle courant.

### `POST /api/v1/me/tokens`

Crée un PAT. Le secret en clair n’est retourné qu’une fois.

**Corps :**
```json
{
  "label": "Claude Desktop",
  "scopes": ["proxies:read", "nodes:read"],
  "expires_at": "2027-01-01T00:00:00Z"
}
```

`expires_at` est optionnel (RFC3339). Scopes bornés aux droits du compte.

**Réponse 201 :** inclut `token` (`gpx_pat_…`).

### `DELETE /api/v1/me/tokens/:id`

Révoque immédiatement le PAT.

### Scope PAT exigé par route

Une requête authentifiée par PAT doit porter le scope de la route (`403 scope insuffisant: <scope>` sinon), en plus du rôle exigé par la route (`adminOnly` : admin/superadmin). Les sessions UI (JWT) ne sont soumises qu'au rôle. `GET` = lecture, toute autre méthode = écriture.

| Préfixe de route | Lecture (`GET`) | Écriture |
|---|---|---|
| `/api/v1/proxies` | `proxies:read` | `proxies:write` (`DELETE` : `proxies:delete`) |
| `/api/v1/nodes`, `/declared-nodes`, `/bootstrap-tickets`, `/node-events`, `/discovered-containers`, `/backends/health`, `/agents` | `nodes:read` | `nodes:write` |
| `/api/v1/alert-channels`, `/alert-channel-types`, `/alert-rules`, `/alert-events` | `alerts:read` | `alerts:write` |
| `/api/v1/domains` | `domains:read` | `domains:write` |
| `/api/v1/certs` (dont `deploy-targets`, `pull-tokens`), `/api/v1/internal-ca`, `/api/v1/ech` | `certs:read` | `certs:write` |
| `/api/v1/snippets` | `snippets:read` | `snippets:write` |
| `/api/v1/security`, `/ip-profiles`, `/auth-providers`, `/rules-engine`, `/scheduled-tasks`, `/playbooks` | `audit:read` | `security:write` |
| `/api/v1/import` | `audit:read` | `import:write` |
| `/api/v1/portal`, `/portal-page-templates` | `portal:read` | `portal:write` (contenu d'un terminal — rejeu, observation — : `portal:write` même en `GET`) |
| `/api/v1/prism`, `/metrics/proxies`, `/metrics/summary` | `metrics:read` | idem |
| `/api/v1/logs` (`/logs/reveal-ip` : `gdpr:reveal`) | `logs:read` | `logs:write` |
| `/api/v1/backups` · `/users` · `/tokens` · `/teams` · `/audit` · `/pairing-secret` | `backups:read` · `users:read` · `users:read` · `teams:read` · `audit:read` · `pairing:read` | idem |

Depuis Admin `0.70.0` : les écritures sur `/alert-*`, `/domains`, `/certs` exigent `alerts:write`, `domains:write`, `certs:write` (le scope de lecture suffisait auparavant), `/internal-ca` exige `certs:read` / `certs:write`, et `/rules-engine`, `/scheduled-tasks`, `/playbooks` exigent `audit:read` / `security:write` (aucun scope n'était vérifié auparavant, seul le rôle admin). Ces scopes d'écriture sont réservés aux rôles admin et superadmin ; un PAT existant ne les reçoit pas, il faut en créer un nouveau.

Depuis Admin `0.70.4` : les écritures sur `/logs` (réglages, effacement RGPD) exigent `logs:write`, réservé aux rôles admin et superadmin ; `logs:read` suffisait auparavant.

### Rôle exigé pour les écritures

Routes ouvertes en lecture à tout compte authentifié mais dont les écritures sont réservées à certains rôles. Le contrôle s'applique aux sessions UI (JWT) comme aux PAT, en plus du scope PAT ci-dessus.

| Routes | Lecture (`GET`) | Écriture (toute autre méthode) |
|---|---|---|
| `/api/v1/certs` (dont `deploy-targets`, `pull-tokens`), `/domains`, `/alert-channels`, `/alert-rules` (dont `simulate`), `/alert-events` (`ack`), `/ip-profiles` (dont `refresh`) | tout compte | admin / superadmin — sinon `403 accès réservé aux administrateurs` |
| `/api/v1/snippets` | tout compte | admin / superadmin, ou `user` disposant d'au moins un grant `write` (équipe ou direct) — sinon `403 accès insuffisant` |
| `/api/v1/logs` (`settings`, `by-ip`, `by-user`) | tout compte | admin / superadmin — sinon `403 accès réservé aux administrateurs` |
| `/api/v1/logs/reveal-ip` | — | détenteur de `gdpr:reveal` (superadmin, rôle `dpo`, droit accordé en propre ou via une équipe), admin ou non — sinon `403` (depuis Admin `0.78.0` ; superadmin seul auparavant) |

Depuis Admin `0.70.4` pour `/logs` : un compte `user` pouvait désactiver l'anonymisation ou la pseudonymisation des IP, réduire la rétention et effacer des logs par IP ou par utilisateur.

Depuis Admin `0.70.2` : jusque-là, seul le scope PAT était vérifié sur ces écritures ; un compte `user` connecté à l'interface pouvait obtenir, importer ou supprimer des certificats, générer un pull token (et donc récupérer la clé privée via `/cert-bundle`), créer ou renouveler des domaines, et créer ou supprimer des canaux et règles d'alerte.

---

## Initialisation (First Boot)

### `GET /api/v1/setup/status` `[PUBLIC]`

Indique si l'Administration est initialisée.

**Réponse 200 :**
```json
{ "initialized": false }
```

### `POST /api/v1/setup/init` `[PUBLIC]`

Crée le compte administrateur initial (uniquement si `initialized: false`).

**Corps :**
```json
{ "email": "admin@example.fr", "password": "..." }
```

---

## Tokens d'appairage

### `POST /api/v1/tokens`

Génère un token cryptographique pour une passerelle ou un Agent.

**Corps :**
```json
{ "role": "edge", "node": "serveur-production-1", "ttl": "0" }
```

`role` : `edge` | `agent`
`ttl` : durée de validité (ex: `"24h"`) ou `"0"` pour permanent.

**Réponse 201 :**
```json
{
  "token": "gpx_edge_a1b2c3d4e5f6...",
  "node": "serveur-production-1",
  "role": "edge",
  "created_at": "2026-07-15T10:00:00Z"
}
```

### `GET /api/v1/tokens`

Liste les tokens générés.

### `DELETE /api/v1/tokens/:id`

Révoque un token.

---

## Proxies

### `GET /api/v1/proxies`

Liste tous les proxies (manuels + labels).

**Réponse 200 :**
```json
[
  {
    "id": "uuid",
    "domain": "myapp.example.fr",
    "source": "manual",
    "enabled": true,
    "meta": { "nom": "Interface myapp", "environment": "production" }
  },
  {
    "id": "uuid",
    "domain": "termix.example.fr",
    "source": "label",
    "readonly": true,
    "meta": { "container": "termix_app_1" }
  }
]
```

`source` : `manual` | `label`
`readonly: true` pour les proxies issus de labels.

### `POST /api/v1/proxies/dry-run`

Valide une config de proxy **sans rien enregistrer ni pousser** (éditeur YAML de la modale proxy, bouton « Tester (dry run) »). Scope `proxies:write` + droit d'écriture sur le domaine.

Corps : `{ "id": "<uuid, optionnel>", "config": {…}, "enabled": true, "probe": false }`.
`probe: true` ajoute une sonde réseau (DNS, TLS, connexion des backends).

Réponse : `{ "ok": bool, "summary": {…}, "checks": [{ "check", "status": "ok|warning|error|skip", "message", "details": [] }], "probes": [{ "step", "status", "message", "latency_ms" }], "route": {…} }`.
Contrôles : `syntax`, `structure` (type, host, backends, URLs, et — depuis Edge `0.51.0` — blocs `ip_filter`, `geo_ip`, `bot`, `waf` validés comme les snippets : mode, CIDR, code pays, expression WAF ; voir `GET /api/v1/detector-types`), `conflicts` (host/alias/port face aux proxies en production des passerelles ; `warning` si aucune passerelle ne répond), `enabled`. (Admin `0.72.0`)

### `POST /api/v1/proxies`

Crée un proxy manuel. Corps : objet conforme au schéma canonique (section `proxies`).

Options avancées de la configuration (Edge 0.37.0, détail dans [fonctionnalites.md](fonctionnalites.md)) : `split`, `maintenance`, `signed_url`, `graphql`, `bandwidth`, `redact_json`, `rate_limit.quota` / `quota_period` / `key_by` (`header:<nom>`, `cookie:<nom>`), condition `jwt_claim`, et pour `sso` : `provider: "oauth2_proxy"`, `forward_auth_signin_url`, `forward_auth_timeout_ms`.

### `GET /api/v1/proxies/:domain`

Détail complet d'un proxy.

### `PUT /api/v1/proxies/:domain`

Met à jour un proxy manuel (interdit sur `source: "label"`).

### `DELETE /api/v1/proxies/:domain`

Supprime un proxy manuel.

### `PATCH /api/v1/proxies/{id}`

Corps `{"enabled": bool}`. Active/désactive le proxy (republié sur toutes les passerelles qui l'hébergent). Utilisé notamment par la Vue Proxy pour « Mettre en maintenance » / « Réactiver ».

### `POST /api/v1/proxies/{id}/cache/purge`

Vide le cache disque de ce proxy sur toutes les passerelles qui l'hébergent (best-effort, un proxy peut être répliqué sur plusieurs Edges). No-op si le cache n'est pas activé pour ce proxy. Corps JSON optionnel `{"tags": ["news"], "paths": ["/blog/*", "/a?x=1"]}` : sans corps, tout le cache est vidé ; sinon seules les entrées portant l'un des tags (en-tête `Cache-Tag` ou `Surrogate-Key` de la réponse backend, retiré avant l'envoi au client) ou correspondant à l'un des chemins (avec ou sans query, suffixe `*` = préfixe) sont supprimées. Réponse `{"purged": <nombre d'entrées supprimées>}`. Relaie en interne `POST /internal/v1/proxies/{id}/cache/purge` (même corps) sur chaque Edge (le cache est stocké par route, un répertoire dédié par proxy — voir `router.Route.Cache`).

Options de cache par proxy (`cache`) : `stale_while_revalidate` (ex. `"30s"` : une entrée expirée est servie `X-Cache: STALE` pendant qu'une seule requête la revalide en arrière-plan), `stale_if_error` (ex. `"1h"` : une entrée expirée remplace une réponse 5xx du backend), `disable_coalescing` (par défaut, les requêtes simultanées sur un même MISS sont regroupées : une seule atteint le backend, les autres reçoivent `X-Cache: COALESCED`). Les directives `stale-while-revalidate` / `stale-if-error` du backend ont priorité sur ces valeurs.

Champ `proxy_protocol` de la config d'un proxy (`"v1"` ou `"v2"`, vide = désactivé) : la passerelle écrit l'en-tête PROXY (IP du client) au début de chaque connexion vers le backend HTTP ou le passthrough TLS ; le backend doit l'attendre. Une route HTTP ouvre alors une connexion backend par requête (pas de keep-alive). Toute autre valeur est refusée par la validation (dry-run). La lecture de l'en-tête en entrée se règle dans la configuration de la passerelle (`network.proxy_protocol: { enabled, trusted_cidrs }`), pas via l'API.

### `POST /api/v1/proxies/:domain/enable`
### `POST /api/v1/proxies/:domain/disable`

Active/désactive un proxy à chaud.

Écritures sur les deploy targets et pull tokens (`POST`, `DELETE`, `trigger`) : admin / superadmin (voir [Rôle exigé pour les écritures](#rôle-exigé-pour-les-écritures)).

### `GET /api/v1/certs/:id/deploy-targets`

Liste les deploy targets d'un certificat. Réponse : `[{id, cert_id, name, type, config, trigger_on, last_deploy, last_status, created_at}]`. Les champs `secret` du manifeste du type sont masqués (`••••••••`) : secret HMAC d'un webhook et **clé privée SSH** d'un `ssh_exec` — avant Admin `0.125.0`, seul `secret` l'était et la clé privée SSH était renvoyée en clair.

### `POST /api/v1/certs/:id/deploy-targets`

Crée un deploy target. Corps : `{name, type ("webhook"|"ssh_exec"), config, trigger_on ("on_renewal"|"manual")}`. `400` si le type est inconnu, un champ requis est vide ou la config contient une clé absente du manifeste (voir `GET /api/v1/cert-deploy-types`).|"manual")}`.

### `PUT /api/v1/certs/:id/deploy-targets/:targetID`

Modifie une cible (`name`, `config`, `trigger_on` ; le type ne change pas). La configuration envoyée **remplace** l'ancienne, sauf les secrets du manifeste (clé privée SSH, secret HMAC) : absents, vides ou égaux au masque, ils sont conservés. Omettre `host_fingerprint` relance la mémorisation de la clé d'hôte SSH à la prochaine connexion. `400` (champ requis vide, clé inconnue, `trigger_on` invalide), `404` (cible inconnue).

### `DELETE /api/v1/certs/:id/deploy-targets/:targetID`

Supprime un deploy target.

### `POST /api/v1/certs/:id/deploy-targets/:targetID/trigger`

Déclenche manuellement le déploiement vers ce target.

### `GET /api/v1/cert-deploy-types`

Manifestes des types de cible de déploiement, dans l'ordre d'affichage : `webhook`, `ssh_exec`. Chaque type est un **module** du registre commun (`internal/admin/certdeploy`, ADR 0007) ; `fields` décrit sa configuration (`key`, `kind`, `secret`, `required`, `multiline`). Un type ajouté au code de l'Admin apparaît ici et dans le formulaire sans autre modification. Lecture pour tout compte authentifié (`certs:read` pour un PAT).

- **`webhook`** : `url` (requise), `secret` (HMAC-SHA256, en-tête `X-GoProxify-Signature`). Les schémas non HTTP, les adresses link-local et les métadonnées cloud sont refusés (`URL refusée`) ; le réseau interne reste permis.
- **`ssh_exec`** : `host`, `user`, `private_key`, `script` (requis), `host_fingerprint` (optionnel, `SHA256:…` comme `ssh-keygen -lf`). **Confiance à la première utilisation** (Admin `0.126.0`) : laissé vide, l'empreinte de la clé d'hôte vue à la première connexion authentifiée est mémorisée dans la cible puis vérifiée aux déploiements suivants ; une clé d'hôte qui change (machine usurpée ou réinstallée) fait échouer le déploiement jusqu'à ce que l'empreinte soit corrigée (`PUT`) ou remplacée par `ignore`, qui désactive la vérification (machines éphémères). Avant, la clé d'hôte n'était jamais vérifiée. Le script reçoit `GPX_DOMAIN`, `GPX_CERT_PEM`, `GPX_KEY_PEM` et `GPX_EXPIRES_AT` (RFC 3339, UTC). Depuis Admin `0.125.0`, les valeurs sont transmises telles quelles, retours à la ligne compris : avant, le PEM arrivait avec des `\n` littéraux et `GPX_EXPIRES_AT` était toujours vide.

### `GET /api/v1/certs/:id/deploy-targets/:targetID/history`

Retourne les 50 derniers résultats de déploiement pour ce target.

### `GET /api/v1/certs/:id/pull-tokens`

Liste les pull tokens d'un certificat (valeur du token non retournée, seulement les métadonnées).

### `POST /api/v1/certs/:id/pull-tokens`

Génère un nouveau pull token. Corps : `{name?, format ("pem"|"key"|"fullchain"|"json"), max_uses (0=illimité), ttl_hours (0=pas d'expiration)}`. Réponse : `{id, token, format}` — le token est retourné **une seule fois**.

### `DELETE /api/v1/certs/:id/pull-tokens/:tokenID`

Révoque un pull token.

### `GET /api/v1/cert-bundle` *(endpoint public)*

Télécharge un bundle de certificat via un token. Paramètres : `token` (requis), `format` (`pem`|`key`|`fullchain`|`json`). Pas d'authentification — le token fait office d'autorisation. Vérifie TTL et max_uses.

```bash
curl -s "https://admin.example.com/api/v1/cert-bundle?token=TOKEN&format=fullchain" -o fullchain.pem
```

---

### `GET /api/v1/metrics/proxies`

Débit, erreurs et latence **par host**, avec un historique récent. L'Admin relève toutes les
passerelles actives toutes les 10 s (`GET /internal/v1/metrics/summary`), calcule la différence
entre deux relevés successifs (une remise à zéro des compteurs après redémarrage est détectée),
additionne les passerelles et garde 1 h de série par host **en mémoire** : la série repart de zéro
au redémarrage de l'Admin. Scope PAT : `metrics:read`.

| Paramètre | Description |
|-----------|-------------|
| `points`  | Nombre de points de la série (défaut 60, max 360 ; un point = 10 s) |

**Réponse 200 :**
```json
{
  "interval_s": 10,
  "sampled_at": "2026-09-26T13:11:37+02:00",
  "proxies": [
    {
      "host": "myapp.example.fr",
      "requests_per_second": 3.8,
      "error_rate": 0.002,
      "p95_ms": 9.3,
      "series": [3.7, 4.0, 3.8]
    }
  ]
}
```

`error_rate` est une **fraction** (0..1) de réponses 5xx sur le dernier intervalle ; `p95_ms` est le
p95 de la latence sur ce même intervalle ; `series` est le débit (req/s) des derniers relevés, du
plus ancien au plus récent. `proxies` est vide (et `sampled_at` nul) tant qu'aucune passerelle n'a
été relevée deux fois.

En plus des séries par host, la réponse porte les agrégats du tableau de bord :

```json
{
  "global": { "requests_per_second": 4.0, "error_rate_5xx": 0.0, "bytes_in_total": 0, "bytes_out_total": 1005480 },
  "edges": [ { "edge_name": "localhost", "requests_per_second": 4.0, "error_rate": 0.0, "p95_ms": 9.5 } ],
  "tls": { "certs": [ { "domain": "myapp.example.fr", "expires_in_seconds": 5184000 } ] }
}
```

`global` = débit et taux de 5xx du dernier intervalle, toutes passerelles et tous hosts confondus ;
`bytes_*_total` = octets cumulés depuis le démarrage des passerelles ; `edges` = dernier intervalle
par passerelle (la page Infrastructure y lit la latence p95 affichée dans le panneau d'une passerelle) ;
`tls.certs` = plus proche expiration par domaine, lue dans les métriques des passerelles.

### `GET /api/v1/metrics/summary`

Synthèse lue par les pages Dashboard, Prism, Domaines/TLS, Infrastructure, Portail et Sécurité :
agrégats du dernier relevé des passerelles (voir `GET /api/v1/metrics/proxies`) et métriques du
processus Admin. Une section est **absente** tant que sa source n'a rien publié. Scope PAT : `metrics:read`.

| Clé | Contenu |
|-----|---------|
| `global`, `edges`, `tls.certs` | comme `/metrics/proxies` ; chaque entrée de `tls.certs` porte en plus `handshake_p95_ms` (pire passerelle) et `active_connections` (somme) quand le domaine a servi des connexions TLS ; `edges[]` ajoute `error_rate` (fraction) |
| `ws` | `admin_connections`, `agent_connections` — connexions WebSocket du plan de contrôle, somme des passerelles |
| `peers` | `avg_sync_ms` — durée moyenne de synchronisation entre passerelles pairs (absent sans pair) |
| `portal.sessions` | `one_shot`, `multi` — sessions du portail actives |
| `waf` | `profiles_active` — profils comportementaux en mémoire |
| `pipeline` | `[{stage, blocked_total}]` — requêtes bloquées par étape du pipeline de sécurité |
| `f2b` | `bans_total`, `scans_total` — Fail2Ban (processus Admin) |
| `crowdsec` | `decisions_new`, `decisions_deleted` — CrowdSec (processus Admin) |
| `rules_engine` | `active_rules`, `actions_total`, `avg_duration_ms`, `evals_per_minute` (nul sans deux relevés) — moteur de règles |

### `GET /api/v1/proxies/:id/revisions`

Liste les révisions sauvegardées d'un proxy. Réponse : `[{"revision":"<uuid>","status":"production|draft","updated_at":"...","created_by":"..."}]`.

### `GET /api/v1/proxies/:id/revisions/diff`

Compare deux révisions d'un proxy. Paramètres : `from` (id de révision ou `"production"`) et `to` (id de révision ou `"latest"`).

Réponse :
```json
{
  "from": {"revision":"...","status":"production","updated_at":"...","created_by":"..."},
  "to":   {"revision":"...","status":"draft","updated_at":"...","created_by":"..."},
  "diffs": [{"key":"backends[0].addr","from":"10.0.0.1:8080","to":"10.0.0.2:8080"}],
  "revisions": [...]
}
```

---

### `GET /api/v1/backups/proxy-history/:proxyID`

Liste les versions sauvegardées (`proxy_history`, 50 dernières) d'un proxy — indépendant du système de révisions passerelle ci-dessus. Réponse : `[{"id","proxy_id","note","created_at"}]` (sans la config).

### `GET /api/v1/backups/proxy-history/:versionID/config`

Retourne la config brute (JSON) d'une version de l'historique — utilisé pour calculer un diff côté client entre deux versions, ou entre une version et la config actuelle.

### `POST /api/v1/backups/proxy-history/:versionID/restore`

Restaure la config de cette version sur le proxy.

---

## Sauvegardes & imports

Contenu détaillé : [sauvegardes.md](sauvegardes.md).

### `GET /api/v1/backups/snapshots/:id/summary`

Résumé du contenu d'un snapshot, sans rien écrire — même format que `import/backup/preview` (`proxies[]`, `user_count`, `token_count`, `pat_count`, `snippet_count`, `channel_count`, `rule_count`, `declared_node_count`, `declared_nodes[]` (`id`, `role`, `name`, `region`, `environment`), `config_row_count`, `config_tables{table: n}`). Utilisé par la fenêtre « Restaurer » de l'Admin. 404 si le snapshot n'existe pas.

Le résumé expose aussi, quand la clé de chiffrement permet de lire les sections chiffrées, `secrets_detail` (`tables`, `files`, `gateways[]` = passerelles dont l'état est sauvegardé, `config_files[]`) et `history_detail` (`tables`, `truncated`) ; `secrets_locked` / `history_locked` valent `true` si la section existe mais ne se déchiffre pas.

### `POST /api/v1/backups/snapshots/:id/restore`

Restaure un snapshot. Corps optionnel `{"selection": {…}}` (mêmes champs que `import/backup/apply`) ; **sans corps**, restauration complète en mode `overwrite` (utilisateurs, tokens, PAT, snippets, canaux, règles, tables de configuration). En `overwrite`, un snapshot de sécurité `avant-restauration-<date>` est pris d'abord ; s'il échoue, la restauration est annulée (500). Réponse : `ImportResult` (dont `secret_rows`, `secret_files`, `secrets_error`). Avec `selection.import_secrets` (ou sans corps, si le snapshot a une section `secrets` et que l'appelant est superadmin), restaure la section secrets chiffrée de `GPX_BACKUP_KEY` : hash des mots de passe, MFA, clés, CA interne, fichiers `state/` et `certs/`. Superadmin seulement (`secrets_error` sinon).

### `POST /api/v1/backups/snapshots`

Crée un snapshot **en arrière-plan** : répond `202 {"status":"started","name":"…"}` aussitôt (une sauvegarde complète peut durer plusieurs dizaines de secondes, au-delà du délai d'un reverse proxy), `409` si une sauvegarde est déjà en cours. L'avancement et le résultat sont dans `GET /backups/status` (`running`, `last_run` : `name`, `ok`, `error`, `at`). Corps optionnel `{"name":"…","history":true}` : `history` joint la section historique chiffrée (journaux, audit, bans passés…, `GPX_BACKUP_KEY` requise). Les planifications portent `include_history`. Restauration (`selection`) : `import_secrets` (hash des mots de passe, MFA, clés, CA interne, fichiers `state/` et `certs/`, config HA dans `restored-config/`, **état des passerelles** renvoyé à chacune), `import_history` (ajout sans écrasement). Les deux sont réservés au superadmin ; la réponse ajoute `secret_rows`, `secret_files`, `gateways[]` (`gateway`, `written`, `rejected`, `error`, `restart_required`), `history_rows`, `secrets_error`, `history_error`.

**Interne (Admin → passerelle)** : `GET /internal/v1/backup/export` renvoie `{files:{chemin: contenu}, skipped:[…]}` ; `POST /internal/v1/backup/restore` réécrit ces fichiers (chemins relatifs filtrés) et répond `{written, rejected, restart_required}`.

### `/api/v1/backups/key`

Clé de chiffrement des sauvegardes. `GET` : `{source: env|file|none, fingerprint, can_change, retired:[{fingerprint, retired_at}]}` (jamais la clé). Superadmin uniquement pour le reste : `POST|PUT` avec `{"action":"generate"}` (clé générée, renvoyée **cette seule fois** dans `key`) ou `{"key":"…"}` (16 caractères au moins) — renvoie `{fingerprint, rotated}`, l'ancienne clé active passant parmi les retirées ; `DELETE` désactive la clé active (conservée parmi les retirées, 204) ; `POST /key/reveal` avec `{"password":"…","fingerprint":"…"}` (empreinte vide = clé active) renvoie la clé après vérification du mot de passe du superadmin ; `POST /key/retired` avec `{"key":"…"}` ajoute une ancienne clé ; `DELETE /key/retired/{fingerprint}` l'oublie. `409` si la clé active vient de `GPX_BACKUP_KEY` (ni changement, ni désactivation, ni révélation), `403` si l'appelant n'est pas superadmin ou si le mot de passe est faux. Toutes ces actions sont auditées.

### `GET /api/v1/backups/status`

État des sauvegardes : `key_set` (GPX_BACKUP_KEY définie), `last_snapshot_at`, `last_verified_at`, `stale[]` (planifications dont une exécution a été manquée), `destinations[]` (`last_ok_at`, `last_error`, `copies`), `running` (présent seulement si une sauvegarde ou une copie externe est en cours : `name`, `phase` parmi `waiting|export|secrets|history|encrypt|store|verify`, `started_at`, `delivering[]` = destinations en cours d'envoi).

### `POST /api/v1/backups/snapshots/:id/verify`

Relit le snapshot stocké : somme de contrôle SHA-256, déchiffrement, format et, s'il existe, déchiffrement de la section secrets. Réponse `{"ok":true}` ou `{"ok":false,"error":"…"}`. `GET /backups/snapshots` expose `sha256`, `verified_at` et `deliveries[]` (copies externes).

### `/api/v1/backups/destinations`

Copies hors serveur de chaque snapshot (10 au plus). `GET` liste ; `POST` crée ; `PUT /:id` modifie ; `DELETE /:id` supprime (les copies déjà déposées sont conservées) ; `POST /:id/test` écrit, relit et supprime un objet (`{"ok":…}`). Corps : `{"name","type":"dir|webdav|s3","enabled","retention","config":{…}}`. `config` — `dir` : `path` (absolu) ; `webdav` : `url`, `username`, `password` ; `s3` : `endpoint`, `bucket`, `access_key`, `secret_key`, `region`, `prefix`, `path_style` (`false` = adressage par sous-domaine). `password` et `secret_key` ne sont jamais renvoyés (`password_set` / `secret_key_set`) ; vides en mise à jour, ils conservent la valeur existante. Admin uniquement.

### `POST /api/v1/import/backup/preview`

Corps : JSON de sauvegarde (32 Mo max). Réponse : résumé (`proxies[]`, `user_count`, `token_count`, `pat_count`, `snippet_count`, `channel_count`, `rule_count`, `declared_node_count`, `config_row_count`, `config_tables{table: n}`). Une `version` ≠ `1` est refusée (400).

### `POST /api/v1/import/backup/apply`

Corps : `{"data": <sauvegarde>, "selection": {"proxy_ids", "import_users", "import_tokens", "import_pats", "import_snippets", "import_alert_channels", "import_alert_rules", "skip_nodes", "import_config", "import_secrets", "on_conflict": "skip|overwrite"}}` (32 Mo max). `proxy_ids` : identifiants des proxies à restaurer (vide = tous, `[""]` = aucun) ; `skip_nodes: true` ne recrée pas la topologie déclarée (restaurée par défaut). En `overwrite`, un snapshot `avant-import-<date>` est pris d'abord. Réponse : `{proxies, users, tokens, pats, snippets, channels, rules, config, declared_nodes, skipped, errors}`.

### `GET /api/v1/import/config-formats`

Formats de configuration tierce pris en charge, dans l'ordre d'affichage. Chaque format est un **module** du registre (`internal/modules`, ADR 0007) ; la CLI (`goproxify import formats`) et le sélecteur de l'Admin en dérivent.

```json
[{ "type": "nginx", "label": "nginx", "fields": [],
   "attrs": { "hint": "Blocs server { }", "extensions": [".conf"], "name_contains": ["nginx"] } }]
```

Formats : `nginx`, `traefik-yaml`, `traefik-toml`, `caddy`, `haproxy`, `goproxify` (export natif), `json` (générique : `host` + `backends`). `attrs` : `hint`, et pour la détection par nom de fichier `extensions`, `basenames`, `name_contains`, `suffixes`.

### `POST /api/v1/import/config/parse` · `POST /api/v1/import/config/apply`

`parse` : corps `{"format", "content"}` ; un `format` inconnu est traité comme du JSON générique. `apply` : corps `{"proxies": [...], "on_conflict": "skip"|"overwrite"}`.

---

## Certificats

Lecture pour tout compte authentifié ; obtention, import et suppression réservés aux admins / superadmins.

### `GET /api/v1/certs`

Liste les certificats gérés.

### `GET /api/v1/certs/{domain}/pem`

Renvoie le certificat public (PEM, `Content-Type: application/x-pem-file`) d'un domaine géré. La clé privée n'est jamais exposée. `404` si le domaine n'a pas de certificat.

### `POST /api/v1/certs/import`

Importe un certificat externe (non-ACME).

**Corps :**
```json
{
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem":  "-----BEGIN PRIVATE KEY-----\n...",
  "issuer":   "custom"
}
```

Le domaine est extrait automatiquement depuis le SAN/CN du certificat. Upsert sur le domaine existant. Le cert est ensuite poussé aux passerelles connectées.

**Réponse 201 :**
```json
{ "id": "abc123", "domain": "*.example.fr", "expires_at": "2027-09-15T00:00:00Z" }
```

### `GET /api/v1/certs/acme-monitor`

Retourne le statut d'expiration de tous les certificats.

**Réponse :**
```json
{
  "total": 5, "ok": 3, "warning": 1, "critical": 1, "expired": 0,
  "certs": [
    {
      "id": "abc123", "domain": "*.example.fr", "domain_id": "dom456", "issuer": "letsencrypt",
      "expires_at": "2026-10-15T00:00:00Z", "updated_at": "2026-09-15T02:00:00Z",
      "days_left": 26, "status": "warning", "dns_provider": "cloudflare", "cert_method": "dns"
    }
  ]
}
```

`status` : `ok` (>30j) · `warning` (≤30j) · `critical` (≤7j) · `expired`
`domain_id` référence `domains.id` (voir `GET/PUT /api/v1/domains/{id}`) — vide si le certificat n'a pas de domaine déclaré correspondant (ex. import manuel via `POST /api/v1/certs/import`).

### `GET /api/v1/acme/providers`

Liste les fournisseurs DNS ACME nommés. Admin uniquement.

**Réponse :**
```json
[
  { "id": "abc123", "name": "cloudflare-prod", "type": "cloudflare", "params": {"api_token": "..."} }
]
```

### `POST /api/v1/acme/providers`

Crée un nouveau fournisseur DNS nommé.

**Corps :**
```json
{ "name": "cloudflare-prod", "type": "cloudflare", "params": {"api_token": "tok_xxx"} }
```

**Réponse :** `201 Created` avec `{"id": "..."}`

### `GET /api/v1/acme/providers/{id}`

Retourne un fournisseur DNS par identifiant.

### `PUT /api/v1/acme/providers/{id}`

Met à jour un fournisseur DNS existant (même corps que POST).

### `DELETE /api/v1/acme/providers/{id}`

Supprime un fournisseur DNS nommé.

### `GET /api/v1/acme/provider-types`

Manifestes des fournisseurs DNS ACME, dans l'ordre d'affichage. Admin uniquement. Chaque fournisseur est un **module** du registre (`internal/modules`, ADR 0007) ; le formulaire de l'Admin, la validation et la lecture de l'environnement en découlent.

```json
[{ "type": "cloudflare", "label": "Cloudflare", "fields": [
  { "key": "api_token", "label": "API Token", "kind": "password", "secret": true, "required": true, "env": "CF_API_TOKEN" },
  { "key": "zone_id", "label": "Zone ID", "kind": "text", "env": "CF_ZONE_ID" } ] }]
```

`env` : variable d'environnement qui fournit la valeur quand un domaine ne la renseigne pas. `attrs.status = "not_implemented"` : réservé à un fournisseur déclaré mais incapable d'émettre (aucun aujourd'hui ; Route 53, qui l'était, fonctionne depuis Admin `0.123.0`). Types : `ovh`, `cloudflare`, `route53`, `hetzner`, `gandi`.

À partir d'Admin `0.122.0`, `POST` et `PUT /api/v1/acme/providers` renvoient `400` pour un type inconnu, un paramètre requis vide ou une clé inconnue ; `GET` masque les paramètres `secret` (`••••••••`) et `PUT` conserve un secret absent, vide ou égal au masque. Avant, la liste renvoyait les jetons en clair.

### `POST /api/v1/certs/request`

Demande un certificat ACME. La méthode suit `domains.cert_method` du domaine : DNS-01 (`dns` + `dns_provider`), HTTP-01 (`acme-http`) ou TLS-ALPN-01 (`acme-tls-alpn`). Avec HTTP-01 / TLS-ALPN-01, l'Admin pose la réponse du challenge sur les passerelles connectées (port 80 / 443 publics du domaine) ; un wildcard est refusé (`400` sur `POST`/`PUT /api/v1/domains`, `cert_method` `acme-http` ou `acme-tls-alpn`).

`edge_id` (passerelle d'entrée) accepte un token passerelle, un `node_name`, ou `ha:<groupe>` pour un groupe HA déclaré dans `architecture.json` : le périmètre domaine est alors posé sur tous les membres et les délégations sont poussées à chacun. Un groupe sans membre renvoie `400 groupe HA introuvable`. `delegated_to_edge_id` reste une passerelle unique.

**Corps :**
```json
{ "domain": "*.example.fr", "acme_provider_id": "abc123" }
```

`acme_provider_id` (facultatif) : identifiant d'un fournisseur DNS nommé (`GET /api/v1/acme/providers`). Depuis Admin `0.123.0` il est réellement utilisé — avant, il était accepté puis ignoré. Priorité à l'émission : **fournisseur nommé > méthode et identifiants du domaine > fournisseur par défaut**. `400` si l'identifiant n'existe pas. Le fournisseur nommé est mémorisé sur le certificat et **réutilisé au renouvellement automatique** ; s'il est supprimé entre-temps, le renouvellement retombe sur les identifiants du domaine.

### `POST /api/v1/certs/:domain/renew`

Force le renouvellement d'un certificat.

### `DELETE /api/v1/certs/:domain`

Supprime un certificat.

---

## CA interne — `/api/v1/internal-ca`

Génération et gestion d'une autorité de certification interne (hors ACME), pour émettre des certificats serveur/client internes. Admin uniquement.

### `GET /api/v1/internal-ca`

Liste les autorités internes.

**Réponse :**
```json
[
  { "id": "abc123", "name": "root", "subject": "GoProxify Internal Root", "cert_pem": "-----BEGIN CERTIFICATE-----\n...", "not_after": "2036-09-24T00:00:00Z", "created_at": "2026-09-24T00:00:00Z" }
]
```

### `POST /api/v1/internal-ca`

Crée une nouvelle CA racine auto-signée (clé ECDSA P-256).

**Corps :**
```json
{ "name": "root", "common_name": "GoProxify Internal Root", "validity_years": 10 }
```

**Réponse 201 :** objet CA (voir ci-dessus).

### `GET /api/v1/internal-ca/{id}/certs`

Liste les certificats émis par la CA `{id}`.

**Réponse :**
```json
[
  { "id": "cert123", "ca_id": "abc123", "common_name": "svc.internal.local", "usage": "server",
    "sans": ["svc.internal.local", "10.0.0.5"], "serial": "1a2b3c...", "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "not_after": "2027-10-26T00:00:00Z", "revoked": false, "created_at": "2026-09-24T00:00:00Z" }
]
```

### `POST /api/v1/internal-ca/{id}/certs`

Émet un certificat serveur ou client signé par la CA `{id}`.

**Corps :**
```json
{ "common_name": "svc.internal.local", "sans": ["svc.internal.local", "10.0.0.5"], "usage": "server", "validity_days": 397 }
```

`usage` : `server` (`ExtKeyUsageServerAuth`) ou `client` (`ExtKeyUsageClientAuth`).

**Réponse 201 :** objet certificat (voir ci-dessus).

### `DELETE /api/v1/internal-ca/{id}/certs/{certID}`

Révoque un certificat émis (marqué `revoked`, ne supprime pas la ligne).

---

## Encrypted Client Hello — `/api/v1/ech`

ECH chiffre le nom du site (SNI) dans le handshake TLS : un observateur réseau ne voit que le **nom public** configuré. Les clés sont générées par l'Admin, poussées aux passerelles (message WS `push_ech_keys`) qui les gardent dans leur cache chiffré. Les clés privées ne sont jamais renvoyées. Admin uniquement.

### `GET /api/v1/ech`

```json
{
  "enabled": true, "public_name": "ech.example.fr",
  "active_config_id": 142,
  "config_list_b64": "AEn+DQBF…",
  "https_record": "ech=\"AEn+DQBF…\"",
  "keys": [{ "id": "…", "config_id": 142, "public_name": "ech.example.fr", "created_at": "…", "retired": false }],
  "warnings": []
}
```

`https_record` est le paramètre à ajouter à l'enregistrement DNS HTTPS (type 65) de chaque domaine protégé (ex. `1 . alpn=h2 ech="…"`). `warnings` contient `no_certificate_for_public_name` quand aucun certificat stocké ne couvre le nom public (une passerelle ne pourrait pas présenter de certificat valide à un client qui rafraîchit sa config).

### `PUT /api/v1/ech`

Corps : `{ "enabled": true, "public_name": "ech.example.fr" }`. Activer sans clé active, ou changer le nom public (gravé dans la config publiée), génère une nouvelle clé et retire l'ancienne. `400` si le nom public est invalide (wildcard, IP, un seul label). Désactiver pousse un jeu vide : les passerelles n'acceptent plus ECH. Répond comme `GET`.

### `POST /api/v1/ech/rotate`

Nouvelle clé active ; l'ancienne devient **retirée** : plus publiée, mais toujours acceptée par les passerelles le temps que les caches DNS expirent. `409` si ECH n'est pas activé. Répond comme `GET`.

### `DELETE /api/v1/ech/keys/{id}`

Supprime une clé **retirée** (`204`) ; `404` pour une clé inconnue ou active.

Limites : ECH n'est servi qu'en TCP (HTTP/1.1, h2), pas en QUIC/HTTP3 ; il est incompatible avec les hôtes en SNI passthrough (le nom interne chiffré n'est pas lisible pour choisir la route).

---

## Canaux de notification — `/api/v1/alert-channels`

Chaque type de canal est un **module** du registre (`internal/modules`) : son manifeste déclare les champs de configuration, ceux qui sont secrets et ceux qui sont requis. L'API, le masquage des secrets et le formulaire de l'interface en découlent.

### `GET /api/v1/alert-channel-types`

Manifestes des types de canal, dans l'ordre d'affichage. Lecture pour tout compte authentifié (`alerts:read`).

```json
[{ "type": "telegram", "label": "Telegram", "fields": [
  { "key": "bot_token", "label": "Bot token", "kind": "password", "secret": true, "required": true },
  { "key": "chat_id", "label": "Chat ID", "placeholder": "-1001234567890", "kind": "text", "required": true } ] }]
```

`kind` : `text`, `password`, `number`, `list` (tableau de chaînes). Types fournis : `email`, `webhook`, `ntfy`, `gotify`, `jira`, `linear`, `github`, `gitlab`, `zammad`, `glpi`, `slack`, `teams`, `telegram`, `sms`.

### `GET /api/v1/auth-provider-types`

Manifestes des 20 types de fournisseur d'authentification (`oidc`, `pocket_id`, `google`, `microsoft`, `entra`, `auth0`, `okta`, `keycloak`, `zitadel`, `casdoor`, `dex`, `github`, `ldap`, `ldap_ad`, `saml`, `basic`, `forward`, `authentik`, `authelia`, `oauth2_proxy`). Les clés sont des chemins pointés (`oidc.client_secret`) ; `basic_users` est une liste dont le mot de passe est secret, clé d'élément `username`. Admin uniquement.

### `/api/v1/auth-providers`

- `GET` (liste) et `GET /:id` : les secrets du manifeste (dont les mots de passe Basic) sont remplacés par `••••••••`. Avant Admin `0.127.0`, la configuration complète était renvoyée en clair.
- `POST` : `400` si le type est inconnu, un champ requis est vide ou une clé est absente du manifeste.
- `PUT /:id` : un secret omis, vide ou masqué est conservé (mots de passe Basic appariés par nom d'utilisateur) tant que le type ne change pas ; `provider` et `name` omis gardent leur valeur.
- `PATCH /:id` `{"enabled": bool}` : active ou désactive sans toucher à la configuration (`204`).

### `GET /api/v1/alert-channels`

Liste des canaux. Les champs `secret` du manifeste sont remplacés par `••••••••`. Avant Admin `0.120.0`, la liste de clés masquées oubliait `webhook_url` (Slack, Teams), `bot_token` (Telegram) et `auth_token` (SMS) : ces secrets étaient renvoyés en clair.

### `POST /api/v1/alert-channels`

Corps : `{ "name", "type", "config", "enabled" }`. `400` si le type est inconnu, si un champ requis manque ou est vide, ou si `config` contient une clé absente du manifeste. Les canaux déjà enregistrés ne sont jamais revalidés.

### `PUT /api/v1/alert-channels/{id}`

Corps : `{ "name", "config", "enabled" }` (le type ne change pas). Un secret absent, vide ou égal au masque est **conservé** : modifier un canal ne l'efface plus. `400` si la configuration obtenue ne passe pas la validation ; `404` si le canal n'existe pas.

### `POST /api/v1/alert-channels/{id}/test`

Envoie un message de test. `DELETE /api/v1/alert-channels/{id}` supprime le canal.

---

## Profils IP

Lecture pour tout compte authentifié ; création, modification, suppression et `refresh` réservés aux admins / superadmins.

### `GET /api/v1/ip-profiles` · `GET /api/v1/ip-profiles/:id`

Liste / détail des profils IP (`id`, `name`, `profile_type`, `mode`, `feed_urls`, `feed_format`, `refresh_interval_h`, `cidrs`, `enabled`, `last_updated_at`…). Champs d'état du rafraîchissement automatique :

| Champ | Description |
|---|---|
| `last_updated_at` | Dernier rafraîchissement **réussi** (un échec ne le modifie pas) |
| `last_error` | Cause du dernier échec ; absent après un succès |
| `consecutive_failures` | Nombre d'échecs consécutifs ; absent (0) après un succès |
| `next_attempt_at` | Prochaine tentative automatique (UTC) après un échec ; absent sinon |

Après un échec (réseau, HTTP ≠ 200, parsing, liste rejetée par le garde-fou), les CIDRs déjà stockés restent appliqués et le profil est retenté avec un délai de 15 min doublé à chaque échec, plafonné à 6 h et à `refresh_interval_h`.

### `POST /api/v1/ip-profiles` · `PUT /api/v1/ip-profiles/:id`

Création / modification. Une liste vient soit d'un feed (`feed_urls`, `feed_format`, `refresh_interval_h`), soit d'une saisie manuelle (`cidrs` : IP ou CIDR, validés, dédupliqués et agrégés). Les deux sont exclusifs, car un rafraîchissement remplacerait la liste manuelle, et un profil manuel n'est jamais rafraîchi. `mode` : `deny` (défaut) ou `allow` ; `profile_type` vaut `custom` par défaut. Un profil s'applique à tout le trafic de chaque passerelle, `allow` prime sur `deny`, les adresses privées ne sont jamais bloquées.

| Cas | Réponse |
|---|---|
| CIDR invalide, `mode` inconnu, `cidrs` avec `feed_urls`, ni `feed_urls` ni `cidrs` (création) | `400 {"error":…}` |
| Création réussie | `201 {"id":…}` |
| Modification réussie | `204` ; sans `cidrs` dans le corps, la liste stockée est conservée |

### `POST /api/v1/ip-profiles/:id/refresh`

Force un rafraîchissement complet (téléchargement inconditionnel, garde-fou de taille ignoré). `200 {"status":"refreshed"}`, ou `400 {"error":…}` en cas d'échec (profil sans feed, feed injoignable…). Le rafraîchissement automatique rejette une nouvelle liste qui perd plus de la moitié d'une liste d'au moins 10 entrées (feed vide ou tronqué) : la liste actuelle est conservée et l'échec est enregistré ; ce endpoint permet de l'accepter.

---

## Snippets

Lecture pour tout compte authentifié ; écritures réservées aux admins / superadmins et aux comptes `user` disposant d'au moins un grant `write`.

### `GET /api/v1/security/engine-types`

Manifestes des moteurs de sécurité globaux : `sentinel` (champs dérivés de la configuration, chemins pointés), `fail2ban`, `crowdsec` (`api_key` secret). Admin uniquement. Outil MCP `list_security_engine_types`, CLI `goproxify security engines`.

### `PUT /api/v1/security/threat-config`, `/fail2ban`, `/crowdsec` — validation

Les trois configurations sont validées avant enregistrement (`400` avec le motif, rien n'est écrit ni poussé) : clé inconnue à tous les niveaux, valeur du mauvais type, durée illisible ou négative, seuil négatif, IP ou CIDR invalide, mode Sentinel hors `block|detect`, code d'erreur HTTP hors 400-599, source de liste non http(s), chemin sans `/` initial, `tarpit.delay_ms` au-delà de 30000 ; CrowdSec activé exige `api_url` (http/https) et `api_key`. `GET /security/crowdsec` remplace `api_key` par `••••••••` (avant Admin `0.130.0`, la clé du bouncer était renvoyée en clair) ; omise, vide ou masquée dans un `PUT`, elle est conservée.

### `GET /api/v1/detector-types`

Manifestes des détecteurs par route : `ip_filter`, `geo_ip`, `bot`, `waf` (champs, secrets, requis). Scope `snippets:read`.

### `/api/v1/snippets` — détecteurs

- `POST` / `PUT` : la configuration d'un snippet `ip_filter`, `geo_ip`, `bot` ou `waf` est validée par son manifeste — clé inconnue, champ requis vide, mode hors `allow|deny` (`ip_filter`, `geo_ip`) ou `block|detect` (`waf`), CIDR invalide, code pays qui n'est pas ISO 3166-1 alpha-2, expression de règle WAF invalide, fournisseur de défi inconnu ⇒ `400`. Les autres types gardent une configuration libre.
- `GET` : `challenge_secret` et `challenge_provider_secret` (bot) sont remplacés par `••••••••` ; omis ou masqués à la modification, ils sont conservés. `PUT` sans `type` conserve le type enregistré ; `404` si le snippet n'existe pas.

### `GET /api/v1/snippets/:section`

`section` : `ip_profiles` | `security_headers` | `tls_profiles` | `rate_limit_policies` | `cors_policies` | `timeout_profiles` | `auth_providers` | `dns_providers`

### `POST /api/v1/snippets/:section`

Crée un snippet custom (`builtin: false` uniquement).

### `PUT /api/v1/snippets/:section/:key`
### `DELETE /api/v1/snippets/:section/:key`

Modification/suppression (interdite sur `builtin: true`).

---

## Nodes (Passerelles & Agents enregistrés)

### `GET /api/v1/nodes`

Liste les passerelles et Agents enregistrés avec leur état.

**Réponse 200 :**
```json
[
  {
    "id": "edge-1",
    "role": "edge",
    "node": "serveur-production-1",
    "ip": "203.0.113.10",
    "status": "healthy",
    "last_seen": "2026-07-15T23:54:00Z"
  }
]
```

### `GET /api/v1/nodes/live`

État temps réel de la topologie : santé, débit et risque de chaque passerelle et Agent. Scope PAT : `nodes:read`. L'UI (Infrastructure → Topologie) l'interroge toutes les 5 s.

**Réponse 200 :**
```json
{
  "window_sec": 60,
  "generated_at": "2026-09-24T20:40:00Z",
  "bans_active": 12,
  "nodes": [
    {
      "node_name": "edge-a", "role": "edge", "status": "online",
      "cpu_pct": 12.5, "mem_pct": 40.1,
      "requests": 600, "rps": 10, "blocked_pct": 33.3, "error_pct": 0,
      "low_traffic": false,
      "risk": 67, "risk_level": "high", "risk_factor": "blocked"
    }
  ]
}
```

Débit et taux viennent des access logs de la dernière minute (`window_sec`), par `node_name`, hors logs de l'Admin. `blocked_pct` = part de `403`/`429`, `error_pct` = part de `5xx`.

**Score de risque (0-100)** : le plus élevé de plusieurs facteurs indépendants, pour que la cause reste lisible (`risk_factor`) :

| Facteur | Score |
|---|---|
| `offline` | 100 si le nœud n'est pas `online` |
| `blocked` | 2 × `blocked_pct` (50 % de refus = 100) |
| `errors` | 4 × `error_pct` (25 % d'erreurs = 100) |
| `resources` | CPU ou mémoire : 0 à 70 %, 100 à 100 % |

`risk_level` : `low` (< 25), `medium` (< 60), `high`. Sous 20 requêtes dans la fenêtre (`low_traffic`), les taux `blocked` et `errors` sont ignorés (bruit statistique). `bans_active` est global (il compte tous les bans, sans filtre par passerelle).

### `DELETE /api/v1/nodes/:id`

Désenregistre un node.

---

## Agents en attente d'approbation

Les Agents qui se connectent pour la première fois via un `JOIN_TOKEN` apparaissent en statut `pending` jusqu'à approbation explicite.

### `GET /api/v1/agents`

Liste tous les Agents (online, pending, offline).

**Réponse 200 :**
```json
[
  {
    "agent_id": "agent-prod-1",
    "name": "agent-prod-1",
    "version": "0.1.0",
    "status": "pending",
    "last_seen_at": "2026-07-30T10:00:00Z"
  }
]
```

### `GET /api/v1/discovery-sources`

Manifestes des sources de découverte de l'Agent, dans l'ordre de démarrage : `docker`, `portainer`, `kubernetes`. Admin uniquement (`nodes:read` pour un PAT). Chaque source est un **module** du registre commun (`internal/agent/sources`, ADR 0007) ; le champ `fields` décrit sa configuration dans `agent.json` (clé, genre, `secret`, `required`). Une source ajoutée au code de l'Agent apparaît ici sans autre modification.

```json
[{ "type": "kubernetes", "label": "Kubernetes", "fields": [
  { "key": "api_server", "label": "API server (empty = in-cluster)", "kind": "text" },
  { "key": "token", "label": "Bearer token (empty = service account)", "kind": "password", "secret": true } ] }]
```

Une source qui n'a pas de section dédiée dans `agent.json` se configure sous `sources.<type>`, validée par son manifeste (champ requis manquant ou clé inconnue : source ignorée, journalisée). Le heartbeat de l'Agent expose désormais la section `kubernetes` (secrets masqués) en plus de `docker` et `portainer`.

### `POST /api/v1/agents/:id/approve`

Approuve un Agent en attente. La passerelle lui envoie immédiatement son `agent_hmac` via la connexion WS active.

**Réponse 200 :**
```json
{ "approved": true }
```

---

## Nœuds déclarés & tickets bootstrap

### `GET /api/v1/declared-nodes`

Liste les nœuds déclarés via le wizard architecture (pas encore connectés, ou reprise de nœuds live).

### `POST /api/v1/declared-nodes`

Déclare un nœud (`role`: `edge`|`agent`, `name`, `region`, `environment`, `config`). Upsert par `(role, name)`.

### `DELETE /api/v1/declared-nodes/:id`

Supprime un nœud déclaré.

### `GET /api/v1/architecture` `[AUTH]`

Rôle admin requis. Retourne le contenu de `architecture.json`, référentiel de la topologie : c'est la source de la vue Infrastructure et du wizard (l'état live n'est qu'une surcouche). Fichier absent = architecture vide.

**Réponse :**
```json
{
  "schema_version": 1,
  "nodes": [
    {"id": "dn_1", "role": "edge", "name": "edge-1", "region": "eu-west",
     "config": {"host": "vps-paris", "internet_exposed": true, "cluster": true, "cluster_group": "ha-1"}}
  ],
  "domains": []
}
```

`config.host` est le nom de l'hôte qui porte le nœud ; les nœuds qui partagent un `host` sont posés sur la même machine.

### `GET /api/v1/architecture/groups` `[AUTH]`

Groupes HA déclarés par le wizard (`config.cluster: true` et `config.cluster_group`) : nom du groupe → membres `{id, name}`. Lecture seule, sans secret ; l'UI s'en sert pour indiquer qu'un réglage de sécurité s'applique à tout le groupe.

### `GET /api/v1/architecture/versions/{name}` `[AUTH]`

Rôle admin requis. Lit une version conservée (même format que `GET /api/v1/architecture`) sans la restaurer. Un nom qui n'est pas une version conservée renvoie `404`.

### `GET /api/v1/architecture/versions` `[AUTH]`

Rôle admin requis. Liste les versions conservées de `architecture.json` (la plus récente d'abord). Une version est enregistrée à chaque écriture qui change le fichier (50 conservées).

**Réponse :**
```json
[{"name": "architecture-20260926T070623359846127Z.json", "saved_at": "2026-09-26T07:06:23Z", "size": 384}]
```

### `POST /api/v1/architecture/restore` `[AUTH]`

Rôle admin requis. Remet en place une version conservée, réaligne la base dessus et reconnecte les passerelles qu'elle décrit. L'état remplacé est lui-même conservé : une restauration est réversible.

**Body :** `{"name": "architecture-20260926T070623359846127Z.json"}`

**Réponse :** `{"restored": "<name>", "applied": {"declared": 2, "removed": 0, "scopes": 0, "domains": 0}}`. Un nom qui n'est pas une version conservée renvoie `404`.

### `POST /api/v1/bootstrap-tickets` `[AUTH]`

Crée un ticket one-shot pour intégrer un hôte (QR + lien + script).

**Body :**
```json
{
  "host_name": "host-1",
  "edge_endpoint": "http://192.0.2.10:8000",
  "payload": {},
  "ttl_hours": 24,
  "auto_accept": true,
  "node_names": ["edge-main"]
}
```

**Réponse 200 :** `token`, `url` (`/i/{token}`), `script_url`, `install_cmd`, `qr_code` (PNG data URL), `expires_at`.

### `GET /i/{token}` / `GET /i/{token}.sh` / `GET /api/v1/bootstrap/{token}` `[PUBLIC]`

Page HTML, script bash (`docker compose up -d`), ou JSON public du ticket.

### `POST /api/v1/nodes/:id/accept` / `POST /api/v1/nodes/:id/reject`

Accepte ou rejette un nœud en attente (`pending_nodes`) après présentation du pairing secret.

### `GET /api/v1/nodes/:id/tunnel-config`

Retourne la configuration Tunnel L4 mTLS du nœud. Réponse : `{"peers":[{"name":"edge-b","addr":"10.0.0.2:9443"},...]}`.

### `PUT /api/v1/nodes/:id/tunnel-config`

Met à jour la liste des peers Tunnel L4 du nœud. Corps : `{"peers":[{"name":"...","addr":"..."}]}`. Déclenche un push WS `push_tunnel_config` vers la passerelle connectée pour application immédiate via `tunnel.Manager.SetPeers`.

---

## Sécurité

### `GET /api/v1/security/overview`

Compteurs globaux : `active_bans`, `active_threats`, `open_cves`, `critical_cves`, `avg_header_score`, `certs_expired`, `certs_expiring`. `headers[].checks[]` (contrôles de posture par proxy) porte depuis Admin `0.52.4` un champ `key` (identifiant stable non traduit, ex. `"tls"`, `"waf"`) en plus de `name` (toujours en français) : le frontend traduit l'affichage depuis `key` et ne retombe sur `name` que pour des données mises en cache avant son ajout.

### `GET /api/v1/security/bans`

Liste tous les bans correspondant aux filtres, du plus récent au plus ancien. Paramètres : `active=true` (non expirés) ou `active=false` (expirés uniquement), `ip` (sous-chaîne), `domain`, `source` (`native|fail2ban|crowdsec|threat|rules_engine:<nœud>`), `edge` (nom du nœud ou id du token : les bans de cette passerelle **et** les bans globaux). Chaque entrée porte `edge_name`, la passerelle d'origine (vide = ban global : créé depuis l'Admin ou antérieur à cette colonne).

`GET /security/bans/countries`, `GET /security/bans/export` (CSV ou JSON, colonne `edge_name` ajoutée) et `GET /security/bans/intel/{kpis,by-reason,by-source,timeline,top-ips}` acceptent le même paramètre `edge`. `intel/kpis` renvoie `history_total` (bans posés), `unbanned` (débans), `rotation_ratio` (`unbanned / history_total`) et `recurring_ips`, le nombre d'IP ayant au moins 3 bans ; le nombre de bans actifs est la longueur de `GET /security/bans?active=true`.

### `POST /api/v1/security/bans`

Crée un ban manuel. Corps : `{ "ip", "domain", "reason", "expires_at", "target_scope" }`. Réponse `201` : `{ "id" }`.

`target_scope` limite les passerelles qui appliquent le ban : vide (défaut) = toutes, sinon le nom (ou l'id du jeton) d'une passerelle enregistrée, ou `group:<nom>` pour les membres d'un groupe HA existant (`400` si inconnu). L'Admin ne pousse à chaque passerelle que les bans globaux, ceux de sa portée et ceux de son groupe. La portée est renvoyée par `GET /security/bans` (`target_scope`) et filtrable par `?scope=<valeur exacte>`.

`ip` est une adresse IPv4/IPv6 **ou une plage CIDR**. La valeur est validée et normalisée avant d'être enregistrée : une plage est ramenée à son adresse de réseau (`203.0.113.7/24` → `203.0.113.0/24`), une adresse seule reste telle quelle (`/32` et `/128` retirés, IPv6 en minuscules, IPv4 mappée dépliée). Une valeur illisible, avec zone IPv6 ou composée (`1.2.3.1-9`) renvoie `400` (avant, elle était enregistrée puis ignorée sans rien dire par les passerelles). Sont aussi refusées : une plage plus large que `/16` en IPv4 ou `/32` en IPv6 (`400` — pour une plage plus large, un profil IP) et une plage qui **contient l'adresse de l'appelant** (`409`, pour ne pas se couper soi-même ; l'adresse est lue dans `X-Forwarded-For` sinon l'adresse distante, et le contrôle ne vise pas une adresse seule). Les passerelles appliquent la plage à toute adresse qu'elle contient, hors réseaux privés. Débannir une adresse située dans une plage bannie ne lève pas le ban de la plage : supprimer la plage elle-même (`DELETE`), ou créer un profil IP en mode allow, qui l'emporte sur les bans.

### `GET|POST|DELETE /api/v1/security/bans/whitelist`

**Liste blanche des bans** : adresses et plages qu'aucun ban n'atteint (manuel, Fail2Ban, CrowdSec, Sentinel, règles automatiques) et que Sentinel n'évalue pas. Réservée aux administrateurs.

- `GET` : `[{ "value", "comment", "added_by", "added_at", "bans_exempted" }]`, `bans_exempted` étant le nombre de bans actifs entièrement couverts par l'entrée (donc sans effet).
- `POST { "ip", "comment" }` : ajoute une adresse ou un CIDR, validé et normalisé comme pour un ban (`400` si illisible ou plus large que `/16` IPv4 / `/32` IPv6). `201 { "added": true, "entry": {…} }` ; si une entrée existante couvre déjà la cible, `200 { "added": false, "covered_by": "<entrée>" }` et rien ne change ; les entrées plus précises que la nouvelle sont retirées (redondantes).
- `DELETE ?ip=<valeur enregistrée>` : retire l'entrée (`204`, `404` si elle n'existe pas). Les bans qu'elle neutralisait s'appliquent de nouveau.

Les bans existants ne sont jamais supprimés par un ajout : ils cessent seulement de s'appliquer, et `GET /security/bans` les marque `"exempt": true` quand la liste blanche couvre toute leur cible. Les entrées sont recopiées dans un profil IP en mode `allow` d'identifiant `bans-whitelist` (nom « Liste blanche (bans) ») que les passerelles reçoivent et conservent : elles l'appliquent sans l'Admin, y compris après un redémarrage. Ce profil est **géré ici** : `PUT` et `DELETE /ip-profiles/bans-whitelist` renvoient `409`. À la différence d'un profil allow ordinaire, il exempte aussi de la détection Sentinel (requêtes non évaluées ni comptées). Un ban dont la cible est entièrement en liste blanche est refusé (`409`) ; une plage qui ne fait que recouper une entrée reste permise, l'entrée en restant exemptée. Outils MCP `list_ban_whitelist`, `add_ban_whitelist`, `remove_ban_whitelist` ; CLI `goproxify security bans whitelist`.

### `GET /api/v1/security/asn` · `GET /preview` · `POST /ban` · `DELETE /ban` · `GET /info` · `POST /refresh`

**Bans par ASN.** Bannir un ASN crée un ban par plage qu'il annonce (CIDR), comme un import de liste. Réservé aux administrateurs. Les données viennent du jeu public ip2asn (iptoasn.com), téléchargé par l'Admin au premier usage (`503` s'il est absent et injoignable).

- `GET /security/asn?q=<AS16276|16276|adresse IP|nom>` : `[{ "asn", "name", "country", "ranges", "v4_addresses", "v6_ranges", "banned_ranges" }]` ; une adresse IP donne l'ASN qui l'annonce, un nom jusqu'à 20 ASN (les plus grands d'abord) ; `banned_ranges` = bans actifs déjà créés pour cet ASN.
- `GET /security/asn/preview?asn=<ASN>&hours=24` : aperçu sans rien créer. `would_create`, `skipped_count`, `rejected_count` (avec `skipped` / `rejected` : `[{ "line", "value", "reason" }]`), `prefixes`, `too_wide`, trafic de la période (`requests`, `blocked`, `ok_requests`, `ips`, `ok_ips`, `top_ips`, `countries`), `requester_in` et `warnings`.
- `POST /security/asn/ban` : corps `{ "asn", "reason", "domain", "expires_at", "scope", "dry_run" }`. Réponse : l'ASN (`asn`, `name`, `country`, `announced_ranges`, `prefixes`, `too_wide`) et le rapport d'import (`created`, `skipped_count`, `rejected_count`, `skipped`, `rejected`, `dry_run`). `reason` vaut par défaut « AS<numéro> <nom> » ; `scope` se comporte comme `target_scope` d'un ban. Les plages plus larges que `/16` (IPv4) sont découpées en `/16` (une plage qui donnerait plus de 1 024 morceaux est ignorée : `too_wide`) ; les plages déjà bannies, en liste blanche ou privées sont ignorées. `409` si l'ASN contient l'adresse de l'appelant ; `404` si l'ASN est inconnu ; `400` pour une valeur invalide. Un seul envoi aux passerelles pour tout le lot. Le ban est un instantané : relancer la même requête ajoute les plages annoncées depuis.
- `DELETE /security/asn/ban?asn=<ASN>` : supprime les bans créés pour l'ASN (historique alimenté) et les lève sur les passerelles en un seul envoi. Réponse `{ "asn", "removed" }`.
- `GET /security/asn/info` : état de la base (`installed`, `updated_at`, `size_bytes`, `asns`, `ranges`) ; `POST /security/asn/refresh` la télécharge à nouveau.

`GET /security/bans` renvoie `asn` (numéro, absent hors ban d'ASN) pour chaque ban créé de cette façon.

### `POST /api/v1/security/bans/import`

**Import de liste** : crée des bans (ou des entrées de la [liste blanche](#getpostdelete-apiv1securitybanswhitelist)) à partir d'une liste d'adresses IP et de CIDR. Corps JSON : `content` (le texte de la liste, 2 Mo et 10 000 entrées au plus), `scope` (portée des bans créés, comme `target_scope` de `POST /security/bans` ; ignorée pour la liste blanche), `format` (`auto` par défaut, `text`, `csv` ou `json`), `target` (`bans` par défaut, ou `whitelist`), `reason` (motif des bans, ou commentaire des entrées, sans motif propre ; `import` par défaut), `domain` (domaine ciblé par les bans sans domaine propre), `expires_at` (expiration RFC3339 des bans sans expiration propre ; vide = permanent) et `dry_run`.

Formats : **texte** (une adresse ou un CIDR par ligne, commentaires `#` et `;` ; le commentaire d'une ligne devient son motif — `1.10.16.0/20 ; SBL256894`, liste Spamhaus DROP, donne le motif `SBL256894` —, ce qui permet d'importer les listes publiques FireHOL, blocklist.de ou Spamhaus), **CSV** (colonne `ip`, `cidr` ou `address` ; colonnes facultatives `reason`, `domain`, `expires_at` ; les autres colonnes sont ignorées, donc le CSV de `GET /security/bans/export` se réimporte tel quel ; sans en-tête : `ip[,reason]`) et **JSON** (tableau de chaînes, ou d'objets `ip`/`cidr`, `reason`, `domain`, `expires_at`, donc l'export JSON aussi). Le format est détecté quand `format` est absent.

Chaque entrée est validée comme à la création unitaire : normalisation (`203.0.113.7/24` → `203.0.113.0/24`), plage plus large que `/16` (IPv4) ou `/32` (IPv6) **rejetée**, plage qui contient l'adresse de l'appelant **rejetée** (pour les bans seulement), expiration illisible **rejetée**. Sont **ignorées** (valides mais sans objet) : un doublon dans la liste, une entrée couverte par une plage plus large de la même liste, une cible déjà couverte par un ban actif ou par la liste blanche, une plage privée ou locale (jamais bloquée par les passerelles). Les bans sont créés en une transaction (source `native`, historique alimenté) puis poussés **une seule fois** aux passerelles ; l'import est audité (`import_bans`).

Réponse `200` : `dry_run`, `target`, `format`, `total` (entrées lues), `created` (créées, ou qui le seraient en `dry_run`), `addresses` (adresses couvertes), `skipped` / `rejected` (`[{ "line", "value", "reason" }]`, 200 premières lignes) avec `skipped_count` / `rejected_count` exacts, et `sample` (quelques valeurs créées). `400` si la liste est vide, trop volumineuse, illisible dans le format demandé, ou si `target`, `format` ou `expires_at` sont invalides. Avec `dry_run`, rien n'est écrit ni poussé : à utiliser d'abord. Outil MCP `import_security_bans`, CLI `goproxify security bans import`, bouton « Importer » de la page Bans.

### `GET /api/v1/security/bans/preview`

Aperçu de l'impact d'un ban **avant de le créer**, sans rien modifier. Paramètres : `ip` (adresse ou CIDR, validé comme à la création, `400` sinon) et `hours` (période de trafic analysée, défaut 24, max 168). Réponse : `target` (forme normalisée), `kind` (`ip|cidr`), `prefix_bits`, `addresses` (nombre d'adresses), `private` (réseau privé ou local, jamais bloqué par les passerelles) ; le trafic de la cible sur la période — `requests`, `blocked` (403, 429, WAF ou Sentinel), `ok_requests` et `ok_ips` (requêtes réussies, donc probablement légitimes, et leurs adresses : ce que le ban couperait), `ips`, `top_ips`, `countries`, `scan_limited` ; `existing_bans` (bans actifs qui recoupent la cible, avec `relation` : `same`, `covers` — la cible est déjà couverte —, `inside` — le nouveau ban les englobe — ou `overlaps`) ; `profiles` (profils IP actifs qui la recoupent, un profil `allow` l'emporte sur un ban) ; `requester_in` (la plage contient l'appelant : la création serait refusée) ; `whitelist` (entrées de la [liste blanche](#get-post-delete-apiv1securitybanswhitelist) qui recoupent la cible) et `whitelisted` (la cible est entièrement exemptée : la création serait refusée) ; et `warnings`, une liste de messages lisibles. Mêmes droits que la liste des bans ; outil MCP `preview_security_ban`, CLI `goproxify security bans preview`.

`expires_at` est une date RFC3339 (décalage horaire et fractions de seconde acceptés), enregistrée en UTC à la seconde (`2026-12-31T23:59:59Z`) ; absent, `null` ou `""` → ban permanent. Depuis Admin `0.69.5`, une date illisible renvoie `400` au lieu d'être enregistrée telle quelle (le ban n'était alors jamais actif). Il n'y a pas de champ `ttl` : une durée se convertit en `expires_at` côté client, comme le fait `goproxify security bans add -ttl`.

### `PATCH /api/v1/security/bans/:id`

Modifie l'expiration d'un ban. Corps : `{ "expires_at": "<RFC3339>" }` (même validation et normalisation qu'à la création, `""` → permanent) ou `{ "permanent": true }`. Réponse `204` ; `400` si l'expiration est illisible ou si le corps ne porte aucun des deux champs.

### `DELETE /api/v1/security/bans/:id`

Supprime un ban par ID.

### `GET /api/v1/security/threats`

Liste les menaces CrowdSec (`security_threats`), triées par `last_seen_at` décroissant. Paramètre : `limit`. Une même menace (`ip`+`scenario`) est dédupliquée : chaque nouvelle occurrence rafraîchit `last_seen_at` et incrémente `occurrences` au lieu de créer une ligne ignorée à date figée. Chaque entrée inclut aussi `edge_name` — la passerelle d'origine, résolu côté serveur depuis le token d'appairage à la réception (vide pour les données antérieures à cette colonne).

### `GET /api/v1/security/ip-trace`

**Étendue ASN.** La réponse contient `scope`, `scope_label` (par exemple `5.0.0.0 – 5.0.1.255 (AS64500 EXEMPLE)` ou `AS64500 EXEMPLE`) et `asn_context` : `{ "asn": { "asn", "name", "country", "ranges", "v4_addresses", "v6_ranges", "banned_ranges" }, "range": { "start", "end", "cidrs": […] } }`, `range` donnant la plage annoncée qui contient l'adresse et sa décomposition en CIDR. `asn_context` n'est renseigné que si la base ASN est **déjà installée** (un traçage simple ne la télécharge jamais), sinon `null` ; avec `scope=range` ou `scope=asn` elle est chargée, et téléchargée au besoin.

Parcours complet d'une IP ou d'un CIDR (rôle admin). Reconstitue, sur la période demandée, les requêtes d'accès (logs), les détections (`security_threats`), les bans et débans (`security_ban_history`), les bans en cours et les profils IP qui contiennent la cible.

| Paramètre | Description |
|-----------|-------------|
| `target` (alias `ip`) | **Requis** (sauf avec `asn`). IP (`203.0.113.7`, `2001:db8::1`) ou CIDR (`198.51.100.0/24`). `400` si invalide |
| `scope` | Étendue du parcours : `ip` (défaut, la cible seule), `range` (la plage que l'opérateur de l'adresse annonce, lue dans la base ASN) ou `asn` (toutes les plages de l'ASN de l'adresse). `404` si l'adresse est inconnue de la base (privée, réservée), `503` si la base ASN est indisponible, `400` si la valeur est inconnue |
| `asn` | Numéro d'ASN (`AS16276`) à tracer en entier, à la place d'une adresse ; exige `scope=asn`. `404` si l'ASN n'annonce aucune plage |
| `node` | Ne garde que les requêtes vues par cette passerelle (nom du nœud). Les bans et détections ne sont pas filtrés |
| `from`, `to` | RFC3339 ou `AAAA-MM-JJ` (`to` en date seule inclut la journée). Défaut : 30 derniers jours jusqu'à maintenant. `400` si `from` ≥ `to` |
| `order` | `asc` (chronologique, défaut) ou `desc` |
| `limit`, `offset` | Pagination des étapes (défaut 500, max 2000) |

Réponse : `target` (normalisé), `kind` (`ip` ou `cidr`), `from`, `to`, `total_steps`, `offset`, `has_more`, et :

- `summary` : `first_seen`, `last_seen`, `requests`, `blocked` (403, 429 ou protection déclenchée), `ip_count`, `episodes`, `bans`, `unbans`, `threats`, `statuses` (par classe `2xx`…), `days` (`day`, `requests`, `blocked`), `top_ips`, `top_domains`, `top_paths`, `waf_matches`, `threat_signals`, `countries` (depuis `geoip_cache`), `active_bans`, `profiles` (profils IP activés dont une entrée recoupe la cible), `scan_limited` (plus de 2 000 000 requêtes : période à réduire). Les totaux couvrent toute la période, pas seulement la page.
- `steps` : étapes datées `ts`, de `kind` `activity` (épisode : `end` et `burst` avec `requests`, `blocked`, `ips`, `ip_count`, `domains`, `nodes`, `statuses`, `top_paths`, `waf_matches`, `threat_signals` ; deux requêtes séparées de moins de 10 min appartiennent au même épisode), `ban`, `unban`, `threat` (`occurrences`) ou `system` (événement de log lié à l'IP, 500 max), avec `ip`, `domain`, `source`, `reason`.

Un ban ou déban recoupant la cible compte dans le parcours (un ban sur un `/24` apparaît pour une IP qu'il contient, et inversement). Les requêtes ne remontent pas plus loin que la rétention des logs d'accès ; les IP pseudonymisées ou tronquées ne sont pas retrouvées. Équivalents : `goproxify security trace`, outil MCP `trace_ip`.

### `GET /api/v1/security/cves`

Liste les CVE détectées (`security_cves`). Paramètres : `status` (`open|ignored|fixed`), `critical=true` (CVSS ≥ 7). Chaque entrée inclut `edge_name` — la passerelle d'origine ayant remonté la CVE (résolu côté serveur depuis le token d'appairage à la réception, vide pour les données antérieures à cette colonne). Vue Admin : agrégat de toutes les passerelles, colonne passerelle affichée. Vue passerelle : déjà filtrée sur cette passerelle via les backends de ses proxies, colonne masquée (redondante).

Depuis Admin `0.52.3`, chaque entrée inclut aussi :
- `kev` (bool) — exploitation activement observée (catalogue CISA Known Exploited Vulnerabilities), rafraîchi en fin de scan (`internal/admin/vulnscan`), catalogue entier mis en cache 24h en mémoire.
- `epss_score` (0-1) et `epss_updated_at` — probabilité d'exploitation sous 30 jours (modèle EPSS, FIRST.org), rafraîchi en fin de scan par lots de 100 CVE.
- `sla_days` et `sla_due_at` — délai de correction attendu et échéance calculée (`detected_at` + `sla_days`), selon la gravité CVSS et le réglage `GET/PUT /api/v1/security/sla-config`. Recalculés à la lecture (jamais stockés), pour refléter immédiatement un changement de seuils. Non significatifs si `status != "open"`.

Les deux enrichissements (KEV, EPSS) sont du meilleur effort : un réseau externe indisponible au moment du scan laisse simplement `kev=false` / `epss_score=0` sans faire échouer le scan.

### `PATCH /api/v1/security/cves/:id`

Change le statut d'une CVE. Corps : `{ "status": "open|ignored|fixed" }`.

### `GET /api/v1/security/sla-config` · `PUT /api/v1/security/sla-config`

Délai de correction attendu (en jours après détection), par tranche de gravité CVSS — réglage global (pas de portée par passerelle : la politique de correction est la même pour tout le parc). Corps / réponse : `{ "critical_days": 7, "high_days": 14, "medium_days": 30, "low_days": 90 }` (CVSS ≥ 9 / ≥ 7 / ≥ 4 / < 4). Valeurs par défaut si le réglage n'a jamais été enregistré ; une valeur ≤ 0 envoyée au `PUT` retombe sur son défaut plutôt que d'être acceptée telle quelle.

### `GET /api/v1/security/fail2ban` · `PUT /api/v1/security/fail2ban`

Lit ou met à jour la configuration Fail2Ban (`enabled`, `window_sec`, `max_errors`, `ban_duration_sec`, `whitelist`). `whitelist` accepte des IPv4, IPv6 et CIDR des deux familles. Depuis Admin `0.69.3` / Edge `0.17.5`, Fail2Ban banne aussi les IPv6, par /64 : l'`ip` d'un tel ban (source `fail2ban`) dans `GET /security/bans` est le préfixe, par exemple `2a01:e0a:1:2::/64` (l'adresse seule si la liste blanche recoupe ce /64) — voir [Fail2Ban natif Go](security.md#fail2ban-natif-go). Depuis Admin `0.71.1` / Edge `0.17.12`, le Fail2Ban de l'Admin ignore les entrées de log dont l'IP a été tronquée par la passerelle (champ `ip_truncated` des logs envoyés à l'Admin, posé en anonymisation comme en pseudonymisation) et ne bannit plus depuis les logs tant que `ip_anonymize` ou `ip_pseudonymize` est actif (`PUT /logs/settings`) ; le Fail2Ban de chaque passerelle bannit sur l'IP réelle.

### `GET /api/v1/security/crowdsec` · `PUT /api/v1/security/crowdsec`

Lit ou met à jour la configuration CrowdSec (`enabled`, `api_url`, `api_key`).

### `POST /api/v1/security/crowdsec/sync`

Déclenche une synchronisation LAPI immédiate.

### `GET /api/v1/security/threat-config` · `PUT /api/v1/security/threat-config`

Configuration du moteur Sentinel. `custom_lists` accepte `ips`, `uas`, `paths` et `tls_fingerprints` : signatures **JA3** (MD5, 32 caractères hexadécimaux) ou **JA4** (ex. `t13d1516h2_8daaf6152771_02713d6af862`, insensible à la casse) dont le client est banni (signal `tls_fp`, score critique comme une IP de liste de menaces). L'empreinte est calculée par la passerelle depuis le ClientHello TLS ; elle ne s'applique ni au HTTP clair ni à HTTP/3, et chaque requête loguée porte `tls_ja3` / `tls_ja4` dans le log d'accès de la passerelle (pour repérer la signature d'un scanner ou d'un scraper avant de la lister). Paramètre optionnel `edge=<id ou nom>` :

- passerelle **membre d'un groupe HA** (déclaré dans `architecture.json`, `config.cluster` + `config.cluster_group`) : la configuration est **celle du groupe** — lue et écrite une seule fois, poussée à tous les membres, et rejouée à la connexion d'un membre qui la manquait ;
- passerelle hors groupe : configuration propre à la passerelle ;
- sans `edge` : configuration globale.

Lecture : valeur du groupe, sinon valeur propre à la passerelle (antérieure aux groupes), sinon globale. Au démarrage, la valeur d'un groupe qui n'en a pas encore est reprise du premier membre (dans l'ordre d'`architecture.json`) qui en avait une ; un désaccord entre membres est signalé dans le log de l'Admin, jamais écrasé.

Chaque passerelle garde une copie chiffrée de la configuration reçue (`/etc/goproxify/threat-config.gpx`) et la recharge à son démarrage : Sentinel reste actif si l'Admin est injoignable. Un nouvel enregistrement remplace cette copie.

### `POST /api/v1/security/threat-config/simulate`

Dry-run Sentinel depuis l'interface (bouton « Simuler » du tiroir de réglages) : rejoue les access logs récents contre une config candidate et la compare à la config actuelle, **sans rien enregistrer ni pousser**. Même moteur et même réponse que l'outil MCP `simulate_sentinel_config`. Paramètre optionnel `edge=<id ou nom>` (même règle de portée que `threat-config` : la config actuelle est celle du groupe HA si la passerelle en fait partie).

Corps :

```json
{ "config": { "rate_limit": 20, "custom_lists": { "paths": ["/wp-admin"] } }, "hours": 6, "domain": "app.example.com" }
```

- `config` (requis) : champs Sentinel surchargés sur la config actuelle, mêmes noms que `threat-config` ;
- `hours` : fenêtre rejouée, défaut `1`, max `24` ; `domain` : limite le rejeu à un domaine.

Réponse `200` : `current` et `candidate` (`events`, `blocked`, `blocked_by_ban`, `legit_blocked`, `blocked_ips`, `by_reason`, `bans`, `top_ips`), `delta` (candidat − actuel), `events_replayed`, `truncated`, `skipped_unattributable_ip` (entrées écartées : IP pseudonymisée, ou tronquée par l'anonymisation RGPD), `not_simulated`, `note`. `400` si `config` est absent ou invalide. Non simulé : listes par défaut, `global_rps`, règles User-Agent, WAF.

### `GET /api/v1/security/ips-provider` · `PUT /api/v1/security/ips-provider`

Fournisseur IPS actif (`native|fail2ban|crowdsec`). Même règle de portée que `threat-config`.

### `GET /api/v1/security/server-config` · `PUT /api/v1/security/server-config`

Timeouts HTTP/QUIC (`read_header_seconds`, `read_seconds`, `write_seconds`, `idle_seconds`, redémarrage de la passerelle requis). Même règle de portée que `threat-config` ; une passerelle qui rejoint le groupe reçoit ceux du groupe à sa connexion.

## Portail d'accès — `/api/v1/portal`

Le paramètre `edge=<id ou nom>` désigne une passerelle. Dans un **groupe HA** (`config.cluster` + `config.cluster_group` dans `architecture.json`), la configuration du portail est **celle du groupe** : lue et écrite une seule fois, poussée à tous les membres (config, destinations, utilisateurs invités). L'activation reste une propriété du nœud : un membre qui n'héberge pas le portail (`config.portal: false`) reçoit la config du groupe **en attente** (`ha_standby`), sans écouter, et réplique le magasin pour pouvoir prendre le relais.

### `GET /api/v1/portal?edge=` · `PUT /api/v1/portal?edge=`

Config du portail (`enabled`, `ssh_port`, `http_port`, `public_host`, `auth_provider_id`, `allow_personal_targets`, `require_2fa`, `session_ttl_sec`, `session_mode`, `theme`, catalogue, utilisateurs). Pour une passerelle membre d'un groupe HA, la réponse ajoute :

`theme` : apparence de l'interface du portail Access, choisie côté Admin et appliquée par la passerelle (`auto` — défaut, suit le système —, `clair`, `sombre`, `ocean`, `foret`, `amethyste`, `contraste`). Toute autre valeur est ramenée à `auto`. Appliqué à la page servie par la passerelle (copie locale chiffrée : fonctionne Admin coupé, y compris après redémarrage).

`views` : liste d'**entrées dédiées** du portail — même passerelle, même annuaire et mêmes destinations, mais une URL, un thème, un titre et un périmètre propres. Absent à l'enregistrement = liste inchangée ; `[]` la vide. Chaque vue :

| Champ | Description |
|-------|-------------|
| `slug` | Chemin : `prestataire` → `https://<hôte public>/prestataire` (minuscules, chiffres, tirets ; `api`, `assets`, `static` réservés) |
| `host` | Hôte dédié optionnel (ex. `presta.example.fr`) : la passerelle publie une route HTTPS supplémentaire vers le portail. Sans `slug`, l'hôte entier est la vue |
| `name`, `title`, `tagline` | Libellé d'administration, titre et sous-titre affichés (défauts : ceux du portail) |
| `theme` | Thème de la vue (même liste que `theme`) ; vide = thème du portail |
| `auth_provider_id` | Fournisseur d'authentification (annuaire) de la vue ; vide = celui du portail |
| `users` | Identifiants (email ou identifiant d'annuaire, comparés sans casse) autorisés sur l'entrée |
| `groups` | Identifiants de groupes Access (voir ci-dessous) autorisés sur l'entrée. Sans `users` ni `groups`, l'entrée est ouverte à tous les comptes du portail. Un jeton émis sur une entrée n'est valable que sur cette entrée |
| `target_ids` | Destinations de l'entrée (identifiants du catalogue). Cochées, elles sont offertes à tous les utilisateurs autorisés de l'entrée, sans condition de tags ; vide = destinations habituelles de l'utilisateur (tags) |
| `dest_groups` | Groupes de destinations de l'entrée (identifiants, voir `/api/v1/portal/destination-groups`) ; toutes leurs destinations sont offertes, en plus de `target_ids` |
| `require_2fa` | `true`/`false` pour surcharger le réglage du portail ; absent = hérité |

Une entrée s'adresse par un chemin (`domaine.fr/prestataire`), un sous-domaine ou domaine dédié (`presta.domaine.fr`), ou les deux. Un hôte égal à l'hôte public est ramené à un simple chemin. Les groupes et destinations inconnus de la passerelle sont ignorés à l'enregistrement. La passerelle ne reçoit que la liste résolue des membres (utilisateurs + membres des groupes).

Un couple hôte/`slug` ne peut apparaître qu'une fois (`400` sinon). La page du portail envoie la vue courante dans l'en-tête `X-Portal-View` ; l'accès SSH direct (port 2222) n'est pas concerné par les vues.

| Champ | Description |
|-------|-------------|
| `ha_group`, `ha_members` | Groupe et membres (calculés, non modifiables) |
| `ha_session_mode` | `sticky` (défaut : une session web reste sur la passerelle qui l'a émise, affinité à assurer sur le répartiteur) ou `shared` (sessions répliquées entre les membres ; à choisir avec un DNS round-robin) |

La clé de réplication du groupe (`ha_key`) n'est jamais renvoyée : l'Admin la génère, la conserve scellée et ne la pousse qu'aux passerelles du groupe.

### `POST /api/v1/portal/push?edge=`

Repousse la config du portail à la passerelle (à tous les membres du groupe HA).

### `GET /api/v1/portal/sessions?edge=` · `DELETE /api/v1/portal/sessions/{id}?edge=`

Connexions SSH et web pontées en cours sur une passerelle. La passerelle envoie l'instantané à chaque connexion ou déconnexion, et toutes les 30 s tant qu'une connexion est ouverte. `GET` renvoie `{"sessions":[{id, actor, target_id, facade, remote, since}]}`. `DELETE` demande à la passerelle de fermer la connexion (`204`, `404` si elle est déjà terminée) et journalise l'action dans l'audit Admin. Portée `portal:read` pour lire, `portal:write` pour terminer.

### `GET /api/v1/portal/sessions/{id}/watch?edge=`

Observe en direct la sortie d'une connexion en cours (flux `text/event-stream`). Chaque événement `data:` porte un morceau de sortie du terminal en base64, précédé de la fin déjà émise (32 Kio) à l'ouverture ; `event: end` annonce la fin de la session. On voit ce que l'utilisateur voit, jamais ce qu'il tape. L'observation est journalisée dans l'audit Admin (`watch`) et dans l'audit du portail (`observed_by_admin`). Elle exige la portée `portal:write`, comme la lecture d'un enregistrement, car elle donne accès au contenu d'un terminal. `404` si la connexion est déjà terminée. La CLI l'expose avec `goproxify access sessions watch`.

### Groupes Access — `/api/v1/portal/groups`

Groupes d'utilisateurs du portail, propres à une passerelle (ou à son groupe HA) ; ils donnent des droits sur les entrées (`views`). Une modification est poussée à la passerelle.

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/groups?edge=` | Groupes de la passerelle : `id`, `name`, `description`, `members` |
| `POST` | `/api/v1/portal/groups?edge=` | Crée un groupe : `name` (unique par passerelle, `409` sinon), `description`, `members` (identifiants de connexion, normalisés en minuscules) |
| `PUT` | `/api/v1/portal/groups/{id}` | Met à jour `name`, `description`, `members` (la liste remplace l'existante) |
| `DELETE` | `/api/v1/portal/groups/{id}` | Supprime le groupe et le retire des entrées qui l'utilisaient |

Les utilisateurs (`/api/v1/portal/users`) exposent `groups` (identifiants des groupes dont ils sont membres) ; `invite` et `PUT` acceptent `groups` pour aligner l'appartenance.

### Groupes de destinations Access — `/api/v1/portal/destination-groups`

Groupes de destinations du catalogue, propres à une passerelle (ou à son groupe HA). Une entrée (`views[].dest_groups`) offre toutes les destinations de ses groupes, en plus de ses `target_ids` ; l'Admin développe les groupes en `target_ids` à l'envoi, la passerelle ne les connaît pas. Une modification est poussée à la passerelle.

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/destination-groups?edge=` | Groupes de la passerelle : `id`, `name`, `description`, `targets` (identifiants de destinations) |
| `POST` | `/api/v1/portal/destination-groups?edge=` | Crée un groupe : `name` (unique par passerelle, `409` sinon), `description`, `targets` (les identifiants absents du catalogue de la passerelle sont ignorés) |
| `PUT` | `/api/v1/portal/destination-groups/{id}` | Met à jour `name`, `description`, `targets` (la liste remplace l'existante) |
| `DELETE` | `/api/v1/portal/destination-groups/{id}` | Supprime le groupe et le retire des entrées qui l'utilisaient |

Supprimer une destination (`DELETE /api/v1/portal/destinations/{id}`) la retire de ses groupes.

### Accès temporaires — `/api/v1/portal/access-requests`

Un utilisateur du portail demande l'accès à une destination qu'il ne voit pas (motif obligatoire, durée de 5 à 480 minutes) ; la passerelle transmet la demande à l'Admin, qui prévient par email les comptes admin et superadmin si le SMTP est configuré. Un administrateur l'approuve ou la refuse. L'accès approuvé est poussé à la passerelle (à tous les membres d'un groupe HA) et expire tout seul.

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/access-requests?edge=&status=` | Demandes de la passerelle (`pending`, `approved`, `denied`, `revoked` ; une demande accordée échue est renvoyée `expired`) |
| `POST` | `/api/v1/portal/access-requests/{id}/approve` | Corps optionnel `{"duration_min": n}` (1 à 1440, défaut : durée demandée) |
| `POST` | `/api/v1/portal/access-requests/{id}/deny` | Refuse une demande en attente |
| `POST` | `/api/v1/portal/access-requests/{id}/revoke` | Retire un accès accordé avant son terme |

Réponse `204` ; `409` si la demande n'est plus dans le bon état, `404` si elle n'existe pas. Une demande en attente pour le même utilisateur et la même destination n'est pas dupliquée. Portée `portal:read` pour lire, `portal:write` pour décider. Côté portail utilisateur : `GET /api/access/requestable` (destinations demandables) et `POST /api/access/requests` (`target_id`, `reason`, `duration_min`).

### `GET /api/v1/portal/policy?edge=` · `PUT /api/v1/portal/policy?edge=`

Politique d'accès du portail, enregistrée avec la config de la passerelle (celle du groupe pour un groupe HA) et poussée à chaque `PUT`. Le formulaire `PUT /api/v1/portal` ne la modifie pas.

| Champ | Description |
|-------|-------------|
| `hours_enabled` | Active la limitation horaire |
| `days` | Jours autorisés, `0` = dimanche à `6` = samedi |
| `start_time`, `end_time` | `HH:MM`, la fin suit le début (pas de plage sur minuit) |
| `timezone` | Nom IANA (`Europe/Paris`), UTC si vide |
| `ip_allow` | Adresses ou plages CIDR autorisées ; vide = toutes |
| `idle_timeout_min` | Ferme une session après N minutes sans saisie de l'utilisateur ; `0` = jamais |
| `record_sessions` | Enregistre la sortie des terminaux (voir ci-dessous) |
| `record_retention_days` | Jours de conservation des enregistrements ; `0` = illimitée |

`400` avec le motif si la politique est invalide. Hors plage horaire ou depuis une adresse non autorisée, la passerelle refuse la connexion au portail, l'ouverture d'une session et la connexion SSH (`403`), et journalise le refus dans l'audit. Les sessions déjà ouvertes ne sont coupées que par l'inactivité. Derrière la passerelle, l'adresse du client est la dernière entrée de `X-Forwarded-For`. Portée `portal:read` pour lire, `portal:write` pour modifier.

### Enregistrements de sessions — `/api/v1/portal/recordings`

Quand `record_sessions` est actif dans la politique, la passerelle enregistre la sortie du terminal de chaque nouvelle session (SSH, web, Docker) au format asciicast v2. La saisie de l'utilisateur n'est jamais gardée. Les fichiers restent sur la passerelle, chiffrés au repos avec une clé dérivée du secret du portail ; l'Admin les relaie à la demande. Un enregistrement est limité à 8 Mio de sortie (marqué `truncated` au-delà) et n'est écrit qu'à la fin de la session. `record_retention_days` supprime automatiquement les plus anciens (`0` = conservation illimitée).

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/recordings?edge=` | `{"recordings":[{id, actor, target_id, facade, remote, started, duration_sec, bytes, truncated}]}`, du plus récent au plus ancien |
| `GET` | `/api/v1/portal/recordings/{id}?edge=` | Fichier asciicast (`application/x-asciicast`), lecture journalisée dans l'audit Admin |
| `DELETE` | `/api/v1/portal/recordings/{id}?edge=` | Suppression définitive (`204`), journalisée |

`502` si la passerelle est injoignable, `404` si l'enregistrement n'existe pas. Portée `portal:read` pour lister ; `portal:write` pour lire le contenu d'un enregistrement ou le supprimer. Le contenu n'est pas exposé en MCP.

Les destinations (`/api/v1/portal/destinations`) et les utilisateurs (`/api/v1/portal/users`) suivent la même règle : rattachés au groupe, visibles et modifiables depuis n'importe quel membre. Au démarrage, les données propres aux membres d'avant les groupes sont rattachées au groupe (config du premier membre, destinations en double retirées, un désaccord de config est signalé dans le log, jamais écrasé).

## Moteur de règles automatiques

### `GET /api/v1/rules-engine/rules`

Liste toutes les règles. Réponse : tableau `Rule[]`.

### `POST /api/v1/rules-engine/rules`

Crée une règle. Corps : `{ name, description, enabled, condition, action, cooldown_sec, require_approval }`. `require_approval` (défaut `false`) : si vrai, l'action attend une décision humaine (`GET/POST /rules-engine/pending…`) au lieu de s'exécuter.

### `PUT /api/v1/rules-engine/rules/:id`

Met à jour une règle existante.

### `DELETE /api/v1/rules-engine/rules/:id`

Supprime une règle.

### `POST /api/v1/rules-engine/rules/:id/run`

Déclenche une évaluation immédiate. Paramètre : `?dry_run=true` (défaut). Réponse : `{ matched, action_taken, detail, error }`.

### `GET /api/v1/rules-engine/history`

Historique des exécutions. Paramètre : `limit`.

### `POST /api/v1/rules-engine/history/:id/replay`

Rejoue l'action d'une entrée d'historique en échec, en réutilisant le `detail` capturé au déclenchement d'origine (la condition n'est pas réévaluée). `400` si l'entrée n'a jamais déclenché de tentative d'action ou si la règle a été supprimée depuis. Réponse : `{ ok: true }`.

### `GET /api/v1/rules-engine/rules/:id/versions`

Liste l'historique des versions d'une règle (20 dernières), la plus récente en premier. Réponse : tableau `{ version, name, description, enabled, condition, action, cooldown_sec, created_at }`.

### `POST /api/v1/rules-engine/rules/:id/versions/:version/restore`

Restaure la règle à l'état de la version indiquée (condition, action, cooldown, activation, nom, description). La restauration ajoute elle-même une nouvelle version. `404` si la règle ou la version n'existe pas. Réponse : `{ ok: true }`.

### `GET /api/v1/rules-engine/condition-types`

Liste les descripteurs de types de conditions disponibles (nom, paramètres, descriptions).

### `GET /api/v1/rules-engine/action-types`

Liste les descripteurs de types d'actions disponibles (nom, paramètres, descriptions).

### `GET /api/v1/rules-engine/templates`

Store de règles préconfigurées. Réponse : tableau `Template[]` (`id, category, name, description, cooldown_sec, condition, action`).

### `POST /api/v1/rules-engine/templates/:id/install`

Installe un template : crée une `Rule` concrète à partir de ses valeurs par défaut. Corps optionnel : `{ name, enabled }` (nom personnalisé, activée par défaut). Réponse : `{ id }` (201).

### `GET /api/v1/rules-engine/silences`

Liste les silences. Réponse : tableau `Silence[]` (`id, name, rule_ids, starts_at, ends_at, created_at`), `rule_ids` vide = toutes les règles des deux moteurs (moteur de règles et moteur d'alertes — voir [docs/security.md](security.md#silences--maintenance)).

### `POST /api/v1/rules-engine/silences`

Crée un silence. Corps : `{ name, starts_at, ends_at, rule_ids }` (`starts_at`/`ends_at` en RFC3339, avec n'importe quel décalage horaire — stockées et renvoyées en UTC ; `rule_ids` optionnel — IDs de `rules_engine_rules` et/ou `alert_rules`, vide = toutes les règles). `400` si `ends_at <= starts_at`. Réponse : `{ id }` (201).

### `DELETE /api/v1/rules-engine/silences/:id`

Supprime un silence (`204`).

### `GET /api/v1/rules-engine/pending?[status=pending|approved|rejected]`

Liste les actions mises en attente par une règle `require_approval` (sans filtre : tous les statuts). Réponse : tableau `{ id, rule_id, rule_name, action, detail, status, created_at, decided_at, decided_by }`.

### `POST /api/v1/rules-engine/pending/:id/approve`

Approuve une action en attente : elle est exécutée immédiatement (avec le détail capturé au déclenchement, la condition n'est pas réévaluée) et le résultat rejoint l'historique de la règle. `400` si l'action n'est plus `pending`. Réponse : `{ ok: true }`.

### `POST /api/v1/rules-engine/pending/:id/reject`

Refuse une action en attente : elle ne sera jamais exécutée. `400` si l'action n'est plus `pending`. Réponse : `{ ok: true }`.

### `GET /api/v1/rules-engine/export`

Exporte en YAML toute la configuration d'automatisation : `{ version, rules[], channels[], silences[] }` (`Content-Type: application/x-yaml`, pièce jointe `automation.yaml`). Les canaux exportent leur `config` en clair.

### `POST /api/v1/rules-engine/import`

Importe un document YAML au format de l'export ci-dessus. Corps : le document YAML brut. Règles et canaux upsertés par nom ; silences toujours créés, dates ramenées en UTC — un silence dont `starts_at` ou `ends_at` n'est pas une date (RFC3339, ou `AAAA-MM-JJ HH:MM:SS` en UTC) est ignoré. Réponse : `{ rules_created, rules_updated, channels_created, channels_updated, silences_created }`.

---

## Planifications (cron)

### `GET /api/v1/scheduled-tasks`

Liste les planifications. Réponse : tableau `{ id, name, cron_expr, action, enabled, last_run_at, created_at, updated_at }`.

### `POST /api/v1/scheduled-tasks`

Crée une planification. Corps : `{ name, cron_expr, action, enabled }` (`cron_expr` : expression cron 5 champs, `action` : mêmes types que le moteur de règles — `condition-types`/`action-types`). `400` si `cron_expr` est invalide. Réponse : `{ id }` (201).

### `PUT /api/v1/scheduled-tasks/:id`

Met à jour une planification existante. Même corps que la création.

### `DELETE /api/v1/scheduled-tasks/:id`

Supprime une planification (`204`).

### `POST /api/v1/scheduled-tasks/:id/run`

Exécute immédiatement l'action de la planification, indépendamment de son expression cron. Réponse : `{ ok: true }`.

### `GET /api/v1/scheduled-tasks/:id/runs`

Historique des 100 dernières exécutions (30 jours conservés). Réponse : tableau `{ id, success, error, ran_at }`.

---

## Playbooks

### `GET /api/v1/playbooks`

Liste les playbooks. Réponse : tableau `{ id, name, description, steps, enabled, created_at, updated_at }`.

### `POST /api/v1/playbooks`

Crée un playbook. Corps : `{ name, description, steps, enabled }`. `steps` : tableau non vide de `{ type: "action"|"wait"|"condition"|"approval", action?, wait_sec?, condition?, note? }`. `400` si `name` vide ou `steps` vide. Réponse : `{ id }` (201).

### `PUT /api/v1/playbooks/:id`

Met à jour un playbook existant. Même corps que la création.

### `DELETE /api/v1/playbooks/:id`

Supprime un playbook (`204`).

### `POST /api/v1/playbooks/:id/run`

Démarre une exécution depuis la première étape. Réponse : `{ run_id }`.

### `GET /api/v1/playbooks/:id/runs`

Liste les 50 dernières exécutions du playbook. Réponse : tableau `{ id, current_step, status, log, started_at, updated_at, finished_at }` (`status` : `running`, `waiting_approval`, `completed`, `failed`, `stopped`).

### `GET /api/v1/playbooks/runs/:run_id`

Détail d'une exécution : `{ id, playbook_id, playbook_name, steps, current_step, status, log, context, started_at, updated_at, finished_at }`.

### `POST /api/v1/playbooks/runs/:run_id/approve`

Approuve une exécution suspendue à une étape `approval` : reprend à l'étape suivante. `400` si l'exécution n'est pas `waiting_approval`. Réponse : `{ ok: true }`.

### `POST /api/v1/playbooks/runs/:run_id/reject`

Refuse une exécution suspendue à une étape `approval` : l'exécution passe au statut `stopped`. `400` si l'exécution n'est pas `waiting_approval`. Réponse : `{ ok: true }`.

---

## Accès MCP (admin)

Périmètre d'accès du serveur MCP, admin uniquement (`RequireAdmin`).

### `GET /api/v1/mcp-access/allowed-ips`

Allowlist d'IP/CIDR sources autorisées à appeler `/mcp`. Réponse : `{ ips: string[] }`. Liste vide = aucune restriction (comportement historique).

### `PUT /api/v1/mcp-access/allowed-ips`

Remplace l'allowlist. Corps : `{ ips: string[] }` — chaque entrée est une IP (`203.0.113.4`) ou un CIDR (`10.0.0.0/24`), validée côté serveur (400 si invalide). Appliquée immédiatement par `internal/admin/mcp.Handler.ServeHTTP` (403 pour toute requête `/mcp` hors liste, avant même l'authentification PAT).

### `GET /api/v1/mcp-access/allowed-backends`

Allowlist des destinations vers lesquelles les outils MCP `create_proxy` / `update_proxy` peuvent pointer un backend (protection contre le détournement de trafic par prompt injection). Réponse : `{ backends: string[] }`. Défaut tant que jamais enregistrée : RFC 1918, loopback, ULA IPv6, `*.internal`, `*.local`, `*.svc`, `*.cluster.local` ; les noms d'hôte à label unique (services Docker/Kubernetes) sont toujours acceptés. Liste vide = aucune restriction. Ne s'applique pas à l'API REST admin ni à l'UI.

### `PUT /api/v1/mcp-access/allowed-backends`

Remplace l'allowlist. Corps : `{ backends: string[] }` — chaque entrée est une IP, un CIDR, un hôte exact (`api.corp.example`) ou un suffixe (`*.corp.example`) ; 400 si invalide. Un backend refusé renvoie une erreur d'outil MCP.

### `GET /api/v1/mcp-access/tokens`

Liste tous les PAT actifs (non révoqués) sur l'instance, tous porteurs confondus, avec leurs scopes — la vue "quels utilisateurs peuvent utiliser le MCP". Réponse : tableau `{ id, label, owner_email, scopes[], expires_at?, last_used_at?, created_at }`. La gestion (création/révocation) reste self-service sur `/api/v1/me/tokens` — un PAT est personnel.

### `GET /api/v1/mcp-access/scopes`

Catalogue des scopes PAT avec les outils MCP couverts par chacun, pour référence. Réponse : tableau `{ id, description, tools[] }`.

---

## Santé

### `GET /health` `[PUBLIC]`

```json
{ "status": "ok", "version": "0.1.0" }
```

### `GET /api/v1/cluster/status`

État du cluster (nodes, leader, sync).

---

## API interne passerelle ↔ Administration

*Ces endpoints ne sont pas exposés publiquement. Authentification par token d'appairage.*

### `POST /internal/v1/register`

Enregistrement d'une passerelle ou Agent.

### `GET /internal/v1/config`

Récupère la configuration complète (routes + certs) pour une passerelle.

### `POST /internal/v1/telemetry`

Soumission des métriques d'un Agent.

### `POST /internal/v1/discovery`

Soumission d'un proxy découvert par labels (depuis un Agent).

### `GET|POST /internal/v1/portal/replica`

Réplication du magasin du portail entre passerelles d'un même groupe HA (comptes, mot de passe et 2FA, coffres, cibles perso, favoris, et sessions web en mode `shared`). L'état échangé est **chiffré (AES-256-GCM) par la clé du groupe** poussée par l'Admin : il ne circule jamais en clair et une clé différente ne déchiffre rien. Fusion « dernier écrit gagne » par clé avec suppressions propagées ; envoi immédiat à chaque modification locale et tirage toutes les 15 s. Répond `204` hors groupe. Sans `GPX_PORTAL_MASTER_KEY` identique sur les membres, les coffres des comptes SSO répliqués ne sont pas déchiffrables ailleurs (un avertissement est journalisé).

### `GET|POST /internal/v1/agents/replica`

Réplication des secrets HMAC des Agents approuvés entre passerelles d'un même groupe HA : un Agent approuvé sur un membre est accepté par tous, il peut donc se reconnecter à un autre membre si sa passerelle tombe, sans l'Admin. L'état est **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre, distinct de celle du portail) ; une autre clé ne déchiffre rien (`400` à l'import). Chaque HMAC porte une estampille et une révocation laisse une pierre tombale : la modification la plus récente l'emporte, une révocation se propage et ferme la connexion de l'Agent sur les autres membres, une rotation horaire se propage. Envoi immédiat à chaque modification locale et tirage toutes les 15 s, entre membres du groupe seulement. Répond `204` hors groupe.

### `GET|POST /internal/v1/ech/replica`

Réplication du jeu de clés ECH (clés privées comprises) entre passerelles d'un même groupe HA, sans l'Admin. Corps **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre) : une autre clé ne déchiffre rien (`400` à l'import). Le jeu porte une estampille (ns) ; le plus récent l'emporte, une désactivation (jeu vide) plus récente aussi, un jeu de version égale ou plus ancienne est ignoré. Envoi après chaque push de l'Admin, tirage à chaque synchro entre pairs. Répond `204` hors groupe ou sans jeu.

### `POST /internal/v1/bans/gossip`

Un ban décidé localement (Sentinel, Fail2Ban) est transmis aux passerelles pairs sans passer par l'Admin ; chaque passerelle récupère aussi périodiquement les bans actifs de ses pairs (`GET /internal/v1/bans`). Les bans expirés, sans IP ou déjà connus (même identifiant ou même IP) sont ignorés ; un ban reçu d'un pair n'est jamais réémis. Ce circuit prend le relais quand l'Admin est indisponible.

### `GET /internal/v1/threat-lists/export` · `POST /internal/v1/threat-lists/sync`

Listes de référence Sentinel (`ua.txt`, `paths.txt`, `ips.txt`) : échangées entre passerelles pairs à chaque cycle de synchronisation, la plus récente l'emporte.

> **Note de migration :** Ces endpoints HTTP sont conservés pour la rétrocompatibilité pendant la migration. La nouvelle architecture utilise les tunnels WebSocket décrits ci-dessous.

---

## Protocole WebSocket

Le plan de contrôle utilise des tunnels WebSocket persistants initiés par Admin et Agent vers la passerelle. La passerelle est le seul hub de connexion.

### `GET /ws/admin` — Connexion Admin↔Passerelle

**Authentification :** header `X-Goproxify-Signature: hmac-sha256 <timestamp>.<hex_sig>`

La signature est calculée sur `"<ts>:<method>:<path>"` avec la clé `GPX_CONTROL_PLANE_ADMIN_HMAC_SECRET`. Fenêtre de rejeu ±5 min.

**Header requis :** `X-Node-ID: <nodeID>` — identifiant unique de l'instance Admin.

### `GET /ws/agent` — Connexion Agent↔Passerelle

**Premier démarrage :** header `X-Join-Token: gpx_join_*` (TTL 24h). L'Agent passe en état `pending` jusqu'à approbation via `POST /api/v1/agents/:id/approve`.

**Après approbation :** header `X-Agent-HMAC: <secret>` (rotatif toutes les heures, envoyé par la passerelle via message `rotate_hmac`).

---

### Format d'enveloppe JSON

Tous les messages WS utilisent l'enveloppe suivante :

```json
{
  "seq": 42,
  "type": "heartbeat",
  "payload": { ... }
}
```

| Champ | Type | Description |
|---|---|---|
| `seq` | int64 | Numéro de séquence croissant (détection de gap → full_sync) |
| `type` | string | Type de message (voir tables ci-dessous) |
| `payload` | JSON | Corps du message, spécifique au type |

---

### Types de messages Admin→Passerelle

| Type | Description |
|---|---|
| `push_routes` | Pousse la table de routage complète (ou partielle RBAC) |
| `delete_route` | Supprime une route par ID |
| `push_cert` | Pousse un certificat TLS (PEM cert + key) |
| `push_snippets` | Pousse tous les snippets actifs |
| `push_auth_providers` | Pousse les fournisseurs d'authentification |
| `push_ip_profiles` | Pousse les profils IP/CIDR |
| `push_settings` | Pousse les paramètres runtime (log level, tracing, protection des IP, etc.) ; la passerelle en garde une copie chiffrée (`edge-settings.gpx`) rechargée au démarrage, un envoi partiel ne modifie que les champs présents |
| `push_cluster_peers` | Pousse la topologie Raft |
| `push_delegations` | Pousse les routes de délégation multi-passerelle |
| `full_sync` | Full sync : envoie toutes les données en une seule enveloppe |
| `approve_agent` | Demande à la passerelle d'approuver un Agent en attente |

### Types de messages Agent→Passerelle

| Type | Description |
|---|---|
| `register` | Premier message après upgrade WS — enregistrement de l'Agent |
| `heartbeat` | CPU%, mém%, runtimes actifs (toutes les 30 s) |
| `containers` | Liste des conteneurs avec labels goproxify.* |
| `metrics` | Métriques par conteneur (CPU, mém, latence, erreurs) pour LB adaptatif |
| `event` | Événement de cycle de vie conteneur (start, stop, die, scale, etc.) |
| `log` | Batch de logs de conteneurs (log forwarding) |

### Types de messages passerelle→Agent

| Type | Description |
|---|---|
| `approve` | Approbation de l'Agent + premier `agent_hmac` |
| `rotate_hmac` | Nouveau `agent_hmac` (rotation toutes les heures) |
| `edge_endpoints` | Adresses des **autres** membres du groupe HA de la passerelle (`{"endpoints": [...]}`), envoyées à l'approbation, à chaque connexion et quand la composition du groupe change. L'Agent les conserve (`/etc/goproxify/agent-edges.json`) et bascule vers l'un d'eux si sa passerelle reste injoignable (3 échecs consécutifs) : il s'y reconnecte avec son HMAC, répliqué dans le groupe, et republie tous ses conteneurs. Absent hors groupe. |
| `command` | Commande à exécuter sur l'Agent (restart conteneur, pull image, etc.) |
| `rescan` | Demande un rescan Docker immédiat |
| `ping` | Ping keepalive (répondu par `pong`) |

### Types de messages passerelle→Admin

| Type | Description |
|---|---|
| `agent_pending` | Un Agent attend l'approbation (notification UI) |
| `node_update` | Mise à jour de l'état d'un Agent (online/offline/metrics) |

---

## Utilisateurs, équipes et permissions — `/api/v1/users`, `/api/v1/teams`

Routes réservées aux admins (`adminOnly`, scope PAT `users:read` / `teams:read`). Rôles plateforme : `superadmin` (unique, non attribuable), `admin`, `user`, `dpo`. Le rôle `dpo` a les droits d'un compte `user` plus la permission `gdpr:reveal`.

**Permissions** : droits de capacité, distincts des grants de ressources (`domain`, `server`, `proxy`, `edge`). Seule permission connue : `gdpr:reveal` (révéler l'IP réelle d'une entrée de log pseudonymisée, voir [Logs RGPD](#logs-rgpd--apiv1logs)). Elle est détenue par le superadmin, par le rôle `dpo`, en propre (`user_permissions`) ou via une équipe (`team_permissions`). Une permission inconnue renvoie `400`.

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/users` · `/api/v1/users/{id}` | Comptes ; chaque compte porte `permissions` (accordées en propre) et `effective_permissions` (y compris rôle et équipes) |
| POST | `/api/v1/users` | `{email, password, role, scopes?, permissions?}` |
| PUT | `/api/v1/users/{id}` | `{email, role, password?, scopes?, permissions?}` ; `permissions` absent = inchangé, `[]` = retirées |
| PUT | `/api/v1/users/{id}/password` | `{password}` |
| DELETE | `/api/v1/users/{id}` | — |
| GET | `/api/v1/teams` · `/api/v1/teams/{id}` | Équipes ; chacune porte `permissions` (accordées à ses membres) |
| GET · PUT | `/api/v1/teams/{id}/permissions` | `{permissions: [...]}` ; `PUT` remplace la liste |
| POST · DELETE | `/api/v1/teams/{id}/members[/{user_id}]` | Membres |
| GET | `/api/v1/me` | Compte courant ; `permissions` = permissions effectives |

Règles (depuis Admin `0.78.0`), contrôlées pour les sessions UI comme pour les PAT :

- **attribuer ou retirer** une permission est réservé au superadmin : rôle `dpo` donné ou retiré, `permissions` d'un compte modifiées, `PUT /teams/{id}/permissions`, ajout ou retrait de membres et suppression d'une équipe qui porte une permission — sinon `403` (`api.err.superadmin_required`). Chaque attribution est auditée (`set_permissions`) ;
- **compte protégé** : un compte superadmin ou détenteur d'une permission (par n'importe quelle voie) ne peut être modifié (`PUT /users/{id}`), voir son mot de passe changé ou être supprimé que par le superadmin — sinon `403` (`api.err.protected_account`). Auparavant, un admin pouvait changer le mot de passe de n'importe quel compte, superadmin compris.

Les permissions sont copiées dans `users.yaml` (comptes et équipes). Elles ne font pas partie des sauvegardes de configuration (`team_permissions` est exclue de la section standard ; elle est dans la section `secrets` chiffrée, restaurable par le seul superadmin). Un import ou une restauration (`POST /api/v1/import/backup/apply`, `POST /api/v1/backups/snapshots/{id}/restore`) lancé par un admin n'attribue jamais le rôle `superadmin` ni `dpo` (compte créé en `user`, rôle d'un compte existant conservé), ne modifie pas le rôle du superadmin ni d'un `dpo`, et n'ajoute aucun membre à une équipe qui porte une permission. Lancé par le superadmin, il restaure le rôle `dpo` et ces membres ; le rôle `superadmin` n'est jamais importé. Auparavant, un import en `overwrite` réécrivait le rôle de tout compte existant, superadmin compris.

## Workspaces — `/api/v1/workspaces`

> Accès : admin / superadmin uniquement.

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/workspaces` | Liste tous les espaces de travail (avec compteurs membres/ressources) |
| POST | `/api/v1/workspaces` | Crée un espace (`name`, `description`) |
| GET | `/api/v1/workspaces/{id}` | Détail complet : membres + ressources |
| PUT | `/api/v1/workspaces/{id}` | Renomme / modifie la description |
| DELETE | `/api/v1/workspaces/{id}` | Supprime (en cascade membres + ressources) |
| POST | `/api/v1/workspaces/{id}/members` | Ajoute un membre (`entity_type`: `user`/`team`, `entity_id`) |
| DELETE | `/api/v1/workspaces/{id}/members/{type}/{entityID}` | Retire un membre |
| POST | `/api/v1/workspaces/{id}/resources` | Ajoute une ressource (`resource_type`: `proxy`/`domain`/`edge`, `resource_id`) |
| DELETE | `/api/v1/workspaces/{id}/resources/{type}/{resourceID}` | Retire une ressource |

---

## Logs RGPD — `/api/v1/logs`

| Méthode | Endpoint | Scope requis | Description |
|---|---|---|---|
| GET | `/api/v1/logs` | `logs:read` | Liste paginée (curseur `before_id`, `page_size`) : filtres `kind` (`access`/`system`), `level`, `component`, `node_name`/`node_id`, `domain`, `ip`, `method`, `status`, `path`, `tls_ja3`, `tls_ja4` (égalité exacte sur l'empreinte TLS du client, depuis Admin `0.115.0`), `search`, `date_from`, `date_to`, `exclude_internal` (`1`/`true` : exclut les IP de réseau privé/loopback — RFC 1918, loopback, link-local IPv4/IPv6 — appliqué en SQL avant `LIMIT`, donc `has_more`/`page_size` restent cohérents) → `{has_more, last_id, entries:[Entry]}`. Chaque `Entry` porte `country` (code ISO alpha-2, résolu au mieux depuis le cache géo-IP déjà alimenté par le tableau de bord/Prism/Bans ; absent si l'IP n'a pas encore été résolue — pas d'appel réseau synchrone sur cette route), `request_id` (identifiant de la requête d'origine, transmis par la passerelle — voir `/logs/correlate?request_id=`), `waf_matches` (catégories de règles WAF déclenchées, tableau, absent si aucune), `threat_signal` (signal Sentinel déclenché, absent sinon), `tls_ja3` / `tls_ja4` (empreintes TLS calculées par la passerelle, absentes en HTTP clair, en HTTP/3 ou pour une entrée antérieure à Admin `0.115.0` / Edge `0.44.0`) et, depuis Admin `0.71.2`, `ip_truncated` (`true` quand la passerelle a tronqué l'IP par l'anonymisation ou la pseudonymisation RGPD — `x.x.x.0`, préfixe /48 `2a01:e0a:1::` — : la valeur regroupe plusieurs clients et ne doit être ni bannie ni analysée ; absent sinon, et absent des entrées stockées avant Admin `0.71.1` ou envoyées par une passerelle antérieure à Edge `0.17.12`). Une entrée pseudonymisée porte aussi `ip_truncated` (son `ip` vaut `[pseudonymisé]`). `exclude_internal` s'applique aussi à `/logs/histogram`, `/logs/facets`, `/logs/export` et `/logs/live` (mêmes filtres) |
| GET | `/api/v1/logs/live` | `logs:read` | Flux SSE des nouvelles entrées, mêmes filtres et mêmes champs que la liste, `ip_truncated` compris (`?_auth=<token>` requis, `EventSource` ne pose pas d'en-tête `Authorization`) |
| GET | `/api/v1/logs/export?format=json\|csv` | `logs:read` | Export des entrées filtrées (mêmes filtres que la liste) |
| GET | `/api/v1/logs/correlate` | `logs:read` | Entrées voisines d'un événement : `request_id`, ou `domain`+`ts`+`window` (secondes, défaut 30) |
| GET | `/api/v1/logs/settings` | `logs:read` | Paramètres de rétention et de pseudonymisation |
| PUT | `/api/v1/logs/settings` | `logs:write` + admin | Modifier rétention, `ip_anonymize`, `ip_pseudonymize`. Les deux modes sont exclusifs : `400` si la requête les laisserait actifs ensemble (en tenant compte de la valeur déjà enregistrée ; envoyer les deux champs pour basculer). Un mode modifié est audité (`logs_ip_anonymize`, `logs_ip_pseudonymize`) et poussé aux passerelles en un seul message `push_settings` portant les deux champs ; une valeur inchangée n'est ni auditée ni poussée. Une entrée pseudonymisée a `ip` = `[pseudonymisé]` dans `GET /logs` |
| POST | `/api/v1/logs/reveal-ip` | `gdpr:reveal` (superadmin, rôle `dpo`, droit délégué — voir [Utilisateurs, équipes et permissions](#utilisateurs-équipes-et-permissions--apiv1users-apiv1teams)) | Révéler l'IP réelle d'une entrée pseudonymisée |
| DELETE | `/api/v1/logs/by-ip/{ip}` | `logs:write` + admin | Effacement RGPD Art.17 par IP, entrées pseudonymisées comprises (empreinte `ip_hmac`), IPv6 quelle que soit sa notation → `{deleted, ip}`. `{ip}` doit être une adresse IP (`400` sinon). L'audit (`rgpd_erasure_ip`) et le log système ne contiennent que l'empreinte de l'IP (`hmac:…`) |
| DELETE | `/api/v1/logs/by-user/{user_id}` | `logs:write` + admin | Effacement RGPD Art.17 par utilisateur |
| GET | `/api/v1/logs/histogram` | `logs:read` | Entrées par tranche de temps et par niveau : mêmes filtres que la liste plus `bucket` (`minute`, `hour`, `day` ; défaut selon l'étendue, 24 h sans `date_from`) → `{bucket, points:[{bucket, total, warn, error}]}` |
| GET | `/api/v1/logs/facets` | `logs:read` | Comptage des entrées filtrées par valeur, pour l'explorateur de logs : mêmes filtres que la liste plus `fields` (CSV parmi `level`, `component`, `node_name`, `domain`, `method`, `tls_ja4`, `tls_ja3` ; par défaut les cinq premiers) → `{<field>: [{value, count}]}`, 12 valeurs les plus fréquentes par champ, valeurs vides exclues |
| GET | `/api/v1/audit/histogram` | authentifié | Actions du journal d'audit par tranche et par gravité : filtres `component`, `action`, `actor`, `severity`, `from`, `to` (RFC 3339) plus `bucket` → `{bucket, points:[{bucket, total, warn, critical}]}` |

### POST `/api/v1/logs/reveal-ip`

Body :
```json
{ "entry_id": 4821, "reason": "Réquisition judiciaire n°2026/1234" }
```

Réponse `200` :
```json
{
  "entry_id": 4821,
  "ip": "203.0.113.42",
  "requested_by": "dpo@example.com",
  "reason": "Réquisition judiciaire n°2026/1234",
  "ts": "2026-09-20T14:32:01Z"
}
```

La révélation reste possible après la désactivation de la pseudonymisation, tant que l'entrée est conservée.

Codes d'erreur :
- `403` — scope `gdpr:reveal` manquant
- `400` — `entry_id` ou `reason` manquant
- `404` — entrée introuvable
- `422` — entrée non pseudonymisée
- `500` — clé de pseudonymisation non chargée

## Prism — bans et scan d'IP

- `GET /api/v1/prism/bans/breakdown` — bans actifs ventilés par source puis par technique de détection : `[{source, source_label, sentinel, technique, label, count}]`. `sentinel: true` pour la source `threat` (moteur Sentinel de la passerelle : techniques `ip`, `ua`, `path`, `rate` et leurs variantes `custom_*`) ; Fail2Ban est rapporté en `errors`, CrowdSec par scénario.
- `GET /api/v1/prism/ip-scan?ip=<ip>[&from&to]` — ré-analyse à la demande d'une IP : `verdict` (`banned` | `suspect` | `clean`), bans actifs (avec source/technique), nombre de bans passés, décisions de menace, requêtes/erreurs sur la période et chemins les plus visés. `ip_truncated: true` (depuis Admin `0.71.2`) quand les logs de la période portent cette valeur tronquée par l'anonymisation RGPD : requêtes et erreurs sont alors celles de tout un /24 ou /48, et l'interface ne propose pas de bannir.
- `GET /api/v1/prism/tls-fingerprints?[from&to&proxy&node_name&ip&path&limit]` — empreintes TLS (JA4) les plus actives (`limit` 30 par défaut, depuis Admin `0.117.0`) : `[{ja4, ja3, requests, errors, flagged, unique_ips}]` ; `flagged` compte les requêtes signalées par le WAF ou Sentinel, `unique_ips` ignore les IP tronquées ou pseudonymisées ; les requêtes sans empreinte (HTTP clair, HTTP/3, entrées antérieures) sont ignorées. Scope `logs:read`
- `GET /api/v1/prism/ips?[from&to&proxy&node_name&ip&path&limit]` — IP les plus actives (`limit` 50 par défaut) : `[{ip, requests, errors, bytes, ip_truncated?}]`. `ip_truncated: true` (depuis Admin `0.71.2`) signale une IP tronquée par l'anonymisation ou la pseudonymisation RGPD, qui regroupe plusieurs clients : l'interface la marque « Tronquée » et n'y propose ni ré-analyse ni ban.
- `GET /api/v1/prism/geo/points?[from&to&proxy&node_name&limit]` — trafic agrégé par ville, les plus actives d'abord (`limit` 300 par défaut, 1000 max) : `[{city, region, country_code, country_name, lat, lon, requests, errors, error_rate, ips, banned_ips}]`. La position est approximative (géolocalisation IP, précision de l'ordre de la ville) ; les IPs pas encore localisées sont ignorées.
- Le paramètre `proxy` des endpoints `/prism/*` (kpis, timeline, status, paths, ips, geo, geo/points, anomalies, live-ips) accepte plusieurs domaines séparés par des virgules (depuis Admin `0.101.0`) : les résultats agrègent tous les domaines listés. Utilisé par la Vue Proxy (sélection cumulable).
- `GET /api/v1/prism/anomalies?[from&to&proxy&node_name]` — écarts détectés sur la période, critiques d'abord : `[{kind, level, subject, label, value, baseline, count, banned?}]`. `kind` : `error_spike` (point de la courbe > moyenne + 2,5 écarts-types, au moins 10 erreurs ; `subject` = tranche horaire), `dominant_ip` (au moins 20 % des requêtes et 50 requêtes ; `banned` si déjà bannie ; depuis Admin `0.71.2`, seules les IP attribuables comptent — une IP tronquée par l'anonymisation RGPD ou `[pseudonymisé]` regroupe plusieurs clients et n'est jamais retenue), `country_errors` (au moins 20 % d'erreurs sur 50 requêtes, 2 max), `backend_errors` (plus de 10 % d'erreurs sur 20 requêtes, 2 max), `bot_share` (au moins 30 %). `level` : `critical` | `warning`.
- `GET /api/v1/prism/slo?[target&days&proxy&node_name]` — SLO de disponibilité (réponses non-5xx) sur une fenêtre glissante (`target` en % : objectif enregistré, 99.9 par défaut ; `days` : 30 par défaut, 90 max ; `from`/`to` ignorés) : `{target, days, requests, errors, availability, budget_total, budget_left_pct, burn_1h, burn_6h, state}`. `burn_*` vaut 1 quand le budget est consommé exactement au rythme de l'objectif. `state` : `exhausted` (budget consommé), `critical` (burn ≥ 14,4 sur 1 h et ≥ 6 sur 6 h), `warning` (burn ≥ 3 sur 6 h), sinon `ok`.
- `GET /api/v1/alert-events?[days&limit&trigger&node]` — alertes déclenchées (30 jours conservés, plus récente d'abord) : `[{id, rule_id, rule_name, trigger, detail, channels, title, body, priority, silenced, fired_at}]` ; `node` filtre sur le nom de passerelle du détail. `silenced=true` : la règle correspondait mais un silence actif (`Automatisation > Alertes > Silences & maintenance`) a bloqué l'envoi — `channels` est alors vide. `POST /api/v1/alert-events/{id}/ack` (acquittement) est réservé aux admins / superadmins.
- `GET /api/v1/prism/slo/config` → `{target}` ; `PUT /api/v1/prism/slo/config` `{target}` (admin, entre 90 et 99.999) — objectif SLO enregistré (réglage `slo.target`, 99.9 par défaut), utilisé par l'écran, `GET /prism/slo` sans `target`, l'outil MCP `get_prism_slo` et l'alerte `slo_burn`.
- `GET /api/v1/prism/live-ips` renvoie en plus `city`, `lat`, `lon` (0/0 tant que l'IP n'est pas localisée).
