# Sauvegardes — comment et quoi

Ce document décrit le menu **Sauvegardes** de l'Administration : le fonctionnement des snapshots, leur contenu exact, ce qui est volontairement exclu, et le comportement à la restauration.

## 1. Fonctionnement

| Élément | Détail |
|---|---|
| Format | JSON (`.gpx-admin-backup`), champ `version: "1"` |
| Déclenchement | Manuel (bouton, CLI) ou planifié (jusqu'à **5 planifications** : quotidienne, hebdomadaire, mensuelle, annuelle, ou cron libre) |
| Stockage | Table `backup_snapshots` de la base Admin **et** copie `<storage.base_path>/backups/<id>.snap` sur disque (fallback si la base est illisible) |
| Rétention | Par planification (`retention` = nombre max de snapshots, 0 = illimité). Les snapshots manuels ne sont jamais purgés automatiquement |
| Chiffrement | AES-256-GCM si la variable `GPX_BACKUP_KEY` est définie (préfixe `GPXBK1:`) : snapshot entier chiffré, relisible uniquement avec la même clé. Sans clé, le snapshot est en clair, **sans secrets et sans section `secrets`** (§4) |
| Import d'un fichier | Menu Sauvegardes → *Restaurer* : analyse (`/api/v1/import/backup/preview`), sélection des entités, application (`/api/v1/import/backup/apply`) |
| CLI | `goproxify backup create / list / restore` (voir [cli.md](cli.md)) |

## 2. Ce qui EST sauvegardé

### 2.1 Entités principales

| Entité | Contenu | Remarques |
|---|---|---|
| Proxies | Configuration complète de chaque proxy (route, TLS, WAF, headers…) + état activé | Restauration : republication vers les passerelles |
| Utilisateurs | `id`, e-mail, rôle | **Sans mot de passe** (voir §3) |
| Tokens de nœuds | `id`, rôle, rôle RBAC, nom et endpoint du nœud, expiration | Secret **jamais** exporté ; tokens révoqués ignorés |
| Scopes de tokens | `token_scopes` | |
| PAT (tokens API utilisateur) | Hash, préfixe, libellé, scopes, expiration | Hash non réversible ; PAT révoqués ignorés |
| Snippets | Nom, type, config | |
| Canaux d'alerte | Nom, type, config, activé | Secrets vidés (§4) |
| Règles d'alerte | Scope, déclencheurs, canaux, cooldown, priorité, activé | |
| Nœuds déclarés | Topologie de l'assistant infrastructure | Les nœuds synthétiques `cfg:*` sont ignorés |

### 2.2 Tables de configuration (section `tables`)

Sauvegardées telles quelles (toutes colonnes), avec redaction des secrets.

| Domaine | Table | Contenu |
|---|---|---|
| Paramètres | `settings` | Paramètres clé/valeur (dont l'allowlist d'IP du MCP `mcp.allowed_ips`) |
| Sauvegardes | `backup_schedule` | Planifications |
| Sécurité | `fail2ban_config`, `crowdsec_config` | Configuration des moteurs IPS |
| Automatisation | `rules_engine_rules`, `rules_engine_rule_versions`, `playbooks`, `scheduled_tasks`, `automation_silences` | Règles automatiques, leurs versions, playbooks, tâches planifiées, silences (condition, action, cooldown, compteurs) |
| Domaines & certificats | `domains`, `cert_deploy_targets` | Domaines, délégation DNS, cibles de déploiement de certificats |
| Authentification | `auth_providers` | Fournisseurs OIDC / SAML / LDAP… |
| Réseau | `ip_profiles`, `node_tunnel_configs` | Profils IP (listes, feeds), tunnels de nœuds |
| Équipes & RBAC | `teams`, `team_members`, `team_members_v2`, `team_scopes`, `team_scopes_v2`, `team_scopes_grants`, `user_scopes`, `token_scopes_v2` | |
| Workspaces | `workspaces`, `workspace_members`, `workspace_resources` | |
| Pages | `error_page_templates`, `error_page_assets`, `portal_page_templates` | Les assets binaires sont encodés en base64 |
| Portail Access | `portal_destinations`, `portal_users`, `portal_groups`, `portal_dest_groups` | Utilisateurs sans hash d'invitation |

### 2.3 Configuration HA et fichiers de config

Les paramètres de Haute Disponibilité (`NodeID`, `Peers`, `RaftPort`, voir [internal/admin/ha/ha.go](../internal/admin/ha/ha.go)) ne sont **pas** en base : ils viennent du fichier de config Admin (YAML/env), pas d'une table SQL. Ils ne sont donc inclus dans le snapshot que via la section `configs` (voir note ci-dessous) — un snapshot standard sans `ExportConfigs` **ne sauvegarde pas la config HA**.

## 3. Ce qui N'EST PAS sauvegardé (volontairement)

| Donnée | Raison |
|---|---|
| Mots de passe (hash), MFA, clés RGPD/ECH, CA interne | Hors section standard ; **inclus dans la section `secrets` chiffrée** (§4 bis) quand `GPX_BACKUP_KEY` est définie |
| Secrets en clair (voir §4) | Snapshot potentiellement téléchargeable |
| Logs, journal d'audit, historique de bans, menaces, CVE, alertes émises, événements de nœuds, exécutions de règles et de tâches, déploiements de certificats | Volumineux : **hors snapshot par défaut**, sauvegardés à la demande dans la section `history` chiffrée (§4 quater) |
| Enregistrements de sessions du portail (`*.cast.gpx`), bases GeoIP, listes de menaces téléchargées, logs d'accès de la passerelle | Volumineux ou re-téléchargeables |
| Certificats TLS et clés privées de la passerelle | Repris avec l'état de la passerelle (`edge-cache.gpx`, §4 quater) ; ceux de l'Admin (`certs/`, CA interne) sont dans la section `secrets` |
| Autres snapshots (`backup_snapshots`) et historique des proxies (`proxy_history`) | Éviter la récursivité ; l'historique a son propre mécanisme de restauration |
| Nœuds actifs / agents enregistrés (`nodes`, `pending_nodes`) | État dynamique ; les nœuds se ré-enregistrent |

> La config HA effective (`NodeID`, `Peers`, `RaftPort`, lue du fichier **et** des variables `GPX_*`) et `admin.json` sont jointes à la section `secrets` (§4 bis) sous `config/admin-ha.json` et `config/admin.json`. À la restauration elles sont écrites dans `<storage.base_path>/restored-config/` : la configuration vivante n'est jamais écrasée, à vous de la reprendre. Les fichiers `edge.json` et `agent.json` ne sont pas lus par l'Admin ; `edge.json` est repris avec l'état de la passerelle (§4 quater).

## 4. Gestion des secrets

À l'export, sont **vidés** (`""`) :
- le secret des tokens de nœuds ;
- dans les canaux d'alerte : `password`, `token`, `secret`, `api_key`, `app_token`, `user_token`, `webhook_url`, `authorization`, `private_key` ;
- dans les tables de configuration : toute clé JSON dont le nom contient `secret`, `password`, `passwd`, `token`, `api_key`, `apikey`, `private_key`, `credential`, `webhook_url` ou `authorization` (ex. `client_secret` OIDC, identifiants DNS) ;
- dans `settings`, `fail2ban_config`, `crowdsec_config` : la valeur de toute clé dont le nom correspond à ces motifs ;
- `portal_users.invite_token_hash`.

**Conséquence** (snapshot sans clé `GPX_BACKUP_KEY`, donc sans section `secrets`) : après une restauration sur une instance vierge, il faut ressaisir ces secrets (tokens de nœuds à ré-émettre, secrets OIDC, identifiants DNS, webhooks…). À la restauration, un secret vidé **n'écrase jamais** une valeur déjà présente.

## 4 bis. Section `secrets` (restauration d'une infrastructure complète)

Si `GPX_BACKUP_KEY` est définie, le snapshot contient en plus une section `secrets` chiffrée à part (AES-256-GCM, préfixe `GPXSEC1:`), même si le reste du fichier est lisible. Elle n'est **jamais** écrite sans clé (journal : avertissement).

| Contenu | Détail |
|---|---|
| Tables sensibles, lignes brutes | `users` (hash des mots de passe), `tokens` (secrets des nœuds), `user_api_tokens`, `user_mfa`, `user_backup_codes`, `user_trusted_devices`, `gdpr_keys`, `ech_keys`, `internal_ca`, `internal_ca_certs`, `cert_pull_tokens`, `alert_channels`, `team_permissions`, `user_permissions` (permissions de capacité : restaurées par le seul superadmin) |
| Tables de configuration, non rédigées | Les tables du §2.2 avec leurs secrets (secrets OIDC/SAML/LDAP, identifiants DNS, webhooks…) |
| Fichiers | Copie du dossier `<storage.base_path>/state/` (`architecture.json`, magasins utilisateurs et configuration) et de `<storage.base_path>/certs/` (CA interne, certificats) ; fichiers de plus de 8 Mo ignorés |

**Restauration** : case *Secrets* (décochée par défaut) de la fenêtre *Restaurer*, ou `import_secrets` dans la sélection. Réservée au **superadmin**. Les lignes sont remplacées (ordre : utilisateurs d'abord) et les fichiers réécrits ; redémarrer l'Admin ensuite pour qu'il relise `state/`. Une restauration de snapshot sans corps, ou par la CLI, l'active d'office si le snapshot la contient. Une mauvaise clé fait échouer cette partie seule (`secrets_error`).

**Responsabilités** : un snapshot avec section `secrets` est sensible. La perte de `GPX_BACKUP_KEY` rend ces secrets irrécupérables : la conserver **hors du serveur**, séparément des snapshots. Les fichiers de la passerelle et de l'Agent ne sont pas inclus (voir [volumes.md](volumes.md)).

## 4 ter. Destinations hors serveur, intégrité et alertes

| Élément | Détail |
|---|---|
| Destinations | Jusqu'à 10 : dossier local ou partage monté (`dir`), WebDAV, stockage compatible S3 (signature SigV4). Gérées dans *Sauvegardes › Destinations*, l'API `/backups/destinations` et `goproxify backup destinations` |
| Copie | Après chaque snapshot, sur toutes les destinations actives : écriture, relecture, comparaison de la somme de contrôle. Résultat par destination et par snapshot dans la liste (☁) |
| Rétention | Par destination (`retention`, 0 = illimité) : les copies les plus anciennes déposées par l'Admin sont supprimées. Supprimer un snapshot localement ne supprime pas ses copies externes |
| Secrets de destination | `password` et `secret_key` ne sont jamais renvoyés par l'API ; ils sont absents des snapshots standard et présents dans la section `secrets` chiffrée |
| Intégrité | SHA-256 enregistré à la création ; le snapshot est relu, déchiffré et contrôlé avant d'être accepté ; `POST /backups/snapshots/{id}/verify` ou le bouton *Vérifier* le refait. Un snapshot altéré est signalé « somme de contrôle différente » |
| Alertes | Déclencheur `backup_failed` : sauvegarde planifiée échouée, copie vers une destination échouée, planification manquée (contrôle toutes les 30 min, tolérance 1 h). À brancher sur un canal via une règle d'alerte |
| État | Bandeau de la page Sauvegardes et `GET /backups/status` : clé absente, aucune destination, destination en échec, exécution manquée |

**Limites** : pas de SFTP ; pas de restauration directe depuis une destination (télécharger la copie, puis *Restaurer › fichier*) ; les envois ne sont pas relancés automatiquement (le prochain snapshot réessaie).

## 4 quater. Passerelles, Agents et historique

| Élément | Détail |
|---|---|
| État des passerelles | À chaque snapshot avec `GPX_BACKUP_KEY`, l'Admin interroge chaque passerelle enregistrée (`GET /internal/v1/backup/export`) et joint son état à la section `secrets` (clé `gateway/<nom>/<fichier>`) : `proxies/` et `proxies-revisions/`, les copies chiffrées `*.gpx` (portail, pairs, tunnels, Sentinel, réglages…), `edge.json`, `edge-node-id`, `edge-tokens.db`, `bans.db` (copie cohérente à chaud par `VACUUM INTO`), `waf-behavior.json`, `agent-hmacs.json`, `join-tokens-used.json` et les états d'Agents. Exclus : `geoip/`, `logs/`, `threat-lists/`, `*.mmdb`, enregistrements `*.cast.gpx` ; fichier > 64 Mo ignoré, 256 Mo au total |
| Passerelle injoignable | Le snapshot est créé quand même, l'incident est journalisé et une alerte `backup_failed` est émise (« Sauvegarde incomplète ») : une sauvegarde de passerelle silencieusement absente est un faux sentiment de sécurité |
| Restauration d'une passerelle | Avec les secrets, l'Admin renvoie à chaque passerelle de même **nom** son état (`POST /internal/v1/backup/restore`, chemins filtrés). Une passerelle absente de l'instance est signalée en erreur (l'enregistrer puis relancer). **Redémarrer la passerelle** ensuite : elle relit ses fichiers au démarrage. Les bases `.db` sont remplacées, leurs fichiers `-wal` / `-shm` supprimés |
| Agents | Chaque Agent approuvé copie ses fichiers d'état (`agent.token`, `agent.hmac`, `agent-node-id`, `agent-edges.json`) chez sa passerelle (message `agent_state`, à chaque connexion et après rotation du HMAC) ; ils font partie de l'état de la passerelle sauvegardé. Un Agent qui revient **sans** token ni HMAC (volume perdu) reçoit ses fichiers de sa passerelle (`restore_state`) ; le HMAC courant de la passerelle fait foi. Redémarrer l'Agent pour l'identité. Sans `GPX_IDENTITY_NODE_NAME`, un Agent au volume perdu reçoit un nouvel identifiant : il est alors un nouvel Agent à approuver |
| Historique | Option *Inclure l'historique* d'une planification, ou *Créer avec l'historique* : journaux, audit, bans passés, menaces, CVE, alertes émises, événements de nœuds, exécutions, historiques de déploiement et de proxy, audit et demandes du portail. Section `history` chiffrée à part (`GPXHIS1:`), **clé obligatoire** (jamais en clair : adresses IP, actions d'administrateurs). `logs` : 100 000 lignes les plus récentes ; autres tables : 500 000. Restauration : case *Historique* (décochée par défaut, superadmin), **ajout sans écrasement** (identifiant déjà présent = ignoré). Les adresses IP des logs sont chiffrées par les clés RGPD : restaurer aussi les secrets, sinon elles restent illisibles |

**Taille** : un snapshot avec historique et états de passerelles peut peser plusieurs centaines de Mo (stocké dans `admin.db` et dans `backups/`). Réserver l'historique à une planification dédiée (hebdomadaire, par exemple) avec une rétention courte.

## 5. Restauration

| Point | Comportement |
|---|---|
| Restauration d'un snapshot (bouton *Restaurer*) | Ouvre une fenêtre listant le contenu du snapshot (compteurs par entité) : on coche les entités à restaurer (proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, configuration) et le mode de conflit (**écraser** par défaut, ou ignorer). Sans sélection (API sans corps, CLI), applique tout : utilisateurs, tokens, PAT, snippets, canaux, règles d'alerte, nœuds déclarés, tables de configuration ; en mode **overwrite** (les lignes existantes de même identifiant sont remplacées) ; proxies republiés vers les passerelles ; planifications de sauvegarde rechargées |
| Snapshot de sécurité | Avant tout écrasement (restauration de snapshot ou import en `overwrite`), un snapshot `avant-restauration-<date>` / `avant-import-<date>` est pris automatiquement ; s'il échoue, l'opération est annulée. Il permet de revenir en arrière |
| Version | Une sauvegarde dont la `version` n'est pas `1` est refusée |
| Résultat | Compteurs par entité : proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, lignes de configuration, nœuds déclarés, ignorés, erreurs |
| Restaurer un seul proxy | Fenêtre *Restaurer* : liste des proxies du snapshot (recherche, cases, « Tous / Aucun », « Seulement celui-ci » qui décoche tout le reste) ; chaque proxy indique s'il sera créé ou s'il existe. La topologie déclarée a sa propre case |
| Import d'un fichier (sélection) | Cases par entité : proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, **configuration** (identique dans *Sauvegardes → Restaurer*, *Import* et l'assistant de premier démarrage) ; conflit `skip` (conserver l'existant) ou `overwrite` |
| Utilisateurs | Créés avec un mot de passe aléatoire ; en overwrite, seul le rôle est mis à jour |
| Ordre | Les tables de configuration sont restaurées dans un ordre fixe (settings → règles → domaines → équipes → workspaces → pages → portail) |
| Tokens de nœuds | Le secret n'étant jamais sauvegardé, les tokens de nœuds sont **ignorés** (comptés « ignorés ») à la restauration : les nœuds doivent être ré-appairés |
| Anciennes sauvegardes | Sans section `tables` : restauration inchangée, la case *Configuration* n'apparaît pas |
| Colonnes inconnues | Ignorées (compatibilité entre versions) |

## 6. Recommandations

1. Définir `GPX_BACKUP_KEY` (**obligatoire** pour une restauration complète) et la conserver **hors** du serveur, séparément des snapshots.
2. Planifier au moins une sauvegarde quotidienne avec rétention ≥ 7.
3. Configurer au moins une **destination hors serveur** (§4 ter) ; à défaut, copier régulièrement `<storage.base_path>/backups/` hors de l'hôte.
4. Pour un cluster HA, définir `GPX_BACKUP_KEY` : la config HA effective est dans la section `secrets`, restaurée dans `restored-config/` (§2.3).
5. Pour les passerelles, vérifier dans la page Sauvegardes (ou les journaux de l'Admin) qu'aucune n'était injoignable lors du snapshot : une passerelle absente est signalée par une alerte `backup_failed`.
6. Tester une restauration sur une instance de test après tout changement majeur.
