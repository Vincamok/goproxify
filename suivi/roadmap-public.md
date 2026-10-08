# Roadmap publique GoProxify

Vue allégée pour la communauté. Le détail interne n’est pas publié.

## Livré

### v0.3 — Sécurité avancée et observabilité _(septembre 2026)_

- **WAF avancé** : scoring anomalie, inspection requête (JSON/form/URI/headers/cookies) **et réponse** (CRS 951xxx), 13 jeux de règles OWASP CRS-4, règles custom hot-reload, métriques `gpx_waf_*`
- **WAF — nouveaux jeux de règles** : Java/Log4Shell (944xxx), RFI (931xxx), NodeJS/Prototype Pollution (934xxx), HTTP Request Smuggling (920xxx), Fichiers sensibles (930xxx), Fuites de données en réponse (951xxx)
- **Sentinel** : moteur de détection comportementale stateful par IP — fenêtre glissante, ban immédiat sur signal, paramètres anti-DDoS configurables depuis l’UI (GlobalRPS, rate_window, rate_ban_threshold), detect mode, listes custom allowlist/denylist
- **Moteur de règles automatiques** : conditions pilotées (CVE critique, pic de bans, moteur silencieux, taux d’erreur, IP récidiviste) → actions (désactiver proxy, bannir IP, alerte, mode strict F2B) ; cooldown par règle, test dry-run, historique d’exécution
- **Menu Automatisation restructuré** : 4 entrées (Vue d'ensemble, Automatisations, Alertes, Journal) avec onglets ; vue d'ensemble, éditeur de flux avec simulation dry-run et journal filtrable ; store de règles (15 templates) en onglet « Modèles »
- **Silences & maintenance** : fenêtres de temps qui suspendent l'exécution des actions du moteur de règles *et* l'envoi des notifications du moteur d'alertes (toutes les règles ou une sélection mêlant les deux), sans interrompre l'évaluation ni le journal
- **Rejeu depuis le Journal** : une entrée d'historique en échec se rejoue en un clic, sans réévaluer la condition
- **Export/import YAML de l'automatisation** : règles, canaux et silences dans un seul document GitOps, réimportable (upsert par nom)
- **Canaux Slack, Microsoft Teams, Telegram, SMS (Twilio)** : quatre types de canal d'alerte supplémentaires, au même titre qu'email/webhook/ntfy/gotify
- **Registre de modules (pilote : canaux de notification)** : paquet commun `internal/modules` (manifestes, validation, secrets), les 14 types de canal migrés, API `/alert-channel-types`, MCP, CLI et formulaire pilotés par le manifeste (ADR 0007, Admin `0.120.0`). Familles Importer (`0.121.0`) et fournisseurs DNS (`0.122.0`) migrées ; Route 53, suppression des TXT OVH/Hetzner et fournisseurs nommés corrigés (`0.123.0`). Famille Discovery migrée (Admin `0.124.0` / Agent `0.9.0`). Famille cibles de déploiement migrée (Admin `0.125.0`). Famille AuthProvider migrée, avec correctifs fail-closed (Admin `0.127.0` / Edge `0.49.0`). Famille Detector (détecteurs par route : filtre IP, GeoIP, bot, WAF) migrée (Admin `0.128.0` / Edge `0.50.0`) ; Sentinel, Fail2Ban et CrowdSec restent des moteurs globaux hors registre
- **Regroupement anti-bruit** : une fenêtre de regroupement par règle d'alerte fusionne les événements similaires en une seule notification
- **Versionnage des règles avec retour arrière** : un instantané par modification, 20 versions conservées par règle, restauration en un clic
- **Escalades avec accusé de réception** : des paliers renotifient un événement non acquitté vers d'autres canaux, jusqu'à acquittement
- **Planifications (cron)** : déclenche une action du moteur de règles à heure fixe (expression cron 5 champs), indépendamment de toute condition
- **Approbation avant action** : une règle peut exiger qu'un admin approuve ou refuse son action avant exécution
- **Playbooks** : enchaîne action, attente, condition et approbation en une séquence, déclenchable comme une action de règle/planification ou manuellement
- **Page admin "Accès MCP"** : allowlist d'IP sources pour `/mcp` (réseaux privés par défaut), vue des utilisateurs porteurs d'un token, catalogue de scopes ↔ outils
- **IP client fiable** : les en-têtes `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` ne sont crus que depuis un proxy de confiance (`GPX_TRUSTED_PROXIES`) — fin du contournement Fail2Ban/Sentinel par IP forgée
- **MCP — allowlist de destinations backend** : `create_proxy` / `update_proxy` ne peuvent pointer que vers des destinations autorisées (réseaux privés par défaut), contre le détournement de trafic par prompt injection
- **MCP — contrôle d'accès complet** : chaque outil et chaque ressource exige le scope de sa route REST équivalente, plus le rôle admin quand la route est réservée aux admins ; un outil sans scope déclaré est refusé. Nouveaux scopes `alerts:write`, `domains:write`, `certs:write` : un scope de lecture ne permet plus d'écrire, via l'API comme via le MCP
- **Écritures réservées aux admins, interface comprise** : certificats (dont pull tokens et cibles de déploiement), domaines, alertes et profils IP ne sont modifiables que par un admin, en session web comme par token API ; les snippets restent ouverts aux comptes disposant d'un droit d'écriture. L'interface masque ces actions aux autres comptes
- **Logs — réglages RGPD réservés aux admins** : rétention, anonymisation, pseudonymisation et effacement des logs ne sont modifiables que par un admin (scope `logs:write` pour un token API) ; anonymisation et pseudonymisation exclusives, l'anonymisation locale de la passerelle l'emportant toujours ; révélation d'une IP possible après désactivation de la pseudonymisation
- **Logs — RGPD dans l'interface et la CLI** : choix du mode de protection des IP (entières, anonymisées, pseudonymisées) dans les réglages de la page Logs, révélation d'une IP pseudonymisée depuis le détail d'une entrée (super-admin, motif obligatoire), effacement par IP couvrant les entrées pseudonymisées ; `goproxify logs delete`, options CLI acceptées avec `-` ou `--`
- **Tableau de bord en trois vues** : Santé (verdict et actions à mener), Cockpit (indicateurs, courbe 1 h, passerelles, certificats) et Carte (origine du trafic par pays, blocages par couche, latence par passerelle)
- **Page Proxies** (ex-Trafic puis Routage) : tuile proxy et vue tableau refaites (hôte en titre, actions secondaires dans un menu ⋯, fonctions en icônes, métriques en ligne) ; modale de proxy unifiée (navigation latérale groupée par intention, section WAF à part avec sélecteur de plateformes applicatives) ; vues « état » (santé, KPIs, courbe) et « maître/détail » ; création de proxy en mode Simple (cartes de protections), lignes dépliables, courbes alimentées par un historique de métriques côté Admin
- **Menu unifié Admin / passerelles** : un rail latéral (Admin + une pastille par passerelle, recherche au-delà de 6) remplace la liste de passerelles ; un seul menu (Proxies, Observabilité, Sécurité) commun, suivi de la section Plateforme (Admin) ou Passerelle (Portail Access, Tunnel L4, Paramètres) ; l’entrée « Trafic » devient « Proxies »
- **Traçage d’une IP ou d’un CIDR** : onglet Sécurité › Traçage IP — parcours chronologique d’une IP malveillante ou d’une plage sur une longue période (requêtes regroupées en épisodes, détections WAF/Sentinel/CrowdSec, bans et débans, bans en cours, profils IP concernés) ; aussi en CLI (`security trace`) et MCP (`trace_ip`) (Admin `0.82.0`) ; raccourci « Analyser l’IP » depuis les bans, menaces, Sentinel, Prism et les logs, sur l’IP ou sa plage (Admin `0.83.0`)
- **Profils IP : saisie manuelle et modèles** : modification d’un profil existant ; un profil peut être une liste d’IP/CIDR saisie à la main (en plus d’un feed), le formulaire propose des modèles de feeds (Bogons, blocklist.de, CINS Army) et explique la portée globale et la priorité `allow` sur `deny` (Admin 0.81.0)
- **Restauration sélective des snapshots** : le bouton *Restaurer* permet de choisir les entités à restaurer et le mode de conflit ; menu Sauvegardes réduit à Snapshots / Planification (Admin `0.80.0`)
- **Sauvegardes : destinations hors serveur (S3, WebDAV, dossier), vérification d’intégrité et alertes** : chaque snapshot est copié, relu et comparé ; alerte sur échec ou exécution manquée (Admin `0.105.0`)
- **Sauvegardes : clé de chiffrement gérée depuis l’interface** : génération, rotation sans perdre les anciens snapshots, révélation par le superadmin avec son mot de passe (Admin `0.111.0`)
- **Sauvegardes complètes** : config HA, état de chaque passerelle et de ses Agents, et historique (journaux, audit, bans) dans des sections chiffrées, restaurables par le superadmin (Admin `0.110.0`, Edge `0.39.0`, Agent `0.8.0`)
- **Sauvegardes : section secrets chiffrée** : avec `GPX_BACKUP_KEY`, les snapshots embarquent mots de passe, MFA, tokens, clés RGPD/ECH, CA interne et fichiers d’état pour restaurer une infrastructure complète (superadmin) (Admin `0.98.0`)
- **Recherche de fonctionnalités (Ctrl+K)** : palette de recherche dans la barre du haut (aussi `/`) pour retrouver n’importe quelle page de l’Admin ou d’une passerelle par titre ou mot-clé (WAF, ACME, SSO, sauvegardes…), retrouve aussi proxies, certificats, domaines, passerelles, snippets et utilisateurs par leur nom, filtrée selon le rôle (Admin `0.73.0`)
- **Menu Sécurité en onglets** (Synthèse, Vulnérabilités, Bans, Sentinel, Score par proxy — note de A à F sur 9 contrôles), Synthèse unique (score, bans par source, menaces, timeline) et fenêtre « Moteurs de sécurité » à interrupteurs par capacité et page **Vulnérabilités** en vue Parc / Liste avec tiroir de détail, identique pour l’Admin et les passerelles, adaptée au mobile
- **Page Bans** refonte : une seule page pour l’Admin et les passerelles (KPI, frise 48 h, pays, sources, liste filtrable avec actions groupées, adaptée au mobile) ; les bans sont rattachés à leur passerelle d’origine
- **Moteurs IPS** : page unifiée Fail2Ban / CrowdSec avec configuration in-place
- **Timeouts serveur HTTP/QUIC** : ReadHeader, Read, Write, Idle configurables depuis l’Admin et propagés aux passerelles
- **Vocabulaire unifié** : « Core » devient « passerelle » (FR) / « Edge » (EN) dans l'interface, la CLI, les variables d'environnement, l'image et le conteneur ; migration automatique des bases et fichiers existants (voir le changelog)
- **Scanner CVE** : toggle UI pour autoriser les backends IP privées (opt-in, anti-SSRF par défaut) ; enrichissement KEV (catalogue CISA, exploitation active) et EPSS (probabilité d'exploitation, FIRST.org) en fin de scan ; SLA de correction réglable par gravité (page Vulnérabilités, fenêtre Moteurs de sécurité, CLI, MCP)
- **Politiques d’accès centralisées** : vue unifiée IP/GeoIP/Bot par proxy dans l’Admin
- **Logs** : corrélation exacte par `request_id`, keyset pagination, vue live mobile
- **Logs d'accès** : refonte de la vue, commune à l'Admin (chips de passerelle colorées) et au menu Edge (portée verrouillée) ; colonne Hôte et chemin fusionnée, colonne Pays (résolue depuis le cache géo-IP déjà utilisé par le tableau de bord/Prism/Bans)
- **Prism** : taux d’erreurs et IPs bannies par pays ; bouton accès rapide depuis la table des bans
- **Prism** : refonte « centre de commande » (carte zoomable, anomalies détectées, onglets) — livré
- **Observabilité** : Synthèse commune à l’Admin et aux passerelles, Prism recentré (onglets Chemins / IP / Sources / Pays), carte Leaflet avec vues par ville et par région et connexions en direct, carte « Attaques en direct » dans la Synthèse sécurité, anomalies calculées côté serveur (API, MCP `get_prism_anomalies` / `get_prism_geo`, CLI `goproxify prism`) — livré
- **Vue Proxy** : nouveau menu racine (remplace « Explorer ») — barre de recherche + période + Live, sélection cumulable de proxies (tuiles, KPI, carte, anomalies, courbe, chemins, IP) ; temps réel uniquement sur demande — livré
- **Serveur de fichiers statiques avec fallback SPA** : option `static` d'un proxy (dossier de la passerelle, repli sur l'index, ETag, cache), sans backend — livré (Edge `0.41.0`)
- **Diff des réponses shadow** : `shadow.compare` compare statut, en-têtes choisis et corps du miroir au primaire, avec métriques et échantillon de log — livré (Edge `0.42.0`)
- **Validation JSON Schema des requêtes** : option `request_schema` (règles par méthode et chemin, mode `block` / `detect`, métriques) — livré (Edge `0.43.0`) ; validation OpenAPI complète (chemins, méthodes, paramètres, corps) — livré (Edge `0.46.0`, option `openapi`)
- **Compression des réponses** : zstd, Brotli et gzip négociés par proxy selon `Accept-Encoding` (Avancé › Compression des réponses) — livré
- [x] **Sentinel — page en onglets et tiroir de réglages** : vue d'ensemble, détections, listes et exceptions ; simulation sur les logs récents avant d'enregistrer (`POST /security/threat-config/simulate`, `goproxify security threat simulate`)

### v0.2 — Architecture distribuée _(juillet – août 2026)_

- Reverse proxy distribué Admin / Passerelle / Agent (un binaire, trois modes)
- Relay passerelle→Passerelle multi-hôtes (Portainer / délégation)
- GoProxify Access (portail SSH / shell, 2FA, sessions TTL)
- Wizard architecture (toile, tickets QR / `curl|bash`, multi-passerelle / HA)
- Sécurité : MFA, CrowdSec bouncer, WAF, GeoIP, RBAC grants, SSO (OIDC/SAML/LDAP/GitHub)
- Tokens API utilisateur (PAT) + MCP server
- CLI opérationnel (`token`, `backup`, `alert`, `import`, `nodes`, `access`)
- Métriques Prometheus, Prism dashboard, Logs d’accès live
- **Observabilité complète** : instrumentation Prometheus de tous les services (backend health, peer sync, WAF, portal sessions, Admin HTTP, VulnScan, Rules Engine) — `docs/services.md`
- i18n EN / FR / ES / DE
- Quickstart Docker Compose + images GHCR (preview)

## En cours / prochain

- [x] **Workspaces** : espaces de travail nommés regroupant proxies, domaines et edges — assignation d'équipes et utilisateurs pour une isolation multi-tenant ; page Admin dédiée (Accès → Espaces de travail)
- [x] Stabiliser les tags SemVer et Releases GitHub régulières
- [x] Hygiène CI publique (lint/tests documentés)
- [x] Polish UX Access et docs opérateur
- [x] **Portail Access en onglets** (Synthèse, Destinations, Utilisateurs, Modèles, Audit, Réglages) — livré
- [x] **Portail Access : refonte visuelle, thèmes et entrées dédiées** (`/prestataire`, `presta.domaine.fr`… : thème, auth, utilisateurs, groupes et destinations par entrée ; 7 thèmes réglés côté Admin) — livré
- [x] **Portail Access : groupes de destinations** (Catalogue Access › Groupes ; une entrée offre toutes les machines de ses groupes ; API, CLI, MCP) — livré
- [x] **Portail Access : sessions en direct** (lister, terminer ; API, CLI, MCP) — livré
- [x] **Portail Access : accès temporaires avec approbation** (demande depuis le portail, onglet Approbations, expiration automatique ; API, CLI, MCP) — livré
- [x] **Portail Access : politiques d'accès** (plages horaires, IP autorisées, déconnexion sur inactivité ; onglet Politiques, API, CLI, MCP) — livré
- [x] **Portail Access : enregistrement et rejeu des sessions** (sortie du terminal chiffrée sur la passerelle, conservation réglable, lecteur dans l'admin ; API, CLI, MCP) — livré
- [x] **Portail Access : observation en direct d'une session** (sortie du terminal, journalisée ; UI, API, CLI) et **notification email** des demandes d'accès — livré
- [x] SBOM attaché à chaque Release (workflow sbom-sign.yml)

### Résilience backend (v0.4)

- [x] **Health-check actif configurable** : `HealthCheckConfig` par route (path, interval, timeout, thresholds) ; `StartChecksFromRoutes` remplace l'appel global avec intervalle fixe
- [x] **Retry + circuit-breaker câblés** : `circuitBreaker` rendu thread-safe (mutex), `RecordSuccess`/`RecordFailure` appelés depuis le handler après chaque tentative
- [x] **Rate-limiting par utilisateur authentifié** : champ `key_by` dans `RateLimitConfig` — `ip` (défaut), `jwt_sub`, `jwt_email`, `jwt_claim:<nom>`

### Certificate Hub (v0.8)

- [x] **Certificate Deploy Hub** : deploy targets (webhook HMAC signé, ssh_exec), pull tokens multi-format (PEM/DER/PKCS#12/JSON), déclenchement automatique à chaque renouvellement ACME, historique d'audit
- [x] **Import de certificats externes** : upload PEM+clé via l'UI ou `POST /api/v1/certs/import` — domaine extrait automatiquement, push immédiat aux passerelles connectées
- [x] **Monitoring ACME** : dashboard statut par cert (days_left, ok/warning/critical/expired), alertes automatiques `cert_expiring_soon` (≤30j warning, ≤7j critical) et `cert_deploy_failed` vers le moteur d'alertes existant
- [x] **ACME HTTP-01 et TLS-ALPN-01** : méthodes de validation par domaine en plus de DNS-01 (`cert_method` `acme-http` / `acme-tls-alpn`), réponses posées par l'Admin sur les passerelles, renouvellement automatique inclus — livré
- [x] **OCSP stapling** : agrafage côté passerelle, autonome (Edge `0.20.0`) — livré
- [x] **ECH** (Encrypted Client Hello) : clés générées par l'Admin, poussées et conservées par les passerelles, rotation, page Admin, CLI, MCP (Admin `0.75.0`, Edge `0.21.0`) — livré ; réplication des clés entre membres d'un groupe HA sans l'Admin (Edge `0.40.0`)
- [x] **Conversion de formats** : package `certformat` — PEM, DER, PKCS#8, PKCS#12/PFX, fullchain, JSON
- [x] **CA interne** : génération d'une autorité racine auto-signée et émission de certificats serveur/client internes (hors ACME) pour les services internes — API `/api/v1/internal-ca`, CLI `goproxify internal-ca`, outils MCP dédiés
- [x] **Page « Domaines & certificats » en vue unique** : certificats publics et locaux dans une même liste (filtre, recherche, compteurs), actions en bout de ligne, assistant d'ajout Public / Local / Importer, réglages ACME, fournisseurs DNS et CA internes dans un tiroir (Admin `0.34.0`)

### Fonctionnalités à venir

- [x] **Forward-auth** compatible Authelia, Authentik, oauth2-proxy (2xx accepté, redirection de connexion, jokers d'en-têtes, en-têtes d'identité forgés retirés) — livré
- [x] **Routage avancé** : split pondéré avec affectation A/B persistante, condition sur claim JWT — livré
- [x] **URLs signées** (HMAC + expiration), **quotas par clé d'API ou cookie**, **plafond de débit par réponse** — livré
- [x] **Mode maintenance par route**, **masquage de champs JSON**, **limites de profondeur et d'introspection GraphQL** — livré
- [x] **Requêtes « hedged »** : GET/HEAD doublé vers un second backend après un délai, première réponse gardée — livré
- [x] **gRPC-Web** vers un backend gRPC — livré
- [x] **Transcodage REST↔gRPC** : option `grpc_transcode` — un backend gRPC unaire exposé en REST/JSON d'après ses annotations `google.api.http`, à partir d'un `.proto` ou d'un `FileDescriptorSet` ; réglable dans l'interface — livré (Edge `0.47.0`, Admin `0.119.0`) ; méthodes à flux (serveur en NDJSON, client, bidirectionnel) — livré (Edge `0.48.0`)
- [x] **Quotas partagés entre les passerelles d'un groupe HA** (`rate_limit.shared`) — livré ; le débit instantané reste local
- [x] **Options de routage avancé en CLI et MCP** (`proxy option`, `update_proxy` `options`) — livré
- [x] **Options de routage avancé dans l'interface graphique** : modale de proxy › Avancé › Routage avancé (split, URLs signées, maintenance, masquage, GraphQL, hedge, gRPC-Web, débit, statique, schéma de requête) et quotas dans Protection › Rate limiting — livré (Admin `0.115.0`)
- [x] **Cache HTTP complet** : `stale-while-revalidate`, `stale-if-error`, coalescing des requêtes, purge par tag (`Cache-Tag`) ou URL — livré
- [x] **PROXY protocol v1/v2** : en entrée (derrière un load balancer L4) et en sortie vers les backends HTTP et le passthrough TLS — livré
- [x] **PROXY protocol : sondes de santé** : l'en-tête est aussi envoyé aux sondes des backends qui l'exigent (`LOCAL` / `UNKNOWN`, sans adresse de client) — livré (Edge `0.45.0`)
- [x] **Challenge anti-bot par preuve de travail** : page de validation navigateur (type Anubis), Turnstile / hCaptcha en option — livré
- [x] **Challenge anti-bot : réglages dans l'interface** : fournisseur, difficulté, durée, clés et chemins exemptés dans Protection › Protection bot — livré (Admin `0.115.0`)
- [x] **Empreinte TLS JA3/JA4** : calculée au ClientHello et branchée sur Sentinel pour bannir sur signature — livré
- [x] **JA3/JA4 dans les logs Admin** : colonne, détail et filtre dans Logs ; API, CLI et MCP — livré (Admin `0.115.0`, Edge `0.44.0`) ; onglet « Empreintes TLS » de Prism (top JA4 : requêtes, erreurs, requêtes signalées, IP distinctes ; API, CLI `prism tls`, MCP `get_prism_tls_fingerprints`) — livré (Admin `0.117.0`)
- [x] **Dashboard Sentinel** : endpoint `/security/bans/countries` (heatmap par pays, JOIN `geoip_cache`)
- [x] **Webhooks sur événements** : canal webhook générique sur `sentinel_ban` et `backend_down` ; `Manager.SetAlertEngine` pour injecter l'engine d'alertes ; callback `BackendHealth.OnDown` → message WS passerelle→Admin
- [x] **Discovery Kubernetes** : Agent qui lit les `Ingress`/`Service` avec annotations `goproxify.*`, symétrique du mode Docker existant
- [x] **Pipeline de transformation de requête** : `RequestTransform` sur `Route` (add/remove request+response headers, réécriture de préfixe URL) — middleware `Transform` hot-reload avec le reste de la config
- [x] **Tunnel L4 mTLS passerelle↔passerelle** : package `internal/edge/tunnel` — `Manager` (pool de pairs, failover automatique) + `Serve` (listener mTLS, protocole CONNECT-like) + UI Admin de configuration des peers + WS push Admin→Passerelle (`push_tunnel_config`) avec `SetPeers` à chaud
- [x] **Diff de config proxy** : endpoint `GET /api/v1/proxies/{id}/revisions/diff?from=&to=` + bouton "Diff config" dans l'UI Traffic — modal interactif avec comparaison champ par champ entre deux révisions (ou production vs. dernière)
- [x] **MCP server étendu** : outils `ban_ip`, `unban_ip`, `rotate_cert` ajoutés au MCP server
- [ ] **SBOM + attestation cosign** : génération SBOM SPDX (syft) + signature keyless cosign des images — assurée jusqu'ici par un workflow GitHub Actions supprimé ; à réintégrer dans le pipeline de publication (plateforme de CI à choisir)
- [x] **Sentinel — compteurs bornés** : sharding, plafond mémoire, IPv6 agrégées par /64, `rate_window` effectif
- [x] **Fail2Ban — IPv6** : clients IPv6 reconnus (avec ou sans port), comptés et bannis par /64 sur l'Admin et les passerelles ; liste blanche IPv6 effective
- [x] **Fail2Ban — IP anonymisées** : l'Admin ne bannit plus sur les IP tronquées par la passerelle (`x.x.x.0`, préfixe /48), signalées ligne par ligne ; les passerelles bannissent sur l'IP réelle
- [x] **Logs et Prism — IP anonymisées** : une IP tronquée est marquée dans le détail d'un log et dans le top IPs de Prism, sans action Bannir ni analyse d'IP ; l'anomalie « IP dominante » ne vise que des IP attribuables ; `ip_truncated` exposé par l'API, le flux temps réel et l'outil MCP `list_logs`
- [x] **Backpressure par route** : plafond de requêtes simultanées, file bornée, 503 + `Retry-After`, métriques Prometheus
- [x] **Slow-start du load balancer** : montée en charge progressive (~5 % → 100 %) d'un backend nouvellement ajouté ou revenu après panne, `slow_start_sec` par route
- [x] **Profils IP — listes optimisées** : agrégation/déduplication des CIDRs, plages privées exclues des listes deny, téléchargements conditionnels (ETag / 304), profils redondants avec FireHOL Level 1 désactivés par défaut
- [x] **Profils IP — résilience** : backoff exponentiel sur les feeds en échec, état (`last_error`, `consecutive_failures`, `next_attempt_at`) exposé API/MCP/CLI/UI, garde-fou contre les listes vidées ou tronquées
- [x] **Profils IP — alerte** : déclencheur `ip_profile_refresh_failed` après N échecs consécutifs (défaut 3, réglage `ipprofile.alert_after_failures`)
- [x] **OpenTelemetry** : propagation W3C `traceparent` jusqu'au backend, span par appel backend, décisions Sentinel/ban en événements, échantillonnage configurable, endpoint OTLP poussé par Admin appliqué à chaud
- [x] **Schéma d'architecture** : la page Infrastructure et le wizard partagent un schéma Internet → passerelles (HA) → Admin → agents lu depuis `architecture.json`, responsive, avec modale Configuration (formats, écarts, versions) ; `GET /api/v1/architecture`, `goproxify architecture show`, outil MCP `get_architecture`
- [x] **Topologie temps réel** : carte Admin → passerelles → Agents rafraîchie toutes les 5 s (santé, débit req/s, score de risque 0-100 avec facteur dominant) ; `GET /api/v1/nodes/live`, `goproxify nodes live`, outil MCP `get_topology_live`
- [x] **Infrastructure — vue globale et mode édition revus** : bandeau d'indicateurs unique, barre « À traiter », schéma en flux Internet → passerelles → agents avec liaisons tracées, panneau de détail du nœud sélectionné ; édition sur place avec palette glisser-déposer, repères Nouveau / Modifié / Retiré, impact de chaque modification et revue avant enregistrement
- [x] **Infrastructure — finitions** : vue Liste filtrable, brouillon d'édition conservé, latence p95 par passerelle, journal complet, diff de `architecture.json` et révocation des nœuds retirés dans la revue, édition au doigt, traductions espagnol / allemand
- [x] **Infrastructure — panneau « Configuration » d'un hôte** : navigation latérale Déployer / Vérifier / Historique, visionneuse de code avec secrets masqués, ticket d'installation guidé, écarts par nœud, frise des versions
- [x] **HA — configuration et données partagées par groupe** : Sentinel, fournisseur IPS, timeouts et portail d'accès suivent le groupe HA (config unique, membre sans portail en attente), magasin du portail répliqué entre passerelles (chiffré par une clé de groupe, sessions `sticky` ou `shared` au choix), listes de référence Sentinel synchronisées, bans échangés entre passerelles sans l'Admin
- [x] **HA — Agent rattaché à un groupe entier** : dans le wizard Infrastructure, le sélecteur « Passerelle cible » d'un Agent propose aussi les groupes HA (2 passerelles ou plus) ; le lien vaut alors pour toutes les passerelles du groupe (actif/actif ou actif/passif), sans dépendre d'une seule passerelle cible
- [x] **Portail Access autonome sur la passerelle** : la passerelle garde une copie chiffrée de la configuration du portail (réglages, politiques, accès temporaires en cours) reçue de l'Admin et redémarre le portail dessus sans l'Admin ; l'Admin reste le point de modification et son envoi remplace la copie locale. La clé du groupe HA est aussi conservée dans le magasin du portail (chiffré par la clé maître de la passerelle), pour que la réplication entre pairs reprenne pendant une coupure de l'Admin
- [x] **Groupe HA autonome** : la passerelle garde la liste de ses pairs HA et la topologie du groupe (copies locales chiffrées, reçues de l'Admin) pour reprendre la synchronisation avec ses pairs après un redémarrage sans Admin
- [x] **Agent — reprise** : l'Agent réannonce tous ses conteneurs à chaque reconnexion à sa passerelle (un changement survenu pendant une coupure n'est plus perdu)
- [x] **Agent — bascule HA** : un Agent rattaché à un groupe HA connaît tous les membres et bascule vers un autre si sa passerelle tombe (HMAC des Agents répliqués dans le groupe, membres annoncés par la passerelle)
- [x] **RGPD — délégation du droit de révélation d'IP** : rôle `dpo`, droit accordé en propre à un compte ou à une équipe, par le superadmin seul ; comptes détenteurs protégés contre la prise de contrôle par un admin (Admin 0.78.0)
- [x] **Audit d'autonomie de la passerelle** : persistance locale de chaque envoi de l'Admin vérifiée (les réglages runtime sont persistés depuis Edge 0.17.10, les règles automatiques et le tunnel L4 depuis Edge 0.24.1, la configuration serveur et les modèles du portail depuis Edge 0.24.2, la topologie du cluster Raft depuis Edge 0.24.3) — voir `docs/adr/0006-autonomie-des-composants.md`
- [x] **Dry-run Sentinel via MCP** : `simulate_sentinel_config` rejoue les logs récents contre une config candidate et la compare à l'actuelle
- [x] **Sentinel — tarpit** : retient la réponse aux IP bloquées ou bannies (délai configurable, nombre de requêtes retenues plafonné, repli sur refus immédiat)
- [x] **Sentinel — score cumulé par IP avec décroissance** : les signaux s'additionnent d'une requête à l'autre et s'estompent avec le temps (demi-vie réglable), l'IP n'est bannie qu'au seuil ; optionnel, réglable depuis l'UI, la simulation et le MCP
- [x] **Sentinel — bans graduels** : la durée du ban croît avec les bans Sentinel précédents de l'IP (facteur, fenêtre et plafond réglables, remise à zéro au déban manuel) ; optionnel, réglable depuis l'UI, la simulation et le MCP
- [x] **Sentinel — 4xx pondérés** : erreurs 4xx pondérées par code (hors 401/403/429) et par route, intégrées au score cumulé ; optionnel, réglable depuis l'UI, la simulation et le MCP
- [x] **Observabilité — fond vectoriel auto-hébergé** : zoomer jusqu'à la rue sur les cartes de l'Admin, sans service de tuiles externe, avec un fichier PMTiles OpenStreetMap posé sur le serveur (zone de son choix, thème clair/sombre suivi)
- [x] **Page Bans — bans par plage CIDR** : un ban vise une adresse ou une plage CIDR, validée et normalisée (plage plus large que /16 IPv4 ou /32 IPv6 et auto-verrouillage refusés), avec un aperçu de l'impact avant validation (trafic récent dont les requêtes réussies, bans et profils qui recoupent la cible) ; UI, API, CLI et MCP
- [x] **Page Bans — liste blanche** : adresses et plages CIDR qu'aucun ban n'atteint (manuel, Fail2Ban, CrowdSec, Sentinel, règles) et que Sentinel n'évalue pas, avec un commentaire ; les bans existants ne sont pas supprimés mais cessent de s'appliquer ; conservée par les passerelles (fonctionne sans l'Admin) ; UI, API, CLI et MCP
- [x] **Page Bans — import de liste** : création de bans (ou d'entrées de la liste blanche) en une fois depuis un texte, un CSV (dont l'export des bans) ou un JSON ; chaque entrée validée comme un ban unitaire, rapport ligne par ligne, mode analyse sans rien créer ; UI, API, CLI et MCP
- [x] **Page Bans — ban ciblant une passerelle ou un groupe** : un ban (manuel ou importé) ne s'applique qu'à une passerelle ou aux membres d'un groupe HA ; chaque passerelle ne reçoit que les bans qui la concernent
- [x] **Page Bans — filtres enregistrés** : combinaisons de filtres de la liste nommées, rappelées et supprimées depuis la page (gardées dans le navigateur)
- [x] **Page Bans — bans par ASN** : recherche d'un ASN (numéro, IP ou nom), aperçu d'impact, ban de toutes ses plages en une opération, levée groupée (UI, API, CLI, MCP) ; données ip2asn publiques téléchargées par l'Admin

### Intégrations Infrastructure as Code

- [ ] **Provider Terraform — publication et ressources restantes** : le provider est écrit (`integrations/terraform-provider-goproxify` : `goproxify_proxy`, `goproxify_ban`, `goproxify_ban_whitelist_entry`, `goproxify_ip_profile`) ; reste à le publier sur le Registry (dépôt public dédié, clé GPG) et à ajouter `goproxify_domain`, `goproxify_workspace`… — gestion déclarative de la config GoProxify depuis Terraform/OpenTofu, appuyée sur l'API existante
- [ ] **Collection Ansible** : modules et rôles (`goproxify_proxy`, `goproxify_cert`, `goproxify_access_target`…) pour provisionner et maintenir GoProxify depuis des playbooks

Proposer des idées via
[Discussions](https://github.com/Vincamok/goproxify/discussions) ou une issue
« feature ». Voir aussi [CONTRIBUTING.md](../CONTRIBUTING.md).
