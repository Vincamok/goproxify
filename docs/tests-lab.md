# Labo de tests — procédure pas à pas

Guide d'exécution du labo `tests/lab/` (charge, sécurité, chaos, fonctionnalités des proxies) sur un daemon Docker distant, avec les résultats du premier passage (2026-09-24). Référence rapide : [tests/lab/README.md](../tests/lab/README.md). Suite fonctionnelle : [rapport-tests-2026-10-03.md](rapport-tests-2026-10-03.md). Dernière campagne sécurité/chaos : [rapport-tests-2026-10-02.md](rapport-tests-2026-10-02.md) (précédent : [rapport-tests-2026-09-24.md](rapport-tests-2026-09-24.md)).

> **Passage rapide, sans stack existante.** `tests/lab/run-security.sh` et `tests/lab/run-load.sh` montent un labo local jetable (`docker-compose.local.yml` : Admin et passerelle compilés depuis les sources, `lab-backend`, `lab-sim`, runners), exécutent la suite de sécurité ou les tests de charge et écrivent un rapport horodaté dans `tests/lab/results/` (`securite-AAAAMMJJ-HHMMSS.md`, `charge-AAAAMMJJ-HHMMSS.md`). Détail et options : [tests/lab/README.md](../tests/lab/README.md). Le reste de ce guide concerne le labo branché sur une stack déployée.

> **Le labo se branche sur la stack existante (`goproxify_net`).** Sur une stack de production, il crée des routes `*.lab.test` dans l'Admin et la passerelle réelles : n'exécuter que les tests « faible impact » (§4) et nettoyer ensuite (§7).

## 1. Principe

| Élément | Rôle |
|---|---|
| `lab-backend` | Backend Go contrôlable (`/`, `/echo`, `/slow`, `/flaky`, `/bytes`, `/upload`, `/sse`), source embarquée dans le compose |
| `lab-toxiproxy` | Injection de pannes réseau entre la passerelle et le backend (route `lab-chaos`) |
| `lab-tools` | Runner bash : `seed.sh`, `attacks.sh`, `chaos.sh`, `cleanup.sh` |
| `lab-k6` | Runner de charge (scénarios `smoke`, `moderate`, `baseline`, `spike`, `stress`, `soak`, `mixed`) |
| `lab-juice` | Cible vulnérable optionnelle (profil `vuln`) |
| `lab-sim` | Applications simulées pour les suites fonctionnelle et sécurité et le trafic réaliste : boutique à 3 instances, canary, shadow, legacy, 2 instances de sonde, écho WebSocket/TCP, port de contrôle interne (détail : [tests/lab/README.md](../tests/lab/README.md)) |

Aucun build ni montage de fichier : les scripts sont embarqués dans `docker-compose.lab.yml` par `tests/lab/gen-compose.sh` (à relancer après toute modification de `scripts/` ou `load/`). Les runners retrouvent eux-mêmes l'IP de la passerelle (`scripts/hosts.sh`).

## 2. Déploiement

1. La stack principale (Admin + Passerelle) doit tourner.
2. Déployer `tests/lab/docker-compose.lab.yml` comme stack séparée (dépôt git). Vérifier :

```bash
sudo docker ps --filter name=lab- --format '{{.Names}} {{.Status}}'
```

Attendu : `lab-backend`, `lab-toxiproxy`, `lab-tools`, `lab-k6` en `Up` (`lab-tools` installe ses paquets au démarrage : quelques secondes).

3. Après **chaque** modification des scripts : pousser, puis redéployer en récupérant à nouveau le dépôt (les scripts sont dans les conteneurs).

## 3. Authentification (seed)

Le seed appelle l'API Admin. Préférer un **jeton d'API (PAT)** à un mot de passe : Admin → Paramètres → Mes tokens API → « + Nouveau token », scopes `proxies:read`, `proxies:write`, `proxies:delete`, expiration courte. À défaut : `LAB_ADMIN_EMAIL` / `LAB_ADMIN_PASSWORD` (les identifiants du compose ne sont que des valeurs par défaut, pas des identifiants valides).

```bash
sudo docker exec -e LAB_ADMIN_TOKEN='gpx_pat_...' lab-tools bash /lab/scripts/seed.sh
```

Attendu : une ligne par route (`lab-fast`, `lab-waf-block`, `lab-waf-detect`, `lab-ratelimit`, `lab-chaos`, `lab-juice`) avec `(201)`, puis `toxiproxy: backend :8666 -> lab-backend:9000`. Relancé, le seed affiche « déjà présent : ignoré ».

## 4. Tests, dans l'ordre

Chaque commande affiche PASS/FAIL ; le code retour de `attacks.sh` et `chaos.sh` est le nombre d'échecs.

| # | Test | Commande | Impact production |
|---|---|---|---|
| 1 | Smoke (2 VUs, 15 s) | `docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/smoke.js"` | Nul |
| 2 | Attaques sans la section Admin | `docker exec -e LAB_SAFE=1 lab-tools bash /lab/scripts/attacks.sh` | Faible (routes `lab-*`) |
| 3 | Chaos réseau | `docker exec lab-tools bash /lab/scripts/chaos.sh` | Faible (route `lab-chaos` seule) |
| 4 | Charge modérée à débit imposé (300 req/s, 1 min ; `RATE` et `DURATION` réglables) | `docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/moderate.js"` | Modéré (partage le CPU de la passerelle) |
| 5 | Saturation (50 VUs sans pause, ~1 min) : débit atteint, sans seuil de latence | `docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/saturation.js"` | Modéré à élevé (sature le CPU de la VM) |
| — | Attaques complètes (brute-force login Admin) | sans `LAB_SAFE=1` | **Élevé** : échecs de connexion réels sur l'Admin, alertes/audit |
| — | `spike`, `stress`, `baseline`, `soak`, `mixed` | `k6 run /scripts/<nom>.js` | **Élevé** : à réserver à un environnement isolé ou à une fenêtre de maintenance |
| 6 | Fonctionnalités (34 routes, 29 sections) | `docker exec lab-tools bash /lab/scripts/features.sh seed` puis `docker exec lab-tools bash /lab/scripts/features.sh run` | Faible : routes `lab-*`, ~500 requêtes au total, quelques rafales de 6 à 8 requêtes concurrentes. Créer les routes demande un PAT (`proxies:write`) ; `LAB_RUNNER_CIDR` ajoute le poste de test à la liste blanche Ephor des routes pour éviter qu'il soit banni par ses propres 403/502 attendus |
| 7 | Trafic réaliste (~150 req/s au pic, 3 min ; `SHOP_RATE`, `DURATION` réglables) | `docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/realistic.js"` | Faible à modéré (route `lab-realistic`) |
| 8 | Sécurité (17 routes `lab-sec-*`, 26 sections) | `docker exec lab-tools bash /lab/scripts/security.sh seed` puis `docker exec lab-tools bash /lab/scripts/security.sh run` | Modéré : une centaine de 403/401/400 volontaires et quelques rafales ; le seed importe un certificat auto-signé `*.lab.test` dans l'Admin et place l'IP du poste (ou `LAB_RUNNER_CIDR`) dans la liste blanche Ephor des routes `lab-sec-*`. `LAB_BRUTE=1` ajoute un brute-force du login Admin (échecs de connexion réels : stack jetable seulement) |

Toutes les commandes `docker` s'écrivent avec `sudo` sur la VM.

## 5. Ce que vérifie chaque test

- **Attaques** : WAF en block/detect (SQLi, XSS, traversal, Log4Shell, injection de commande), `X-Forwarded-For` complété par la passerelle, en-têtes hop-by-hop, Host inconnu/dupliqué, `TRACE`, en-tête de 64 Ko, corps > `max_body_mb` transmis intact, request smuggling CL+TE, rate-limit, slowloris (coupure attendue à 10 s), et hors `LAB_SAFE` : API Admin sans jeton, JWT `alg=none`, traversal API, frein anti brute-force.
- **Chaos** : latence +1,5 s propagée, backend coupé → 502 immédiat puis reprise, connexion réinitialisée, backend muet (coupure à 30 s), bande passante 50 Ko/s. Toxiproxy est sans état : `chaos.sh` recrée son proxy à chaque lancement et s'arrête si la route de référence n'est pas saine.
- **Charge** : `moderate` fixe le débit (modèle ouvert) pour mesurer la latence de service (p95 < 100 ms, p99 < 300 ms, aucune itération abandonnée) ; `saturation` lance 50 utilisateurs sans pause pour mesurer le débit atteint (facteur limitant : k6, Passerelle ou VM). En modèle fermé la latence reflète la file d'attente (loi de Little : latence moyenne ≈ VUs / débit), d'où l'absence de seuil de latence.
- **Fonctionnalités** (`features.sh`) : une route `lab-*.lab.test` par fonctionnalité du proxy, devant les applications simulées de `lab-sim`. Chaque section vérifie le comportement observable de bout en bout (instance qui répond, en-têtes reçus par le backend, en-têtes reçus par le client, codes, délais) et pas seulement le code retour. Sections : `lb weighted sticky health retry cb transform paths redirect subfilter cors cache ip vars backpressure canary shadow cond errpages ws body secheaders timeout auth bot wafcustom headers stream toggle` (`features.sh run lb,cache` pour en lancer quelques-unes). L'état des instances simulées est remis à zéro en sortie.
- **Trafic réaliste** (`realistic.js`) : visiteurs (page, 3 à 5 assets, catalogue JSON, 30 % se connectent et valident un panier), clients API, flux SSE de 3 s, échanges WebSocket, téléchargements de 2 Mo et envois de 512 Ko, avec une courbe de journée à débit imposé (modèle ouvert). Les seuils sont posés par type de requête (`page`, `api`, `slow`, `asset`, `sse`, `download`, `upload`) et le résumé les détaille.
- **Sécurité** (`security.sh`) : sections `trust acl ratelimit inject protocol waf cache ws jwt errleak admin spoof rights bans ephor tarpit decoys challenge ipcontrols geoip mtls asn http3 internal redirect tls`. Un pair en réseau privé est un proxy de confiance par défaut : `trust` le détecte et les contrôles d'usurpation d'IP sont alors ignorés (à tester depuis une source non privée). Résultats du premier passage : [rapport-securite-2026-10-03.md](rapport-securite-2026-10-03.md).
  - Ajoutées avec le modèle de droits ([ADR 0022](adr/0022-modele-de-droits-niveaux-et-perimetres.md)) : **`rights`** (un PAT `proxies:read` ne peut ni écrire ni lire les comptes, les bans ou le secret d'appairage, ne crée pas de PAT et cesse de fonctionner une fois révoqué ; un compte `user` sans équipe ne voit rien ; un compte `user` ne se promeut pas administrateur ni ne crée de proxy ; un accès d'équipe en lecture sur `lab-sec-plain*` ne laisse voir, lire par identifiant ou supprimer que ce périmètre ; le compte et l'équipe de test sont supprimés ensuite), **`bans`** (`1.2.3.1-9`, texte libre, `/8` et `0.0.0.0/0` refusés ; un ban posé par l'API est appliqué par la passerelle en quelques secondes, n'atteint pas une autre IP, et le déban est appliqué de même) et **`internal`** (`/internal/v1/*` et `/mcp` de l'Admin refusent l'absence de jeton et un jeton inventé, pas de pprof, API interne de la passerelle `:8000` fermée ou sous jeton). La section `admin` couvre aussi comptes, équipes, audit, logs, sauvegardes et secret d'appairage sans jeton.
  - **`ephor`** (labo local seulement, il règle la configuration globale d'Ephor) : Ephor est désactivé par défaut. La section l'active en `block` avec `error_threshold: 5`, envoie 12 requêtes vers des chemins inexistants depuis une IP annoncée par `X-Forwarded-For` (une adresse publique, car Ephor ne bannit jamais une adresse privée) et vérifie que la 6ᵉ est refusée, que le ban `threat: erreurs 4xx répétées` apparaît dans l'Admin, qu'une autre IP n'est pas touchée et que le déban rend l'accès ; en `detect`, les mêmes erreurs ne refusent rien. La configuration d'origine est rétablie ensuite.
  - **`tarpit`, `decoys`, `challenge`** (labo local seulement, comme `ephor`) : ils règlent la configuration globale d'Ephor avec une IP annoncée publique et lisent les compteurs `gpx_threat_*` de la passerelle, rendus lisibles par `GPX_METRICS_PUBLIC=1` sur la passerelle du labo (jamais ailleurs ; les sections sont ignorées sans eux). *Tarpit* : avec `delay_ms: 2000` et `max_concurrent: 2`, la requête qui déclenche le ban et celles de l'IP bannie sont retenues 2 s avant le 403 ; sur 5 requêtes simultanées 2 sont retenues et 3 refusées aussitôt (`held` +4, `full` +3) ; un ban manuel et un tarpit désactivé refusent sans délai. *Leurres* : en `detect`, `/.git/config` est servi par l'application et seul `shadow` augmente ; en `block`, le refus est immédiat, le ban porte le signal `decoy` (8 points) et `hit` augmente ; un chemin servi par une location de la route (`/api/v1/admin/` sur `lab-sec-acl`) n'est jamais un piège (`skipped`). *Défi* : un leurre verse 8 points (au-dessus du seuil de défi 4, sous le ban 10) ; en `detect` la navigation n'est pas défiée (`shadow`) ; en `block` elle reçoit la page de défi, un client d'API de la même IP non (`served`) ; le test résout la preuve de travail (SHA-256 du jeton et du nonce avec 4 bits de tête à zéro, `solved`), refuse un mauvais nonce et un jeton falsifié (`failed`), vérifie que la navigation passe avec le cookie `_gpx_ephor` et qu'un second leurre bannit malgré la preuve.
  - **`ipcontrols`** (IP annoncées par `X-Forwarded-For`, donc depuis un poste de confiance) : filtre IP d'une route, ban de plage, listes blanches, profils IP. *Filtre de route* : `lab-sec-ipfilter` (allow `198.51.100.160/28`) laisse passer l'IP listée et refuse les autres, `lab-sec-ipdeny` (deny `198.51.100.176/28`) l'inverse. *Ban de plage* : `198.51.100.192/28` refuse la plage entière (première et dernière adresse), pas la voisine, et la levée rend l'accès. Ces deux parties tournent aussi sur une cible distante. Le reste est réservé au labo local car il règle la configuration globale : *liste blanche d'Ephor d'une route* (`lab-sec-wl`) : l'IP listée n'est jamais bannie après 10 erreurs 4xx alors que sa voisine l'est (témoin) ; *liste blanche des bans* : même immunité, ban manuel refusé en `409`, retrait en `204` ; *profils IP* : un profil `deny` refuse sa plage `/30` en quelques secondes, un profil `allow` sur une adresse l'emporte sur le `deny`, la suppression des profils rend l'accès.
  - **`geoip`** (labo local seulement) : la route `lab-sec-geo` refuse `GB` avec la base de test de MaxMind (`GeoIP2-Country-Test.mmdb`, téléchargée par `run-security.sh` dans `tests/lab/fixtures/`, ignorée par git, montée en lecture seule dans la passerelle du labo). Les adresses connues de la base donnent `81.2.69.142` et `2.125.160.216` (Royaume-Uni) refusées, `89.160.20.112` (Suède), `216.160.83.56` (États-Unis) et `67.43.156.1` (Bhoutan) acceptées ; une adresse absente de la base (`198.51.100.230`) n'est pas refusée. Si la base n'a pas pu être téléchargée, la section est ignorée avec son témoin (sans base lisible la route laisse tout passer et rien ne prouverait quoi que ce soit).
  - **`mtls`** (labo local seulement : l'autorité de test est lue par la passerelle dans `tests/lab/fixtures/mtls/`, générée par le seed avec `openssl`) : route `lab-sec-mtls` (certificat exigé, SAN `lab-client.lab.test`, en-tête du sujet) et `lab-sec-mtls-opt` (facultatif). Un client valide est servi et son sujet transmis au backend, l'en-tête du sujet forgé par le client est écrasé ; sans certificat, avec le certificat d'une autre autorité, sans l'usage « client » ou expiré, la poignée de main échoue ; un SAN non autorisé reçoit `403` ; en mode facultatif on passe sans certificat, un certificat valide est lu, celui d'une autre autorité reçoit `401`.
  - **`asn`** (labo local seulement) : l'Admin lit une mini-base ip2asn (`GPX_ASN_DB_PATH`, fichier écrit par `run-security.sh`) avec deux ASN de documentation (64496 et 64497) sur `198.51.100.208` à `.249` en quatre plages non contiguës (pas `203.0.113.0/24` : les profils IP publics activés par défaut la refusent une fois chargés, ce qui rendrait le résultat dépendant du moment du démarrage). Recherche par adresse, par numéro et par nom, aperçu, `dry_run` sans effet, `404` pour un ASN inconnu, `400` pour une valeur invalide, `409` pour l'ASN qui contient l'appelant ; un ban d'ASN crée un ban par plage annoncée, refuse les deux plages et pas l'autre ASN, les bans portent l'ASN dans la liste, relancer ne duplique rien, la levée supprime les deux bans et rend l'accès.
  - **`http3`** (labo local seulement) : `tests/lab/tools/h3probe`, un client QUIC minimal (le curl d'Alpine n'a pas HTTP/3), est compilé avec le Go du poste par `run-security.sh` ; sans Go la section est ignorée. Vérifie qu'une requête QUIC est servie sur `443/udp`, que `Alt-Svc: h3=":443"` est annoncé en HTTPS et pas en clair ni sur une route mTLS, que la redirection HTTPS ne s'applique pas à une requête déjà sécurisée, qu'une route mTLS exigeante répond `401` en QUIC, et qu'un ban s'applique aussi en QUIC.
  - **Deux passages en local.** Le premier joue tout depuis un poste que la passerelle croit (réseau privé) ; le second, `GPX_TRUSTED_PROXIES=none` sur l'Admin et la passerelle, rejoue `trust`, `ratelimit`, `spoof` et `redirect` (sections préfixées « [none] ») : rotation de `X-Forwarded-For`, journal d'audit, allowlist du MCP, `X-Forwarded-Proto` d'un pair non fiable. `--no-strict-pass` le supprime, `--strict-ip` ne joue que le mode strict. Le brute-force du login (25 essais sur un compte inexistant) est joué par défaut en local (`--no-brute` pour l'éviter), jamais sur une cible.
  - **`redirect`** (route `lab-sec-redirect`, `redirect_https`) : `308` vers la même adresse en HTTPS, POST conservé, aucune redirection ouverte (`//evil.example`, `/evil.example`, `/@evil.example`), aucun en-tête injecté par un CRLF encodé, `X-Forwarded-Proto: https` cru d'un pair de confiance seulement. La section `admin` vérifie aussi les en-têtes de sécurité de l'Admin (`nosniff`, `X-Frame-Options`, CSP `frame-ancestors`, `Referrer-Policy`, `no-store` sur l'API).
  - **`spoof` et `--strict-ip`** : depuis un poste du LAN, la passerelle voit un pair privé de confiance et les contrôles d'usurpation d'IP sont ignorés. `run-security.sh --strict-ip` démarre le labo local avec `GPX_TRUSTED_PROXIES=none` : `trust`, `ratelimit` (rotation de `X-Forwarded-For`) et `spoof` sont alors joués. `spoof` vérifie que l'adresse annoncée par un pair non fiable n'entre pas au journal d'audit de l'Admin et ne fait pas franchir l'allowlist d'IP du MCP (avec un contrôle positif depuis un pair de la liste). Sans `--strict-ip`, la section est ignorée.
  - Non couverts : CrowdSec, le SSO autre que Basic, les bans par ASN sur la vraie base ip2asn (le labo en utilise une minuscule), la saturation (rapid reset), `testssl` complet, les suites TLS faibles (RC4, 3DES, EXPORT : indisponibles dans le client OpenSSL du runner), Ephor sur la production (les sections qui le règlent sont réservées au labo local) et l’usurpation d’IP depuis une source réellement publique.
  - Chaque passage de `run-security.sh` recrée les routes `lab-sec-*` existantes : une route restée d'un passage interrompu ne fausse plus le résultat.

### Production du LAN (`--target`)

`run-security.sh --target FICHIER` et `run-load.sh --target FICHIER` pilotent une Admin et une passerelle existantes sans labo local : seuls `lab-backend`, `lab-sim` (publiés sur l'IP LAN du poste de test) et les runners tournent ici, via `docker-compose.target.yml`. Les routes `lab-*.lab.test` et le certificat de test sont créés par l'API Admin avec un PAT à durée courte (scopes dans `tests/lab/targets/exemple.env`), puis supprimés en fin de passage, y compris sur Ctrl-C ou erreur. Le script affiche la cible et exige d'en retaper le nom avant d'envoyer quoi que ce soit.

| Garde-fou | Effet |
|---|---|
| Pas de `--attacks` ni `--brute` | pas de brute-force du login Admin ni de slowloris |
| `LAB_ALLOW_ACCOUNTS=0` (défaut) | la section `rights` ne crée ni compte ni équipe ; avec un PAT la partie « jeton à portée limitée » est aussi ignorée (créer un PAT exige une session) |
| Charge plafonnée | `smoke` (≈ 40 req/s) et `moderate` (50 req/s par défaut, 100 au plus, 2 min au plus) ; `--allow-heavy` en fenêtre de maintenance |
| `--skip bans` | évite de poser un ban de quelques secondes sur `198.51.100.200` |

La passerelle de la cible doit joindre les ports 9000-9008 et 9999 du poste de test (pare-feu). Le 9999 est l'API de contrôle de `lab-sim` : ne l'ouvrir qu'à la passerelle et au poste de test. Procédure complète : [tests/lab/README.md](../tests/lab/README.md).

## 6. Résultats (2026-09-24, VM partagée avec la production)

| Test | Résultat |
|---|---|
| Smoke | 7 486 req (499/s), 0 % d'échec, p95 6,6 ms, p99 28,6 ms |
| Chaos | Tous PASS : latence 1,45 s, 502 en 3 ms si backend coupé, reprise auto, timeout amont à 30 s |
| Saturation (ancien `moderate`, modèle fermé) | 56 809 req (947/s), 0 % d'échec, p95 117,6 ms, p99 180,9 ms (seuil p95 < 100 ms franchi ; k6 et la passerelle se partagent le CPU de la VM) |
| Attaques | 16 PASS (WAF, traversal, XFF, Host dupliqué en 400, smuggling : une seule réponse, rate-limit 88/120 en 429, slowloris coupé à 10 s) ; 3 échecs : `TRACE`, en-tête de 64 Ko, corps de 3 Mo (constats ci-dessous) |
| Attaques (après passerelle `0.7.0`) | **Tous les contrôles passent** : `TRACE` en 405, en-tête de 64 Ko en 431, corps de 3 Mo transmis intact, plus les 19 contrôles précédents |

### Constats

| Constat | Gravité | Statut |
|---|---|---|
| WAF : corps > `max_body_mb` tronqué (502 ou données corrompues) | Moyenne | Corrigé dans la passerelle `0.7.0` ; **vérifié en production** |
| `TRACE` transmis au backend (200) | Faible | Corrigé dans la passerelle `0.7.0` (405) ; **vérifié en production** |
| Aucune limite de taille d'en-tête (64 Ko accepté ; défaut Go 1 Mo) | Faible | Corrigé dans la passerelle `0.7.0` (`timeouts.max_header_kb`, défaut 32 Ko, 431) ; **vérifié en production** |
| Pages d'erreur exposant l'URL de l'Admin, apprise des en-têtes d'une session (`X-Forwarded-Host`, schéma `javascript:` compris) | Moyenne | Corrigé dans l'Admin `0.256.4` et la passerelle `0.147.3` : le lien ne vient que de `GPX_ADMIN_PUBLIC_URL` |

Non-constats (faux positifs corrigés dans les scripts) : redirection 301 de nettoyage de chemin, `X-Real-IP` repris depuis un pair de réseau privé (proxy de confiance par défaut), slowloris mesuré sur un `sleep` au lieu de la connexion.

## 7. Nettoyage

```bash
sudo docker exec -e LAB_ADMIN_TOKEN='gpx_pat_...' lab-tools bash /lab/scripts/cleanup.sh
```

Puis : vérifier dans l'UI qu'il ne reste aucune route `lab-*` (y compris des révisions `pending` issues de seeds refusés), révoquer le PAT, supprimer le stack lab, effacer l'historique du shell (`history -c`) si un mot de passe a été saisi.

## 8. Dépannage

| Symptôme | Cause | Remède |
|---|---|---|
| `401` au seed | Identifiants invalides pour cet Admin | Utiliser un PAT ; sans variables `GPX_FIRST_ADMIN_*`, le compte a été créé via l'UI |
| `moduleSpecifier … couldn't be found` (k6) | Stack lab déployé avant l'ajout du scénario | Pousser puis redéployer |
| `LAB_SAFE` ignoré | Script déployé antérieur à son ajout | Redéployer avant de lancer |
| Seed : `422` `conflit host …` | Routes déjà créées (ancienne version du seed) | Utiliser le seed actuel (idempotent) ; `cleanup.sh` pour repartir de zéro |
| Attaques : 502 partout juste après un redéploiement | `lab-backend` recréé, en cours de compilation : la passerelle reçoit `connection refused` et met le backend en quarantaine 15 s | Transitoire ; `attacks.sh` attend désormais jusqu'à 60 s que `lab-fast` réponde 200, sinon s'arrête |
| Chaos : 502 partout en 3 ms | Proxy Toxiproxy perdu au redémarrage | Version actuelle de `chaos.sh` (recréation automatique) |
| Erreur de build « listing workers » | Endpoint Docker sans BuildKit | Aucun build dans ce compose : redéployer la version actuelle |
| `bind source path does not exist` | Montage de fichier sur daemon distant | Sources embarquées : redéployer la version actuelle |
| `\r: command not found` | Fins de ligne CRLF ajoutées par git sous Windows | Forcer LF pour `tests/lab` (`.gitattributes`) |
