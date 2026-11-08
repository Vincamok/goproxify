# Labo de tests GoProxify

Environnement isolé, branché sur la stack Docker existante (`goproxify_net`), pour éprouver la passerelle
**sans toucher aux routes réelles** : toutes les routes du labo sont en `*.lab.test`.

> Procédure complète, résultats et dépannage : [docs/tests-lab.md](../../docs/tests-lab.md).
>
> Usage strictement local. Ne jamais pointer ces scripts vers un système dont vous n'êtes pas propriétaire.

## Démarrage rapide : deux scripts, un rapport horodaté chacun

Labo local jetable (Admin et passerelle compilés depuis les sources, backends et runners inclus), sans stack existante ni production. Prérequis : Docker et Git Bash.

```bash
tests/lab/run-security.sh     # suite de sécurité (26 sections, ~1 min une fois les images compilées) -> results/securite-AAAAMMJJ-HHMMSS.md
tests/lab/run-load.sh         # smoke + charge modérée + saturation (~3 min) -> results/charge-AAAAMMJJ-HHMMSS.md
```

Chaque script recompile Admin et passerelle depuis les sources (le cache Docker rend le cas « rien n'a changé » quasi instantané : le test porte toujours sur le code courant), démarre la stack, la laisse en marche pour le passage suivant, écrit son rapport (`.md` lisible, `.log` brut, `*-dernier.md` = le plus récent) et rend 0 si tout passe, 1 sinon (utilisable en CI), 2 si le labo n'a pas pu démarrer. Options communes : `--no-build` (réutiliser les images), `--fresh` (stack vierge), `--down` (tout supprimer après) ; `--help` pour le reste.

```bash
tests/lab/run-security.sh --sections waf,jwt,tls --attacks   # sections au choix (ou --skip bans,rights), + attacks.sh
tests/lab/run-security.sh --strict-ip                        # GPX_TRUSTED_PROXIES=none : joue aussi les contrôles d'usurpation d'IP
tests/lab/run-load.sh moderate --rate 500 --duration 2m      # scénarios au choix (smoke moderate saturation baseline spike stress mixed realistic soak)
tests/lab/run-load.sh --full                                  # tous sauf soak (~20 min)
```

Le rapport de charge donne par scénario le verdict des seuils, le débit, les latences p50/p95/p99/max, le taux d'erreur, les itérations abandonnées, le pic de VUs réellement occupés et le CPU/la mémoire de la passerelle (docker stats en local ; sur une cible, ceux que la passerelle déclare à l'Admin, scope `nodes:read`). Une section « Évolution » le compare au dernier passage de mêmes conditions (cible, débit, durée) et signale une hausse de latence p95 (+25 % et plus de 2 ms), une hausse du taux d'échec ou une baisse de débit de plus de 20 %.

## Contre une cible existante (production du LAN…) : `--target`

Les deux scripts acceptent `--target FICHIER` : plus de labo local ni de compilation, seuls tournent sur ce poste `lab-backend` et `lab-sim` (publiés sur son IP LAN) et les runners, qui visent l'Admin et la passerelle de la cible. Les routes de test y sont créées par l'API Admin, utilisées, puis **supprimées** (y compris sur Ctrl-C ou erreur), ainsi que le certificat de test `*.lab.test`.

```bash
cp tests/lab/targets/exemple.env tests/lab/targets/prod-lan.env     # à remplir ; ignoré par git
LAB_ADMIN_TOKEN=gpx_pat_... tests/lab/run-security.sh --target tests/lab/targets/prod-lan.env
LAB_ADMIN_TOKEN=gpx_pat_... tests/lab/run-load.sh     --target tests/lab/targets/prod-lan.env
```

**Sous Windows (PowerShell)** : `run-security.ps1` et `run-load.ps1` lancent les scripts bash avec Git Bash (et non le `bash` de WSL, que PowerShell trouve en premier). Ils acceptent les mêmes options ; sur une cible, le jeton est demandé sans affichage s'il n'est pas déjà dans `$env:LAB_ADMIN_TOKEN`.

```powershell
.\tests\lab\run-security.ps1 --target tests\lab\targets\prod-lan.env
.\tests\lab\run-load.ps1     --target tests\lab\targets\prod-lan.env
.\tests\lab\run-security.ps1 --sections waf,jwt        # aussi en local, sans --target
```

À préparer : un jeton d'API à durée courte (scopes dans `exemple.env`), l'IP LAN de ce poste (`LAB_BACKEND_HOST`, `LAB_RUNNER_CIDR`), et un pare-feu qui laisse la passerelle joindre les ports 9000-9008 et 9999 de ce poste (le 9999 est l'API de contrôle de `lab-sim` : à ne pas ouvrir au-delà de la passerelle et de ce poste). Sous Windows le pare-feu bloque par défaut les connexions entrantes vers les ports publiés par Docker quand le réseau est en profil « Privé » (la règle de Docker Desktop ne couvre que « Public ») : dans une PowerShell **administrateur**, `New-NetFirewallRule -DisplayName "GoProxify lab" -Direction Inbound -Protocol TCP -LocalPort 9000-9008,9999 -RemoteAddress <IP de la passerelle> -Action Allow -Profile Private`, puis `Remove-NetFirewallRule -DisplayName "GoProxify lab"` après le test. Si la route de référence ne répond pas, le script le dit (`ATTENTION : lab-sec-plain ne répond pas 200`), distingue passerelle qui ne joint pas le backend (502/504), route pas encore appliquée (404, `LAB_ROUTE_WAIT=180` allonge l'attente) et backend mort, et le rapport porte alors le verdict **NON EXÉCUTÉE** (code retour 2) au lieu d'un faux « échec ». Avant tout envoi, le script affiche la cible et ce qu'il va faire, et exige d'en retaper le nom (`--yes` hors terminal).

Garde-fous en mode cible : pas de `--attacks` ni `--brute` (brute-force du login, slowloris) ; aucun compte créé (`LAB_ALLOW_ACCOUNTS=0`) ; charge limitée à `smoke` (≈ 40 req/s) et `moderate` (50 req/s, 1 min ; plafond 100 req/s et 2 min), `--allow-heavy` lève ces plafonds en fenêtre de maintenance ; le rapport nomme la cible et ne contient jamais le jeton. La section `bans` pose puis retire un ban sur `198.51.100.200` (plage de documentation) ; `--skip bans` pour l'éviter. Depuis un poste du LAN, la passerelle voit un pair de réseau privé (proxy de confiance) : les contrôles d'usurpation d'IP sont ignorés, et le CPU de la passerelle n'est pas mesuré.

## Démarrage sur la stack principale

> Déploiement direct du compose (Portainer…) : seuls `lab-backend` et `lab-toxiproxy` démarrent (`EDGE_IP` vaut `127.0.0.1` par défaut, sans effet sur eux). Les runners (`k6`, `tools`, `zap`, `nuclei`) exigent `EDGE_IP` = IP de la passerelle sur `goproxify_net` : passez par `lab.sh`.

```bash
docker compose up -d          # stack principale (.env rempli, dont GPX_FIRST_ADMIN_*)
tests/lab/lab.sh up           # backend contrôlable + Toxiproxy
tests/lab/lab.sh seed         # crée les routes via l'API Admin
tests/lab/lab.sh all          # smoke + attaques + chaos
tests/lab/lab.sh down         # nettoyage (routes lab-* à supprimer depuis l'Admin)
```

Sans aucune stack existante (validation d'un build, développement) : `docker compose -f tests/lab/docker-compose.local.yml up -d --build` monte Admin, passerelle compilée depuis les sources, `lab-sim` et un runner ; voir l'en-tête du fichier.

Rapports dans `tests/lab/results/` (ignoré par git).

## Daemon distant (Portainer…) : docker exec, sans clone ni copie

Le stack déployé contient `lab-tools` et `lab-k6` (conteneurs permanents) avec **tous les scripts embarqués** dans le compose
(régénéré par `tests/lab/gen-compose.sh` après toute modif de `scripts/` ou `load/`). Depuis n'importe quelle machine dont `docker`
atteint le bon daemon (sur la VM : ajouter `sudo`) :

```bash
docker exec -e LAB_ADMIN_TOKEN=gpx_pat_... lab-tools bash /lab/scripts/seed.sh   # ou -e LAB_ADMIN_EMAIL=... -e LAB_ADMIN_PASSWORD=...
docker exec lab-tools bash /lab/scripts/attacks.sh
docker exec lab-tools bash /lab/scripts/chaos.sh
docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/smoke.js"   # baseline | spike | stress | soak | mixed
```

Les scripts trouvent eux-mêmes l'IP de la passerelle (`scripts/hosts.sh`) : `EDGE_IP` n'est pas nécessaire. ZAP, Nuclei et `soak` restent en mode local.

## Sur une stack partagée avec la production

Le labo se branche sur la vraie stack : préférez ces commandes à faible impact.

```bash
# attaques sans la section Admin (brute-force login compris) : ne touchent que les routes lab-*
docker exec -e LAB_SAFE=1 lab-tools bash /lab/scripts/attacks.sh
# chaos : agit uniquement sur la route lab-chaos (Toxiproxy)
docker exec lab-tools bash /lab/scripts/chaos.sh
# charge plafonnée : 50 VUs, ~1 min
docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/moderate.js"
```

Nettoyage des routes du labo (après les tests) :

```bash
docker exec -e LAB_ADMIN_TOKEN=... lab-tools bash /lab/scripts/cleanup.sh
```

À éviter sans fenêtre de maintenance : `spike`, `stress`, `baseline`, `soak`, `mixed`.

## Ce que couvre le labo

| Domaine | Commande | Outil | Vérifie |
|---|---|---|---|
| Charge | `lab.sh load smoke\|baseline\|mixed` | k6 | latence p95/p99, taux d'erreur, trafic mixte (gros corps, upload, SSE, backend lent/instable) |
| Pic | `lab.sh load spike` | k6 | 20 → 1000 VUs en 10 s, absence d'effondrement, reprise |
| Rupture | `lab.sh load stress` | k6 | débit maximal avant >10 % d'erreurs (arrêt automatique) |
| Endurance | `lab.sh soak` | k6 + docker stats | fuites mémoire/PIDs de la passerelle (`results/soak-edge-stats.csv`) ; `DURATION=2h RATE=500` |
| Attaques ciblées | `lab.sh attacks` | bash/curl/nc | WAF block/detect, XFF/X-Real-IP usurpés, hop-by-hop, Host inconnu/dupliqué, TRACE, en-têtes 64 Ko, corps trop gros, smuggling CL+TE, rate-limit, slowloris, API Admin (sans jeton, JWT `alg=none`, brute-force login) |
| Chaos | `lab.sh chaos` | Toxiproxy | latence, backend coupé, RST, timeout amont, bande passante : erreur rapide + reprise automatique |
| Fonctionnalités | `lab.sh seed-features && lab.sh features [sections]` | bash/curl + `lab-sim` | 29 sections, une route `lab-*.lab.test` par fonctionnalité du proxy : équilibrage (round-robin, pondéré, sticky), health check, failover/retry, circuit breaker, transformation d'URL/en-têtes, locations, proxy_redirect/cookies, sub_filter, CORS, cache + purge, filtrage IP, request_vars, backpressure, limit_conn, canary, shadow, routage conditionnel, pages d'erreur, WebSocket, taille de corps, en-têtes de sécurité, délai de réponse, Basic auth, bot, règle WAF, en-têtes transmis, SSE/gros fichiers, maintenance (API Admin) |
| Trafic réaliste | `lab.sh load realistic` | k6 + `lab-sim` | visiteurs (pages, assets, panier), clients API (CORS, requêtes lentes), flux SSE, WebSocket, téléchargements/envois ; courbe de journée à débit imposé (`SHOP_RATE`, défaut 20 itérations/s au pic ≈ 150 req/s ; `DURATION`) ; seuils par type de requête |
| Sécurité | `lab.sh seed-security && lab.sh security [sections]` | bash/curl/openssl + `lab-sim` | 26 sections, 17 routes `lab-sec-*` (dont TLS et redirection HTTPS) : droits de l'API Admin (jeton à portée limitée, compte sans équipe, périmètre d'équipe), bans de bout en bout, API interne fermée, contournement de contrôle d'accès par le chemin, usurpation d'IP et rate-limit, injection d'en-têtes/Host/SSRF, smuggling et entrées malformées, corpus d'évasion WAF + faux positifs, cache (fuite entre utilisateurs, empoisonnement), WebSocket (origine), JWT (jetons forgés, expirés, confusion d'algorithme), fuites d'information, API Admin, TLS (protocoles, suites, certificat, HTTP/2, cookies) |
| Scanners | `lab.sh up-vuln && lab.sh zap` / `nuclei` | ZAP, Nuclei, Juice Shop | détection de vulnérabilités via le WAF (mode detect) |

Chaque contrôle d'`attacks` et `chaos` affiche PASS/FAIL ; le code retour est le nombre d'échecs (utilisable en CI).

## Backend de test

`/` · `/echo` (ce que le backend a réellement reçu) · `/slow?ms=` · `/flaky?p=` · `/bytes?n=` ·
`/status/{code}` · `/upload` · `/sse?n=&ms=`

## Applications simulées (`lab-sim`, `sim/main.go`)

Un seul conteneur, plusieurs « serveurs » derrière les reverse proxy (routes dans `scripts/feature-routes.json`) :

| Port | Rôle |
|---|---|
| 9001-9003 | Boutique, instances `a`, `b`, `c` (équilibrage, sticky, retry) : page HTML avec URL interne, `/api/…` JSON, `/login` (cookie Domain/Path interne), `/redirect`, `/static/*` cacheable (`X-Origin-Hit`), `/ws` (écho WebSocket), `/sse`, `/fail-first`, `/echo`, `/slow`, `/bytes`, `/upload`, `/status/{code}`, `/whoami` |
| 9004 / 9005 / 9006 | `canary`, `shadow` (garde le dernier `X-Lab-Marker` reçu), `legacy` |
| 9007 / 9008 | `h1`, `h2` : dédiés au health check (la config de sonde est partagée par URL de backend, voir le rapport) |
| 9009 | volontairement fermé : backend mort |
| 9100 | écho TCP (bannière `LAB-TCP-BANNER`) |
| 9999 | contrôle, réseau interne seulement : `/ctl/stats`, `/ctl/reset`, `/ctl/<id>/health?up=0\|1`, `/ctl/<id>/fail?n=` (503), `/ctl/<id>/drop?n=` (connexion coupée), `/ctl/<id>/latency?ms=`, `/jwks.json` et `/ctl/jwt?alg=RS256|none|HS256&iss=&aud=&exp=&tamper=1` (jetons de test, clé RSA éphémère) |

## Prérequis

Docker (Compose v2), Bash (Git Bash sur Windows). Les images k6, ZAP, Nuclei, Toxiproxy et Juice Shop sont tirées au premier lancement.

## Limites connues

- Pas de TLS dans le labo (routes HTTP) : la charge TLS/QUIC et testssl restent à ajouter.
- Le test slowloris dure ~75 s ; les tests de charge lourds doivent tourner sur une machine dédiée (les résultats sur poste de dev ne sont pas comparables à `docs/benchmark.md`).
- La route L4 (TCP/UDP) n’est pas couverte : elle exige un port d’écoute dédié sur la passerelle (l’écho TCP `lab-sim:9100` est prêt pour ce test).
- Les scénarios ont été écrits et validés statiquement (syntaxe, `docker compose config`, build Go) ; un premier passage réel peut nécessiter d'ajuster les seuils.
