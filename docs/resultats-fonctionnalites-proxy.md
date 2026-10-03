# Résultats des tests des fonctionnalités du proxy

Dernier passage de `tests/lab/scripts/features.sh` : **2026-10-03, `main` au commit `c4d9ea33`**, après correction des 8 défauts du [rapport](rapport-tests-2026-10-03.md). Stack locale jetable (`tests/lab/docker-compose.local.yml`, applications simulées `lab-sim`) : **87 PASS, 0 FAIL** (avant correctifs : 75 PASS, 10 FAIL). Ce n'est pas une mesure de la production. Contexte et analyse des défauts : [rapport-tests-2026-10-03.md](rapport-tests-2026-10-03.md) ; procédure : [tests-lab.md](tests-lab.md).

Légende : ✅ conforme.

| Fonctionnalité | Section | Verdict | Contrôles et valeurs mesurées |
|---|---|---|---|
| Équilibrage round-robin + alias de domaine | `lb` | ✅ | 10/10/10 requêtes sur 30 ; alias → 200 |
| Équilibrage pondéré (8/1/1) | `weighted` | ✅ | 48 requêtes sur 60 vers l'instance pondérée |
| Sessions collantes (`sticky_cookie`) | `sticky` | ✅ | cookie `LABSID` posé ; 15 requêtes avec cookie sur la même instance ; sans cookie : répartition sur 3 instances |
| Health check actif | `health` | ✅ | aucune requête vers l'instance malsaine, réintégration, fail-open (tous malsains → 200) |
| Failover et retry | `retry` | ✅ | 8/8 réponses 200 avec un backend mort, avec et sans retry ; attente de retry 0,4 s observée |
| Circuit breaker | `cb` | ✅ | 3 requêtes sur 12 atteignent le backend, trafic repris après guérison |
| Transformation (réécriture d'URL, en-têtes) | `transform` | ✅ | `/shop/v1` → `/api` ; en-têtes ajoutés/retirés vers le backend et vers le client |
| Routage par chemin (locations) | `paths` | ✅ | `strip_prefix`, regex avec `$1`, chemin par défaut |
| `proxy_redirect`, cookies `Domain`/`Path` | `redirect` | ✅ | `Location` et attributs de cookie réécrits |
| Réécriture du corps (`sub_filters`) | `subfilter` | ✅ | URL interne et texte réécrits |
| CORS | `cors` | ✅ | pré-vol accepté (origine autorisée, `max-age` 600), refusé sinon |
| Cache disque, bypass, purge | `cache` | ✅ | 2ᵉ GET servi par le cache ; bypass par en-tête ; purge via l'API |
| Filtrage IP | `ip` | ✅ | allow-list sans notre IP → 403 ; deny-list sans notre IP → 200 |
| Variables de requête (`request_vars`) | `vars` | ✅ | `X-Plan: gold` → `premium`, sinon `standard` |
| Backpressure | `backpressure` | ✅ | 2 requêtes passent, 4 en 503, `Retry-After` présent |
| Limite de connexions par IP (`limit_conn`) | `backpressure` | ✅ | 3 requêtes passent, 5 refusées en 503 |
| Canary (en-tête, pourcentage) | `canary` | ✅ | `X-Canary` → canary ; 24 % sur 100 pour un poids de 30 |
| Shadow mirror | `shadow` | ✅ | réponse du principal, requête reçue par le miroir |
| Routage conditionnel | `cond` | ✅ | en-tête `X-Device: mobile` → legacy ; `?beta=1` → canary ; défaut → a |
| Pages d'erreur personnalisées | `errpages` | ✅ | page 502 servie, code conservé |
| WebSocket | `ws` | ✅ | upgrade 101 et écho ; `websocket:false` → 400 |
| Taille maximale du corps | `body` | ✅ | 100 Ko → 200 ; 2 Mo avec limite 1 Mo → 413 |
| En-têtes de sécurité | `secheaders` | ✅ | HSTS, X-Frame-Options, CSP, en-tête personnalisé ; `Server` et `X-Powered-By` du backend masqués |
| Délai de réponse backend | `timeout` | ✅ | coupé à 1,00 s (502) ; requête rapide inchangée |
| Authentification Basic | `auth` | ✅ | sans identifiants et mauvais mot de passe → 401 ; bons identifiants → 200 |
| Protection bot | `bot` | ✅ | `LabBadBot` → 403 ; navigateur normal → 200 |
| Règle WAF personnalisée | `wafcustom` | ✅ | motif interdit en query et en corps → 403 ; requête saine → 200 |
| En-têtes transmis (`Host`, `X-Request-ID`, `X-Forwarded-*`) | `headers` | ✅ | `preserve_host`, `request_id:false`, `forwarded_headers` vide (aucun `X-Forwarded-*`, XFF compris) ; XFF sans doublon |
| Streaming SSE, gros téléchargement | `stream` | ✅ | premier événement en 1 ms sur un flux de 2,5 s ; 5 Mo intacts |
| Maintenance (désactiver/réactiver un proxy) | `toggle` | ✅ | 404 après désactivation, 200 après réactivation |

**Bilan par fonctionnalité** : 30 conformes sur 30.

Non testé : routes L4 (TCP/UDP), TLS/QUIC, HTTP/2 vers le backend, GeoIP (base MaxMind), JWT, SSO autre que Basic, mTLS. Relancer la suite après chaque changement de la passerelle : `features.sh run [section]`.
