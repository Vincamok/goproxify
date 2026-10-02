# Résultats des tests des fonctionnalités du proxy

Dernier passage de `tests/lab/scripts/features.sh` : **2026-10-03, `main` au commit `bc8fde5`** (avec les correctifs du circuit breaker `645e1e7` et de la construction des handlers `a8cb3f9`). Stack locale jetable (`tests/lab/docker-compose.local.yml`, applications simulées `lab-sim`) : **76 PASS, 9 FAIL**. Ce n'est pas une mesure de la production. Contexte et analyse des défauts : [rapport-tests-2026-10-03.md](rapport-tests-2026-10-03.md) ; procédure : [tests-lab.md](tests-lab.md).

Légende : ✅ conforme · ❌ défaut de la passerelle (jamais du test).

| Fonctionnalité | Section | Verdict | Contrôles et valeurs mesurées |
|---|---|---|---|
| Équilibrage round-robin + alias de domaine | `lb` | ✅ | 10/10/10 requêtes sur 30 ; alias → 200 |
| Équilibrage pondéré (8/1/1) | `weighted` | ✅ | 48 requêtes sur 60 vers l'instance pondérée |
| Sessions collantes (`sticky_cookie`) | `sticky` | ❌ | aucun cookie posé, 15 requêtes réparties sur 3 instances ; sans cookie : répartition correcte |
| Health check actif | `health` | ❌ | l'instance malsaine garde la moitié du trafic ; réintégration et fail-open (tous malsains → 200) corrects |
| Failover et retry | `retry` | ✅ | 8/8 réponses 200 avec un backend mort, avec et sans retry ; attente de retry 0,4 s observée |
| Circuit breaker | `cb` | ✅ | 3 requêtes sur 12 atteignent le backend, trafic repris après guérison |
| Transformation (réécriture d'URL, en-têtes) | `transform` | ✅ | `/shop/v1` → `/api` ; en-têtes ajoutés/retirés vers le backend et vers le client |
| Routage par chemin (locations) | `paths` | ✅ | `strip_prefix`, regex avec `$1`, chemin par défaut |
| `proxy_redirect`, cookies `Domain`/`Path` | `redirect` | ✅ | `Location` et attributs de cookie réécrits |
| Réécriture du corps (`sub_filters`) | `subfilter` | ❌ | réponse vide dès que la longueur change |
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
| En-têtes de sécurité | `secheaders` | ❌ | HSTS, X-Frame-Options, CSP, en-tête personnalisé OK ; `Server` et `X-Powered-By` du backend exposés malgré `hide_server` |
| Délai de réponse backend | `timeout` | ✅ | coupé à 1,00 s (502) ; requête rapide inchangée |
| Authentification Basic | `auth` | ✅ | sans identifiants et mauvais mot de passe → 401 ; bons identifiants → 200 |
| Protection bot | `bot` | ✅ | `LabBadBot` → 403 ; navigateur normal → 200 |
| Règle WAF personnalisée | `wafcustom` | ❌ | motif interdit en query et en corps → 200 au lieu de 403 ; requête saine → 200 |
| En-têtes transmis (`Host`, `X-Request-ID`, `X-Forwarded-*`) | `headers` | ❌ | `preserve_host`, `request_id:false` et `forwarded_headers` vide OK ; IP du client en double dans `X-Forwarded-For` |
| Streaming SSE, gros téléchargement | `stream` | ✅ | premier événement en 1 ms sur un flux de 2,5 s ; 5 Mo intacts |
| Maintenance (désactiver/réactiver un proxy) | `toggle` | ✅ | 404 après désactivation, 200 après réactivation |

**Bilan par fonctionnalité** : 24 conformes, 6 en défaut (`sticky`, `health`, `subfilter`, `secheaders`, `wafcustom`, `headers`). Les 9 contrôles en échec sont : 2 (`sticky`), 1 (`health`), 1 (`subfilter`), 2 (`secheaders`), 2 (`wafcustom`), 1 (`headers`).

Non testé : routes L4 (TCP/UDP), TLS/QUIC, HTTP/2 vers le backend, GeoIP (base MaxMind), JWT, SSO autre que Basic, mTLS. La suite est à relancer après chaque correctif : `features.sh run <section>`.
