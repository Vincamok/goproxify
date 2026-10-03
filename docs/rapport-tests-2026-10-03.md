# Rapport de tests — suite fonctionnelle des proxies (2026-10-03)

Premier passage de la suite fonctionnelle `tests/lab/scripts/features.sh` (29 sections, 34 routes `*.lab.test`) et du scénario de trafic réaliste `tests/lab/load/realistic.js`, devant des applications simulées (`lab-sim`). Procédure : [tests-lab.md](tests-lab.md).

## 1. Synthèse

| Domaine | Résultat |
|---|---|
| Suite fonctionnelle | **75 PASS, 10 FAIL** : les 10 échecs correspondent à **7 défauts de la passerelle** (D1 à D7, §4), aucun n'est un défaut du test ; un 8ᵉ (D8) a été observé hors suite |
| Trafic réaliste (3 min, ~45 req/s, 5 types de clients) | 7 993 requêtes, **0 % d'échec**, 100 % des checks, tous les seuils respectés |

## 2. Périmètre et environnement — écart avec la demande

Le labo devait tourner contre une passerelle de production existante. **Ce passage n'a pas été fait contre la production** : aucune URL ni jeton Admin n'étaient fournis, et plusieurs sections créent des routes, déclenchent des 403/502 attendus et lancent des rafales concurrentes. La suite a été validée sur une **stack locale jetable** (`tests/lab/docker-compose.local.yml`) :

| Élément | Valeur |
|---|---|
| Passerelle | construite depuis les sources de `main` (`c51946d`, `docker build -f services/edge/Dockerfile`) |
| Admin | image `ghcr.io/vincamok/goproxify/admin:preview` |
| Applications simulées | `lab-sim` (Go 1.22) : boutique à 3 instances, canary, shadow, legacy, 2 instances de sonde, port fermé, écho WebSocket/TCP |
| Réseau | Docker dédié, aucun port publié |

Pour la production : `features.sh seed` puis `features.sh run` avec le jeton `proxies:read/write/delete` (procédure et précautions : [tests-lab.md](tests-lab.md) §3-4), et `LAB_RUNNER_CIDR` pour exempter le poste de test de Sentinel. Ce passage ne prouve rien sur la production elle-même, en particulier ni son routage TLS ni ses certificats.

## 3. Résultats par section

| Section | Verdict | Contrôles |
|---|---|---|
| `lb` | PASS | répartition 10/10/10 sur 30 requêtes ; alias de domaine |
| `weighted` | PASS | pondération 8/1/1 : 48 requêtes sur 60 vers l'instance pondérée |
| `sticky` | **FAIL** | aucun cookie `LABSID` posé (D1) ; répartition sans cookie correcte |
| `health` | **FAIL** | l'instance malsaine continue de recevoir la moitié du trafic (D2) |
| `retry` | PASS | 8/8 réponses 200 avec un backend du pool mort, avec et sans politique de retry ; attente de retry 0,4 s observée |
| `cb` | **FAIL** | circuit ouvert sans effet : 12/12 requêtes atteignent le backend (D3) |
| `transform` | PASS | réécriture `/shop/v1` → `/api`, en-têtes ajoutés/retirés vers le backend et vers le client |
| `paths` | PASS | location avec `strip_prefix`, location regex avec `$1`, chemin par défaut |
| `redirect` | PASS | `proxy_redirect`, `Domain` et `Path` des cookies réécrits |
| `subfilter` | **FAIL** | réponse vide (D4) |
| `cors` | PASS | pré-vol accepté pour l'origine autorisée (`max-age`), refusé sinon |
| `cache` | PASS | 2ᵉ GET servi par le cache, bypass par en-tête, purge via l'API |
| `ip` | PASS | allow-list sans notre IP → 403, deny-list sans notre IP → 200 |
| `vars` | PASS | `request_vars` → `X-Tier` (`premium` / `standard`) |
| `backpressure` | PASS | 2 requêtes passent, le reste en 503 avec `Retry-After` ; `limit_conn` 3 par IP (route déjà servie, voir D8) |
| `canary` | PASS | par en-tête ; 29 % pour un poids de 30 |
| `shadow` | PASS | réponse du principal, requête reçue par le miroir |
| `cond` | PASS | routage par en-tête et par paramètre de requête |
| `errpages` | PASS | page 502 personnalisée, code conservé |
| `ws` | PASS | upgrade 101, écho bidirectionnel ; `websocket:false` → 400 |
| `body` | PASS | 100 Ko acceptés, 2 Mo refusés en 413 (`max_body_size` 1 Mo) |
| `secheaders` | **FAIL** | HSTS, X-Frame-Options, CSP et en-tête personnalisé OK ; `Server` et `X-Powered-By` du backend exposés (D5) |
| `timeout` | PASS | backend lent coupé en 502 à 1,0 s |
| `auth` | PASS | Basic : 401 sans identifiants et avec un mauvais mot de passe, 200 sinon |
| `bot` | PASS | `LabBadBot` → 403, navigateur normal → 200 |
| `wafcustom` | **FAIL** | la règle WAF personnalisée de la route n'est jamais appliquée (D6) |
| `headers` | **FAIL** | `Host` conservé, `X-Request-ID`, `preserve_host:false`, `request_id:false`, `forwarded_headers` vide OK ; IP du client en double dans `X-Forwarded-For` (D7) |
| `stream` | PASS | SSE non bufferisé (premier événement en moins de 1 s sur un flux de 2,5 s), 5 Mo intacts |
| `toggle` | PASS | désactivation puis réactivation d'un proxy propagées |

## 4. Défauts de la passerelle

Tous reproduits sur le build de `main` ci-dessus ; chaque défaut a une tâche de correction ouverte.

| # | Gravité | Défaut | Cause (lecture du code) |
|---|---|---|---|
| D1 | Moyenne | `sticky_cookie` : le cookie n'est jamais envoyé, les sessions collantes ne fonctionnent pas | `handler.go` : `http.SetCookie` est appelé après `h.do(...)`, donc après l'écriture de la réponse par le reverse proxy |
| D2 | Moyenne à haute | `health_check` sans effet sur les proxies créés via l'Admin : zéro sonde envoyée, un backend en 503 garde sa part de trafic | `StartChecksFromRoutes` n'est appelé que pour les routes poussées par l'Admin et le snapshot ; les proxies du proxystore ne font que `table.Upsert`. De plus la config de sonde est partagée par URL de backend, première route gagnante |
| D3 | Moyenne | circuit breaker ouvert sans effet : 12/12 requêtes atteignent le backend | `circuitBreaker.Next` renvoie `nil` ouvert, mais `failoverCandidates` ajoute ensuite tous les backends comme candidats |
| D4 | Haute | `sub_filters` : la réponse est vide dès que la longueur du corps change (« Empty reply from server ») | `applySubFilters` met à jour `resp.ContentLength` mais pas l'en-tête `Content-Length` |
| D5 | Faible à moyenne | `headers.hide_server` : deux en-têtes `Server:` (le second est celui du backend) ; `X-Powered-By` jamais retiré, contrairement à `docs/fonctionnalites.md` | `middleware/headers.go` fait `Set("Server", "")` avant que le reverse proxy ajoute ceux du backend |
| D6 | Moyenne | `waf.custom_rules` d'une route ignorées : un motif interdit passe en 200, sans alerte | `Engine.UpdateConfig` n'est appelé que par les tests ; seul `custom_rules_path` (fichier global) fonctionne |
| D7 | Faible | `X-Forwarded-For: 172.18.0.4, 172.18.0.4` : l'IP du client est ajoutée deux fois | ajout par le reverse proxy Go et par `applyForwardedHeaders` |
| D8 | Faible | à froid (première requête après démarrage ou changement de config), les limites ne sont pas partagées : 6 requêtes concurrentes sur 6 acceptées avec `max_inflight=2` | `handlerForRoute` fait `Load` puis `Store` au lieu de `LoadOrStore` : chaque requête concurrente construit sa propre chaîne de middlewares |

Comportements constatés, à connaître (ni défaut ni test en échec) :

- Retry et failover ne réagissent qu'aux **pannes de transport** (connexion refusée ou coupée), jamais à un 5xx renvoyé par le backend, et ne jouent qu'**entre backends du pool** : un proxy à un seul backend n'est jamais rejoué.
- Avec `forwarded_headers: []`, `X-Forwarded-For` est tout de même ajouté (par le reverse proxy Go) ; `X-Forwarded-Host`, `-Proto` et `X-Real-IP` sont bien absents.
- Pas de test d'une route L4 (TCP/UDP) : elle exige un port d'écoute dédié sur la passerelle.

## 5. Trafic réaliste

`realistic.js` : visiteurs, clients API, flux SSE, WebSocket, téléchargements et envois, `SHOP_RATE=10`, `DURATION=3m`, route `lab-realistic` (3 instances, health check, retry, rate-limit, HSTS, `hide_server`).

| Type | p95 | Échecs |
|---|---|---|
| page | 1,8 ms | 0 % |
| api | 2,1 ms | 0 % |
| slow (100-500 ms côté backend) | 489 ms | 0 % |
| asset | 1,5 ms | 0 % |
| sse (3 s côté backend) | 3 011 ms | 0 % |
| download (2 Mo) | 20 ms | 0 % |
| upload (512 Ko) | 2,8 ms | 0 % |

Total : 7 993 requêtes, 43 req/s en moyenne, 100 % des checks. Mesure sur un poste de dev avec k6, passerelle et backends sur la même machine : ces latences ne sont pas comparables à `docs/benchmark.md`.

## 6. Reproduire

```bash
docker compose -f tests/lab/docker-compose.local.yml up -d --build
docker compose -f tests/lab/docker-compose.local.yml exec lab-tools bash /lab/scripts/features.sh seed
docker compose -f tests/lab/docker-compose.local.yml exec lab-tools bash /lab/scripts/features.sh run
docker compose -f tests/lab/docker-compose.local.yml down -v
```

Le résultat attendu à ce jour est celui du §3 ; chaque défaut corrigé fait passer sa section au vert. Le scénario k6 se lance avec la commande indiquée en tête de `tests/lab/docker-compose.local.yml`.

## 7. Après correction (2026-10-03, `main` `c4d9ea33`)

Les 8 défauts D1 à D8 sont corrigés sur `main`. Même suite, même stack locale, passerelle recompilée depuis les sources : **87 PASS, 0 FAIL**. Décisions prises : la sonde de santé est propre à chaque route (config et verdict par route et backend) ; avec `forwarded_headers: []`, `X-Forwarded-For` n'est plus envoyé du tout. Résultats par fonctionnalité : [resultats-fonctionnalites-proxy.md](resultats-fonctionnalites-proxy.md). Les §1, §3 et §4 ci-dessus décrivent l'état avant correctifs.
