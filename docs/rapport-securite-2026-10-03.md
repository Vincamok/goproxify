# Rapport de tests de sécurité — passerelle (2026-10-03)

Premier passage de la suite `tests/lab/scripts/security.sh` (12 sections, 9 routes `lab-sec-*` dont une en TLS, applications simulées `lab-sim`). Procédure : [tests-lab.md](tests-lab.md).

## 1. Synthèse

| Résultat | Valeur |
|---|---|
| Contrôles | **126 PASS, 15 FAIL, 5 ignorés** (le test de force brute du login Admin, hors défaut, a donné 14 PASS / 0 FAIL sur la section `admin`) |
| Défauts | **5 constats** (S1 à S5, §4) qui expliquent les 15 échecs |
| Bien tenu | smuggling (6 variantes), injection d'en-têtes, Host forgé et SSRF par URI absolue, forgeries JWT, API Admin sans jeton, frein anti brute-force, TLS (1.3, pas de 1.0/1.1, HSTS, cookie `Secure`/`HttpOnly`/`SameSite`, HTTP/2) |

## 2. Périmètre et environnement

Passage sur la **stack locale jetable** (`tests/lab/docker-compose.local.yml` : Admin, passerelle compilée depuis les sources de `main`, `lab-sim`, runner), réseau Docker dédié, aucun port publié. **Pas de passage sur la production** : ce rapport ne dit rien d'elle.

Poste de test et réseaux locaux : le runner est sur un réseau privé, donc **proxy de confiance par défaut** (le `X-Forwarded-For` qu'il envoie est repris : un `X-Forwarded-For` en plage de documentation y est refusé en 403 par les profils IP). Les contrôles d'usurpation d'IP (rotation de `X-Forwarded-For` contre le rate-limit) sont donc **ignorés** ici ; ils ne peuvent se tester que depuis une source non privée. Le seed place l'IP du runner dans la liste blanche Sentinel des routes `lab-sec-*` pour que les 403 volontaires ne le fassent pas bannir.

## 3. Résultats par domaine

| Domaine | Contrôles | Résultat |
|---|---|---|
| Contournement du contrôle d'accès par le chemin (`acl`) | 17 variantes de chemin (`//`, `/./`, `..`, `%61dmin`, `;`, `%2f`, `%00`, `%5c`…) + identifiants | 15 refusées ; **2 contournent** (S3) |
| Rate-limit (`ratelimit`) | rafale de 40 requêtes : 35 en 429 | conforme ; rotation de `X-Forwarded-For` ignorée (§2) |
| Injection d'en-têtes, Host, SSRF (`inject`) | CRLF encodé, obs-fold, 9 `Host` détournés vers le port de contrôle interne, URI absolue, `X-Forwarded-Host` | conforme |
| Protocole (`protocol`) | 6 variantes de smuggling, `Content-Length` doublé ou négatif, `CONNECT`, version HTTP inconnue, URI et en-tête de 120 Ko, octet nul, UTF-8 invalide, `TRACE` | conforme |
| WAF (`waf`) | 31 attaques (SQLi, XSS, traversal, commande, SSRF, XXE, Log4Shell, SSTI, corps JSON/formulaire/chunked) et 8 requêtes légitimes | 25 bloquées sur 31, **1 faux positif** (S5) |
| Cache (`cache`) | réponses personnalisées par cookie et par `Authorization`, empoisonnement par `X-Forwarded-Host` | **fuite entre utilisateurs** (S1) ; pas d'empoisonnement |
| WebSocket (`ws`) | origine autorisée, étrangère, `null` | **origine non vérifiée** (S2) |
| JWT (`jwt`) | valide, absent, `alg=none`, confusion HS256, charge modifiée, expiré, mauvais émetteur et audience, illisible, `X-Claims` forgé | conforme ; **`header_name: Authorization` refuse tout** (S4) |
| Fuites d'information (`errleak`) | page 502, hôte inconnu, en-têtes révélateurs | conforme (voir §5) |
| API Admin (`admin`) | 7 endpoints sans jeton, jeton invalide, `alg=none`, préfixe de PAT inventé, traversal, injections sur le login, force brute | conforme (le frein anti brute-force répond 429/423 dès les premiers essais) |
| TLS (`tls`) | TLS 1.3, TLS 1.0/1.1 refusés (alerte du serveur), HTTP/2, HSTS, cookie sticky, signature et clé du certificat, compression, renégociation sécurisée | conforme ; suites faibles non testables depuis le client OpenSSL du runner (ignoré) |

## 4. Constats

| # | Gravité | Constat | Contrôles en échec |
|---|---|---|---|
| S1 | **Haute** | Le cache partagé sert à un autre client la réponse personnalisée d'un utilisateur : la clé de cache ne tient pas compte du `Cookie` ni de `Authorization`, et `Cache-Control: private` n'est pas respecté. Une route avec `cache.enabled` qui sert des pages authentifiées fuit des données entre utilisateurs | 3 |
| S2 | Moyenne | L'upgrade WebSocket n'est pas filtré par `cors.allowed_origins` : une page de `https://evil.test` ou une origine `null` ouvre le WebSocket de la route (détournement entre sites si l'authentification repose sur un cookie) | 2 |
| S3 | Moyenne à haute | Les `locations` comparent le chemin en sensible à la casse : `/API/V1/ADMIN/x` et `/api/v1/%41dmin/x` contournent l'authentification d'une location `/api/v1/admin` face à un backend insensible à la casse (IIS, ASP.NET…) | 2 | **Corrigé en Edge 0.21.3** (locations sans casse par défaut si auth/ip_filter/rate_limit).
| S4 | Moyenne | Avec `jwt.header_name: "Authorization"` (configuration naturelle), la valeur brute `Bearer …` est validée au lieu du jeton : tout jeton valide reçoit 401. Sans `header_name`, la validation fonctionne. Par ailleurs le JWKS n'accepte que des clés RSA : un fournisseur qui signe en ES256 n'est pas supporté | 1 |
| S5 | Moyenne à faible | WAF : non bloqués `admin'--` en formulaire, l'injection SQL dans un cookie, `$(id)`, `\|\| id`, `{{7*7}}` et `${7*7}` ; **faux positif** sur la phrase `select an option from the list`. Les cookies, les expressions de commande et les gabarits (SSTI) sont un trou de couverture ; le faux positif bloque du contenu légitime | 7 |

## 5. À connaître (information, pas des échecs)

- Une route `tls_enabled` est **servie aussi en clair** sur le port 80, sans redirection vers HTTPS.
- La page d'hôte inconnu contient un lien vers l'Admin (`GPX_ADMIN_PUBLIC_URL` ; à vider pour ne pas l'exposer, comme noté au [rapport du 2026-09-24](rapport-tests-2026-09-24.md)).
- Un pair de réseau privé est un proxy de confiance : derrière un répartiteur de charge privé c'est voulu, mais tout poste du LAN peut alors choisir son IP vue par la passerelle (rate-limit, filtre IP, bans).
- `X-Content-Type-Options` est absent de `/api/v1/health` ; 600 en-têtes de petite taille et une méthode inconnue (`FOOBAR`) sont acceptés ; pas d'agrafage OCSP avec un certificat auto-signé.

## 6. Non couvert

Fail2Ban, Sentinel et CrowdSec (ils banniraient le poste de test), mTLS, SSO autre que Basic, GeoIP, HTTP/3, saturation (rapid reset, connexions), `testssl` complet, suites TLS faibles, usurpation d'IP depuis une source non privée.

## 7. Reproduire

```bash
docker compose -f tests/lab/docker-compose.local.yml up -d --build
docker compose -f tests/lab/docker-compose.local.yml exec lab-tools bash /lab/scripts/security.sh seed
docker compose -f tests/lab/docker-compose.local.yml exec lab-tools bash /lab/scripts/security.sh run            # ou : run waf,jwt,tls
docker compose -f tests/lab/docker-compose.local.yml exec -e LAB_BRUTE=1 lab-tools bash /lab/scripts/security.sh run admin
docker compose -f tests/lab/docker-compose.local.yml down -v
```

## 8. Après correction (2026-10-03, `main` `28928981`)

Les 5 constats S1 à S5 sont corrigés sur `main` : cache (`7e94c860`), WebSocket (`28928981`), locations (`5b7de746`), JWT (`48e9486c`) et WAF (`15893d42`). Même suite, stack locale neuve avec une passerelle recompilée depuis les sources : **146 PASS, 0 FAIL, 5 ignorés** (usurpation d'IP depuis un pair privé, brute-force du login hors `LAB_BRUTE`, trois suites TLS faibles non testables depuis le client OpenSSL du runner). Le nombre de PASS monte de 126 à 146 : les 15 échecs sont devenus des PASS et les contrôles ajoutés par les correctifs (JWT ES256 et EdDSA) s'y ajoutent. La suite fonctionnelle reste à **87 PASS, 0 FAIL**. Les §1, §3 et §4 ci-dessus décrivent l'état avant correctifs.
