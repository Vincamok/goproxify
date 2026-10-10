# Plugins WebAssembly

Un plugin est un module WebAssembly que les passerelles exécutent dans une sandbox pour décider du sort d'une requête ou d'une réponse : règle d'authentification maison, règle métier, en-tête calculé. Le choix d'architecture est dans [l'ADR 0008](adr/0008-moteur-de-plugins-wasm.md). Les fonctions standard d'un reverse proxy restent natives ; un plugin sert à ce qu'on ne veut pas compiler dans GoProxify.

## Installer et attacher un plugin

Trois façons de l'attacher à une route : le formulaire (route → Sécurité → onglet **Plugins**, avec l'ordre d'exécution et les champs du manifeste), le JSON de la route, ou des labels Docker (`goproxify.plugins=a,b` et `goproxify.plugin.<nom>.<clé>=<valeur>`, voir [labels.md](labels.md)). Les routes TCP/UDP s'éditent dans le JSON de la route ou par labels.

```bash
goproxify plugin install -manifest plugin.json -wasm plugin.wasm        # admin uniquement
goproxify plugin list
goproxify plugin update  -manifest plugin.json -wasm plugin.wasm
goproxify plugin delete  geo-headers
```

Un plugin s'attache à une route dans sa configuration, avec sa propre configuration :

```json
{ "plugins": [ { "name": "geo-headers", "config": { "header": "X-Geo" } } ] }
```

Les plugins d'une route s'exécutent dans l'ordre de la liste. Ils s'exécutent **après** le WAF, le filtre anti-bot, la limitation de débit et les filtres IP/GeoIP, et **avant** l'authentification (SSO, JWT, mTLS) : un plugin peut donc compléter ou remplacer une authentification, sans voir les requêtes déjà refusées par la sécurité réseau.

L'Admin pousse la liste complète aux passerelles. Une passerelle installe les plugins nouveaux ou modifiés (empreinte SHA-256 vérifiée), retire les absents, les stocke **chiffrés** et les recharge à son démarrage : les plugins fonctionnent Admin coupé, y compris après un redémarrage.

## Signature

L'empreinte SHA-256 vérifie l'intégrité d'un module, pas son origine. La signature **Ed25519** prouve qui a publié le paquet. Elle couvre le **manifeste normalisé en entier** (politique d'erreur et limites comprises) et l'empreinte du module : un manifeste plus permissif ne peut pas être accolé à un module signé.

```bash
goproxify plugin keygen -out editeur                      # editeur.key (privée, à garder), editeur.pub
goproxify plugin sign -key editeur.key -manifest plugin.json -wasm plugin.wasm   # affiche la signature
goproxify plugin keys add -name "Éditeur" -public-key <base64 de editeur.pub>     # côté Admin
goproxify plugin install -manifest plugin.json -wasm plugin.wasm -signature <signature>
```

- **Aucune clé de confiance enregistrée** : la signature est facultative. Une signature fournie est refusée (elle ne se vérifie pas) : enregistrez d'abord la clé.
- **Au moins une clé enregistrée** : tout plugin installé ou **remplacé** doit être signé par l'une d'elles ; sinon `400`.
- Retirer une clé ne retire pas les plugins qu'elle a signés ; l'identifiant de la clé signataire (`signed_by`) est conservé et affiché.
- L'Admin vérifie la signature à l'installation ; les passerelles font confiance à l'Admin qui leur pousse la liste (comme pour le reste de la configuration).

## Dépôts de plugins

Un dépôt est une URL HTTPS qui sert un index JSON :

```json
{ "version": 1, "name": "Mon dépôt",
  "plugins": [ { "name": "geo-headers", "version": "1.2.0", "description": "…", "homepage": "…",
                 "manifest": { … }, "wasm_url": "geo-headers-1.2.0.wasm", "sha256": "…", "signature": "…" } ] }
```

`wasm_url` peut être relative à l'index. `goproxify plugin repo add -name … -url https://…/index.json`, `plugin catalog` liste les plugins proposés (avec l'état installé et les mises à jour), `plugin fetch <nom> -repo <id> [-version v]` installe ou met à jour ; la page *Plugins* fait la même chose. Sans `-version`, la version la plus récente est choisie (comparaison numérique : 1.10.0 > 1.9.0).

**Un dépôt ne confère aucune confiance.** L'installation depuis un dépôt applique les mêmes contrôles qu'une installation manuelle : empreinte SHA-256 de l'index vérifiée sur le module téléchargé, module compilé et contrat contrôlé, et — dès qu'une clé de confiance est enregistrée — signature obligatoire, d'une de ces clés. Sans clé de confiance, l'empreinte ne protège que du transport : son origine n'est garantie par rien. Le serveur Admin relit l'index lui-même (le client ne fournit jamais l'URL du module), n'accepte que HTTPS, refuse les adresses internes (boucle locale, réseaux privés, link-local, métadonnées cloud) sauf dépôt déclaré `allow_private`, suit au plus 3 redirections et borne l'index (1 Mio) et le module (2 Mio).

## Manifeste

```json
{
  "name": "geo-headers", "version": "1.0.0", "api_version": 1,
  "hooks": ["request", "response"],
  "on_error": "deny",
  "limits": { "memory_pages": 16, "timeout_ms": 50 },
  "fields": [ { "key": "header", "label": "En-tête", "kind": "text", "required": true } ]
}
```

| Champ | Rôle |
|---|---|
| `name` | minuscules, chiffres, `-` et `_` (63 caractères au plus) |
| `api_version` | `1` |
| `hooks` | `request`, `response` (au moins un) ; chacun exige l'export `on_<hook>` |
| `on_error` | `deny` (défaut : `503`) ou `allow` (laisse passer en journalisant) quand le plugin échoue |
| `limits.memory_pages` | pages de 64 Kio, 16 par défaut, 256 au plus |
| `limits.timeout_ms` | 50 par défaut, 1 000 au plus ; une boucle infinie est interrompue |
| `fields` | champs de configuration, au format des manifestes de modules (clés, genres, secrets, requis). La configuration d'une route est validée par ce manifeste |
| `hooks` (suite) | `request_body`, `response_body` (corps tamponné), `connect` (routes TCP/UDP) ; un plugin sans hook applicable au type de la route est refusé à la validation |
| `limits.max_body_bytes` | taille maximale du corps présenté aux hooks de corps : 32 Kio par défaut, 1 Mio au plus |
| `on_oversize` | `deny` (défaut : `413` sur une requête, `502` sur une réponse) ou `skip` (le corps passe sans que le plugin le voie), pour un corps plus gros que `max_body_bytes` |
| `capabilities` | fonctions de l'hôte que le plugin peut importer en plus de `gpx.log` : `kv` (état), `http` (liste d'hôtes joignables), `http_allow_private` — voir ci-dessous |

## ABI v1

Le module exporte `memory`, `alloc(size i32) i32`, et `on_request(ptr i32, len i32) i64` et/ou `on_response(ptr i32, len i32) i64`. L'hôte réserve la place de l'entrée avec `alloc`, y écrit un JSON, appelle le hook, puis lit le JSON de sortie à l'adresse et de la longueur contenues dans la valeur retournée (`ptr << 32 | len`) ; une longueur nulle équivaut à `allow`.

**Entrée de `on_request`** : `{"method","host","path","query","headers":{"Nom":["valeur"]},"client_ip","config":{…}}` — `on_response` y ajoute `"status"` et `"response_headers"`. Les en-têtes transmis comprennent `Authorization` et `Cookie` : un plugin est du code de politique, à relire comme tel.

**Sortie** : `{"action":"allow"|"deny"|"modify","status":403,"body":"…","set_headers":{},"remove_headers":[],"log":"…"}`

- `allow` (ou sortie vide) : laisse passer.
- `deny` : répond avec `status` (4xx/5xx, 403 par défaut) et `body`. Sur `on_response`, le corps du backend est écarté.
- `modify` : pose et retire des en-têtes (de la requête pour `on_request`, de la réponse pour `on_response`), puis laisse passer.
- `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Trailer` ne peuvent être ni posés ni retirés ; une valeur contenant CR, LF ou NUL est refusée.

Si le module exporte `_initialize` (TinyGo, Rust en « reactor »), l'hôte l'appelle sur chaque instance neuve avant `alloc` : sans lui, le tas et les variables globales du module ne sont pas prêts. Il doit être sans argument ni résultat.

L'hôte n'importe qu'une fonction : `gpx.log(ptr i32, len i32)` (journal, 1 Kio par appel). Tout autre import (WASI, système de fichiers, réseau, horloge, aléa) est refusé au chargement. Une instance neuve est créée à chaque appel : un plugin n'a pas d'état.

## Hooks de corps

`request_body` et `response_body` reçoivent le corps en entier, tamponné en mémoire et encodé en base64 dans le JSON (`"body"`). La sortie `modify` peut porter `"replace_body": "<base64>"` pour remplacer le corps ; `Content-Length` est recalculé. Un corps plus gros que `limits.max_body_bytes` suit `on_oversize`.

- La **requête** est lue jusqu'à la limite ; si tous les plugins sont en dépassement (`skip`), le flux d'origine est restitué en entier au backend.
- La **réponse** est retenue jusqu'à son terme : elle n'est plus transmise au fil de l'eau tant qu'un plugin de réponse est attaché. Un flux (`text/event-stream`) ne peut pas être retenu : il est traité comme un dépassement. HEAD, 1xx, 204 et 304 n'ont pas de corps : rien n'est examiné. Le corps est vu tel que le backend l'envoie (`Content-Encoding` compris : un backend qui compresse livre des octets compressés).
- Un refus tardif (`deny` sur la réponse) retire les en-têtes propres à la réponse du backend (`Set-Cookie`, `Content-Encoding`, `ETag`…).

## État et réseau (capacités)

Un plugin n'a **aucune capacité par défaut**. Celles qu'il déclare dans `capabilities` sont les seules fonctions de l'hôte qu'il peut importer ; un import non déclaré est refusé au chargement.

- **`kv`** — état clé/valeur propre au plugin, en mémoire de la passerelle (perdu au redémarrage et au remplacement du plugin). `gpx.kv_get(kptr,klen) -> i64` (−1 si absent, sinon `ptr<<32|len`), `gpx.kv_set(kptr,klen,vptr,vlen,ttl_ms) -> i32` (0 ok, 1 quota atteint, 2 arguments invalides), `gpx.kv_incr(kptr,klen,delta,ttl_ms) -> i64` (compteur à fenêtre fixe, utile pour une limitation de débit ; `math.MinInt64` en cas d'erreur). Bornes : 1 024 clés, clé de 128 octets, valeur de 4 Kio, durée de vie 1 h par défaut et 24 h au plus.
- **`http`** — `gpx.http_fetch(ptr,len) -> i64` envoie la requête JSON `{method,url,headers,body,timeout_ms}` et retourne `{status,headers,body,error}`. Seuls les hôtes de `capabilities.http` (noms exacts ou `*.exemple.fr`) sont joignables ; les adresses internes (boucle locale, réseaux privés, link-local, métadonnées cloud) sont refusées *à la connexion* (contre le rebinding DNS) sauf `http_allow_private` ; pas de redirection suivie, pas de proxy d'environnement, méthodes GET/HEAD/POST/PUT/DELETE, 3 appels par hook, réponse tronquée à 64 Kio, délai limité à 80 % du temps restant du hook (déclarez un `timeout_ms` suffisant, 1 000 au plus).

## Routes TCP/UDP

Le hook `connect` reçoit `{client_ip, protocol, listen_port, route_id, config}` et répond `allow` ou `deny` (la connexion est fermée avant tout appel au backend, ou le datagramme ignoré). En UDP la décision est mémorisée une seconde par adresse source. Un plugin absent de la passerelle refuse la connexion, comme pour une route HTTP.

La passerelle ouvre un écouteur par route `tcp`/`udp` qui porte un `listen_port`, le ferme quand la route disparaît et le recrée quand son backend ou ses plugins changent ; ils se rouvrent après un redémarrage sans l'Admin.

## Coût d'un appel

Mesuré avec un module de deux pages mémoire (`go test ./internal/edge/plugins -bench .`, Ryzen 7 5700G) : environ **55 µs et 165 Kio alloués par appel** en amd64 (moteur compilé), environ 58 µs en 386 (interpréteur), un hook trivial. L'essentiel est l'instanciation d'une instance neuve (mémoire linéaire remise à zéro), qui garantit qu'aucun état ne passe d'une requête à l'autre. À 10 000 requêtes/s avec un plugin, cela représente de l'ordre d'un demi-cœur et 1,6 Go/s d'allocations pour le ramasse-miettes. Conséquences pratiques :

- déclarez le **minimum de mémoire** dont le module a besoin (le coût suit sa taille mémoire initiale) ;
- un plugin par route et un seul hook suffisent presque toujours ; chaque plugin et chaque hook s'additionnent ;
- le temps passé dans le plugin lui-même (`timeout_ms`) s'ajoute à ce coût fixe.

Ces chiffres sont une base : à mesurer avec votre propre module et votre trafic avant de généraliser un plugin à toutes les routes.

## Coût d'un vrai module

Le plugin d'exemple (TinyGo, `encoding/json`, 427 Kio non optimisé) coûte environ **0,54 ms et 270 Kio par appel** en amd64 (1,9 ms en 386 interprété), soit dix fois le module assemblé à la main ci-dessus : l'instanciation et le décodage JSON dominent. Pour un plugin sur le chemin chaud, préférez une analyse minimale de l'entrée plutôt qu'`encoding/json`, optimisez avec `wasm-opt`, et mesurez avec votre module.

## Limites

- Pas d'état partagé entre passerelles (le `kv` est local à une passerelle).
- Pas de compilateur fourni : produisez le WASM avec la chaîne de votre langage (Rust `wasm32-unknown-unknown`, TinyGo `wasm-unknown`). `examples/plugins/path-guard` est un plugin Go compilé avec TinyGo 0.43 (`tinygo build -target=wasm-unknown -no-debug -scheduler=none`), exécuté par la suite de tests ; un plugin Rust n'a pas été essayé.
- Pas de mesure en charge réelle (seulement le micro-benchmark ci-dessus).
