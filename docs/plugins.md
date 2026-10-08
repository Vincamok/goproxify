# Plugins WebAssembly

Un plugin est un module WebAssembly que les passerelles exécutent dans une sandbox pour décider du sort d'une requête ou d'une réponse : règle d'authentification maison, règle métier, en-tête calculé. Le choix d'architecture est dans [l'ADR 0008](adr/0008-moteur-de-plugins-wasm.md). Les fonctions standard d'un reverse proxy restent natives ; un plugin sert à ce qu'on ne veut pas compiler dans GoProxify.

## Installer et attacher un plugin

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

## ABI v1

Le module exporte `memory`, `alloc(size i32) i32`, et `on_request(ptr i32, len i32) i64` et/ou `on_response(ptr i32, len i32) i64`. L'hôte réserve la place de l'entrée avec `alloc`, y écrit un JSON, appelle le hook, puis lit le JSON de sortie à l'adresse et de la longueur contenues dans la valeur retournée (`ptr << 32 | len`) ; une longueur nulle équivaut à `allow`.

**Entrée de `on_request`** : `{"method","host","path","query","headers":{"Nom":["valeur"]},"client_ip","config":{…}}` — `on_response` y ajoute `"status"` et `"response_headers"`. Les en-têtes transmis comprennent `Authorization` et `Cookie` : un plugin est du code de politique, à relire comme tel.

**Sortie** : `{"action":"allow"|"deny"|"modify","status":403,"body":"…","set_headers":{},"remove_headers":[],"log":"…"}`

- `allow` (ou sortie vide) : laisse passer.
- `deny` : répond avec `status` (4xx/5xx, 403 par défaut) et `body`. Sur `on_response`, le corps du backend est écarté.
- `modify` : pose et retire des en-têtes (de la requête pour `on_request`, de la réponse pour `on_response`), puis laisse passer.
- `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Upgrade`, `TE`, `Trailer` ne peuvent être ni posés ni retirés ; une valeur contenant CR, LF ou NUL est refusée.

L'hôte n'importe qu'une fonction : `gpx.log(ptr i32, len i32)` (journal, 1 Kio par appel). Tout autre import (WASI, système de fichiers, réseau, horloge, aléa) est refusé au chargement. Une instance neuve est créée à chaque appel : un plugin n'a pas d'état.

## Limites de la v1

- Pas de hook sur le corps de la requête ou de la réponse.
- Pas d'état partagé ni d'appel réseau depuis un plugin.
- Un plugin ne s'attache qu'à une route HTTP, pas à un flux TCP/UDP.
- Paquets non signés : l'empreinte SHA-256 vérifie l'intégrité, pas l'origine.
- Le coût d'un appel (instanciation et aller-retour JSON) n'est pas encore mesuré en charge.
