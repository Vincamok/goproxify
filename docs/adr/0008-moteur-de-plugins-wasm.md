# ADR 0008 — Moteur de plugins WASM

**Statut :** accepté (phase 1 : moteur d'exécution) · **Date :** 2026-10

## Contexte

L'ADR 0007 a mis en place les modules internes : des implémentations Go d'une interface, compilées dans le binaire et déclarées dans un registre avec un manifeste. Ils couvrent ce que nous écrivons. Ils ne couvrent pas ce qu'un utilisateur veut ajouter sans recompiler GoProxify — une règle d'authentification maison, une règle métier sur une requête, un en-tête calculé — ni ce qu'on ne veut pas exécuter sans isolation.

Un plugin externe s'exécute dans le même processus que la passerelle, qui sert le trafic de production : il doit être **isolé** (mémoire, CPU, aucune capacité implicite), **borné** (une boucle infinie ne bloque pas une requête) et **autonome** (actif Admin coupé, y compris après un redémarrage, ADR 0006).

## Décision

Les plugins sont des modules **WebAssembly** exécutés par [wazero](https://wazero.io) (Go pur, pas de cgo, compatible avec le binaire unifié de l'ADR 0001). Le registre de modules reste la couche commune : un plugin déclare le même `modules.Manifest` qu'un module interne et se branche sur les mêmes points d'extension. Le moteur WASM n'est qu'une implémentation de fabrique de plus.

### Paquet

Un plugin est un fichier `.wasm` et un **manifeste** JSON :

```json
{
  "name": "geo-headers", "version": "1.0.0", "api_version": 1,
  "hooks": ["request", "response"],
  "on_error": "deny",
  "limits": { "memory_pages": 16, "timeout_ms": 50 },
  "fields": [ { "key": "header", "label": "En-tête", "kind": "text", "required": true } ]
}
```

`fields` est un manifeste de configuration (ADR 0007) : l'Admin en tire la validation, le masquage des secrets et le formulaire. L'empreinte SHA-256 du `.wasm` est enregistrée à l'installation et vérifiée à chaque chargement.

### ABI v1 (JSON)

JSON plutôt qu'un ABI binaire : il se produit depuis n'importe quel langage qui compile en WASM sans bibliothèque. Le coût est acceptable pour des hooks légers ; les hooks sur corps de requête, qui le rendraient trop cher, ne font pas partie de la v1.

Le plugin exporte :

| Export | Rôle |
|---|---|
| `memory` | mémoire linéaire |
| `alloc(size i32) i32` | réserve `size` octets, retourne l'adresse |
| `on_request(ptr i32, len i32) i64` | hook de requête |
| `on_response(ptr i32, len i32) i64` | hook de réponse (optionnel) |

L'hôte écrit l'entrée JSON dans la mémoire du plugin (via `alloc`), appelle le hook, et lit la sortie à l'adresse et de la longueur contenues dans la valeur retournée (`ptr << 32 | len`).

Entrée de `on_request` : `{"method","host","path","query","headers":{"Nom":["valeur"]},"client_ip","config":{…}}`. Entrée de `on_response` : la même plus `"status"` et les en-têtes de réponse.

Sortie : `{"action":"allow"|"deny"|"modify", "status":403, "body":"…", "set_headers":{}, "remove_headers":[], "log":"…"}`. `allow` (ou une sortie vide) laisse passer ; `deny` répond directement ; `modify` applique les en-têtes puis laisse passer.

### Isolation et limites

- **Aucune capacité implicite** : pas de WASI, pas de système de fichiers, pas de réseau, pas de variables d'environnement, pas d'horloge ni d'aléa. L'hôte n'expose que `gpx.log(ptr, len)`.
- **Mémoire** plafonnée par `memory_pages` (64 Kio la page, 16 par défaut, 256 au plus).
- **Temps** plafonné par `timeout_ms` (50 par défaut, 1 000 au plus) : le contexte annule l'exécution, y compris une boucle infinie.
- **Entrée et sortie** limitées à 64 Kio.
- **Une instance par appel** à partir d'un module compilé une seule fois : aucun état ne fuit d'une requête à l'autre ni d'un client à l'autre.

### Politique d'erreur

Une erreur du plugin (échec, dépassement, sortie illisible, panique) applique `on_error` : `deny` (défaut) répond `503` ; `allow` laisse passer en journalisant. Une route ne devient jamais publique parce qu'un plugin de sécurité a échoué, sauf si le manifeste le demande explicitement.

### Stockage et autonomie

Le `.wasm` et son manifeste sont poussés par l'Admin, **stockés chiffrés** sur la passerelle (même clé que le cache chiffré, ADR 0006) et compilés au démarrage. Un plugin installé continue de fonctionner Admin coupé, y compris après un redémarrage de la passerelle. Rien de nécessaire à son exécution n'existe uniquement en base Admin.

### Confiance

Installer un plugin est une action d'administration (admin uniquement) qui exige l'empreinte SHA-256 attendue. La sandbox borne ce qu'un plugin peut *consommer* ; elle ne dit rien de ce qu'il *décide* : un plugin d'authentification qui répond `allow` à tout ouvre la route. Un plugin n'a donc pas de privilège de plus qu'une règle de routage, mais il faut le tenir pour du code de politique, à relire comme tel.

## Phases

1. **Moteur d'exécution** (`internal/edge/plugins`) : chargement, validation du manifeste, ABI v1, limites, politique d'erreur, stockage chiffré local. Testé avec des modules WASM assemblés à la main (aucune chaîne de compilation requise).
2. **Branchement** : plugins attachés à une route (`plugins: [{name, config}]`), exécutés dans la chaîne du `dispatch` ; poussés par l'Admin ; API, CLI, MCP.
3. **Interface et distribution** : page Admin, signature des paquets, dépôt de plugins.

## Conséquences

- Écrire un plugin demande de produire du WASM (Rust, TinyGo, AssemblyScript…) ; une trousse d'exemples accompagnera la phase 2.
- Le coût d'un hook est celui d'une instanciation et d'un aller-retour JSON : à mesurer en phase 2 avant d'ouvrir les hooks à toutes les routes.
- Les plugins ne remplacent pas les modules internes : ce qui est stable et standard reste natif (voir « Native vs plugin »).
