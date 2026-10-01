# MCP Goproxify — Guide d'implémentation

Ce document décrit l'architecture interne du serveur MCP de Goproxify, à destination des développeurs qui souhaitent comprendre le code, ajouter des outils ou adapter le serveur.

**Fichier source :** `internal/admin/mcp/server.go`  
**Point de montage :** `internal/admin/server.go` — `/mcp` et `/mcp/`

---

## Vue d'ensemble

```
Client MCP (Claude Desktop, Claude Code…)
          │
          │  POST /mcp          ← JSON-RPC 2.0 (outils et ressources)
          │  GET  /mcp/sse      ← Server-Sent Events (keepalive)
          ▼
  mcp.Handler (http.Handler)
          │
          ├── handleInitialize        → capacités et version protocole
          ├── handleToolsList         → catalogue d'outils
          ├── handleToolsCall         → dispatch vers toolXxx()
          ├── handleResourcesList     → catalogue de ressources
          ├── handleResourcesRead     → lecture via toolXxx()
          └── serveSSE                → stream keepalive
                    │
                    ▼
              sql.DB (SQLite Administration)
```

Le handler n'a pas d'état propre — toutes les données sont lues depuis SQLite à chaque requête. La concurrence est gérée par le pool de connexions SQLite (WAL, 10 conns max).

---

## Structure du package

```
internal/admin/mcp/
├── server.go          JSON-RPC, outils proxies/nodes/sécurité, ressources
├── portal_tools.go    Outils + helpers GoProxify Access (délégation API)
└── infra_tools.go     Outils declared-nodes / bootstrap / accept|reject
```

Le choix d'un fichier unique est intentionnel : le serveur MCP est une façade de lecture sur la base de données et n'a pas de logique métier propre. Si le nombre d'outils dépasse une vingtaine, envisager de découper en `tools.go` et `resources.go`.

---

## Types JSON-RPC

```go
type rpcRequest struct {
    JSONRPC string          `json:"jsonrpc"`
    ID      any             `json:"id"`       // string, number ou null
    Method  string          `json:"method"`
    Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
    JSONRPC string    `json:"jsonrpc"`
    ID      any       `json:"id,omitempty"`
    Result  any       `json:"result,omitempty"`
    Error   *rpcError `json:"error,omitempty"`
}
```

`ID` est `any` car la spec JSON-RPC 2.0 autorise string, number ou null. Le serveur renvoie l'ID reçu tel quel, sans transformation.

---

## Helpers de schéma

Les outils MCP décrivent leurs paramètres via un JSON Schema (`inputSchema`). Deux helpers simplifient la construction :

```go
type param struct {
    name, typ, desc string
    required        bool
}

func req(name, typ, desc string) param { return param{name, typ, desc, true} }
func opt(name, typ, desc string) param { return param{name, typ, desc, false} }

func schema(params ...param) map[string]any { ... }
```

Exemple d'utilisation :

```go
// Outil sans paramètre
schema()

// Tous requis
schema(
    req("host",    "string",  "Domaine (ex: app.example.com)"),
    req("backend", "string",  "URL du backend"),
)

// Mélange requis / optionnel
schema(
    req("id",          "string",  "ID du proxy"),
    opt("tls_enabled", "boolean", "Active HTTPS (défaut: false)"),
)
```

Le champ `required` du JSON Schema n'est émis que s'il contient au moins un élément — Claude comprend l'absence du champ comme "aucun paramètre obligatoire".

---

## Ajouter un outil

### 1. Déclarer l'outil dans `tools`

```go
var tools = []map[string]any{
    // ... outils existants ...
    {
        "name":        "mon_outil",
        "description": "Ce que fait l'outil, en une phrase.",
        "inputSchema": schema(
            req("param1", "string", "Description du paramètre obligatoire"),
            opt("param2", "number", "Paramètre optionnel"),
        ),
    },
}
```

### 2. Dispatcher l'appel dans `handleToolsCall`

```go
case "mon_outil":
    p1, _ := p.Arguments["param1"].(string)
    p2 := 0
    if v, ok := p.Arguments["param2"].(float64); ok {
        p2 = int(v)
    }
    result, toolErr = h.toolMonOutil(r, p1, p2)
```

> **Note :** Les nombres JSON sont toujours désérialisés en `float64` par `encoding/json`. Convertir explicitement en `int` si nécessaire.

### 3. Implémenter la méthode

```go
func (h *Handler) toolMonOutil(r *http.Request, param1 string, param2 int) (any, error) {
    rows, err := h.DB.QueryContext(r.Context(), `SELECT ... FROM ma_table WHERE ...`, param1)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var out []map[string]any
    for rows.Next() {
        // ... scan ...
        out = append(out, map[string]any{ ... })
    }
    if out == nil {
        out = []map[string]any{} // toujours retourner un tableau, jamais null
    }
    return out, nil
}
```

Règles à respecter :
- Utiliser `r.Context()` sur toutes les requêtes SQL pour propager l'annulation.
- Retourner `[]map[string]any{}` (et non `nil`) pour les listes vides — `null` confond les LLM.
- Ne jamais exposer des champs sensibles (`password_hash`, `cert_pem`, `key_pem`, secrets).

### 4. Déclarer le scope (obligatoire)

Dans `internal/admin/rbac/pat_scopes.go` :

- `ToolRequiredScope` : le scope que `RequiredScopeForRequest` exige pour la route REST équivalente (même chemin, même méthode). Un outil sans scope est **refusé** par `handleToolsCall` (`outil sans scope déclaré`).
- `ToolRequiresAdmin` : ajouter l'outil si la route REST équivalente est montée avec `adminOnly` dans `internal/admin/server.go` (le MCP n'applique pas `RequireAdmin`).
- `mcpTools` : ajouter le nom, pour qu'il apparaisse dans le catalogue scope → outils de `/mcp-access`.

`TestEveryToolHasScope` et `TestScopeCatalogueListsEveryTool` (`internal/admin/mcp/tool_scopes_test.go`) échouent si l'une de ces étapes manque. Si aucun scope existant ne correspond, en créer un dans le catalogue (`AllPATScopes`, `ScopeCatalog`, `AvailableScopesForUser`) et l'utiliser aussi dans `RequiredScopeForRequest`, pour que REST et MCP restent alignés.

---

## Ajouter une ressource

Les ressources sont des données accessibles sans paramètre, identifiées par une URI.

### 1. Déclarer la ressource dans `handleResourcesList`

```go
{"uri": "goproxify://ma-ressource", "name": "Ma Ressource", "description": "...", "mimeType": "application/json"},
```

### 2. Ajouter le cas dans `handleResourcesRead`

```go
case "goproxify://ma-ressource":
    data, err = h.toolMonOutil(r, "", 0)
```

Les ressources réutilisent directement les implémentations d'outils — pas de duplication de code SQL.

### 3. Associer la ressource à son outil dans `resourceTools`

```go
"goproxify://ma-ressource": "mon_outil",
```

La lecture applique les droits de l'outil (scope, rôle admin). Une URI absente de `resourceTools` renvoie `resource not found` ; `TestEveryResourceMapsToTool` vérifie que chaque ressource listée y figure.

---

## Transport SSE

`GET /mcp/sse` implémente le transport Server-Sent Events défini par la spec MCP. Le flux :

1. Le serveur émet immédiatement un événement `endpoint` contenant l'URL POST où envoyer les requêtes JSON-RPC.
2. Un ticker envoie un commentaire `: keepalive` toutes les 15 secondes pour maintenir la connexion TCP.
3. La goroutine se termine dès que le contexte HTTP est annulé (client déconnecté).

```
Client                          Serveur
  │── GET /mcp/sse ──────────────▶ │
  │◀── event: endpoint ────────── │
  │    data: https://host/mcp      │
  │                                │
  │◀── : keepalive ─────────────── │  (toutes les 15 s)
  │◀── : keepalive ─────────────── │
```

Ce transport est utilisé par les clients qui ne supportent pas les appels HTTP directs (certaines versions de Claude Desktop). Les clients modernes (Claude Code) utilisent directement le transport HTTP sans SSE.

---

## Montage dans le serveur Admin

Dans `internal/admin/server.go` :

```go
mcpH := &mcp.Handler{
    DB: s.db, Log: s.log, Pusher: manager,
    Access: manager, AccessTemplates: manager,
    ListAgents:   ..., // registre AgentStore
    ApproveAgent: ..., // BroadcastApproveAgent
    RevokeAgent:  ..., // BroadcastRevokeAgent
    OnBansChange: pushBans,
}
mux.Handle("/mcp",  auth.RequirePAT(s.db)(mcpH))
mux.Handle("/mcp/", auth.RequirePAT(s.db)(mcpH))
```

Le middleware `RequirePAT` n’accepte que les tokens utilisateur `gpx_pat_*` (créés via `/api/v1/me/tokens`). Un JWT de session UI est refusé sur `/mcp`. `/mcp` n'est protégé que par `RequirePAT` : ni `EnforcePATScope` ni `RequireAdmin`. `handleToolsCall` (et `handleResourcesRead`, via `resourceTools`) appelle donc `denyTool`, qui joue le rôle des deux middlewares de la route REST équivalente :

1. `rbac.ToolRequiredScope` vide → refus (`outil sans scope déclaré`), le contrôle échoue fermé ;
2. `rbac.EffectiveHasScope` (scopes PAT ∩ droits actuels du compte) → sinon `scope insuffisant: <scope>` ;
3. `rbac.ToolRequiresAdmin` et compte non admin → `accès réservé aux administrateurs`.

Chaque outil exige le scope que `RequiredScopeForRequest` exige pour sa route REST (ex. `list_security_*` → `audit:read` comme `GET /api/v1/security`, `ban_ip` → `security:write`, `obtain_cert` → `certs:write` comme `POST /api/v1/certs`, `list_rules` → `audit:read` et `run_rule` → `security:write` comme `/api/v1/rules-engine`). Le rôle admin est exigé en plus pour les outils dont la route REST est `adminOnly` (sécurité, moteur de règles, planifications, playbooks, CA interne, fournisseurs d'auth, Agents, architecture, sauvegardes, Access…) : sans lui, un compte `user` tenant `audit:read` ou `certs:read` passerait. La table complète est dans [mcp.md](mcp.md#contrôle-daccès-des-outils).

Le handler reçoit `*sql.DB` directement — pas de couche de repository intermédiaire, par cohérence avec le reste du code Admin qui accède aussi à SQLite directement. Les outils Access et Infrastructure délèguent aux handlers HTTP Admin (`PortalHandler`, `DeclaredNodesHandler`, `BootstrapHandler`, `NodesHandler`) via `httptest` pour réutiliser validation, auto-accept et génération QR.

---

## Version du protocole

La constante `mcpVersion` définit la version annoncée lors du handshake `initialize` :

```go
const mcpVersion = "2025-03-26"
```

Lors d'une montée de version du protocole MCP :
1. Mettre à jour `mcpVersion`.
2. Vérifier les changements de spec (capacités, formats de réponse, nouveaux champs obligatoires).
3. La capacité `listChanged: false` indique que la liste des outils/ressources est statique — pas de notification de changement en cours de session.

---

## Conventions de nommage

| Élément          | Convention                                  | Exemple                    |
|------------------|---------------------------------------------|----------------------------|
| Nom d'outil      | `snake_case`, verbe_sujet                   | `list_proxies`, `get_proxy` |
| Méthode Go       | `tool` + CamelCase du nom d'outil           | `toolListProxies`           |
| URI de ressource | `goproxify://` + nom pluriel sans underscore| `goproxify://proxies`       |
| Paramètre JSON   | `snake_case`                                | `tls_enabled`, `proxy_id`  |

---

## Tests

Des tests unitaires couvrent les outils proxies (create/update/enable), bans sécurité et agents :

`internal/admin/mcp/server_test.go` — base SQLite temporaire via `admindb.Open` + faux serveur passerelle (`httptest.NewServer`) qui simule les endpoints `/internal/v1/proxies/*`. Les outils proxy appellent la passerelle directement ; SQLite n'est utilisé que pour la table `tokens`.

```go
h := &Handler{DB: db, Log: slog.Default()}
out, err := h.toolCreateProxy(r, map[string]any{
    "host": "app.example.com", "backend": "http://10.0.0.5:3000",
})
```

Pour tester le chemin JSON-RPC complet avec scopes, envelopper le handler avec `RequirePAT` et un PAT en base : `mcpClient` dans `internal/admin/mcp/tool_scopes_test.go` crée le compte (rôle au choix), le PAT et ses scopes, et renvoie un client JSON-RPC (`TestToolsCallAuthorization`, `TestResourcesReadAuthorization`).
