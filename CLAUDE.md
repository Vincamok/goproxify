# GoProxify — instructions Claude

## Branche de travail

Travailler **directement sur `main`** — ne pas créer de branche de feature, ne pas ouvrir de PR sauf si le user le demande explicitement.

```
git checkout main && git pull origin main
# ... modifications ...
git push origin main
```

## Stack

- Go 1.22+, module `github.com/vincamok/goproxify`
- Stockage proxies : YAML (`internal/core/proxystore/`) — lire/écrire via `proxystore.Store`
- UI admin : Vanilla JS sans framework (`internal/admin/ui/src/js/`)
- Images Docker depuis Harness artifact registry, services dans `services/`

## Conventions

- Pas de commentaires sauf si le WHY est non-obvious
- Pas de gestion d'erreur pour des cas impossibles
- Tests dans le même package (`_test.go`)
