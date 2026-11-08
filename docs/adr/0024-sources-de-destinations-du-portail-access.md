# ADR 0024 — Sources de destinations du portail Access

**Statut :** accepté (cadre et Proxmox VE livrés : Admin 0.262.0, Edge 0.150.0) · **Date :** 2026-11

## Contexte

Le catalogue du portail Access (`portal_destinations`, kinds `ssh` et `docker`) se remplit à la main, ou depuis les conteneurs découverts par les Agents. Une infrastructure qui vit dans un hyperviseur ou chez un fournisseur cloud (Proxmox, vCenter, Hetzner…) oblige l'opérateur à recopier chaque machine, avec son adresse, et à corriger le catalogue à chaque création ou suppression de VM.

On veut que le portail **interroge ces plateformes par leur API** et propose leurs machines comme destinations, sans saisie.

## Décision

### Une famille de modules : les *sources de destinations*

Nouveau paquet `internal/edge/destsync`, bâti sur `internal/modules` ([ADR 0007](0007-registre-de-modules.md)). Une source déclare un manifeste (type, libellé, champs dont les secrets) et une fabrique ; ajouter un fournisseur = un fichier qui appelle `Register` depuis `init()`.

```go
// Une source liste les machines joignables par SSH qu'elle connaît. Elle ne modifie rien chez le fournisseur.
type Source interface {
    List(ctx context.Context) ([]Machine, error)
}

type Machine struct {
    ExternalID string   // identifiant stable chez le fournisseur (vmid, UUID, instance-id) — clé de rapprochement
    Name       string
    Host       string   // IP ou nom joignable depuis la passerelle
    Port       int      // 22 par défaut
    Tags       []string // étiquettes du fournisseur (pool, tags Proxmox, labels cloud), normalisées
    Running    bool
    Detail     map[string]string // nœud, type (qemu/lxc), région… : affichage seulement
}
```

Premier lot de fournisseurs :

| Famille | Types | Authentification |
|---|---|---|
| Hyperviseur | `proxmox` (VE : VM QEMU, conteneurs LXC, nœuds), `vcenter`, `incus` (Incus/LXD), `libvirt` | jeton d'API Proxmox ; compte en lecture seule vCenter ; jeton de confiance Incus ; clé SSH pour libvirt (`virsh`) |
| Cloud | `hetzner`, `digitalocean`, `scaleway`, `aws_ec2` | jeton d'API en lecture seule ; clés IAM pour EC2 |
| Réseau privé / inventaire | `tailscale`, `netbird`, `netbox` | jeton d'API |

Une source n'a **que des droits de lecture** chez le fournisseur ; la documentation de chaque type indique le rôle minimal à créer (ex. `PVEAuditor` sur Proxmox).

### Où ça s'exécute : sur la passerelle

La passerelle détient le portail et doit joindre les machines : c'est elle qui interroge les API. Conséquences :

- **Configuration.** L'Admin reste le point de saisie et de supervision. La liste des sources (type, configuration, intervalle, filtres) est portée par la config du portail, donc poussée avec elle (`push_portal`) et conservée dans `portal-config.gpx` (chiffré) : une passerelle qui redémarre pendant une coupure de l'Admin reprend ses sources sans lui ([ADR 0006](0006-autonomie-des-composants.md)). Les secrets sont masqués par l'API et conservés à la modification (`KeepSecrets`), comme pour les canaux de notification.
- **Qui interroge.** Uniquement le membre qui héberge le portail (pas les réplicas en attente) : un groupe HA n'envoie pas N fois la même requête au fournisseur. À la bascule, le nouveau membre actif prend le relais.
- **Remontée.** Après chaque passage, la passerelle envoie à l'Admin l'inventaire complet de chaque source : message `portal_dest_inventory` (état, pas journal : un envoi perdu est corrigé par le suivant, comme `surface_suggestions`). Un passage en erreur n'envoie **pas** d'inventaire, il envoie l'état d'erreur de la source.

### Politique de publication : candidates à valider

Une machine découverte **n'est jamais visible des utilisateurs** tant qu'un opérateur ne l'a pas publiée.

- L'Admin range l'inventaire dans `portal_dest_candidates` (clé : source + `external_id`). États : `new`, `published`, `ignored`, `missing`.
- **Publier** crée une destination ordinaire (`portal_destinations`, kind `ssh`) rattachée à la candidate (`source_id`, `external_id`) et pousse le catalogue. Le filtrage par tags (R9–R10) et les groupes de destinations s'appliquent ensuite comme pour toute destination.
- **Règles de publication** facultatives par source (filtre sur pool, tag, nœud ; tags à ajouter ; « publier automatiquement ») : sans règle, rien n'est publié seul. La publication automatique est un choix explicite par source, jamais le défaut.
- **Ignorer** masque la machine de la file sans la publier ; elle ne revient pas tant qu'on ne la rétablit pas.
- **Changement d'adresse ou de nom chez le fournisseur** : la destination publiée suit (même `external_id`), sauf champ que l'opérateur a modifié à la main.
- **Disparition** : une machine absente d'un inventaire *réussi* passe en `missing` ; sa destination publiée est **désactivée** (pas supprimée) et signalée. Une machine arrêtée reste publiée (le portail ne sait de toute façon pas la démarrer). Un passage en erreur ne modifie rien.

### Ce que cela ne fait pas

- Pas de secrets SSH côté catalogue : l'utilisateur garde ses identifiants dans son coffre du portail (R14), comme aujourd'hui.
- Pas de démarrage/arrêt de machine, pas d'écriture chez le fournisseur.
- Pas de kind `docker` : les conteneurs viennent des Agents.

## Droits

La gestion des sources est de l'administration du portail, avec une permission explicite de plus que « modifier le catalogue » parce qu'elle manipule des identifiants d'API : à caler avec le catalogue de l'[ADR 0022](0022-modele-de-droits-niveaux-et-perimetres.md) (nouvelle permission dans le service portail, périmètre par passerelle) avant toute route.

## Conséquences

- Nouvelles tables Admin : `portal_dest_sources` (configuration, secrets scellés), `portal_dest_candidates`. Pas de migration : l'existant n'est pas touché.
- Nouveau message Edge → Admin et nouveau champ de la config du portail : rétro-compatibles.
- La passerelle doit joindre l'API du fournisseur (réseau, pare-feu) ; c'est le prix de l'autonomie, et c'est vérifié par un bouton « Tester » qui s'exécute sur la passerelle.
- Surface : API `/api/v1/portal/dest-sources` et `/api/v1/portal/dest-candidates`, outils MCP, commande `access sources`, page « Sources » dans le catalogue Access.

## Points ouverts

1. **EC2 :** la signature SigV4 existe peut-être déjà côté Agent (source ECS) ; à réutiliser plutôt que dupliquer.
2. **libvirt :** pas d'API HTTP ; passe par SSH (`virsh list`, `domifaddr`). C'est le module le plus fragile et le dernier à livrer.
3. **Fréquence :** 5 min par défaut, avec gigue, minimum 60 s ; bouton « Synchroniser maintenant ».
4. **Adresse retenue :** IP privée par défaut pour les hyperviseurs ; option « privée / publique » pour le cloud.

## Mise en œuvre

**Cadre et Proxmox VE (Admin 0.262.0, Edge 0.150.0).**

- `internal/edge/destsync` : registre (`Register`, `Manifests`, `Build`), `Runner` (une goroutine par source, premier passage 1 à 5 s après la configuration, puis intervalle + 10 % de gigue ; une panique devient une erreur de source ; un inventaire de plus de 5 000 machines est refusé, jamais tronqué), `Test`. La configuration des sources voyage dans `portalPushPayload.dest_sources` : absent (Admin plus ancien) = sources inchangées, liste vide = toutes retirées.
- Message `portal_dest_inventory` (passerelle → Admin) à chaque passage ; routes internes `POST /internal/v1/portal/dest-sources/test` et `/{id}/sync` (Admin → passerelle) pour le bouton *Tester* et *Synchroniser*.
- Admin : tables `portal_dest_sources` (configuration scellée par la clé des jetons de nœud) et `portal_dest_candidates` ; rapprochement transactionnel (`reconcileInventory`) ; routes `/api/v1/portal/dest-sources` et `/dest-candidates`.
- **Droits** : permission explicite `portal_catalog:sources` (créer, modifier, supprimer, tester une source) ; lecture des sources et candidates sous `portal_catalog:read`, publication et synchronisation sous `portal_catalog:manage`. Le périmètre par passerelle s'applique comme au reste du catalogue.
- Une destination suit son fournisseur champ par champ tant que sa valeur est encore celle que la synchronisation y avait mise ; supprimer la destination remet la machine dans la file.
- Points ouverts 3 et 4 tranchés : intervalle 5 min (minimum 60 s) avec bouton *Synchroniser* ; adresse = première IPv4 privée, sinon première IPv4 publique, interfaces virtuelles (ponts Docker, veth) écartées.

**Reste à livrer**, un fichier par fournisseur sur ce cadre : vCenter, Incus/LXD, libvirt (SSH, le plus fragile), Hetzner, DigitalOcean, Scaleway, AWS EC2 (signature SigV4 à réutiliser de la source ECS de l'Agent si possible), Tailscale, NetBird, NetBox. Aucun n'est vérifié contre un vrai service : les modules sont testés contre de faux serveurs, comme Proxmox.
