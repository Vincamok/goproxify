# Portail Access — guide opérateur

Le portail Access offre aux utilisateurs finaux un accès SSH / shell aux backends, avec authentification 2FA et sessions à durée limitée (TTL). Ce guide couvre l'installation, la configuration SMTP et le cycle de vie des comptes.

## Prérequis

- GoProxify Admin + au moins une passerelle en fonctionnement
- Serveur SMTP accessible depuis l'Admin (requis pour les invitations par email)
- Optionnel : domaine dédié (ex. `access.example.com`) pointant vers la passerelle concernée

## Configuration SMTP

L'envoi d'invitations repose sur la configuration SMTP globale.

Dans l'Admin → **Paramètres → SMTP** :

| Champ | Exemple |
|---|---|
| Hôte | `smtp.example.com` |
| Port | `587` |
| Utilisateur | `noreply@example.com` |
| Mot de passe | (secret) |
| TLS | STARTTLS recommandé |
| Expéditeur | `"GoProxify Access" <noreply@example.com>` |

Tester la configuration avec le bouton **Envoyer un email test** avant d'inviter des utilisateurs.

## Inviter un utilisateur

1. Admin → **Access → Users** → bouton **Inviter**
2. Saisir l'email, les tags optionnels, et choisir la passerelle d'hébergement
3. L'utilisateur reçoit un lien d'activation valable 24 h
4. À l'activation, il choisit son mot de passe et configure le 2FA (TOTP ou clé passkey)

Pour renvoyer une invitation expirée : icône ✉ dans la table, colonne Actions.

## Cycle de vie des comptes

| Statut | Description |
|---|---|
| `invited` | Invitation envoyée, compte non activé |
| `active` | Compte opérationnel, accès autorisé |
| `disabled` | Accès révoqué sans suppression (conservation des logs) |

Changer le statut : bouton édition (crayon) → sélecteur **Status**.

Supprimer définitivement : bouton corbeille. Les sessions actives sont terminées immédiatement.

## Sessions et TTL

Chaque session Access a une durée maximale configurable par passerelle :

- Admin → **Nodes** → passerelle cible → **Access → Session TTL**
- Par défaut : 8 h
- Minimum : 15 min, maximum : 7 jours

L'utilisateur peut fermer sa session avant expiration via le bouton **Déconnexion** du portail.

## Tags et filtres

Les tags permettent de segmenter les utilisateurs (ex. `prod`, `ops`, `readonly`).  
Ils sont visibles dans les logs d'accès et utilisables dans les règles RBAC.

Filtrer par tag dans la vue Users : champ de recherche libre.

## Sources de destinations (Proxmox…)

Plutôt que de saisir chaque machine, **Catalogue Access › Sources** relie le portail à une plateforme : la passerelle interroge son API à intervalle régulier (5 min par défaut, 60 s au minimum) et liste ses machines. Premier fournisseur : **Proxmox VE** (VM, conteneurs LXC, et au choix les nœuds).

1. **Côté Proxmox**, créer un utilisateur et un jeton d'API **en lecture seule** (rôle `PVEAuditor` sur `/`, séparation de privilèges décochée ou rôle donné au jeton). Le certificat auto-signé de Proxmox se colle dans « CA certificate » ; à défaut, cocher « Do not verify the TLS certificate ».
2. **Ajouter la source** : passerelle, type, URL (`https://pve.example.com:8006`), identifiant et secret du jeton, filtres facultatifs (pool, étiquette, machines en marche seulement). Le bouton **Tester** lit Proxmox *depuis la passerelle* : c'est d'elle que le réseau doit le joindre.
3. **Publier** : les machines arrivent dans « À publier », invisibles des utilisateurs. Publier une machine (ou la sélection) en fait une destination SSH du catalogue ; ses étiquettes Proxmox, celles de la source et celles saisies à la publication décident ensuite qui la voit (filtrage par tags, comme toute destination). Une machine dont Proxmox ne donne pas l'adresse (agent invité absent, DHCP) se publie en saisissant l'adresse.
4. **Ensuite** : la destination suit Proxmox (renommage, changement d'adresse) sauf champ corrigé à la main. Une machine qui disparaît de Proxmox est **désactivée**, pas supprimée, et réactivée si elle revient. Une panne de l'API Proxmox ne change rien au catalogue.

La publication automatique (« Publish discovered machines automatically ») est désactivée par défaut : activée, toute machine découverte avec une adresse devient visible sans validation. Droit requis pour créer, modifier, supprimer ou tester une source : `portal_catalog:sources` (elle porte des identifiants d'API) ; publier relève de `portal_catalog:manage`.

## Supervision

- Logs d'accès : Admin → **Logs** → filtre `source=access`
- Sessions actives : Admin → **Access → Sessions** (durée restante, IP client, hôte cible)
- Métriques Prometheus : `gpx_access_sessions_active`, `gpx_access_logins_total`

## Sécurité

- Le 2FA est obligatoire pour tous les comptes Access (non contournable depuis l'UI)
- Les tokens de session sont signés HS256, rotation automatique à chaque reconnexion
- L'accès SSH est limité aux hôtes déclarés dans le catalogue de la passerelle (`Access → Catalogue`)
- Les IP bannies par Ephor bloquent également l'accès au portail
