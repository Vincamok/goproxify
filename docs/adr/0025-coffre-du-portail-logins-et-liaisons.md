# ADR 0025 — Coffre du portail Access : base de logins, base de destinations, liaisons

**Statut :** accepté (livré : Admin 0.263.0, Edge 0.151.0) · **Date :** 2026-11

## Contexte

Le coffre actuel (`internal/edge/portal/vault.go`) est une table `identifiant de destination → {login, mot de passe, clé privée}`, propre à chaque utilisateur et chiffrée avec une clé dérivée de son mot de passe. Conséquences :

- le même compte (`root`, `deploy`) est ressaisi pour chaque destination, et à chaque utilisateur ;
- aucun login ne peut être préparé par un administrateur : un compte de service partagé n'existe pas, chacun doit connaître son secret ;
- le coffre mêle deux choses, ce qu'on est (le login) et où on s'en sert (la destination).

On veut deux bases distinctes, **logins** et **destinations**, et un coffre qui **relie** un login, préconfiguré ou manuel, à une ou plusieurs destinations.

## Décision

### Deux bases, un coffre qui les relie

- **Base de destinations** : le catalogue (ADR 0024 compris) et les cibles personnelles. Inchangée. Les destinations `docker` passent par l'Agent et n'utilisent aucun login.
- **Base de logins** : deux origines.
  - **Login préconfiguré** (partagé) : créé par un administrateur dans l'Admin. Nom, identifiant SSH, type de secret (mot de passe ou clé privée), secret, **droit d'usage** (groupes Access et tags d'utilisateur). L'utilisateur s'en sert sans jamais voir le secret.
  - **Login manuel** (personnel) : créé par l'utilisateur dans son coffre. Même forme, secret chiffré avec sa clé dérivée de son mot de passe, comme aujourd'hui.
- **Liaison** : *login ↔ destination*, plusieurs à plusieurs. Un login se lie à une ou plusieurs destinations, une destination peut avoir plusieurs logins. Les liaisons d'un login préconfiguré sont posées par l'administrateur (destinations ou groupes de destinations) ; celles d'un login manuel, par l'utilisateur.

### Choix du login à la connexion

Pour une destination et un utilisateur, les logins applicables sont : les logins préconfigurés liés à la destination **dont l'utilisateur a le droit d'usage**, plus ses logins manuels liés à cette destination. Un login n'ouvre rien que l'utilisateur ne voie déjà : la destination doit être visible (tags, entrée, accès temporaire) avant que ses logins comptent.

- aucun login applicable : refus avec le message actuel (« renseignez un login ») ;
- un seul : utilisé ;
- plusieurs : la création de session répond `409` avec la liste (nom, identifiant, origine) et l'interface demande ; `login_id` dans la requête tranche. L'utilisateur peut marquer un login par défaut pour une destination (non secret, gardé dans son coffre).

La façade SSH (UUID à usage unique) choisit le login à la création de l'UUID, comme la façade web. L'audit de session retient **quel login** a servi (nom et origine, jamais le secret).

### Secrets des logins préconfigurés : chiffrés pour la passerelle

La promesse de la documentation (« les secrets du coffre ne sont jamais envoyés à l'Admin ») est conservée : l'Admin ne stocke et ne relaie que du chiffré qu'il ne sait pas lire.

- La passerelle dérive de sa clé maître de portail (`GPX_PORTAL_MASTER_KEY`, déjà identique sur tous les membres d'un groupe HA) une paire **ECDH P-256** déterministe (HKDF, étiquette `goproxify-portal-login-seal`). Elle expose la clé publique à l'Admin (message `portal_login_pubkey`, rejoué à la connexion).
- Le **navigateur** (WebCrypto) ou la **CLI** chiffre le secret en ECIES : clé éphémère ECDH, HKDF, AES-256-GCM. L'Admin reçoit `{ephemeral_pub, nonce, ciphertext}`, le stocke dans `portal_logins.secret_sealed` et le pousse tel quel avec `push_portal`.
- La passerelle l'ouvre à l'usage avec sa clé privée dérivée. Elle garde la configuration poussée dans `portal-config.gpx` : les logins partagés fonctionnent **sans l'Admin**, y compris après un redémarrage ([ADR 0006](0006-autonomie-des-composants.md)).
- Une rotation de la clé maître repose sur le mécanisme des anciens secrets déjà utilisé par le magasin du portail ; les secrets scellés avec l'ancienne clé publique restent lisibles tant qu'elle figure parmi les anciennes clés, et se rechiffrent à la prochaine saisie.

**Limite assumée** : la garantie porte sur ce que l'Admin *stocke et relaie*. Une interface d'Admin compromise pourrait servir un JavaScript qui capte le secret avant de le chiffrer. Le chiffrement dans le navigateur ne protège pas d'un Admin hostile ; il protège de la base, des sauvegardes, des journaux, des API et des outils.

L'API et le MCP n'acceptent **que** des secrets déjà scellés. Un outil MCP ne reçoit donc jamais de mot de passe en clair : il crée et lie le login, et le secret se saisit dans l'interface ou par la CLI (qui scelle localement).

### Données

**Passerelle** — le magasin du portail (`Snapshot`) gagne :
- `SharedLogins` : reçus de l'Admin (configuration poussée), pas de secret en clair ;
- la charge du coffre personnel passe de `targetID → creds` à `{logins: id → {name, username, password, private_key}, links: destID → [loginID], defaults: destID → loginID}`. Le chiffrement par clé dérivée du mot de passe (ou clé SSO dérivée du secret maître) ne change pas.

**Admin** — deux tables :
- `portal_logins` : `id`, `edge_name` (passerelle ou groupe HA), `name`, `username`, `secret_kind` (`password`/`key`), `secret_sealed`, `groups_json`, `tags_json`, `enabled` ;
- `portal_login_links` : `login_id`, `dest_id` (un lien vers une destination supprimée disparaît avec elle).

### Surface

- API `/api/v1/portal/logins` (CRUD, secret scellé seul, jamais renvoyé : `has_secret`), `/api/v1/portal/logins/pubkey?edge=`, liaisons dans le corps du login (`dest_ids`, `dest_groups`).
- Outils MCP et commande `goproxify access logins`.
- Page **Catalogue Access › Logins** (liste, formulaire avec scellement dans le navigateur, éditeur de liaisons par destination ou groupe de destinations).
- Portail utilisateur, onglet **Coffre** refait : « Mes logins » à gauche, liaisons aux destinations à droite ; les logins préconfigurés apparaissent en lecture seule (nom et identifiant), avec les destinations qu'ils ouvrent.
- Droits : permission explicite `portal_catalog:logins` (créer, modifier, supprimer un login préconfiguré, comme `portal_catalog:sources`), lecture sous `portal_catalog:read`.

### Remplacement sans migration

Le produit n'est pas déployé : l'ancienne forme du coffre (`/api/vault/{id}`, une entrée par destination) est **remplacée**, sans passerelle de compatibilité. Les entrées déjà saisies dans un coffre existant ne sont pas converties ; elles sont à ressaisir.

## Points à confirmer avant de coder

1. **Ressaisie du coffre existant** : acceptable puisque rien n'est déployé ?
2. **Un login par défaut** par destination, mémorisé par l'utilisateur : retenu ici, à valider.
3. **Login préconfiguré à clé privée avec phrase secrète** : hors périmètre pour l'instant (clé non chiffrée seulement, comme aujourd'hui).
4. **WebCrypto** : ECDH P-256 est pris en charge par tous les navigateurs actuels, ce qui motive ce choix plutôt qu'X25519.

## Mise en œuvre

**Livré (Admin 0.263.0, Edge 0.151.0)**, avec ces précisions par rapport à la proposition :

- **Liaisons des logins préconfigurés** : portées par la ligne du login (`dest_ids_json`, `dest_groups_json`) plutôt que par une table `portal_login_links`. Supprimer une destination la retire de ces listes ; un groupe de destinations supprimé est ignoré à l'envoi.
- **Droit d'usage** : `all_users`, ou groupes Access (développés par l'Admin en identités, comme les entrées du portail), ou tags d'utilisateur ; **aucun des trois : personne** (refus par défaut). L'ADR proposait « groupes et tags » sans fixer le cas vide.
- **Clé publique de scellement** : lue sur la passerelle à la demande (`GET /internal/v1/portal/login-pubkey`), gardée côté Admin pour le cas où elle est hors ligne, au lieu d'un message WebSocket `portal_login_pubkey`. Plus simple et toujours à jour.
- **Rotation de la clé maître** : l'enveloppe s'ouvre avec la clé courante puis avec les anciens secrets d'appairage (`GPX_PAIRING_SECRET_PREVIOUS`), comme le magasin du portail. Un secret scellé pour une clé qui n'est plus connue est signalé (« le ressaisir dans l'Admin ») et jamais utilisé.
- **Login sans secret** : il existe côté Admin mais n'est pas poussé ; la passerelle ne le propose pas. L'API et le MCP n'acceptent un secret que scellé.
- **Interopérabilité** : un test croisé (`loginseal_interop_test.go`) ouvre en Go une enveloppe produite par le code WebCrypto de l'interface d'Admin.
- **Choix du login** : `login_id` (`shared:<id>` ou `personal:<id>`) à la création de session ; sinon un seul applicable, le favori, ou `409 login_required`. Un favori n'est accepté que pour un login applicable.
- **Cibles personnelles** : les secrets saisis avec une cible deviennent un login personnel `t-<id>` lié à cette cible, retiré avec elle.

Points à confirmer tranchés : l'ancien coffre n'est pas converti (ressaisie) ; un login par défaut par destination est retenu ; les clés privées protégées par une phrase secrète restent hors périmètre.
