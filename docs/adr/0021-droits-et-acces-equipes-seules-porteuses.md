# ADR 0021 — Comptes et équipes : l'équipe porte les droits des utilisateurs, l'administrateur est celui de la plateforme, le DPO est une équipe intégrée

**Statut :** accepté le 2026-11-01 (après trois révisions le même jour, les décisions de l'[ADR 0022](0022-modele-de-droits-niveaux-et-perimetres.md) ayant été validées une à une avec le propriétaire) ; livraisons 1 (espaces de travail retirés, Admin 0.242.0) et 2 (administrateur global, fin des droits personnels, équipe DPO, capacités RGPD, accès effectif, Admin 0.243.0) mises en œuvre, le reste à suivre avec l'ADR 0022 · **Date :** 2026-11-01
**Retire :** les espaces de travail (`/api/v1/workspaces`, tables `workspaces`, `workspace_members`, `workspace_resources`), l'administrateur « limité à un domaine », le rôle `dpo`, les droits personnels d'un compte · **Respecte :** ADR-0006 (autonomie des composants), ADR-0002 (SQLite pour l'administration) · **Complété par :** [ADR 0022](0022-modele-de-droits-niveaux-et-perimetres.md) (ce que contient un accès d'équipe : niveaux, périmètres, catalogue) · **Touche :** le contrôle d'accès des proxys, conteneurs découverts, surface applicative et MCP (Admin 0.241.1 à 0.241.3) reste tel quel

---

## Contexte

La gestion des comptes, des équipes et des espaces de travail se recoupe : l'interface empile trois blocs qui disent presque la même chose, et la page « Utilisateurs » doit afficher une carte pour expliquer le modèle. L'examen du code (2026-11-01) donne sept constats.

1. **Trois objets, deux relations.** Dire « ces personnes accèdent à ces ressources » se fait de trois façons :

   | Objet | Il porte | Appliqué ? |
   |---|---|---|
   | **Compte** | rôle plateforme (`superadmin`, `admin`, `user`, `dpo`), droits personnels (domaine, serveur, proxy, passerelle × lecture/écriture), permission `gdpr:reveal` | Oui (`rbac.UserEffectiveGrants`) |
   | **Équipe** | membres, les mêmes droits, la même permission | Oui |
   | **Espace de travail** | membres (comptes ou équipes), ressources (proxy, domaine, passerelle), sans mode lecture/écriture | **Non** |

2. **L'espace de travail n'est lu par rien.** Seul son CRUD (`api/workspaces.go`) le touche : aucun contrôle d'accès, aucune liste, aucune requête ne le consulte. La roadmap publique annonce une « isolation multi-tenant » qui n'existe pas. Il n'est pas audité, n'est pas dans `users.yaml` (les comptes et les équipes y sont), et n'a ni commande CLI (la documentation en annonce une) ni outil MCP.
3. **Les droits d'un compte ont trois origines**, qu'aucun écran ne réunit : ses droits personnels, ceux de ses équipes, son rôle. La permission RGPD en a trois aussi : le rôle `dpo`, la permission du compte, celle de l'équipe.
4. **Le calcul des droits effectifs est écrit trois fois** : `rbac.UserEffectiveGrants`, une réimplémentation dans `api/me.go` (requêtes une à une), et un recalcul côté navigateur dans `access-policies.js`. Les trois peuvent diverger.
5. **L'édition est éclatée.** Les membres d'une équipe ne se modifient que depuis la fiche du compte ; les droits d'une équipe, depuis la fenêtre de l'équipe ; les membres d'un espace, depuis l'espace. Aucune commande CLI ni outil MCP ne gère un droit (`goproxify teams` n'a que membres et permissions, avec un drapeau `-role` mort que l'API ignore ; le MCP n'a que `list_users` et `list_teams`).
6. **L'« administrateur limité à un domaine » n'en est pas un.** Sur un même domaine, un `user` en écriture crée, modifie et active ou désactive des proxys et écrit des snippets ; un `admin` avec le même droit peut en plus supprimer des proxys, et les routes `adminOnly` lui sont ouvertes : sécurité (bannissements, WAF, Ephor), jetons, comptes, équipes, sauvegardes, import, plugins, portail, automatisation. **Aucune de ces routes ne filtre par domaine.** Il peut aussi, depuis `PUT /users/{id}` ou en s'ajoutant à une équipe, supprimer ses propres droits et devenir administrateur global (un `admin` sans aucun droit voit tout ; lui en ajouter un le restreint, règle implicite `len(grants) == 0`). Le périmètre qu'on lui donne ne borne donc rien, et deux comptes aux pouvoirs différents sur un même domaine portent le même mot « droits ».
7. **Le droit RGPD n'a pas de mécanisme propre.** La révélation d'une IP exige `gdpr:reveal`, un motif obligatoire, et est auditée au nom du compte qui l'a faite : il faut des personnes nommées derrière. Le droit passe pourtant par trois voies (constat 3), et le rôle `dpo` est exclusif (un DPO ne peut pas être aussi `admin`), ce qui a justifié la permission propre au compte. La voie « équipe » n'est pas fautive en soi : la composition d'une équipe qui porte une permission est déjà réservée au superadmin (`guardTeamPermissions`).

Les droits des **passerelles** (`token_scopes`), des **jetons API** (scopes de PAT, toujours bornés par les droits du compte) et du **portail Access** (comptes et groupes de ses utilisateurs finaux) sont d'autres concepts. Le contenu des droits d'équipe (lecture ou écriture sur quoi, logs, portail, périmètres) fait l'objet de l'ADR 0022.

## Décision

### 1. Deux sortes de comptes : l'administrateur de la plateforme, l'utilisateur à périmètre

- **L'administrateur** (`admin`, `superadmin`) gère la **plateforme entière**. Son périmètre est toujours « tout » : aucun droit d'équipe ne le restreint, ni ne l'étend. Il n'y a plus d'administrateur limité à un domaine ; la règle implicite `len(grants) == 0` et le piège qu'elle posait disparaissent. Pour limiter quelqu'un, on le crée `user`.
- **L'utilisateur** (`user`) n'a **que** les droits de ses équipes. Sans équipe, il ne voit rien.
- Ce qu'un utilisateur peut faire d'un domaine (au-delà de lire et d'écrire un proxy : supprimer, gérer certificats et alertes) se règle par le **niveau** de l'accès d'équipe (ADR 0022), pas par un rôle intermédiaire.

### 2. Un seul porteur de droits pour l'utilisateur : l'équipe

- **Le compte** porte l'identité, le rôle plateforme (`admin` ou `user`) et ses équipes. Il ne porte **aucun droit sur les ressources** en propre.
- **L'équipe** est le seul endroit où l'on dit qui peut quoi : **membres**, **accès** (contenu défini par l'ADR 0022) et **capacités** (droits qui ne portent sur aucune ressource, aujourd'hui `gdpr:reveal`). Une exception individuelle se fait avec une équipe d'une personne.
- **L'espace de travail est supprimé**, sans équivalent. Un besoin « par projet » ou « par environnement » se règle par des étiquettes et des périmètres (ADR 0022), pas par un troisième objet.

### 3. Équipes de base

Aucune équipe qui accorde des droits n'est créée d'office, sauf l'équipe DPO (décision 4) : une équipe de ce type ne doit pas exister sans décision de l'exploitant. En revanche, la création d'une équipe propose des **modèles** qui préremplissent sa fenêtre (« Équipe vide », « Lecture seule », « Exploitation d'un domaine »… ; leur liste suit les niveaux de l'ADR 0022). L'équipe créée est une équipe ordinaire, modifiable.

### 4. Le DPO est une équipe intégrée

Le DPO est une ou plusieurs personnes désignées ; la révélation d'une IP est tracée à leur nom. Plutôt qu'un rôle ou une permission sur le compte :

- **L'équipe « DPO » existe d'office.** Elle est créée au démarrage, ne peut être ni supprimée ni renommée, ne porte aucun accès sur les ressources et **quatre capacités RGPD** (`gdpr:reveal`, `gdpr:export`, `gdpr:erase`, `gdpr:hold`, ADR 0022, D1) que l'on peut aussi donner séparément à une autre équipe.
- **Sa composition est réservée au superadmin** (c'est déjà la règle de `guardTeamPermissions`). Ses membres sont des comptes nommés ; plusieurs sont possibles (suppléant, cabinet externe). Un administrateur peut en faire partie : la capacité se cumule avec n'importe quel rôle.
- Le rôle `dpo` et la permission propre au compte (`user_permissions`) disparaissent : une seule voie, l'appartenance à l'équipe. La liste des DPO est la liste des membres de cette équipe, affichée en tête de la page Accès, avec un badge « DPO » sur leurs comptes.
- Le motif reste obligatoire, chaque révélation reste auditée au nom du compte, et un membre de l'équipe reste un compte protégé (`IsProtectedAccount`).
- D'autres capacités, quand elles existeront, suivront le même principe : une équipe intégrée par capacité sensible, ou une capacité cochée sur une équipe ordinaire.

### 5. Un seul calcul des droits effectifs

`rbac.UserEffectiveGrants` devient la seule définition (union des accès des équipes du compte). `api/me.go` l'appelle au lieu de la refaire. Un nouveau point d'accès rend l'**accès effectif d'un compte avec l'origine de chaque droit** (équipe, rôle administrateur) : la fiche du compte l'affiche en lecture seule, la page « Politiques d'accès » le consomme au lieu de recalculer dans le navigateur.

### 6. Interface

Une page **Accès** à deux vues cohérentes, **Comptes** et **Équipes**, sans carte d'explication.

- **Fiche d'un compte** : e-mail, mot de passe, rôle (administrateur ou utilisateur), équipes (cases à cocher, l'équipe DPO réservée au superadmin), puis « Accès effectif » en lecture seule avec l'origine de chaque droit.
- **Fenêtre d'une équipe** : nom, **membres**, **accès** (forme définie par l'ADR 0022), **capacités**, modèle proposé à la création. Les membres s'y ajoutent et s'y retirent (ils ne le sont plus seulement depuis la fiche du compte).
- Les espaces de travail quittent le menu « Accès ».

### 7. CLI, MCP, API : les droits deviennent pilotables

- API : `GET|POST|DELETE /teams/{id}/scopes` existent déjà (leur forme change avec l'ADR 0022) ; s'y ajoute l'accès effectif d'un compte (`GET /users/{id}/access`). Le champ `scopes` de `PUT /users/{id}` disparaît, ainsi que `/workspaces` (9 points d'accès).
- CLI : `goproxify teams scopes list|add|remove <équipe>`, retrait du drapeau mort `-role`, ajout de `goproxify users access <compte>`. Les lignes `workspaces …` de la documentation sont retirées.
- MCP : outils d'écriture de droits d'équipe (`add_team_scope`, `remove_team_scope`, `add_team_member`, `remove_team_member`) et lecture de l'accès effectif d'un compte (`get_user_access`), réservés aux administrateurs comme `list_teams`.

### 8. Données

`users.yaml` reste la source de vérité des comptes et des équipes (ADR-0006 inchangé : les droits d'un compte sont un sujet d'Admin seul, la passerelle n'en reçoit rien). Sont supprimées les tables `workspaces`, `workspace_members`, `workspace_resources`, `user_scopes` et `user_permissions`, avec leur entrée dans la sauvegarde (`importer/tables.go`, `docs/sauvegardes.md`) et dans `UserEntry` (`Scopes`, `Permissions`). `team_permissions` reste : elle porte les capacités d'équipe. Aucune instance n'est déployée en production : **pas de migration**.

## Alternatives écartées

- **Garder les trois objets et faire appliquer les espaces de travail.** Conserve trois porteurs de droits, ajoute une règle de combinaison (un espace donne-t-il plus ? moins ?) et un mode lecture/écriture que l'espace n'a pas. C'est le contraire de la demande.
- **Garder l'espace de travail et supprimer l'équipe.** Même relation, mais l'équipe est appliquée, persistée dans `users.yaml`, auditée, présente en CLI, MCP, sauvegarde et documentation : le coût de bascule serait bien plus grand pour un résultat identique.
- **Garder les droits personnels du compte.** Ils sont l'origine du deuxième endroit où éditer les droits et obligent la fiche à les mêler à ceux des équipes. Une équipe d'une personne les remplace.
- **Garder l'administrateur limité à un domaine.** Il n'est pas réalisable sans filtrer par domaine chaque route `adminOnly` (sécurité, jetons, comptes…) et sans l'empêcher de modifier ses propres droits. Les niveaux de l'ADR 0022 couvrent le besoin légitime (déléguer plus que l'écriture sur un périmètre).
- **Le DPO comme désignation sur le compte.** Évite d'avoir une équipe particulière, mais crée un deuxième mécanisme à côté des équipes et n'offre aucune liste unique des DPO. L'équipe intégrée donne le même contrôle (composition au superadmin, personnes nommées, cumul avec n'importe quel rôle) avec le mécanisme qui existe déjà.
- **Créer des équipes de base d'office.** Une équipe qui accorde des droits existerait sans décision de l'exploitant ; un modèle à la création donne le même gain sans cet effet. Seule l'équipe DPO, qui ne donne aucun accès aux ressources, est intégrée.

## Conséquences

- **Positif.** Un seul endroit pour accorder, un seul calcul, un seul écran de lecture de l'accès effectif ; un administrateur est toujours « toute la plateforme », un utilisateur toujours « ses équipes » ; le DPO est un groupe nommé, listable, au mécanisme unique ; moins de tables, de points d'accès et de textes d'aide ; CLI et MCP peuvent enfin gérer les droits ; la roadmap cesse de promettre une isolation qui n'existe pas.
- **Négatif.** Une exception individuelle passe par une équipe d'une personne. Un administrateur ne peut plus être limité : qui l'est aujourd'hui doit devenir `user`, et perd alors les routes d'administration. Les 9 points d'accès `/workspaces` (publiés dans `api_specs.md`) et la ligne de la roadmap Terraform (`goproxify_workspace` → `goproxify_team`) changent. Le schéma de `users.yaml` perd deux champs.
- **Neutre.** Passerelles, Agents, jetons API et portail Access ne changent pas.

## Questions ouvertes

- **Le DPO lit-il tous les logs ?** Retenu par défaut : non. L'appartenance à l'équipe DPO n'ouvre que les quatre capacités RGPD (révéler, exporter, effacer, gel légal : ADR 0022, D1). Un DPO qui doit lire tous les logs reçoit en plus un accès (ADR 0022) ou est administrateur.

## Ordre de mise en œuvre

1. **Admin : suppression des espaces de travail** (API, tables, sauvegarde, interface, documentation, roadmap) ; `me.go` appelle `rbac.UserEffectiveGrants`.
2. **Admin : rôles et droits** : l'administrateur voit toujours tout, le rôle `dpo`, `user_permissions` et `user_scopes` disparaissent, l'équipe DPO intégrée, `GET /users/{id}/access`.
3. **Le contenu des accès d'équipe, le catalogue et l'application aux logs, certificats, alertes et portail : ADR 0022** (livraisons propres). La fenêtre d'équipe, la CLI et le MCP des droits sont construits **une fois**, avec la forme des accès de l'ADR 0022, pas avant.
4. **Interface, CLI, MCP et documentation** de l'ensemble (page Accès, fiche de compte, équipe DPO en tête, modèles) une fois l'ADR 0022 livré.

Les livraisons 1 et 2 sont testables seules et ne touchent pas à la forme des accès.
