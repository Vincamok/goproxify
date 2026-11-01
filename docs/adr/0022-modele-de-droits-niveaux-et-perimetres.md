# ADR 0022 — Modèle de droits : un niveau par service, appliqué à un périmètre, dans un catalogue que chaque fonctionnalité alimente

**Statut :** accepté le 2026-11-01 (catalogue et seize décisions validés un par un avec le propriétaire) ; rien n'est mis en œuvre · **Date :** 2026-11-01
**Complète :** [ADR 0021](0021-droits-et-acces-equipes-seules-porteuses.md) (l'équipe porte les droits ; ici, ce qu'un accès d'équipe contient) · **Catalogue :** [annexe](0022-annexe-catalogue-des-droits.md) (services, niveaux, permissions, profils, décisions) · **Remplace :** les accès « type / valeur / lecture ou écriture » (`user_scopes`, `team_scopes`) · **Respecte :** ADR-0006 (les droits des utilisateurs sont un sujet d'Admin seul, la passerelle n'en reçoit rien), ADR-0014 (le groupe de passerelles est l'unité de service)

---

## Contexte

Le propriétaire veut des équipes « de production » et « de test » qui voient ou modifient, par exemple, les logs d'un proxy selon l'environnement, avec un périmètre qui peut porter sur les backends, le proxy, le domaine ou un groupe de passerelles (le groupe LAN, pas celui d'internet), des proxys désignés par leur nom, et tous les services de GoProxify, pas seulement les proxys : le portail Access n'était qu'un exemple. L'examen du code (2026-11-01) montre que le modèle actuel ne le permet pas.

1. **« Écriture » ne dit pas sur quoi.** Un accès est `(type, valeur, lecture|écriture)` et n'a de sens que pour les proxys. Les logs, certificats, alertes, métriques et le portail n'en dépendent pas.
2. **Les lectures sont ouvertes à tout compte par conception.** `AvailableScopesForUser` accorde à tout compte authentifié la lecture des proxys, nœuds, alertes, métriques, sauvegardes, snippets, domaines, certificats, logs et de l'audit (`adminWrites` laisse passer les lectures). Un `user` limité à un domaine lit donc les logs, certificats et alertes de tous les domaines. Seuls les proxys, domaines, conteneurs découverts et la surface applicative sont filtrés (Admin 0.241.1 à 0.241.3).
3. **L'accès « passerelle » ne borne rien.** `Scope.match` répond vrai pour toute route quand le type est `edge`, et `UserScopedEdgeGlobs`, qui devait le restreindre, n'est appelée nulle part. Or ce n'est pas la passerelle qu'il faut désigner mais son **groupe** (ADR 0014 : « il n'y a plus d'edge hors groupe, une passerelle isolée est un groupe d'un membre »). Le lien entre une route et une passerelle existe : l'Admin ne pousse à une passerelle que les routes que couvre le périmètre de son jeton (`FilterRoutesByScopes`, `token_scopes`). Les nœuds portent déjà `region`, `environment` et `tags`.
4. **Aucune façon de dire « production » ou « test » sur un proxy.** Les proxys n'ont aucune étiquette ; les nœuds et les destinations du portail (`tags_json`) en ont. Les critères disponibles sont des globs sur le domaine et sur l'URL d'un backend, jamais sur le nom d'un proxy.
5. **Le portail Access est tout entier réservé aux administrateurs, sans objet de droits**, et il n'est pas le seul : plusieurs services récents (surveillance des domaines, moteurs adaptatifs, surface applicative, canaux de notification, haute disponibilité…) n'ont pas d'objet de droits. Une fonctionnalité ajoutée reçoit son droit après coup, ou jamais.
6. **Le catalogue existe, mais n'est pas relié aux équipes.** Les 26 scopes de jetons API (`proxies:read`, `logs:read`, `portal:write`…) sont déjà un catalogue « service × action », avec la correspondance outil MCP → scope et la liste revue des routes ouvertes à tout compte (`routes_guard_test`).
7. **Les alertes ont déjà un périmètre** (une règle porte des passerelles et un glob de domaine, `alerting.Scope`), et la fenêtre d'un proxy suit sept étapes (Entrée, Sécurité, Routage, Transformation, Backends, Résilience, Observabilité).

## Décision

### 1. Un accès d'équipe est un périmètre et une grille de niveaux par service

Une équipe a des **membres**, des **capacités** (ADR 0021) et des **accès**. Un accès est un **périmètre** (sur quoi) et une **grille** : pour chaque service, un **niveau** (que peut-on y faire), « Aucun » par défaut. Une équipe peut avoir plusieurs accès, dont les droits s'additionnent.

```
Équipe « Exploitation prod »
  Accès 1 — périmètre : étiquette env=prod
      Proxys = Exploitation · Logs d'accès = Lecture · Alertes = Acquittement · Portail = Aucun · …
  Accès 2 — périmètre : groupe « Paris - LAN »
      Infrastructure = Lecture · Portail : demandes = Décision · …
```

- **Les niveaux sont propres à chaque service et cumulatifs.** Il n'y a aucun niveau global : « Lecture seule » ne veut rien dire sans dire de quoi (proxys, logs, portail…). Proxys : Lecture → Exploitation → Gestion ; Alertes : Lecture → Acquittement → Gestion des règles ; Sécurité réseau : Lecture → Analyse → Réponse ; etc. Le catalogue complet est dans l'annexe.
- **Trois classes de permissions.** Courantes (dans un niveau) ; destructives ordinaires (supprimer un proxy, un domaine, une destination : dans le niveau « Gestion » du service) ; **sensibles** (exécute du code ou une commande, expose un secret, une IP réelle ou un contenu de session, coupe des clients légitimes : jamais dans un niveau, case à cocher à part, usage audité).
- **Le portail Access se découpe en huit sous-services**, chacun avec son échelle (demandes d'accès, sessions, enregistrements, catalogue, utilisateurs, politiques, audit, modèles et réglages).
- **Droits par section d'un proxy, en option.** « Exploitation » couvre toutes les sections ; « affiner par section » donne Lecture ou Modification à chacune des sept (l'équipe sécurité règle WAF et filtre IP sans toucher aux backends).
- **Profils :** des préréglages de la grille (Lecture du trafic, Lecture de la sécurité, Lecture du portail, Exploitation, Propriétaire de domaine, SOC, PKI, Infrastructure, Astreinte, Auditeur, Portail : support, Portail : gestion, Approbateur d'automatisation, DPO, Équipe vide). Production et test ne sont pas des profils mais des périmètres.

### 2. Un périmètre est un ensemble de critères, tous requis

Un critère est de l'un de ces types ; un périmètre vide veut dire « tout ». Les critères d'un accès se combinent par **ET**, les accès d'une équipe par **OU**.

| Critère | Valeur | Ce qu'il retient |
|---|---|---|
| **domaine** | glob (`*.corp.io`) | les routes dont l'hôte ou un alias le couvre ; les logs, certificats et règles de ces domaines |
| **proxy** | identifiant, ou **nom** en glob (`alpha-*`) ou en **expression régulière** (`re:^alpha-\d+$`) | les proxys désignés |
| **backend** | glob sur l'URL | les routes qui ont un backend correspondant |
| **groupe de passerelles** | nom (glob), ou attributs du groupe : `environment`, `region`, `tags` | les routes que ce groupe sert, les logs qu'il produit, les objets du portail et les réglages qui lui sont rattachés ; **vaut pour tous ses membres, présents et futurs** |
| **étiquette** | `clé=valeur` | les proxys et destinations du portail qui la portent |

- **Le droit se donne sur le groupe, pas sur la passerelle.** Un groupe LAN de deux passerelles reçoit un droit pour les deux ; le groupe exposé sur internet n'est pas concerné. La passerelle (le membre) reste l'objet des actions du service Infrastructure (mise à jour, jeton, suppression), limitées aux groupes du périmètre. Les attributs `environment`, `region` et `tags` se posent **sur le groupe**.
- **Un périmètre sans critère de groupe est une vue globale de l'Admin** ; les services qui n'existent qu'au niveau d'un groupe (portail, tunnel L4, réglages de la passerelle) se donnent par groupe.
- Les expressions régulières sont celles de Go (RE2, temps linéaire : pas de risque de blocage), validées à l'enregistrement. L'interface propose le glob par défaut et l'expression régulière en option.
- **Prévisualisation :** la fenêtre d'un accès affiche « ce périmètre couvre N proxys » et les liste, avant l'enregistrement.

### 3. Des étiquettes sur les proxys

Un proxy porte des **étiquettes** (`env=prod`, `projet=alpha`…), dans sa configuration. Elles servent à l'Admin seul pour juger les droits ; la passerelle les ignore (à vérifier : la lecture de la configuration d'une route doit tolérer ce champ). Toute équipe qui peut modifier un proxy peut poser ses étiquettes, sous la règle « dans le périmètre avant et après la modification » ; chaque changement est audité.

### 4. Un catalogue que chaque fonctionnalité alimente

Les **permissions** sont celles des jetons API (`service:action`), étendues là où une action doit se distinguer. Chacune déclare l'une de deux natures : **sur une ressource** (le périmètre s'applique ; un *descripteur de ressource* dit comment : hôte et alias, backends, groupe, nom, étiquettes) ou **de plateforme** (aucun périmètre : réservée à l'administrateur ou donnée comme capacité). Les objets partagés (snippets, profils IP, fournisseurs d'authentification, détecteurs, pages d'erreur, plugins) sont en lecture pour les équipes qui les utilisent et en écriture pour la plateforme seule. Le journal d'audit est de plateforme. L'administrateur détient toutes les permissions sur toutes les ressources. Les capacités RGPD sont au nombre de quatre (`gdpr:reveal`, `gdpr:export`, `gdpr:erase`, `gdpr:hold`) et forment l'équipe intégrée « DPO » (ADR 0021).

### 5. Une seule application du droit

`rbac.Can(ctx, permission, ressource)` répond pour un objet ; `rbac.Scope(ctx, permission)` rend le périmètre à appliquer à une liste. Tous les handlers, outils MCP et commandes passent par ces deux fonctions ; les calculs actuels (`CanReadProxyWithGrants`, `me.go`, le navigateur) disparaissent.

- **La lecture de base ouverte à tout compte disparaît pour un `user`** : sans accès, rien n'est visible, hormis le libre-service (profil, MFA, ses jetons). L'administrateur voit tout.
- **Les listes volumineuses (logs) sont filtrées à la source**, pas ligne à ligne : le périmètre est résolu en ensemble de groupes et d'hôtes (à partir des proxys et domaines connus), puis passé à la requête. Une expression régulière sur le nom se résout sur les proxys, jamais sur les lignes. Les lignes dont l'hôte est inconnu (analyses, hôtes inventés) ne sont visibles que de l'administrateur.
- **Séparation des tâches :** on ne peut pas approuver sa propre demande d'accès au portail ni valider l'exécution d'un flux qu'on a déclenchée.

### 6. Une fonctionnalité sans droit fait échouer la CI

Toute route, tout outil MCP et toute commande CLI **déclarent** leur service, leur permission et, si elle porte sur une ressource, son descripteur. C'est l'extension de ce que `routes_guard_test` et `ToolRequiredScope` font déjà : un test échoue pour une route, un outil ou une commande sans permission déclarée. La règle entre dans la **liste de documentation obligatoire** de `CLAUDE.md` : toute fonctionnalité déclare ses services, niveaux et permissions, son descripteur de ressource et ses étiquettes éventuelles, et met à jour le catalogue.

### 7. Jetons API

Un jeton choisit des permissions du catalogue (les 26 scopes actuels deviennent des groupes de permissions). Son pouvoir réel est l'intersection de ses permissions et de celles du compte, **avec le périmètre du compte** : un jeton d'un utilisateur limité à `env=test` ne lit que les logs de `env=test`. Un jeton n'a pas de périmètre propre.

## Alternatives écartées

- **Des niveaux globaux (Observateur, Opérateur, Gestionnaire).** Écartés par le propriétaire : « Lecture seule » ne dit pas de quoi (proxys, logs, portail). Le niveau est propre à chaque service.
- **Étendre le mode (lecture, écriture, suppression…) sans périmètre combinable.** Ne dit pas « les logs de la production » : il faudrait un mode par service et par environnement.
- **Un objet « environnement » ou « espace » qui regroupe des ressources.** Recrée le troisième objet que l'ADR 0021 supprime. Une étiquette sur la ressource et un critère sur l'accès disent la même chose.
- **Le droit sur la passerelle (le membre).** Les droits suivraient chaque membre à la main ; le groupe donne automatiquement les droits à ses membres futurs.
- **Un langage de politiques (Rego, CEL).** Trop lourd à écrire, à revoir et à expliquer pour des équipes qui doivent comprendre ce qu'elles accordent.
- **Seulement des expressions régulières pour les noms.** Moins lisibles et sources d'erreurs ; le glob couvre la plupart des cas.

## Conséquences

- **Positif.** Les cas demandés (production et test, groupe LAN, domaine complet, ensemble de proxys par nom, portail, sections d'un proxy) se disent avec les mêmes briques ; le droit s'applique aux logs, certificats, alertes et métriques ; le droit « groupe » existe enfin ; une nouvelle fonctionnalité ne peut plus échapper au modèle ; un seul calcul remplace plusieurs.
- **Négatif.** C'est le plus gros chantier des deux ADR : il touche tous les handlers, outils et commandes, et la grille compte une trentaine de services (les profils la rendent praticable). Le filtrage des logs par périmètre demande un index sur l'hôte et le groupe (à mesurer sur la base de logs). Les étiquettes sont à poser sur les proxys existants (en lot, par nom ou domaine). Le rattachement de chaque champ de configuration d'un proxy à sa section reste à établir.
- **Neutre.** Les passerelles ne reçoivent toujours aucun droit d'utilisateur ; les jetons de passerelle (`token_scopes`) restent un autre concept.

## Questions ouvertes

- **Où vit l'étiquette d'un proxy** : dans sa configuration (elle suit le proxy, la sauvegarde et les passerelles ; recommandé), à vérifier avec la lecture de la configuration par la passerelle. Les routes découvertes par labels Docker pourraient en porter via un label (`goproxify.tags`).
- **Le DPO lit-il tous les logs ?** Recommandation retenue par défaut : non, l'équipe DPO n'ouvre que les quatre capacités RGPD ; un DPO qui lit tous les logs reçoit en plus un accès.
- **Étiquettes sur les domaines et les certificats**, ou seulement le critère « domaine » (recommandé au départ).
- **Index et coût du filtrage des logs** à grande échelle (ADR 0018).

## Ordre de mise en œuvre

L'ordre de l'[ADR 0021](0021-droits-et-acces-equipes-seules-porteuses.md) (livraisons 1 et 2 : espaces de travail, rôles et DPO) précède ce qui suit.

1. **Catalogue et garde par test** *(livrée, Admin 0.243.1)* : déclarer le service, la permission et le descripteur de chaque route, outil MCP et commande CLI, avec le test qui échoue à l'oubli. Aucun comportement ne change. Le catalogue (`rbac/catalog.go`, 40 services, 108 permissions) précède les niveaux appliqués : une déclaration de route mêlant plusieurs services est marquée `Mixed` et sera découpée par opération à la livraison 2 ; le descripteur de ressource (comment lire hôte, backends, groupe, nom, étiquettes d'un objet) arrive avec elle.
2. **Descripteurs, `rbac.Can` / `rbac.Scope` et critères** *(livrée, Admin 0.244.0 : moteur, critères, étiquettes et attributs de groupe ; le branchement sur les handlers vient avec la livraison 4. Un proxy sans nom se désigne par son hôte)* : domaine, nom (glob et expression régulière), backend, groupe (par nom et attributs, réparé), étiquette ; étiquettes sur les proxys ; attributs `environment`, `region`, `tags` sur les groupes.
3. **Niveaux, grille et accès d'équipe** (stockage, API) à la place des modes lecture/écriture ; capacités. *(livrée, Admin 0.245.0 : table `team_accesses` à la place de `team_scopes`, `rbac.TeamAccess` et `Engine` sur la grille, profils, API `/teams/{id}/accesses` et `/rights/*`, MCP, CLI et fenêtre d'équipe. Les contrôles de proxys, conteneurs, surface et domaines passent déjà par le moteur, puisque leur ancien calcul lisait `team_scopes` ; le « Gestion » des proxys donne la suppression. Les lectures de base d'un `user` disparaissent pour les jetons API ; les routes REST des autres services gardent leur contrôle actuel jusqu'à la livraison 4.)*
4. **Application par service** : proxys (existant, repris sur le nouveau moteur), puis logs, certificats, alertes et métriques, puis le portail sous-service par sous-service, puis les services restants. *(première partie livrée, Admin 0.246.0 : les **lectures** des logs, certificats, alertes et métriques exigent la permission et se filtrent par périmètre (`rbac.Gate`, `Visibility`, `logs.Restriction`) ; le MCP refuse les outils de lecture globale aux accès à périmètre. Deuxième partie, Admin 0.247.0 : écritures des alertes, certificats et domaines dans le périmètre, journal d'audit sous `audit:read`, liste fermée des outils MCP ouverts aux non-administrateurs. Troisième partie, Admin 0.248.0 : portail (huit sous-services), sécurité réseau et automatisation sous leur permission, pour un accès sans critère ; séparation des tâches sur l'approbation d'un flux. Quatrième partie, Admin 0.249.0 : les lectures de topologie exigent un accès d'équipe (le détail par groupe reste à faire), snippets et profils IP sous leur permission de lecture. Cinquième partie, Admin 0.250.0 : la surface applicative se juge par proxy sous les permissions du service `surface`. Sixième partie, Admin 0.251.0 : la topologie est bornée aux groupes de passerelles visibles. Restent : le périmètre par groupe du portail, de la sécurité réseau et de l'automatisation, de l'infrastructure, les moteurs adaptatifs, la surface, l'infrastructure et les lectures de nœuds, les cibles de déploiement, `source=edge` filtré à la source et une mesure des logs sur gros volume.)*
5. **Interface** (fenêtre d'équipe : accès, grille, profils, prévisualisation ; fiche de compte avec accès effectif), **CLI** et **MCP**.
6. **Documentation** : `api_specs.md`, `cli.md`, `mcp.md`, `fonctionnalites.md`, `CLAUDE.md`, roadmap publique, changelog.

Chaque livraison est testable seule ; la première ne change aucun comportement et protège les suivantes.
