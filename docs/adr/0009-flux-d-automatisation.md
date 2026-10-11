# ADR 0009 — Flux d'automatisation unifiés

**Statut :** accepté · **Date :** 2026-10

## Contexte

L'Admin avait trois objets d'automatisation, chacun avec son moteur, son API, ses outils MCP, son CLI et son éditeur :

- **Règle** : une condition, une action, un délai minimum, une approbation facultative.
- **Planification** : une expression cron, une action.
- **Playbook** : une suite d'étapes (action, attente, condition, approbation), sans déclencheur propre (à la main, ou par l'action `run_playbook` d'une règle).

L'« éditeur de flux » n'était qu'une vue figée d'une règle en quatre nœuds. Pour répondre à un incident, il fallait aller dans trois onglets. Les listes de conditions et d'actions étaient écrites à la main dans le JavaScript, la collecte des champs était copiée trois fois, les modèles n'avaient pas de paramètres et la règle installée ne savait pas d'où elle venait.

Il y avait aussi des défauts :
- les règles exécutables par une passerelle tournaient aussi sur l'Admin (l'action avait lieu deux fois) ;
- elles n'étaient renvoyées aux passerelles qu'à la reconnexion ;
- une notification émise par une passerelle n'atteignait aucun canal ;
- l'avancement d'un playbook vivait en mémoire et se perdait au redémarrage de l'Admin.

## Décision

Un seul objet, le **flux** (`internal/admin/automation`) : un déclencheur, un garde-fou, une suite d'étapes.

- **Déclencheurs** :
  - `condition` : arbre `all` / `any` / `not` de conditions, évalué à intervalle ;
  - `event` : événement du moteur d'alertes, reçu par `alerting.Engine.Subscribe` ;
  - `schedule` : cron ;
  - `manual` : paramètres déclarés comme des champs de manifeste.
- **Garde-fou** : délai minimum (par flux, ou par valeur avec `cooldown_key`), exécutions simultanées, placement. Un lancement manuel l'ignore.
- **Étapes** : `action`, `wait`, `if` (branches `then` / `else`), `approval`, `call` (lance un flux manuel, en attendant sa fin ou non), `stop`. Les variables `{{detail.x}}`, `{{steps.<id>.x}}`, `{{flow.*}}` et `{{run.id}}` sont résolues par simple substitution : aucune logique dans les variables, la logique vit dans les étapes.
- **Onglets** : Règles (condition, événement), Planifications (horaire) et Playbooks (manuel) sont des **vues filtrées** des flux. On crée un flux dans l'éditeur ou depuis un modèle.
- **Catalogue** : les briques sont des modules (ADR 0007) ; l'éditeur, les listes et le CLI se construisent à partir de `GET /api/v1/automation/catalog`.

### Exécution

- **Persistance** : une exécution est enregistrée (`flow_runs`) après chaque étape, avec la copie de la définition, le curseur, les variables et l'échéance de reprise. Attentes et approbations reprennent après un redémarrage de l'Admin.
- **Arrêt pendant une étape** : l'exécution passe à `interrupted` et n'est **jamais relancée d'office**, car une action pourrait agir deux fois ; « Rejouer » la relance à la main.
- **Concurrence** : une reprise, une décision et une échéance « réclament » l'exécution par une mise à jour conditionnelle, pour qu'elle n'avance jamais deux fois.
- **Haute disponibilité** : seul le leader d'un Admin HA déclenche et fait avancer les flux.
- **Boucles** : un événement porte la chaîne des flux qui l'ont produit (`flow_chain`). Un flux ne se redéclenche pas sur sa propre notification, et une chaîne s'arrête à cinq.

### Modèles

Un modèle est un squelette de flux où `{{param.x}}` est remplacé à l'installation, avec des paramètres décrits comme des champs de manifeste.

- Le flux installé garde son origine (`template_id`, `template_version`, `params`) et se réédite par ces paramètres, reconstruit avec la version courante du modèle.
- Modifier directement sa définition est refusé (`409`).
- Le **détacher** en fait un flux de l'éditeur.

### Autonomie des passerelles (ADR 0006)

Un flux est exécuté par les passerelles (`placement: edge`) quand toutes ces conditions sont réunies :
- son déclencheur est une condition simple que la passerelle sait évaluer sur ses données ;
- sa seule étape est une action qu'elle sait exécuter ;
- ses variables sont celles que la passerelle résout d'elle-même ;
- il n'a pas de clé de délai.

Dans ce cas :
- l'Admin le traduit dans le format de règle des passerelles, sans nouvelle version de la passerelle ;
- il l'envoie à chaque modification, avec les fenêtres des mises en sourdine qui le visent (renvoyées à chaque création ou suppression d'une mise en sourdine) : la passerelle les applique seule ;
- il **ne l'évalue plus** lui-même ;
- il journalise ce que les passerelles remontent et achemine leurs notifications (`automation_notify`).

Tout le reste — attente, approbation, si/sinon, appels, conditions sur les données de l'Admin — s'exécute sur l'Admin, puisque ces étapes dépendent de lui. Le garde-fou « Toujours sur l'Admin » force l'évaluation sur la vue du cluster.

## Conséquences

- **Remplacements** : `internal/admin/rulesengine`, `scheduler`, `playbooks`, leurs API (`/rules-engine`, `/scheduled-tasks`, `/playbooks`), leurs tables, outils MCP et commandes CLI sont remplacés par `/api/v1/automation`, les outils `*_flow*` et `goproxify automation`. Aucune migration : GoProxify n'était pas déployé.
- **Import / export** : le document passe en `version: 2`.
- **Mises en sourdine** : la table `automation_silences` est conservée et partagée avec le moteur d'alertes.
- **Limites connues** :
  - `metric_threshold` n'est évaluée que sur l'Admin ;
  - une exécution planifiée manquée pendant un arrêt de l'Admin n'est pas rattrapée ;
  - les libellés du catalogue sont en français, comme les autres familles de modules.
