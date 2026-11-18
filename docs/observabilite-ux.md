# Menu Observabilité — refonte ergonomique : inventaire de parité et architecture

Ce document accompagne la refonte des interactions du menu **Observabilité** (Admin `0.277.0`). Il fait foi pour la règle de parité : **aucune fonction du menu n'a été retirée**. Il liste ce que fait chaque page, la mécanique d'interaction retenue, comment la fonction reste accessible, et où en est la refonte.

Périmètre : les huit entrées de l'Admin (Synthèse, Logs d'accès, Logs système, Prism, Vue Proxy, Métriques, Alertes et SLO, Journal d'audit) et leurs variantes de passerelle (`edge-obs-synthese`, `edge-logs-access`, `edge-logs-system`, `edge-prism`, `edge-proxy-inspector`, `edge-metrics`, `edge-obs-alerts` ; pas de journal d'audit côté passerelle). Les règles d'alerte et les canaux (menu Alertes) et l'exporteur SIEM (réglages des logs) n'en font pas partie, sauf leur point d'entrée.

Méthode : l'inventaire vient de la lecture de `obs-synthese.js`, `logs.js`, `prism.js`, `proxy-inspector.js`, `obs-metrics.js`, la page `edge-metrics` d'`edge.js`, `obs-alerts.js`, `audit.js` et `obs-widgets.js` (fonctions, gestionnaires `window.*`, attributs `data-*`, appels API). La colonne **Statut** distingue ce qui est refait de ce qui est conservé tel quel.

## Principes d'interaction

| Principe | Application |
| --- | --- |
| Une période se tape | Partout où une période se choisit, les puces gardent leur place et un champ **autre…** accepte `90min`, `3h`, `2j`, `2sem` (la même écriture que les durées de ban). Sur Alertes, la valeur est arrondie au jour (1 à 30). |
| Un graphique se trace | Glisser sur un histogramme (Logs, Audit) ou sur la courbe de requêtes (Prism) choisit une plage ; un simple clic garde son effet d'avant (zoomer sur la tranche). Depuis la Synthèse, la plage ouvre Prism dessus. |
| Une IP est un objet | Partout où une IP s'affiche (logs, Prism, Vue Proxy, flux en direct, Audit), elle se glisse vers la barre de dépôt de Sécurité (bannir 1 h / 24 h / à vie, toujours autoriser, tracer) et ouvre le menu de Sécurité au clic droit (ou au clic quand l'IP n'a pas d'autre effet). Son clic garde son effet d'avant : filtrer. |
| Pas de confirmation, une annulation | Bannir une IP depuis Prism ou depuis le tiroir d'un log ne demande plus confirmation : l'action s'applique et un toast propose **Annuler** (9 s, aussi `Ctrl+Z`). Même chose pour l'objectif SLO. |
| Saisir plutôt que remplir | La recherche des logs accepte des jetons : `status:5xx ip:203.0.113.7 domain:example.com since:6h` ; chaque jeton complet (espace ou Entrée) devient un filtre visible, avec des propositions à la frappe. |
| Éditer là où on lit | L'objectif SLO se choisit sur ses puces ou se tape (`99.95`) à la place d'un sélecteur ; le nom d'une vue de la Vue Proxy se saisit sur place (plus de fenêtre `prompt()`). |
| Divulgation progressive | Les dates exactes de Prism passent derrière **Plage précise** ; les réglages des logs et l'exporteur SIEM restent à l'engrenage, dans la palette et dans la modale. |
| Un point d'entrée unique | La palette `Ctrl+K` / `/` reçoit des **actions contextuelles** : période, direct, export, actualiser, filtres de la page, jetons de requête, nom d'hôte, adresse IP. |

## 1. Inventaire de parité

Statuts : **Refait** = nouvelle mécanique livrée et testée ; **Conservé** = fonction intacte ; **Étendu** = fonction intacte, avec une mécanique en plus.

### Transverse (toutes les pages Observabilité)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Huit entrées de menu (sept côté passerelle) | Une entrée de la barre latérale, quatre onglets (**Synthèse**, **Trafic**, **Journaux**, **Santé**) et une sous-navigation dans chaque espace. Toutes les adresses (`#logs`, `#prism`, `#obs-alerts`…) restent valables | Barre latérale, onglets, sous-navigation, `Ctrl+K` | Refait |
| Journal d'audit réservé aux administrateurs | Même garde : la puce n'apparaît pas aux autres rôles | Sous-navigation Journaux | Conservé |
| Rail d'espaces Admin / passerelle, bandeaux de portée | Inchangé | Rail latéral | Conservé |
| Compteur d'alertes non acquittées (24 h) | Pastille sur l'onglet Santé et sur la puce Alertes et SLO | Automatique | Nouveau |
| Palette de pages `Ctrl+K` | Inchangée ; reçoit les actions contextuelles | `Ctrl+K`, `/` | Étendu |
| Annuler la dernière action | Toast + `Ctrl+Z` (celui de Sécurité) | Toast, `Ctrl+Z` | Nouveau |
| Menu d'une IP, barre de dépôt | Ceux de Sécurité, avec une action de plus : **Logs de cette IP** | Clic droit, glisser | Nouveau |

### Synthèse (`obs-synthese`, `edge-obs-synthese`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Filtre de passerelle (Admin) | Puces (jusqu'à 8 passerelles, au-delà le sélecteur d'avant) | Barre du haut | Refait |
| Périodes 15 min, 1 h, 6 h, 24 h, 7 j | Mêmes puces + champ libre (`3h`, `2sem`) | Barre du haut ; palette | Étendu |
| Actualiser, Ouvrir Prism | Inchangés | Boutons ; palette | Conservé |
| Anomalies détectées (3 premières) et leur action (zoomer, filtrer, bannir, détail) | Inchangé | Carte | Conservé |
| Carte SLO : disponibilité, état, budget d'erreur, consommation 1 h / 6 h | Inchangé | Carte | Conservé |
| Objectif SLO (99, 99,5, 99,9, 99,95, 99,99) | Puces + valeur libre entre 90 et 99,999 % ; s'applique et s'annule ; l'objectif propre à une passerelle revient au global d'un clic, annulable | Puces, « … » | Refait |
| Six indicateurs (requêtes, bande passante, taux d'erreur, IP uniques, latence, part de bots), écarts, courbes | Les cartes ouvrent leur détail : Prism, les logs en 5xx sur la période, les métriques | Clic ou Entrée sur la carte | Étendu |
| Courbe de requêtes et d'erreurs, repères de déploiement | Clic sur un point : Prism sur la tranche (comme avant) ; **glisser** : Prism sur la plage | Courbe | Étendu |
| Codes HTTP, liens vers les logs par classe et par code | Inchangé | Anneau | Conservé |
| Flotte : statut, requêtes, erreurs, latence par passerelle (12 premières) | Inchangé | Tableau (clic = sélectionne la passerelle) | Conservé |
| Backends à surveiller, pays principaux, certificats à moins de 30 jours | Inchangé | Cartes | Conservé |

### Journaux : logs d'accès et logs système (`logs`, `logs-system`, `edge-logs-access`, `edge-logs-system`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Bandeau de portée, note « passerelles injoignables / recherche partielle » | Inchangés | — | Conservé |
| Export JSON / CSV, bascule direct, réglages (administrateurs) | Inchangés dans la barre du haut ; aussi dans la palette | Icônes ; palette | Étendu |
| Puces de passerelle colorées (Admin) | Inchangé | Barre de filtres | Conservé |
| Périodes de 15 min à 10 ans selon la rétention, « Tout » | Mêmes puces + champ libre ; une période tapée dans la recherche (`since:6h`) la règle aussi | Barre ; palette ; jeton | Étendu |
| Recherche libre | Jetons `status:` (`code:`), `ip:`, `domain:` (`host:`), `path:`, `method:`, `level:`, `node:` (`edge:`), `component:`, `ja3:`, `ja4:`, `since:` ; propositions de clés et de valeurs (codes, niveaux, méthodes, passerelles, proxies) ; Entrée applique le dernier jeton | Champ de recherche ; palette | Refait |
| Puces de classe de statut (2xx à 5xx) ou de niveau (warn, error) | Inchangé | Barre de filtres | Conservé |
| Masquer le trafic interne | Inchangé | Interrupteur | Conservé |
| Histogramme des accès (avertissements, erreurs) | Clic : zoom sur la tranche ; **glisser** : plage | Histogramme | Étendu |
| Puces des filtres actifs (retirer, tout effacer) | Inchangé ; « Effacer les filtres » aussi dans la palette | Puces ; palette | Conservé |
| Filtrer par clic sur une cellule (domaine, chemin, IP, méthode, code, JA4, composant), `Maj` pour ajouter, re-clic pour retirer | Inchangé ; l'IP se glisse en plus | Cellules | Étendu |
| Tableau (9 colonnes en accès, 6 en système), liste mobile, pagination par curseur | Inchangés | Tableau | Conservé |
| Tiroir d'un accès : badges WAF et Ephor, verdict d'analyse de l'IP, champs détaillés, IP tronquée ou pseudonymisée | Inchangé | Clic sur une ligne | Conservé |
| Bannir l'IP depuis le tiroir | Sans confirmation, **Annuler** ; ban à vie comme avant | Bouton du tiroir ; glisser ; menu d'IP ; palette | Refait |
| Révéler une IP pseudonymisée (motif obligatoire, audité) | Inchangé : la confirmation reste, l'action est auditée et ne s'annule pas | Tiroir | Conservé |
| Ouvrir Prism, copier la commande curl, tracer l'IP | Inchangés ; « Logs de cette IP » dans le menu | Tiroir ; menu | Étendu |
| Tiroir d'un log système : message, filtre de composant, copier le message, copier le JSON | Inchangé | Clic sur une ligne | Conservé |
| Direct (flux SSE) : filtres (texte, niveau, composant, passerelle, domaine), pause, vider, état de connexion | Inchangé ; les IP du flux se glissent aussi ; aussi dans la palette | Bouton ⚡ ; palette | Étendu |
| Réglages : conservation (volume de l'Admin, passerelles, par passerelle), source de lecture, protection des IP, lignes d'accès | Inchangés (modale) | Engrenage ; palette | Conservé |
| Exporteur SIEM : destinations (HTTP, OTLP, syslog), état par passerelle | Inchangé (modale) | Réglages ; palette | Conservé |
| Liens entrants (`openLogs`, `openLogsFiltered`, lien d'une page d'erreur de passerelle) | Inchangés | Autres pages | Conservé |

### Journaux : journal d'audit (`audit`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Export JSON / CSV (filtres appliqués) | Inchangé ; aussi dans la palette | Barre du haut ; palette | Étendu |
| Périodes 1 h, 24 h, 7 j, 30 j, « Tout » | Mêmes puces + champ libre | Barre ; palette | Étendu |
| Puces de gravité | Inchangé | Puces | Conservé |
| Histogramme des actions | Clic : zoom ; **glisser** : plage | Histogramme | Étendu |
| Filtres composant, action, acteur, gravité (champs) | Inchangés ; chaque **valeur du tableau** filtre d'un clic (re-clic retire) | Champs ; cellules | Étendu |
| Tableau, pagination, total | Inchangés ; l'IP ouvre le menu d'IP | Tableau | Étendu |
| Tiroir : détail JSON, filtrer par acteur ou action, logs de l'IP, copier | Inchangé | Clic sur une ligne | Conservé |

### Trafic : Prism (`prism`, `edge-prism`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Filtres passerelle (Admin) et proxy, puces de filtres (retirer, effacer, → Logs) | Inchangés | Barre ; puces | Conservé |
| Périodes rapides selon la rétention | Mêmes puces + champ libre ; la puce active suit la période courante | Barre ; palette | Étendu |
| Dates De / à | Rangées derrière **Plage précise** ; une date choisie s'applique tout de suite | Barre | Refait |
| Actualiser, export CSV / JSON | Inchangés ; aussi dans la palette | Boutons ; palette | Étendu |
| Direct (courbe minute, carte animée, flux des connexions) | Inchangé ; les IP du flux ont leur menu | Bouton ; palette | Étendu |
| Comparer deux périodes | Ouvre déjà sur **la période courante contre la précédente** ; trois préréglages (précédente, 24 h contre 24 h, 7 j contre 7 j) lancent la comparaison | Bouton ; palette | Refait |
| Six indicateurs | Les cartes mènent aux IP, aux sources, ou aux logs en 5xx | Clic ou Entrée | Étendu |
| Carte (zones, villes, régions ; requêtes, taux d'erreur, IP bannies), tiroirs pays et ville | Inchangés | Carte | Conservé |
| Anomalies, pays principaux, codes HTTP | Inchangés | Cartes | Conservé |
| Courbe de requêtes, repères de déploiement | Clic : zoom ; **glisser** : plage | Courbe | Étendu |
| Onglets Chemins (recherche, pagination, filtre, → logs), IP, Sources, Pays, Empreintes TLS, Trafic direct, lien Bans | Inchangés | Onglets | Conservé |
| IP : filtrer, → logs, tracer, ré-analyser, bannir, badges « banni » et « tronquée » | Inchangés ; l'IP se glisse et s'ouvre au clic droit | Onglet IP | Étendu |
| Bannir une IP | Sans confirmation, **Annuler** ; le badge « banni » se met à jour | Bouton ; glisser ; anomalie ; palette | Refait |
| Tiroir d'analyse d'une IP (bans actifs, décisions, chemins visés) | Inchangé | Bouton d'analyse | Conservé |

### Trafic : Vue Proxy (`proxy-inspector`, `edge-proxy-inspector`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Sélection par recherche (nom, backend, conteneurs découverts), `Entrée`, `Maj+Entrée` pour tout ajouter, flèches, `Échap` | Inchangé | Champ de recherche | Conservé |
| Puces de sélection avec point d'état, tout retirer, compteur | Inchangés | Barre | Conservé |
| Périodes (15 min à 90 j) | Mêmes puces + champ libre | Barre ; palette | Étendu |
| Direct, masquer le trafic interne | Inchangés ; direct aussi dans la palette | Bouton ; palette | Étendu |
| Tuiles : statut, backend, débit, p95, erreurs, courbe | Inchangées | Tuiles | Conservé |
| Actions d'une tuile : logs, Prism complet, purger le cache, maintenance / réactiver, bans | Inchangées | Icônes | Conservé |
| Ordre des tuiles | **Glisser** une tuile sur une autre | Tuiles | Nouveau |
| Vues enregistrées (ensembles de proxies) | Un clic recharge ; le nom se saisit sur place ; propres au navigateur | Rangée « Vues » | Nouveau |
| Indicateurs, carte, anomalies, pays, courbe, codes, chemins | Inchangés | Page | Conservé |
| IP des meilleures IP et du flux | Cliquer ouvre le menu d'IP ; glisser bannit ou trace | Page | Étendu |
| Arrivée depuis Métriques | Une ligne de proxy ouvre la Vue Proxy dessus | Métriques ; palette (`example.com`) | Nouveau |

### Santé : Métriques (`obs-metrics`, `edge-metrics`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Actualiser, bandeau « Prometheus », six tuiles de la flotte | Inchangés | Page ; palette | Conservé |
| Passerelles : statut, débit, erreurs 5xx, p95 ; clic ouvre ses métriques | Inchangé | Tableau | Conservé |
| Proxies : filtre texte, tri (p95, 5xx, débit), courbe, 25 premiers | Inchangés ; une ligne ouvre la **Vue Proxy** | Tableau | Étendu |
| Certificats à renouveler, compteurs de sécurité (pipeline, seuils multi-passerelles, CrowdSec, WAF) | Inchangés | Cartes | Conservé |
| Passerelle : latence p95 (p50, p99), TTFB, taux d'erreur, requêtes actives, routes, backends, certificats TLS, pipeline | Inchangés | Page passerelle | Conservé |

### Santé : Alertes et SLO (`obs-alerts`, `edge-obs-alerts`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Filtre de passerelle | Puces (jusqu'à 8), sinon le sélecteur d'avant | Barre | Refait |
| Période 24 h, 7 j, 30 j | Mêmes puces + champ libre (arrondi au jour, 1 à 30) | Barre ; palette | Étendu |
| Bandeau « aucune règle ne couvre le SLO », création d'une règle, lien vers les canaux | Inchangé | Bandeau | Conservé |
| Carte SLO et objectif | Comme la Synthèse : puces, valeur libre, annulable | Carte | Refait |
| SLO par passerelle (disponibilité, budget, consommation, état) | Inchangé ; clic = sélectionne la passerelle | Tableau | Conservé |
| Alertes récentes, puces de déclencheur avec compteurs, histogramme | Inchangés | Page | Conservé |
| Liste des alertes | Lignes à glisser : **droite = acquitter**, **gauche = détail** ; le bouton ✓ apparaît au survol | Lignes | Refait |
| Tiroir d'une alerte : acquitter, mise en sourdine, corps, détail JSON, canaux, priorité | Inchangé | Clic sur une ligne | Conservé |
| Règles (lecture), lien « Gérer » | Inchangés | Carte | Conservé |

### Code présent mais non branché

| Élément | État |
| --- | --- |
| `pages/obs-explore.js` (Explorer : logs d'accès et système réunis, facettes, vues enregistrées) | Non chargé par `index.html`, aucune entrée de menu ni adresse : inatteignable avant la refonte, **laissé tel quel** |

## 2. Architecture visuelle et composants

```
┌────────────────────────────── Observabilité (une entrée de la barre latérale) ───────────────────────────────┐
│  [ Synthèse ]  [ Trafic ]  [ Journaux ]  [ Santé ●n ]                                  ← onglets de page       │
│  ( Prism · Vue Proxy )  ou  ( Accès · Système · Audit )  ou  ( Métriques · Alertes et SLO ●n )  ← sous-nav    │
│  période : [15m 1h 6h 24h 7j] [ autre… ]   passerelle : (Toutes)(Paris)(Lyon)    ← puces + saisie libre         │
│  zone de travail : cartes, graphiques (glisser = plage), tableaux, tiroirs                                     │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 ░ Barre de dépôt (au glisser d'une IP) : 1 h · 24 h · à vie · autoriser · tracer     ← celle de Sécurité
 ░ Toasts « Annuler »  ·  Menu d'IP (clic droit)  ·  Propositions de jetons  ·  Palette Ctrl+K
```

Le noyau est un seul fichier, `internal/admin/ui/src/js/shared/obs-ux.js`, qui expose `ObsUX`. Les pages l'appellent ; il ne connaît aucune page, sauf par les crochets qu'elles lui donnent (`ObsUX.setPage`). Il réutilise `SecUX` pour les bans, l'annulation, le menu d'IP, la barre de dépôt et l'édition sur place.

| Composant (dans `ObsUX`) | Rôle | Utilisé par |
| --- | --- | --- |
| `subNav` | Sous-navigation d'un espace, déduite de la page courante, avec compteur | Prism, Vue Proxy, logs, audit, métriques, alertes |
| `loadBadges` | Alertes des dernières 24 h non acquittées (`/alert-events`), pastille de l'onglet Santé | Routeur |
| `parseSpan`, `spanLabel`, `rangeHTML` | Période tapée (`90min`, `3h`, `2j`, `2sem`) et puces de période | Toutes les pages à période |
| Plage tracée (écouteurs de pointeur) | Glisser sur `svg.gpx-hist-svg` ou sur la courbe de requêtes appelle `brush({from,to})` ; le clic qui suit est avalé | Logs, audit, Prism, Synthèse |
| `ipBtn` | IP déplaçable (`data-secip`, `draggable`) ; menu au clic droit ou au clic | Logs, Prism, Vue Proxy, audit |
| `parseQuery`, `attachSuggest` | Jetons de requête et propositions à la frappe | Recherche des logs, palette |
| `sloSet`, `sloReset` | Objectif SLO : enregistre, propose d'annuler (retour à l'objectif global si la passerelle n'en avait pas) | Synthèse, Alertes |
| `openProxyView` | Ouvre la Vue Proxy sur un hôte | Métriques, palette |
| `paletteProvider` | Actions de page, jetons, nom d'hôte, période tapée | `Ctrl+K` |

Crochets qu'une page donne au noyau (`ObsUX.setPage({ … })`, remis à zéro à chaque navigation) : `reload` (se redessiner après une action), `range(ms)`, `brush({from,to})`, `live()` et `liveOn()`, `export(fmt)`, `refresh()`, `actions()`.

Intégration dans l'existant :

| Fichier | Changement |
| --- | --- |
| `shared/obs-ux.js` (nouveau), `css/obs-ux.css` (nouveau) | Le noyau et ses styles `.oux-*` ; chargés après `obs-widgets.js` dans `index.html` |
| `app.config.js` | Une entrée de menu `admin-observability` / `edge-observability` sans sous-entrées ; deux groupes d'onglets (`pageTabs`) |
| `core/router.js` | Remise à zéro des crochets et chargement du compteur à chaque navigation |
| `shared/sec-ux.js` | Le garde `inScope()` ouvre aux pages Observabilité le glisser-déposer, `Ctrl+Z` et les actions d'IP de la palette ; action « Logs de cette IP » ; `refresh()` rappelle la page |
| `shared/obs-widgets.js`, `shared/hist.js` | Carte SLO à puces ; indicateurs cliquables (option `links`) ; classe et unité des graphiques pour la plage tracée |
| `pages/logs.js`, `prism.js`, `proxy-inspector.js`, `obs-synthese.js`, `obs-alerts.js`, `obs-metrics.js`, `audit.js`, `edge.js` | Sous-navigation, période, crochets, jetons, IP, lignes à glisser, vues, préréglages |
| `shared/i18n.js` | 44 clés en anglais, français, espagnol et allemand (`obs.ux.*`, `sec.tab.o_*`) |

Aucune route, aucun outil MCP ni aucune commande CLI n'est ajouté : la refonte n'utilise que l'API existante (`POST/DELETE /security/bans`, `PUT/DELETE /prism/slo/config`, `POST /alert-events/{id}/ack`, `GET /alert-events`). Le catalogue de droits (`internal/admin/rbac/catalog.go`, `rights.go`) est inchangé : chaque action garde la permission de sa route.

Limites connues :

- Acquitter une alerte **ne s'annule pas** : l'API n'a pas de levée d'acquittement.
- Annuler un ban depuis Prism ou les logs **le supprime** : l'historique des bans garde la trace du ban puis du déban (voir [Sécurité](securite-ux.md)).
- Le glisser-déposer n'existe pas au toucher : le menu d'IP (clic droit, appui long sur Android), la palette et les puces couvrent les mêmes actions.
- Les vues de la Vue Proxy et les périodes tapées restent dans le navigateur ; elles ne suivent pas d'un poste à l'autre.

## 3. Ce qui reste

| Élément | Mécanique envisagée | Pourquoi pas encore |
| --- | --- | --- |
| Réglages des logs (conservation, protection des IP, source de lecture) | Valeurs en chips éditables sur place, protection des IP en commutateur à trois positions, annulables | Un seul `PUT /logs/settings` porte tout, et réduire la conservation du volume supprime des données : cette confirmation doit rester |
| Exporteur SIEM | Cartes de destination dépliables, test d'envoi | Formulaire long (en-têtes, certificat), peu fréquent |
| Direct des logs : ouvrir le tiroir d'une ligne | Clic sur une ligne du flux | Les lignes du flux n'ont pas d'index dans le tableau des entrées |
| Plage tracée sur la Vue Proxy et sur Alertes | Glisser sur la courbe | Ces pages travaillent sur une durée glissante (Vue Proxy) ou en jours (Alertes) |
| Acquitter en lot | Sélection de plusieurs alertes | Pas de route de lot ; une boucle d'appels sans annulation possible |
| Explorer (`obs-explore.js`) | Le brancher comme sous-page de Journaux | Décision de produit : il double les logs sans les remplacer |
| Appui long sur iOS | Menu d'IP | Safari n'émet pas l'évènement `contextmenu` ; l'IP d'une page sans clic propre ouvre déjà son menu |

## 4. Comment la refonte a été vérifiée

L'interface a été exécutée dans le navigateur contre un faux serveur (données générées, sans passerelle) : sous-navigation et compteur, période tapée sur les sept pages, jetons et propositions des logs, glisser d'une IP vers « Bannir 24 h » puis **Annuler**, menu au clic droit, plage tracée sur l'histogramme des logs, sur celui de l'audit et sur la courbe de Prism, clic simple conservé, objectif SLO (puce, valeur libre refusée à 50 %, annulation), acquittement par glissement et détail par glissement inverse, vues et ordre des tuiles de la Vue Proxy, ligne de Métriques vers la Vue Proxy, palette (période, nom d'hôte, jetons, adresse IP), variantes de passerelle. Non vérifié : le comportement avec de vraies passerelles, le tactile, les graphiques avec des dizaines de milliers de points.
