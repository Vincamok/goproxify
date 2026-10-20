# ADR 0012 — Logs : la passerelle possède ses lignes, l'Admin supervise

**Statut :** proposé · **Date :** 2026-10-20
**Remplace :** étapes 2 et 3 de l'ADR 0010, et oriente autrement son étape 1 · **Respecte :** ADR-0006 (autonomie des composants) · **Précise :** ADR-0002 (SQLite hors de l'Admin)

---

## Contexte

L'ADR 0010 traite un symptôme : une table `logs` de plus de 5 millions de lignes dans `admin.db`. Il propose de mieux ranger ces lignes sur l'Admin (cumuls par minute, base séparée, fichiers par période). Il ne remet pas en cause d'où elles viennent, et c'est là que se trouve le défaut de conception.

Trois constats, vérifiés dans le code le 2026-10-20 :

1. **Une coupure de l'Admin perd des logs pour de bon.** La passerelle écrit un fichier JSON local et pousse chaque ligne à l'Admin par `BroadcastToAdmins` (`internal/edge/ws/hub.go`). Sans Admin connecté la boucle d'envoi ne s'exécute pas : le lot disparaît. Il n'y a ni numéro de séquence, ni accusé de réception, ni rejeu à la reconnexion. Les canaux d'envoi (8 192 accès, 2 048 lignes système) jettent aussi leurs entrées quand ils sont pleins. Les logs de conteneurs de l'Agent sont relayés par la passerelle « sans stockage local » (`internal/edge/agenthandlers.go`) : ils se perdent de la même façon. La donnée existe encore dans le fichier de la passerelle, mais l'historique de l'Admin (Prism, SLO, anomalies, recherche) garde un trou que rien ne comble.
2. **L'Admin est devenu un point de passage des données.** L'ADR-0006 dit que l'Admin est « point de modification et de supervision, jamais point de passage du service » et que la passerelle fait tourner ce qui lui est confié. Ici, chaque requête de chaque passerelle est copiée vers un seul SQLite. La passerelle, qui produit la donnée, ne sait ni la chercher ni la résumer : son fichier JSON n'est lisible qu'à la main.
3. **Les volumes viennent de cette copie centrale.** 220 000 lignes d'accès par jour en octobre sur un serveur réel, environ 1 Ko par ligne index compris : près de 20 Go à 90 jours, environ 80 Go à un an, tous nœuds confondus. L'ADR 0010 les range mieux sur l'Admin, mais l'Admin les reçoit toujours toutes.

Deux faits d'environnement :

- Le pilote SQLite est `modernc.org/sqlite` (pur Go) : il ne chiffre pas les fichiers. Le chiffrement sera fait par colonne.
- L'ADR-0002 écrivait que la passerelle est « entièrement volatile (zéro disque) ». Ce n'est plus vrai : la passerelle a déjà une base SQLite des bans (`internal/edge/bansdb`) et plusieurs copies locales chiffrées (ADR-0006). Cette note de l'ADR-0002 est caduque.

---

## Décision

### 1. Répartition des rôles

| Composant | Rôle pour les logs |
|---|---|
| **Passerelle** | Propriétaire des lignes brutes de ses requêtes. Les garde dans une base locale, calcule les cumuls, sait chercher, effacer et exporter sans l'Admin. |
| **Admin** | Supervision : reçoit des cumuls, des compteurs et des événements de sécurité ; interroge les passerelles pour les lignes brutes ; garde son propre audit. Ne stocke plus les accès ordinaires. |
| **Agent** | Garde un curseur sur les logs de ses conteneurs et les redonne à sa passerelle après une coupure. |
| **Groupe HA** | Chaque membre possède ses propres lignes. Une vue de groupe se construit en interrogeant tous les membres. |

Les logs d'accès (`status > 0`) sont le sujet principal. Les logs système de la passerelle suivent les mêmes mécanismes de stockage et de rejeu. L'audit de l'Admin et ses propres logs système restent sur l'Admin, dans leur table : il en est le producteur.

### 2. Base de logs locale sur la passerelle

- **Fichiers** : un SQLite par semaine pour les accès, un par mois pour le système, dans le dossier `logs/` de la passerelle. Seul le fichier courant est ouvert en écriture.
- **Écriture** : par lots (jusqu'à 500 lignes ou 250 ms), branchée sur la goroutine qui écrit déjà chaque requête. Un disque plein ou une base corrompue fait perdre des lignes ; ils ne ralentissent jamais le trafic.
- **Identifiant global** : `(numéro de fichier << 40) | rowid`, croissant. C'est le curseur de tous les consommateurs.
- **Rétention** : **365 jours** pour les accès (durée de conservation des données de connexion confirmée par le propriétaire du produit), par suppression du fichier entier, sans `DELETE` ni `VACUUM`. Dans le fichier à cheval sur la limite, la purge par ligne s'applique. Les durées restent réglables par type et par passerelle. Cette valeur remonte celle de 90 jours posée par Admin 0.163.0.
- **Statistiques** : `ANALYZE` à la fermeture d'un fichier de période.
- **Le fichier JSON actuel est supprimé** : la base le remplace. L'effacement RGPD qui réécrivait ces fichiers (`internal/edge/logger/erase.go`, écritures suspendues pendant la réécriture) devient un `DELETE` par empreinte d'IP. Suivre les logs en direct et alimenter un SIEM passent par le flux de la base (sections 6 et 7), pas par un fichier.

### 3. Protection de l'IP, sur la passerelle

Aujourd'hui, en mode pseudonymisation, la passerelle envoie l'IP réelle à l'Admin, qui la chiffre avec sa clé (`internal/admin/logs/store.go`). La passerelle étant propriétaire, c'est elle qui chiffre :

| Mode | Ce que la passerelle stocke |
|---|---|
| Normal | IP réelle en clair |
| Anonymisation | IP tronquée seulement ; l'IP réelle n'est gardée nulle part |
| Pseudonymisation | IP tronquée visible, plus l'IP réelle chiffrée (AES-GCM) avec la clé locale, et une empreinte HMAC pour la retrouver |

- **Clé** : aléatoire, propre à la passerelle, scellée par le chiffrement local existant (`cache.Store.SaveFile`, dérivé du secret d'appairage). Elle fait partie de la sauvegarde d'état ; le dossier `logs/` en est exclu.
- **L'IP réelle ne quitte plus la passerelle.** L'Admin ne la reçoit plus, ce qui est un gain RGPD net.
- **Révéler une IP** et **chercher par IP** : l'Admin envoie la demande, la passerelle déchiffre ou calcule l'empreinte avec sa propre clé. Il n'y a plus d'index commun entre passerelles, et il n'en faut pas.
- **Groupe HA** : une clé par membre, chaque membre révèle ses lignes. Une clé de groupe partagée élargirait ce qu'une seule compromission expose.
- **Perte de la clé** : les lignes pseudonymisées deviennent illisibles. D'où l'inclusion dans la sauvegarde d'état.
- Les primitives (`Encrypt`, `Decrypt`, `IPIndex`, `CanonicalIP` de `internal/admin/gdpr`) sont extraites dans un paquet neutre utilisé par l'Admin et la passerelle. La clé de l'Admin continue de servir pour ses logs d'audit.

### 4. Cumuls et événements envoyés à l'Admin

- **Cumuls par minute** : nœud × domaine × code de statut, avec requêtes, 5xx, refus, octets, somme des latences et comptes par bucket de latence (mêmes bornes que `internal/edge/metrics`). Aucune IP. Ils sont écrits par la passerelle **dans la même transaction que le lot de lignes** : ils ne peuvent pas diverger des lignes, ce que la tâche de fond actuelle de l'Admin (`internal/admin/logs/agg.go`) ne garantit pas. Ils sont envoyés à l'Admin avec un numéro de séquence et conservés 400 jours.
- **Compteurs d'erreurs 4xx par IP et par minute**, pour le Fail2Ban global de l'Admin (`internal/admin/fail2ban`). Même règle qu'aujourd'hui : rien n'est envoyé pour une IP tronquée. Conservés 24 h sur l'Admin. Chaque passerelle bannit déjà seule (Fail2Ban local plus propagation des bans) : l'Admin n'ajoute que la vue globale.
- **Événements de sécurité en lignes brutes** : refus 403 et 429, détections WAF, signaux Ephor. Petit volume, conservés sur l'Admin (90 jours, réglable) pour la trace d'IP, la simulation Ephor et l'activité WAF, même si une passerelle est éteinte.
- **Ce que l'Admin ne reçoit plus** : les accès ordinaires (200, 304, etc.).
- **Lecteurs de l'Admin** : `monitor` et `automation` (fenêtres de 5 minutes) lisent les cumuls ; `topology_live`, `analytics/*`, Prism et SLO aussi. Les IP uniques et les facettes passent par la recherche déportée ou, pour les IP uniques, par un sketch HyperLogLog dans le cumul (question ouverte).

### 5. Flux avec curseur et rejeu

- L'Admin retient, par passerelle, le dernier numéro reçu pour chaque flux (cumuls, événements de sécurité, système).
- À la connexion WebSocket il demande « depuis N » ; la passerelle rejoue depuis sa base. Déduplication par (passerelle, numéro).
- **Une coupure de l'Admin ne perd plus rien**, y compris si la passerelle redémarre pendant la coupure : la base est locale. C'est le correctif du premier constat, et il est livrable avant tout le reste.
- **Agent** : curseur sur les logs de chaque conteneur (reprise par l'option `since` de Docker), rejeu vers sa passerelle à la reconnexion. Livraison au moins une fois.

### 6. Recherche déportée

La recherche est une **capacité de la passerelle**, pas un composant à part. Elle suit le canal Admin→passerelle qui existe déjà (`edgeproxy.Client` et les routes `/internal/v1/...`).

- **Routes** de la passerelle : recherche, histogramme, facettes, export, révélation d'IP. Lecture seule, une ou deux requêtes à la fois, délai maximal, fenêtre par défaut de 24 h. Au-delà, le résultat est marqué « partiel ».
- **Page « Logs d'accès »** : 50 lignes par page, comme aujourd'hui. Menu d'une passerelle : appel direct. Menu global : l'Admin demande 50 lignes à chaque passerelle, fusionne par date et garde les 50 plus récentes. Le curseur devient un jeton opaque portant la position de chaque passerelle.
- **Histogramme et facettes** : sur les cumuls quand les filtres se limitent à passerelle, domaine et code ; sur les lignes brutes de chaque passerelle sinon.
- **Total** : plafonné (« 10 000+ »).
- **Passerelle injoignable** : ses lignes manquent, et la page l'affiche (« résultats incomplets »). C'est le coût principal de ce choix, accepté.
- **Mode Live** : l'Admin abonne les passerelles seulement quand une vue est ouverte. Aujourd'hui chaque ligne part en permanence, même sans spectateur.
- **Export depuis la page** : limité en nombre de lignes ; au-delà, l'export complet de la section 8.
- **Prism et la recherche** sont deux vues des mêmes données, séparées par leur nature : Prism lit les cumuls (rapide, indépendant des passerelles), la recherche lit les lignes brutes.

### 7. Exporteur SIEM

Consommateur du flux de la passerelle, avec son propre curseur persistant.

- Syslog RFC 5424 sur TCP/TLS, et HTTP en NDJSON (Splunk HEC, Elastic, Loki). OTLP plus tard.
- Livraison au moins une fois ; l'identifiant global sert à dédupliquer.
- Filtrage par type (accès, système) et par niveau.
- Configuration poussée par l'Admin et gardée en copie locale chiffrée.
- SIEM injoignable : le curseur reste en place. La rétention passe quand même, pour ne pas remplir le disque, et une alerte signale un retard sur des données qui vont être purgées.

### 8. Export complet pour les autorités, sans l'Admin

Commande locale de la passerelle (binaire Edge), utilisable Admin éteint.

- **Contenu** : toutes les lignes d'une plage, filtrables par IP et domaine, avec l'IP réelle déchiffrée par la clé locale. NDJSON ou CSV, sans pagination d'interface.
- **Intégrité** : manifeste avec empreintes SHA-256, signé par une clé de la passerelle, horodaté. La valeur de preuve dépend de l'heure de la passerelle (NTP).
- **Accès** : opérateur privilégié, sortie chiffrée par mot de passe, entrée dans l'audit local.
- **Minimisation** : on exporte ce qui est demandé, pas toute la base.
- **Gel légal** : un indicateur par période qui empêche la purge tant que la procédure dure.
- **Groupe HA** : un export par membre, chacun avec son manifeste.

### 9. Effacement RGPD

`TypeEraseIPs` et la file `edge_erasure_queue` de l'Admin (`internal/admin/gdpr/erasure_queue.go`) existent déjà : l'Admin envoie l'ordre, le garde pour une passerelle absente et le rejoue à sa reconnexion. Ils sont conservés. Changements : l'effacement devient un `DELETE` par empreinte d'IP dans la base de la passerelle, et la purge de la file passe de 90 à 365 jours pour suivre la rétention.

---

## Alternatives écartées

- **Garder l'Admin dépositaire et améliorer son stockage** (ADR 0010 tel quel) : ne corrige ni le trou après une coupure, ni l'inversion des rôles. Reste valable pour les tables que l'Admin garde (audit, événements de sécurité).
- **Garder le fichier JSON en plus de la base** : double les écritures. Aucun usage de ce fichier n'est documenté (aucune mention de SIEM, syslog ou `tail` dans `docs/deployment.md`, `docs/fonctionnalites.md` ni la roadmap) ; le flux de la base couvre les deux besoins.
- **Chiffrer le fichier SQLite entier** : `modernc.org/sqlite` ne le permet pas, et SQLCipher imposerait cgo. Le chiffrement par colonne vise ce qui est personnel (l'IP).
- **DuckDB, ClickHouse, PostgreSQL pour les logs** : un service ou une dépendance de plus, déjà écartés par l'ADR 0010. À reconsidérer au-delà de quelques dizaines de millions de lignes par jour et par passerelle.
- **Journal binaire maison** : écrit plus vite mais oblige à écrire un moteur de requêtes.
- **Clé de pseudonymisation partagée dans le groupe HA** : élargit l'effet d'une compromission. Une clé par membre.

---

## Conséquences

**Gains**

- Plus de trou de données sur coupure de l'Admin, redémarrage de la passerelle compris.
- L'Admin ne porte plus le volume des accès : cumuls (quelques milliers de lignes par jour et par passerelle), compteurs, événements de sécurité, audit.
- L'IP réelle ne quitte plus la passerelle.
- Une passerelle peut chercher, effacer et exporter ses logs sans l'Admin (ADR-0006).
- Les écritures de logs de l'Admin deviennent marginales.

**Coûts et risques**

- La recherche brute dépend de passerelles joignables ; la page affiche un résultat incomplet sinon.
- Une couche de lecture multi-passerelles à écrire : fusion, curseur composite, délais, export, MCP, CLI.
- Une base SQLite à entretenir sur chaque passerelle : disque (environ 80 Go par an sur l'ensemble des nœuds au trafic actuel, à mesurer par passerelle), compression éventuelle des fichiers clos.
- Débit d'écriture : mesuré en livraison 1 (`BenchmarkAddAndFlush`, Windows 386, IP chiffrée, 5 index) à environ 26 µs par ligne, soit près de 39 000 lignes par seconde : l'écriture n'est pas le facteur limitant, le volume sur disque l'est. À 1 000 requêtes par seconde, une passerelle écrit environ 86 millions de lignes par jour, soit de l'ordre de 86 Go par jour à 1 Ko par ligne : au-delà de quelques dizaines de millions de lignes par jour, échantillonnage par proxy (les cumuls restent exacts) ou SIEM comme stockage.
- Migration d'une vingtaine de lecteurs de la table `logs` côté Admin (analytics, monitor, automation, fail2ban, sécurité, MCP).
- Conservation légale d'un an face au droit à l'effacement : la rétention reste réglable, c'est à l'exploitant de la fixer selon sa situation.

**Autonomie (ADR-0006)** : la passerelle fonctionne, journalise, cherche, efface et exporte sans l'Admin, même après un redémarrage. Si l'Admin tombe, seuls l'historique centralisé et la recherche transversale s'interrompent, puis se rattrapent à la reconnexion.

**Migration** : aucune instance n'est déployée en production. L'ancienne table `logs` d'accès, `logs_minute` alimentée depuis les lignes et l'envoi brut sont remplacés sans reprise ni façade de compatibilité.

---

## Ordre de mise en œuvre

Chaque livraison tient seule.

1. Base de logs locale de la passerelle et clé de l'IP (remplace le fichier JSON). L'envoi à l'Admin reste inchangé. *Livrée en Edge 0.74.0* : `internal/edge/logstore`, dossier `engine.log_store_dir`, rétention `engine.log_retention_days` (365) et `engine.system_log_retention_days` (90), clé dans `log-ip-key.gpx` (variable `GPX_LOG_IP_KEY_PATH`), primitives partagées dans `internal/ipcrypt`. Jusqu'à la livraison 3, l'Admin reçoit encore l'IP réelle et la chiffre aussi.
2. Numéro de séquence et rejeu, pour la passerelle et pour l'Agent : le trou disparaît. *Livrée en Edge 0.75.0 / Admin 0.165.0 pour la passerelle* : messages `log_resume` (Admin → passerelle) et `log_stream` (passerelle → Admin), position écrite avec les lignes dans `edge_log_cursors`, flux `access` et `system`. *Agent livré en Agent 0.12.0 / Edge 0.76.0* : l'Agent reprend sa lecture Docker (`since`) depuis une position qu'il n'avance qu'après l'accusé de réception de la passerelle (`log-cursors.json`), et la passerelle garde les logs de conteneurs dans sa base (flux `system`, composant `agent`) avant d'acquitter.
3. Cumuls, compteurs par IP et événements de sécurité calculés à la passerelle ; migration des lecteurs de l'Admin ; l'Admin cesse de recevoir les accès ordinaires. **Découpée**, parce que l'Admin ne peut cesser de recevoir les lignes brutes qu'une fois la recherche déportée en place (sinon la page « Logs d'accès », la trace d'IP et la simulation Ephor se vident) :
   - **3a. Cumuls par minute calculés à la passerelle.** *Livrée en Edge 0.77.0 / Admin 0.166.0* : table `minute` dans chaque fichier d'accès, écrite dans la même transaction que les lignes ; flux `minute` (`agg_stream`) vers l'Admin, qui remplace la valeur de la minute dans `logs_minute` et enregistre la position dans la même transaction ; l'agrégation des lignes brutes de l'Admin ignore une passerelle qui envoie ses cumuls. L'Admin reçoit encore les lignes brutes.
   - **3b. Compteurs d'erreurs 4xx par IP** pour le Fail2Ban global de l'Admin. *Livrée en Edge 0.78.0 / Admin 0.167.0* : table `ip_errors` (minute × IP, 48 h) dans les fichiers d'accès, flux `iperr` (`ip_stream`) avec le même contrat que les cumuls, table `edge_ip_errors` côté Admin (24 h), jamais pour une IP tronquée ; le Fail2Ban de l'Admin additionne les compteurs de toutes les passerelles qui en envoient et lit encore les lignes brutes des autres. La minute qui contient le début de la fenêtre n'est pas comptée (moins de bans, jamais plus).
   - **3c. Arrêt de l'envoi des accès ordinaires** et copie brute des seuls événements de sécurité sur l'Admin : après la livraison 4, avec la migration des lecteurs restants de la table `logs` (voir livraison 8).
4. Recherche déportée, page « Logs d'accès », CLI et MCP. **Découpée** : *4a livrée en Edge 0.79.0 / Admin 0.168.0* — routes `/internal/v1/logs/{search,histogram,facets,reveal}` sur la passerelle, `source=edge` sur les routes de logs de l'Admin (fusion, curseur par passerelle, passerelles injoignables, révélation d'IP chez la passerelle), parité vérifiée avec la copie de l'Admin. *4b reste* : l'interface (bandeau « résultats incomplets », fusion avec les logs propres de l'Admin, Live à la demande), la CLI et le MCP.
5. Effacement RGPD sur la nouvelle base, purge de la file à 365 jours.
6. Exporteur SIEM.
7. Export complet signé et gel légal.
8. Nettoyage de l'Admin : arrêt des accès ordinaires bruts (3c), migration des lecteurs restants, retrait de la table `logs` d'accès, de l'agrégation des lignes brutes et de l'envoi `access_log`.

## Questions ouvertes

- **IP uniques** : sketch HyperLogLog dans les cumuls (erreur de 1 à 2 %), ou calcul sur les lignes brutes avec une fenêtre maximale ?
- **Période des fichiers d'accès** : semaine, ou jour pour de très gros volumes ?
- **Compression** des fichiers clos : nécessaire à 365 jours ?
- **Événements de sécurité** : liste exacte des événements copiés sur l'Admin, et durée par défaut.
- **Échantillonnage par proxy** des accès réussis : utile à haut volume, mais en conflit avec l'export complet ; le défaut reste « tout journaliser ».
- **Gel légal** : un indicateur par période, ou par filtre (IP, domaine) ?
- **Clé de signature de l'export** : la même que la clé IP, ou une clé dédiée ?
