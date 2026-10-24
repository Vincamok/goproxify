# ADR 0010 — Logs : agrégats par minute, base séparée, fichiers par période

**Statut :** remplacé par l'[ADR 0012](0012-logs-proprietaire-edge.md), mis en œuvre (Admin 0.192.1, Edge 0.105.0) : les cumuls par minute sont calculés par les passerelles, la base séparée et les fichiers par période sont ceux des passerelles · **Date :** 2026-10-18
**Complète :** ADR-0002 (SQLite pour l'Admin) · **Respecte :** ADR-0006 (autonomie des composants)

> **Réorienté par l'[ADR 0012](0012-logs-proprietaire-edge.md) (2026-10-20).** Cet ADR range mieux les logs sur l'Admin sans remettre en cause leur provenance : chaque requête de chaque passerelle y est copiée, et une coupure de l'Admin laisse un trou que rien ne comble. L'ADR 0012 donne la propriété des lignes brutes aux passerelles. Les étapes 2 et 3 (base séparée, fichiers par période) sont **remplacées** : elles s'appliquent à la passerelle, pas à l'Admin. L'étape 1 est **réorientée** : les cumuls par minute sont calculés par la passerelle ; les tables livrées en Admin 0.164.0 et 0.164.2 sont une étape intermédiaire que l'ADR 0012 supprime à sa livraison 8. Le contexte ci-dessous reste exact.

---

## Contexte

Tous les logs (accès HTTP des passerelles, système, audit de l'Admin lui-même) vont dans une seule table `logs` de `admin.db`, à côté des nœuds, des tokens, des bans et de la configuration. Sur un serveur réel elle dépasse 5 millions de lignes. L'Admin écrit ses propres requêtes dans cette table : chaque appel d'API ajoute une ligne.

Quatre problèmes mesurés les 2026-10-18 et 2026-10-19 :

1. **Les tableaux de bord relisent toute leur fenêtre à chaque appel.** Sur ce serveur, `/prism/compare` met 5,2 s, `/logs/histogram` 4,7 s, `/prism/kpis` 3,5 s, `/prism/anomalies` 2,6 s, `/prism/slo` 1,7 s. Le coût suit le nombre de lignes de la période, donc le trafic.
2. **Un mauvais plan suffit à parcourir toute la table.** Sans `ANALYZE` (jamais exécuté), la sonde `/nodes/live`, appelée toutes les 5 s, lisait tout un index : 1,2 s par appel, jusqu'à 9 s sous charge. Corrigé avec `INDEXED BY` (Admin 0.156.1), mais rien n'empêche la même erreur ailleurs.
3. **Les logs et la configuration partagent un fichier.** Une grosse lecture ou une purge de logs ralentit la configuration, les sauvegardes embarquent des gigaoctets de logs, et la purge (`DELETE` massif) laisse un fichier qui ne rétrécit pas.
4. **Le WAL ne se recycle jamais.** Relevé le 2026-10-19 sur ce serveur : `admin.db` 5,3 Go, `admin.db-wal` **16,3 Go**. Le point de contrôle automatique ne recycle le WAL que lorsqu'aucune lecture n'est en cours ; les tableaux de bord rafraîchis toutes les quelques secondes sur 10 connexions ne laissent jamais ce créneau. Corrigé en Admin 0.163.1 (point de contrôle `TRUNCATE` chaque minute, `journal_size_limit`, `auto_vacuum` incrémental), indépendamment des trois changements ci-dessous. Admin 0.163.1 cesse aussi de journaliser les lectures de rafraîchissement et les fichiers statiques de son interface (253 000 des 5,4 millions de lignes mesurées : une part mineure). La part principale venait des passerelles : 2,76 millions de lignes « ip bloquée par ban/profil » sans domaine, une par requête refusée à une IP déjà bannie, regroupées depuis Edge 0.73.1 (une ligne par IP, motif et minute). Reste le volume des accès eux-mêmes : environ 220 000 lignes par jour en octobre, soit près de 20 Go en régime établi à 90 jours de rétention.

Deux faits relevés dans le code limitent ce qu'on peut affirmer :

- Le pool compte 10 connexions en mode WAL : le blocage observé de fichiers statiques (jusqu'à 4 s) **n'est donc pas** un verrou de connexion unique. La cause n'est pas établie (CPU, disque, point de contrôle WAL ?) ; à mesurer avant de promettre que la séparation la supprime.
- `Store.Write` fait un `INSERT` et une transaction par entrée, sans regroupement.

La rétention existe déjà en deux classes : accès HTTP 90 jours (ramené de 365 à 90 par Admin 0.163.0, défauts RGPD), système 90 jours, historique des bans 365 jours (`retained_until`, purge quotidienne par `DELETE`).

---

## Décision

Trois changements, livrables chacun seul, dans cet ordre.

### 1. Agrégats pré-calculés par minute

Une table de cumuls, alimentée à l'écriture des logs, que les tableaux de bord lisent à la place des lignes brutes.

- **Clé** : minute (UTC) × nœud × domaine × code de statut.
- **Valeurs** : nombre de requêtes, de 5xx, de refus (403/429), octets, somme des latences, **comptes par bucket de latence** (mêmes bornes que l'histogramme de la passerelle, pour un p95 exact au bucket près), nombre d'entrées par niveau.
- **Contenu** : aucune IP, aucun identifiant d'utilisateur. Ce sont des données non personnelles, qui peuvent donc être gardées plus longtemps que les lignes brutes (par défaut 400 jours, réglable).
- **Écriture** : en mémoire, vidée toutes les quelques secondes dans la même transaction que les lignes du lot. Un arrêt brutal perd au plus ces secondes d'agrégat ; une commande de reconstruction recalcule une plage depuis les lignes brutes tant qu'elles existent.
- **Lecteurs déplacés** : `/prism/kpis`, `timeline`, `slo`, `compare`, `anomalies` (références), `/logs/histogram`, `/nodes/live` (au lieu d'un `GROUP BY` sur les logs).
- **Restent sur les lignes brutes** : la recherche, la trace d'une IP, les empreintes TLS, les facettes, le scan d'IP. Ces lectures sont ciblées (un filtre) et bornées par la période choisie.
- **À trancher** : les IP uniques ne s'additionnent pas d'une minute à l'autre. Soit un sketch (HyperLogLog) par minute et par domaine, avec une erreur d'environ 1 à 2 %, soit un calcul sur les lignes brutes avec une durée maximale de fenêtre. Je recommande le sketch.

### 2. Base de logs séparée de `admin.db`

Les logs passent dans leurs propres fichiers SQLite, dans un dossier voisin de la base de l'Admin ; `admin.db` ne garde que la configuration et l'état.

- **Isolement** : une lecture ou une purge de logs ne partage plus de fichier, de WAL ni de cache avec la configuration. Si les logs sont indisponibles (disque plein, fichier corrompu), l'Admin démarre et travaille avec un historique vide.
- **Écriture regroupée** : une transaction par lot (jusqu'à 500 entrées ou 250 ms). La diffusion SSE ne change pas.
- **Sauvegarde** : par défaut elle n'embarque que `admin.db` et les agrégats ; les fichiers de logs sont optionnels.
- **Statistiques** : `ANALYZE` (ou `PRAGMA optimize`) à la fermeture d'un fichier de période, qui ne bouge plus ensuite.

### 3. Un fichier par période et par type

- **Accès HTTP** (`status > 0`) : un fichier par semaine. **Système et audit** : un fichier par mois. La rétention de chaque type garde ses valeurs par défaut (90 jours chacun).
- **Écriture** : seul le fichier courant est ouvert en écriture ; les autres sont en lecture seule.
- **Lecture** : une requête interroge les fichiers qui recouvrent sa fenêtre, un par un, et fusionne dans le code Go (pas d'`ATTACH`, limité à 10 fichiers par défaut). Une fenêtre de 24 h touche un ou deux fichiers.
- **Identifiants** : `id` devient global, `(numéro de fichier << 40) | rowid`, pour que `before_id` et la pagination continuent de fonctionner à travers les fichiers.
- **Rétention** : on supprime le fichier dont la dernière ligne a dépassé la durée, sans `DELETE` ni `VACUUM`. Dans le fichier à cheval sur la limite, la purge par ligne existante (`retained_until`) continue de s'appliquer : la durée reste un maximum, comme l'exige le RGPD.
- **Effacement RGPD** (par IP, par utilisateur) : exécuté sur chaque fichier encore conservé, en tâche de fond, avec index `ip` et `ip_hmac` par fichier. Coût proportionnel à la rétention, acceptable pour une opération rare.

---

## Alternatives écartées

- **Seulement `ANALYZE` et des `INDEXED BY`** : règle les mauvais plans, pas le coût d'une agrégation qui relit une fenêtre entière. Reste nécessaire en complément.
- **PostgreSQL, ClickHouse ou DuckDB pour les logs** : adaptés à des milliards de lignes, mais ajoutent un service externe, ce que l'ADR-0002 écarte pour l'Admin. À reconsidérer si une instance dépasse environ 1 milliard de lignes d'accès par an ou veut des analyses libres sur des mois.
- **Une seule base partitionnée** : SQLite n'a pas de partitionnement ; la suppression par partition serait un `DELETE` de plus.
- **Découper par type seul, sans période** : isole les volumes, mais la purge et la taille des fichiers restent les mêmes.

---

## Conséquences

**Gains attendus**

- Le coût d'un tableau de bord ne dépend plus du volume de logs mais du nombre de minutes affichées (au plus quelques milliers de lignes).
- Rétention instantanée, fichiers qui rétrécissent, sauvegardes de configuration légères.
- Les écritures de logs n'attendent plus un `fsync` par ligne.

**Coûts et risques**

- Une couche de lecture multi-fichiers à écrire et à tester : pagination, tri, filtres, SSE, export CSV/JSON, MCP, CLI.
- Les agrégats doublent une partie des données : il faut les tester contre les lignes brutes (un test compare les deux sur un jeu fixe).
- L'agrégat arrondit les p95 au bucket et les IP uniques à environ 1 à 2 % si le sketch est retenu.
- La requête d'un utilisateur sur une fenêtre très large (un an) lit jusqu'à 52 fichiers d'accès : à limiter ou à servir par les agrégats.

**Autonomie (ADR-0006)** : les passerelles ne changent pas ; elles gardent leurs journaux et leurs métriques et n'écrivent pas dans la base de logs de l'Admin autrement que par le flux existant. L'Admin n'est toujours pas un point de passage du service.

**Migration** : aucune instance n'est déployée en production, donc l'ancienne table `logs` est remplacée sans reprise automatique. Sur le serveur de développement, l'historique actuel serait perdu, sauf import ponctuel à décider.

---

## Ordre de mise en œuvre

1. Agrégats par minute et écriture par lots, dans `admin.db` (gain le plus grand, aucun changement de fichier). Mesurer à ce stade si les blocages de fichiers statiques disparaissent.
   *Livré en Admin 0.164.0 (agrégats seuls)* : table `logs_minute` (requêtes, octets, latences, robots ; clé minute × passerelle × domaine × code), alimentée par une tâche de fond qui avance un repère d'id dans la même transaction (au lieu d'une accumulation en mémoire à l'écriture : même résultat, rattrapage de l'historique inclus, `Store.Write` inchangé). KPIs, courbe, codes HTTP et SLO les lisent pour toute fenêtre d'au moins une heure sans filtre IP ni chemin. *Écriture par lots livrée en Admin 0.164.2* : `Store.WriteBatch` (jusqu'à 500 entrées par transaction) sur le chemin d'ingestion des passerelles, environ 10 fois moins de WAL mesuré à 1 500 lignes. Restent : l'histogramme de logs, `/nodes/live`, les p95 par bucket et les IP uniques.
2. Déplacer les logs et les agrégats dans leurs fichiers, hors de `admin.db`.
3. Découper par période et par type, avec la couche de lecture multi-fichiers, la rétention par fichier et l'effacement RGPD.

## Questions tranchées

- **IP uniques** : un résumé fusionnable par passerelle (liste exacte puis HyperLogLog), calculé à l'affichage (ADR 0012).
- **Périodes d'accès** : la semaine, sur la passerelle (ADR 0012, Edge 0.74.0).
- **Import de l'historique existant** : non. Aucune instance n'est déployée en production ; l'ancienne table `logs` d'accès est remplacée sans reprise.
- **Conservation des agrégats** : 400 jours (`DefaultRetentionAggDays`), inchangée.

Les tables livrées en Admin 0.164.0 (`logs_minute`) et 0.164.2 (écriture par lots) restent, mais `logs_minute` n'est plus alimentée que par les cumuls des passerelles ; l'agrégation depuis les lignes brutes a été supprimée en Admin 0.176.0.
