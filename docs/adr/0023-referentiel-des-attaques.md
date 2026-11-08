# ADR 0023 — Référentiel des attaques : apprendre des IP bannies, partager des signatures

**Statut :** proposé ; étape 1 mise en œuvre (Admin 0.259.0) : mineur, dossiers, classeur, entrées candidates, page, API, CLI, MCP, droits `attack_ref`, RGPD · **Date :** 2026-11-07
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0011 (moteurs qui apprennent : mode `detect`, note commune), ADR-0016 (gabarits de chemins, « le trafic non légitime n'enseigne rien »), ADR-0018 (l'Admin dépositaire des logs) · **Précise :** ADR-0013, type d'échange `signature` (avancé de la phase 5 à la phase 4, élargi à plusieurs genres)

---

## Contexte

Une IP bannie est le meilleur moment pour apprendre : on sait avec certitude que ce qu'elle a fait était hostile. Aujourd'hui on n'en retient que l'adresse.

- **Ce qui est déjà gardé.** Le ban porte son motif, ses signaux (`BanSignal` : nom, points, valeur observée) et le dernier User-Agent (`security_bans`, `security_ban_history`). Le volume de logs de l'Admin (ADR 0018) garde, pour chaque requête : méthode, chemin, statut, IP, UA, référent, catégories WAF déclenchées, signal Ephor, empreintes TLS JA3/JA4.
- **Ce qui est perdu.** Rien ne relit ces lignes **après** le ban pour répondre à : quels chemins cette IP a-t-elle sondés ? avec quel outil ? a-t-elle aussi tenté des injections, des mots de passe, une énumération ? Le même scanner banni sur dix installations reste inconnu de la onzième.
- **Ce que les protections savent.** Les listes d'Ephor (`internal/edge/threat/defaults/` : 69 chemins, 62 UA, 9 plages) et les règles du WAF sont écrites à la main, versionnées avec le binaire. La liste de chemins sait déjà se recharger depuis une URL (`fetchAndCache`), mais aucune source n'est alimentée par ce que les passerelles voient réellement.
- **Ce que le collecteur prévoit.** L'ADR 0013 échange des IP (`ban`, `unban`, `range`) et laisse un type `signature` (UA ou chemin scanné) pour plus tard. Il ne dit ni comment une installation **produit** une signature, ni comment s'assurer qu'elle ne bloque pas du trafic légitime.

Le risque central est le faux positif : une IP bannie charge aussi `/`, `/favicon.ico`, `/robots.txt`, `/api/…`. Apprendre « tout ce que font les attaquants » reviendrait à interdire le site. Tout le dessin tient donc dans la **discrimination** : n'est retenu que ce que les attaquants font et que les visiteurs ne font pas.

---

## Décision

### 1. Un référentiel d'entrées normalisées, jamais d'IP

Le référentiel est un ensemble d'**entrées** : un *genre*, une valeur normalisée, une famille d'attaque, des compteurs.

| Genre | Valeur | Exemple |
|---|---|---|
| `path` | gabarit de chemin sondé (ADR 0016), sans valeur de requête | `/wp-content/plugins/{var}/readme.txt` |
| `ua` | UA normalisé (famille d'outil + version majeure) | `sqlmap/1.x` |
| `tls` | famille d'empreinte JA4 | `t13d1516h2_8daaf6152771_…` |
| `payload` | catégorie WAF + identifiant de règle + forme (jamais la charge brute) | `sqli/942100` sur le paramètre `id` |
| `playbook` | suite ordonnée de gabarits sondés par une même IP, dédoublonnée | `/.env → /.git/config → /wp-login.php` |

Chaque entrée porte : `family` (taxonomie ci-dessous), `distinct_ips` et `distinct_hosts` (estimations, sans liste), `first_seen`, `last_seen`, `lift` (voir 3), `status` (`candidate | detect | enforce | rejected`) et `origin` (`local` ou identifiant d'un flux). **Ni IP, ni nom d'hôte, ni valeur de paramètre** n'y entrent : c'est ce qui rend le référentiel partageable et sans objet pour un effacement RGPD.

**Taxonomie des familles** (petite, stable, alignée sur les catégories du WAF) : `config_leak`, `cms_probe`, `admin_panel_probe`, `scanner_generic`, `sqli`, `xss`, `lfi`, `rce`, `bruteforce`, `enumeration`, `api_abuse`, `bot_abusive`, `exploit_cve` (avec identifiant CVE quand il est connu). Une entrée a une famille principale ; une famille inconnue reste `unclassified` et n'est pas partagée.

### 2. Un dossier par IP bannie, construit par l'Admin

À chaque ban (et à chaud pour les bans en cours), un **mineur** relit sur le volume de logs de l'Admin la fenêtre d'activité de l'IP : de 24 h avant le premier signal jusqu'à 1 h après le ban (les requêtes refusées après le ban comptent : elles montrent ce que l'IP continue d'essayer).

Le dossier est un résumé, pas une copie des lignes : gabarits de chemins sondés avec leur statut, UA et empreintes, catégories WAF, signaux, méthodes, répartition des statuts, ordre et cadence. À partir du dossier, un **classeur déterministe** (règles, pas d'apprentissage opaque) attribue le profil de l'attaquant : `scanner` (beaucoup de 404 sur des chemins distincts), `bruteforcer` (POST répétés vers une route à 401), `exploiter` (catégories WAF critiques), `enumerator`, `crawler_abusif`. Un dossier alimente les entrées du référentiel ; le dossier lui-même est gardé pendant la rétention des bans (365 jours par défaut) et effacé avec l'IP.

**Pourquoi l'Admin et pas la passerelle.** L'Admin détient l'historique complet (ADR 0018) et sait lire plusieurs passerelles ensemble ; la passerelle n'en garde qu'un tampon et doit rester légère sur le chemin du trafic. Le test de l'ADR 0006 est fait en 5 : le **mineur** s'arrête si l'Admin tombe, l'**application** non.

### 3. Discriminer : ce que les visiteurs légitimes ne font pas

Une valeur devient `candidate` seulement si **toutes** ces conditions tiennent :

1. **Soutien** : vue chez au moins K IP bannies distinctes (défaut 5) sur au moins J jours distincts (défaut 2). Un seul scanner ne crée pas d'entrée.
2. **Lift** : `lift = part du trafic banni qui la contient ÷ part du trafic non banni qui la contient`, mesuré sur les mêmes périodes et les mêmes hôtes. Seuil par défaut : ≥ 50, et jamais de valeur vue en 2xx par des IP sans note de risque.
3. **Hors surface apprise** : un gabarit déjà dans le profil de surface d'un proxy (ADR 0016) en est exclu pour ce proxy. Le référentiel ne contredit jamais ce que l'administrateur a validé.
4. **Hors liste de protection** : `/`, `/robots.txt`, `/favicon.ico`, `/sitemap.xml`, `/.well-known/*`, `/health*`, `/api` et les UA de navigateurs courants ne sont jamais proposables, quel que soit leur lift.
5. **Spécificité** : un gabarit d'un seul segment générique, un UA vide ou plus court que 6 caractères, un préfixe qui couvrirait plus d'un seuil de trafic légitime mesuré sont refusés.

Un attaquant qui provoque lui-même des bans pour empoisonner le référentiel doit donc réunir K IP distinctes bannies sur J jours **et** que le même chemin n'apparaisse jamais côté visiteurs : ce coût est le même que celui d'un vrai scanner, sans bénéfice (le chemin n'existe pas chez la victime).

### 4. Du candidat à l'application : toujours `detect` d'abord

Même chaîne que l'ADR 0011 et l'ADR 0016 :

| État | Effet sur le trafic |
|---|---|
| `candidate` | aucun ; visible dans l'Admin avec ses preuves (IP, jours, lift, ce qu'il aurait refusé sur 7 jours de logs) |
| `detect` | une requête qui correspond est journalisée, comptée, versée à la note de risque d'Ephor, sans refus |
| `enforce` | la correspondance devient un signal pesé d'Ephor (`ref_path`, `ref_ua`, `ref_tls`) : le ban se déclenche par le score, comme les listes actuelles |

La promotion `candidate → detect` peut être automatique (réglage, désactivé par défaut) ; `detect → enforce` est **toujours** validée par un humain, entrée par entrée ou par famille. Une entrée en `detect` qui correspondrait à du trafic de visiteurs sains (note de risque nulle, 2xx) repasse en `rejected` et alerte.

L'application ne crée pas de nouveau moteur : le référentiel actif est compilé en **listes** et injecté dans celles que l'engine d'Ephor lit déjà (`MatchPath`, `MatchUA`), plus un index JA4. La passerelle en garde une copie chiffrée (`attack-ref.gpx`, comme `threat-config.gpx`) et la recharge au démarrage sans l'Admin ; les groupes HA la reçoivent comme le reste de la configuration.

### 5. Autonomie (ADR 0006)

| Coupure | Ce qui continue | Ce qui s'arrête |
|---|---|---|
| **Admin injoignable** | Application du référentiel (copie locale), bans, gossip | Mineur, validation des candidats, import de flux |
| **Collecteur injoignable** | Tout, y compris l'application des signatures déjà reçues | Réception des nouvelles, envoi des siennes |
| **Passerelle redémarrée sans Admin** | Dernier référentiel actif connu | Rien d'autre |

### 6. Partage : le type `signature` du collecteur, en trois étapes

Le référentiel est la source unique de ce qui se partage ; le collecteur (ADR 0013, dépôt séparé) en est la base commune.

1. **Bundle signé, sans collecteur** : export du référentiel `enforce` en un fichier JSON signé (Ed25519), importable depuis l'Admin (fichier ou URL). C'est livrable seul, sert de format de contrat (`schema`, entrées, signature) et permet à un premier flux d'être hébergé comme un fichier statique, avec le mécanisme de rafraîchissement par URL que les listes d'Ephor possèdent déjà.
2. **Rapports de signatures vers le collecteur** : opt-in **distinct** du partage d'IP, désactivé par défaut. Une installation n'envoie que les entrées `enforce` ou `detect` confirmées, avec `{genre, valeur, famille, compteurs bornés}`. Rien d'autre.
3. **Consensus côté collecteur** : une entrée est publiée quand N installations distinctes, de plages et de comptes différents, la rapportent dans la fenêtre (même mécanisme que pour les IP, ADR 0013 section 5), avec les mêmes listes de protection, **renforcées** : les chemins, UA et empreintes de la liste de protection de la section 3 sont rejetés à la réception, même si N installations les rapportent.

**Réception.** Toute entrée reçue arrive en `candidate`, `origin` = le flux. Elle suit la section 4 de bout en bout : `detect` d'abord, où elle est évaluée sur le trafic **local** (son lift local décide), puis validation. Un flux ne pousse donc jamais directement un refus : c'est le trafic de l'installation qui tranche. Les entrées d'un flux sont bornées et nettoyées avant affichage (longueur, caractères, aucune interprétation).

**La base unique** est la table des entrées du collecteur : `entries` (genre, valeur normalisée, famille, première et dernière observation, nombre d'installations distinctes, score de confiance, statut) et `observations` agrégées par jour (jamais par installation en clair : identifiant pseudonyme seulement, pour la réputation). Elle est publiée en lecture seule sous forme de flux incrémental `GET /v1/feed/signature?since=` (ADR 0013, section 3).

### 7. Vie privée

- Seules des **valeurs normalisées** sont stockées dans le référentiel et partagées. Un chemin contenant un segment qui ressemble à un identifiant, un jeton long ou une adresse électronique est ramené à `{var}` avant d'être retenu ; une valeur d'entropie élevée n'est jamais conservée.
- Les dossiers par IP restent sur l'Admin et suivent la rétention et l'effacement des bans. Ils ne quittent pas l'installation.
- L'écran d'activation dit exactement ce qui part : un exemple d'entrée, sans autre champ.

### 8. Droits (ADR 0022)

Nouveau service au catalogue : `attack_reference`, avec les permissions `read` (consulter, dossiers compris), `write` (promouvoir, rejeter, régler les seuils) et `share` (export, import de flux, rapports au collecteur). `share` n'est jamais donné par un niveau : il est explicite, comme tout ce qui sort de l'installation. Routes, outils MCP et commandes CLI les déclarent aux trois endroits prévus (CLAUDE.md, règle 12).

---

## Alternatives écartées

- **Mineur sur la passerelle.** Relire l'historique d'une IP sur le chemin du trafic est exactement ce que l'ADR 0018 a retiré des passerelles.
- **Partager les dossiers ou les lignes brutes.** Plus riche, mais ce sont des données personnelles et du trafic réel ; le collecteur n'en a pas besoin pour juger une signature.
- **Appliquer directement les signatures d'un flux.** C'est la porte à l'empoisonnement : le flux n'est qu'une suggestion, la décision reste locale.
- **Apprentissage automatique de classification.** Les règles du classeur sont explicables ligne par ligne, comme les signaux d'Ephor (ADR 0011) ; un classeur appris le serait moins et ne se corrigerait pas à la main.

## Conséquences

- Nouveau paquet Admin `internal/admin/attackref` (mineur, classeur, store SQLite : tables `attack_dossiers`, `attack_entries`), un job périodique, et une copie chiffrée sur la passerelle (`attack-ref.gpx`).
- Ephor gagne trois signaux (`ref_path`, `ref_ua`, `ref_tls`) en `detect` puis en `enforce`, avec leurs points réglables et leur place dans la simulation sur logs (ADR 0011) : on peut rejouer une entrée candidate sur 7 jours avant de la promouvoir.
- Admin : page « Référentiel » (candidats, preuves, promotion, rejet), API, CLI `goproxify attack-ref …`, outils MCP, export/import. Toute la documentation obligatoire du dépôt suit.
- Contrat de partage : le format du bundle (étape 1) devient le contrat du type `signature` de l'ADR 0013 ; il est versionné (`schema`) et copié dans `docs/api_specs.md`.
- La qualité repose sur K, J, le lift et la liste de protection : à calibrer sur de vrais logs (comme l'ADR 0020), jamais en `enforce` automatique avant.

## Phasage proposé

Chaque étape est livrable seule.

1. **Mineur et dossiers, en lecture seule** : un dossier par ban, classeur, entrées `candidate` avec preuves ; page Admin, API, CLI, MCP. Aucun effet sur le trafic ; apporte déjà la compréhension de ce que le parc reçoit.
2. **Application** : `candidate → detect → enforce`, signaux Ephor, copie chiffrée sur la passerelle, simulation sur logs, alerte sur faux positif.
3. **Bundle signé** : export, import de fichier ou d'URL, entrées reçues en `candidate`.
4. **Collecteur, type `signature`** : rapports, consensus, flux (côté dépôt du collecteur, après les phases 1 à 3 de l'ADR 0013).
5. **Genres avancés** : `playbook`, `tls`, `payload`, regroupement par campagne (mêmes playbooks, mêmes ASN), identifiants CVE.

## Questions ouvertes

- Valeurs de départ K = 5, J = 2, lift ≥ 50 : jamais calibrées, à mesurer sur le parc réel avant l'étape 2.
- Taxonomie : s'aligner sur MITRE ATT&CK / CAPEC / OWASP plutôt que sur une liste maison ? Une liste maison est plus simple à classer de façon déterministe ; un mapping vers CAPEC peut s'ajouter en attribut.
- Faut-il aussi des entrées **négatives** (« ce chemin est légitime ») dans le flux partagé, pour que les installations s'évitent mutuellement les faux positifs ? Plus sensible : reporté.
- Licence du flux public (CC0, ODbL) : à décider avec la construction du collecteur.
- Un référentiel par installation ou par groupe HA : par installation (l'Admin), le groupe n'en recevant que la compilation.
