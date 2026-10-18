# ADR 0011 — WAF et Ephor : des moteurs qui apprennent

**Statut :** proposé · **Date :** 2026-10-18
**Nom :** Ephor est le nouveau nom de Sentinel (renommé pour éviter la confusion avec Microsoft Sentinel). Les clés techniques restent `threat` : source de ban, préfixe de motif (`threat: …`), paquet `internal/edge/threat`, `threat-config`, métriques `gpx_threat_*`.
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0007 (moteurs de sécurité globaux), ADR-0010 (agrégats par minute) · **Complète :** ADR-0008 (les plugins ne remplacent pas les moteurs internes)

---

## Contexte

Les deux moteurs internes de détection reposent surtout sur des seuils fixes et des listes.

- **Ephor** (`internal/edge/threat`) additionne des signaux à poids fixes : `ip`, `custom_ip`, `ua`, `custom_ua`, `path`, `custom_path`, `tls_fp` (listes) et `rate` (seuil). Un score cumulé à demi-vie (`ip_score`), des 4xx pondérés par code et par route, l'escalade des durées de ban et le tarpit s'y ajoutent. Les compteurs sont bornés (64 shards × 4096 clés, purge à 10 minutes, IPv6 agrégées par /64) mais **seulement en mémoire** : un redémarrage de la passerelle remet à zéro les scores et les fenêtres (les bans, eux, sont persistés).
- **WAF** (`internal/edge/waf`, `waf/behavior`) inspecte le contenu par règles, et son moteur comportemental calcule par IP et par hôte sept signaux (`high_4xx_rate`, `path_scanning`, `waf_score_accumulation`, `ua_rotation`, `request_burst`, `high_post_ratio`, `high_path_entropy`) et un signal par sous-réseau (`distributed_scan`). Il a un bonus de confiance (+1 par 100 requêtes propres, jusqu'à 5), une synchronisation HA et un snapshot disque. Il n'est actif que sur les routes qui l'activent (`behavior_enabled`).

Conséquences constatées dans le code :

1. **Deux scores pour une même IP**, qui ne se rejoignent que dans le magasin de bans (les bans du WAF passent par le callback d'Ephor). Fail2Ban garde ses propres compteurs, CrowdSec apporte des décisions.
2. **Des mesures comportementales utiles enfermées dans le WAF** (diversité des chemins, rotation d'UA, rafales, sous-réseau) : Ephor, qui voit toutes les requêtes avant le routage, ne les a pas.
3. **Aucun signal ne compare deux sources** : l'empreinte TLS (`tlsfp`) n'est confrontée qu'à une liste d'empreintes connues, jamais à l'`User-Agent` annoncé.
4. **Un seuil ne s'adapte pas au trafic** : `rate_limit` et `ban_threshold` valent autant pour un site à 5 requêtes par seconde que pour un site à 5 000. Seul le bonus de confiance du WAF s'ajuste.
5. **Un ban ne dit pas pourquoi en détail** : sa raison est le signal principal (`threat: score cumulé`, `threat: <signal>`).

Les listes vieillissent et se contournent (changer d'UA ou d'adresse). Un comportement est plus coûteux à imiter.

---

## Décision

Faire évoluer WAF et Ephor par des **signaux de comportement et des valeurs de référence apprises**, plutôt que par de nouvelles listes. Chaque étape est livrable seule, dans cet ordre.

### Principes

- **Apprendre = estimer un comportement normal et mesurer l'écart.** Statistiques simples et auditables (moyennes glissantes, médiane et écart absolu médian, cardinalité approchée). Pas de modèle opaque sur la passerelle : chaque décision doit pouvoir être expliquée à l'administrateur qui conteste un blocage.
- **L'état appris n'est pas de la configuration.** Il se calcule sur la passerelle, se voit dans l'interface (valeur apprise, date, volume observé) et ne modifie jamais un réglage de l'administrateur. Il se règle par un mode, pas par un chiffre.
- **Tout nouveau signal naît en `detect`.** Par signal : `off | detect | block`. Il passe en `block` après lecture de la simulation sur logs (`legit_blocked`), jamais d'office.
- **Rien n'oblige à choisir entre WAF et Ephor pour savoir où vit un signal** : un signal vit là où l'information est disponible, et alimente la note commune (étape 2).

### 1. Prérequis : l'état survit à un redémarrage, et un ban explique ses signaux

- **Persistance** : les compteurs de score d'Ephor rejoignent le snapshot chiffré de la passerelle (comme le profil comportemental du WAF), restaurés au démarrage sans l'Admin (ADR 0006).
- **Explicabilité** : chaque ban garde la liste des signaux qui l'ont causé, avec leurs points (nom, points, valeur observée). Visible dans le Journal, la page Bans, la trace d'une IP et l'API.

### 2. Une note de risque commune par IP

Le magasin comportemental du WAF devient celui de la passerelle : il est alimenté par Ephor **et** par le WAF, sans activation par route, et chaque moteur y verse ses signaux (WAF : règles déclenchées ; Ephor : listes, débit, erreurs ; Fail2Ban et CrowdSec : décisions comme entrées). Le ban reste posé par Ephor (callback existant), sur une seule note, avec l'ensemble des signaux dans l'explication. La synchronisation HA du profil est conservée (fusion par maximum).

### 3. Nouveaux signaux de comportement (chacun en `detect` d'abord)

| Signal | Idée |
|---|---|
| `ua_tls_mismatch` | l'`User-Agent` annonce un navigateur, l'empreinte JA4 est celle d'un client programmatique. Demande une petite table famille d'UA ↔ famille d'empreinte (courte, stable, versionnée) |
| `no_assets` | beaucoup de pages HTML, jamais d'image, CSS ni script |
| `regular_interval` | intervalles entre requêtes anormalement réguliers (variation faible sur une série) |
| `scan_breadth` | chemins distincts en erreur ramenés au volume de requêtes (reprend `path_scanning` du WAF, globalement) |
| `asn_aggregate` | attaque distribuée « lente » : agrégation par ASN, en plus du /24 (IPv4) et du /48 (IPv6) actuels du WAF |

`asn_aggregate` demande la base ASN sur la passerelle (elle n'est aujourd'hui que côté Admin) : poussée par l'Admin, copie chiffrée locale (ADR 0006).

### 4. Références apprises

- **Débit normal par route** (moyenne glissante par heure de la semaine, ou plus simple au départ : par heure), comparé au débit courant ; l'écart devient un signal, `rate_limit` reste un plafond dur.
- **Confiance accrue** pour les IP à longue histoire propre (généralisation du bonus de confiance du WAF).
- **Côté Admin, hors du chemin de requête** : les agrégats par minute de l'ADR 0010 (sans IP) servent à proposer des seuils, que l'administrateur accepte ; l'Admin ne pousse que des valeurs de configuration, comme aujourd'hui.

---

## Règles

- **Autonomie (ADR 0006)** : apprentissage, signaux et note commune tournent sur la passerelle seule. L'état appris est chiffré localement. L'Admin n'est requis ni pour apprendre ni pour décider.
- **Démarrage à froid** : tant qu'une référence n'a pas assez d'observations (durée et volume minimaux, affichés), son signal reste en `detect` quel que soit son mode.
- **Empoisonnement** : un attaquant peut tenter d'enseigner un « normal » trop haut. Les références s'estiment par statistiques robustes (médiane, écart absolu médian), excluent les IP à note non nulle ou bannies, et leur dérive est plafonnée par période.
- **Mémoire bornée, O(1) par requête** : un état par IP avec plafond et éviction, comme les compteurs actuels. Mesurer le coût par requête et par signal avant de livrer (le registre des détecteurs mesure déjà environ 185 ns par étape).
- **Faux positifs** : NAT d'entreprise et CGNAT mêlent beaucoup de personnes derrière une IP. Les signaux de volume tiennent compte de la liste blanche des bans et du bonus de confiance ; la simulation sur logs est le critère de passage en `block`.
- **Vie privée** : les profils par IP ne vivent que le temps de leur fenêtre (comme aujourd'hui) ; les références apprises par route ne contiennent aucune IP ni identifiant, donc rien de personnel à purger.
- **Sécurité par défaut** : une référence absente, illisible ou périmée ne bloque jamais plus : le signal retombe en `detect`, jamais en `block`.

---

## Conséquences

- Le WAF et Ephor cessent d'être deux mondes parallèles : un ban dit quels signaux, de quels moteurs, l'ont causé.
- Les listes restent (ce sont des signaux à part entière, rapides et fiables) mais cessent d'être le principal axe d'évolution.
- Le magasin comportemental passe de « option d'une route » à « état de la passerelle » : consommation de mémoire permanente, à dimensionner (plafonds configurables).
- L'étape 4 introduit un état dépendant du temps : les tests rejouent des séries temporelles (les compteurs d'Ephor ont déjà une horloge injectable pour la simulation).

## Questions ouvertes

1. **Où vit la table UA ↔ JA4** : livrée dans le binaire et versionnée, ou poussée par l'Admin ? (Elle reste une liste ; l'objectif est qu'elle soit courte et stable.)
2. **Fenêtre d'apprentissage** : durée minimale avant qu'une référence compte (24 h ? 7 jours pour la saisonnalité hebdomadaire ?).
3. **Taille de la base ASN sur la passerelle** et fréquence de mise à jour.
4. **Note commune et mode `detect` d'Ephor** : en `detect`, la note est calculée et affichée mais ne bannit pas ; faut-il aussi une note « fantôme » en simulation pour comparer avant/après ?
5. **Granularité de la note commune dans un groupe HA** : fusion par maximum (comme le profil du WAF) ou somme ?
