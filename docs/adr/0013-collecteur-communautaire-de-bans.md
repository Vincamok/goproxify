# ADR 0013 — Collecteur communautaire de bans

**Statut :** proposé · **Date :** 2026-10-20
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0007 (registre de modules) · **Complète :** le gossip entre passerelles pairs (`internal/edge/ban_gossip.go`) et le bouncer CrowdSec (`internal/edge/crowdsec`)

---

## Contexte

Une passerelle ne connaît que les attaquants qui l'ont déjà touchée. Les bans circulent aujourd'hui dans trois cercles : l'Admin vers ses passerelles, les passerelles d'un même groupe entre elles (gossip), et CrowdSec (source externe consommée par le bouncer). Il manque un cercle **entre installations indépendantes** : un scanner banni chez dix installations est encore inconnu de la onzième.

Le service qui rend cet échange possible est **public** : n'importe quelle installation peut y participer. Il est donc exposé à l'empoisonnement (une instance compromise ou malveillante signale une IP légitime), à la fuite de données (les rapports décrivent du trafic réel) et à l'abus (rapports en masse).

La landing `goproxify.dev` n'est pas le collecteur. L'adresse du ou des collecteurs n'est pas connue à ce jour : elle est une configuration, jamais une constante du code.

---

## Décision

### 1. Un service séparé, dans son propre dépôt

Le collecteur est un service autonome (dépôt `goproxify-collector`), déployé et versionné à part. Il ne fait pas partie du binaire unique de l'ADR-0001 : il est opéré par une seule équipe, pour tout le monde, alors que le binaire GoProxify est opéré par chaque utilisateur chez lui. Le contrat entre les deux est le **protocole d'échange** (section 3), publié et versionné (`/v1`).

### 2. Un client dans la passerelle, jamais dans l'Admin

Conformément à l'ADR-0006, c'est la **passerelle** qui parle au collecteur. L'Admin est le point de configuration et de supervision (activer, choisir les types d'échange, voir les statistiques) et la passerelle en garde une copie locale chiffrée (`community-config.gpx`, comme `threat-config.gpx`). Test de l'ADR-0006 :

| Coupure | Ce qui continue | Ce qui s'arrête |
|---|---|---|
| **Collecteur injoignable** | Trafic, bans locaux et déjà reçus (copie `community-bans.gpx` chiffrée, rechargée au démarrage), gossip entre pairs | Réception des nouveaux bans, envoi des rapports (file locale bornée, renvoyée au retour) |
| **Admin injoignable** | Participation au collecteur avec la configuration en copie locale | Modification des réglages communautaires |
| **Passerelle redémarrée sans collecteur** | Bans communautaires du dernier état connu, tant qu'ils n'ont pas expiré | Rien d'autre |

Dans un groupe HA, un seul membre (le leader Raft) interroge le collecteur et rediffuse aux autres par le gossip existant : le collecteur voit une installation, pas N passerelles.

### 3. Protocole : des types d'échange extensibles

Un échange a un **type**. Chaque type a son schéma, sa règle de consensus et son opt-in propre. Le client et le serveur ignorent les types qu'ils ne connaissent pas, ce qui permet d'en ajouter sans casser les anciennes passerelles.

| Type | Contenu | Règle de publication |
|---|---|---|
| `ban` | IP, motif normalisé (`scan`, `bruteforce`, `waf`, `ddos`…), gravité, durée suggérée | Consensus de N installations distinctes dans une fenêtre |
| `unban` | IP bannie à tort (faux positif) et motif | Fait retomber le score de consensus ; un seuil de contestations retire la publication |
| `range` | CIDR ou ASN agrégé issu de plusieurs `ban` | Le collecteur agrège lui-même au-delà d'un seuil d'IP distinctes dans une plage ; jamais proposé directement par une installation |
| `signature` | User-Agent ou chemin scanné | Version suivante : plus sensible à valider (un motif trop large bloque du trafic légitime) ; chaque signature passe par un mode « détection seule » avant d'être appliquée |

Échanges :

- `POST /v1/reports` : lot de rapports signés (jusqu'à 500), idempotents (identifiant par rapport).
- `GET /v1/feed/{type}?since=<curseur>` : flux incrémental (ajouts et retraits), avec `ETag` ; réponse `304` si rien n'a changé. Mode **tirer**, pas pousser : une installation est le plus souvent derrière un NAT. Un long polling (`?wait=30`) donne une diffusion quasi instantanée sans que le collecteur ait besoin de joindre les installations.
- `POST /v1/enroll` : voir section 4.

Chaque réponse porte `schema` et une signature du collecteur (clé publique épinglée côté passerelle, rotation par liste de clés), pour qu'un intermédiaire ne puisse pas injecter de bans.

### 4. Identité : une clé par installation, rattachée à un compte

- Chaque installation (l'Admin au nom de ses passerelles, ou chaque groupe HA) génère une paire de clés **Ed25519** ; la clé privée reste chiffrée par la clé maître de la passerelle. Chaque rapport est signé.
- La clé est **inscrite** auprès du collecteur avec un jeton d'inscription à usage unique. Le jeton s'obtient depuis un **compte du collecteur** : le compte porte le consentement (les types d'échange acceptés), la liste des installations et leur réputation. Les comptes sont gérés par le serveur de collecte lui-même, qui n'est pas encore construit : ils sont repoussés à sa construction. Il devra permettre de **créer un compte et de se connecter avec un fournisseur d'authentification externe** (Google et GitHub au départ, d'autres ensuite) : les fournisseurs sont une liste configurable de fournisseurs OAuth 2.0 / OpenID Connect, et en ajouter un ne demande aucune modification du protocole ni des passerelles. Un compte peut lier plusieurs fournisseurs ; l'identité retenue est le couple fournisseur + identifiant stable du fournisseur (jamais l'e-mail seul), pour qu'un changement ou une réattribution d'adresse ne donne pas accès au compte d'un autre. Le protocole ne dépend que de la clé et du jeton, de sorte que ce choix n'oblige pas à modifier les passerelles ; d'ici là, les jetons d'inscription sont émis à la main.
- Le collecteur ne stocke ni le nom de la passerelle ni les domaines protégés : un identifiant d'installation pseudonyme suffit à la réputation.
- Plusieurs collecteurs sont possibles : la configuration est une **liste ordonnée** `{url, clé publique, types}`. Chaque collecteur a son propre curseur et ses propres réglages.

### 5. Confiance : consensus et réputation

Un rapport seul ne devient jamais un ban publié.

1. **Consensus** : une IP est publiée quand `N` installations distinctes (défaut 3, jamais deux de la même plage ou du même compte) la rapportent dans une fenêtre glissante (défaut 24 h).
2. **Pondération** : le poids d'un rapport dépend de la réputation de l'installation (ancienneté, part de ses rapports confirmés par d'autres, part contestée par des `unban`). Une installation à réputation négative n'est plus comptée, sans que cela lui soit signalé.
3. **Liste de protection** (jamais publiable) : réseaux privés, loopback, plages réservées, résolveurs DNS publics, plages CDN et fournisseurs d'authentification connus, et toute adresse d'une installation inscrite. Un ban sur une adresse de cette liste est rejeté à la réception.
4. **Expiration courte** : une publication dure au plus 7 jours et se renouvelle seulement tant que le consensus persiste.
5. **Limites** : débit par clé et par IP, taille de lot, nombre de rapports par IP et par jour. Les rapports qui dépassent sont ignorés et abaissent la réputation.

### 6. Côté passerelle : une source distincte, en option

Deux réglages séparés, tous deux désactivés par défaut :

- **Partager** : la passerelle envoie ses bans de haute confiance (sources `threat`, `waf`, `fail2ban` ; jamais `manual`, `admin`, `crowdsec` ni `community`, pour ne pas renvoyer ce qu'elle a reçu). Elle n'envoie que `{ip, motif normalisé, gravité, heure}`, sans hôte, chemin, en-tête ni identifiant d'utilisateur.
- **Consommer** : les bans reçus portent la source `community`, avec leur collecteur d'origine dans le motif. Ils s'affichent et se suppriment depuis la page Bans, **la liste blanche l'emporte toujours**, et un déban local est mémorisé (table `unbans` existante) pour que le même ban ne revienne pas au prochain flux. Un ban `community` n'est jamais réémis par le gossip ni par le partage.

Le motif des bans reçus est borné et nettoyé avant affichage (aucun contenu venant du collecteur n'est interprété).

### 7. Vie privée et conformité

- Une adresse IP est une donnée personnelle (RGPD). Seules des IP bannies pour comportement malveillant sont envoyées, sur consentement explicite du compte, avec rétention courte côté collecteur (rapports bruts 30 jours, publications 7 jours) et procédure de retrait d'une IP sur demande.
- Le mode « consommer seulement » ne transmet rien d'autre que les requêtes de flux (le curseur et la clé).
- Les paramètres de pseudonymisation et d'anonymisation des IP de la passerelle ne s'appliquent pas aux rapports (la valeur doit être l'IP réelle), ce qui est affiché dans l'écran de consentement.

### 8. Abonnement payant aux mises à jour

Un service de paiement en ligne permettra d'**adhérer aux mises à jour** du collecteur. Il appartient au serveur de collecte, comme les comptes (section 4) : il est repoussé à sa construction, et les passerelles ne manipulent jamais de paiement.

- L'abonnement est rattaché au **compte** et donne un **droit d'accès** (`entitlement`) par type d'échange. Le collecteur l'applique en refusant ou en limitant le flux (`GET /v1/feed/{type}`) d'une clé dont le compte n'a pas le droit ; le protocole n'a besoin que d'un code de réponse dédié (`402`/`403` avec un motif lisible) que la passerelle affiche dans l'Admin.
- Un abonnement qui s'arrête ne coupe rien de ce que la passerelle a déjà reçu (ADR-0006) : les bans communautaires déjà en copie locale restent appliqués jusqu'à leur expiration (7 jours au plus). Seule la réception de nouveaux bans s'arrête.
- Le prestataire de paiement (jeton de paiement, webhooks, factures, TVA) est un détail du collecteur et peut être remplacé sans toucher au protocole.

---

## Conséquences

- Nouveau paquet côté passerelle `internal/edge/community` (client, file locale, magasin chiffré), nouvelle source de ban `community`, nouvelle section de réglages (Admin, CLI `goproxify community …`, outil MCP), conformément à la règle de documentation du dépôt.
- Le contrat de protocole (schémas JSON, exemples, vecteurs de signature) vit dans le dépôt du collecteur et est copié dans `docs/api_specs.md` à la livraison.
- Le consensus (N, fenêtre, liste de protection) est le principal levier de qualité du service : il se règle côté collecteur sans toucher aux passerelles.

## Phasage proposé

1. **Collecteur minimal** : `enroll`, `reports`, `feed/ban`, consensus par nombre d'installations, liste de protection, stockage SQLite, limites de débit ; compte par jeton émis à la main.
2. **Client passerelle** : réglages partager/consommer, source `community`, copies chiffrées, file d'envoi, bascule entre collecteurs ; Admin, CLI, MCP.
3. **`unban` et réputation**, puis **`range`**.
4. **Comptes en libre-service** (connexion Google, GitHub puis d'autres fournisseurs OAuth 2.0 / OpenID Connect), abonnement payant (section 8), tableau de bord de l'installation (ce qu'elle a envoyé, reçu, contesté).
5. **`signature`**, en détection seule d'abord.

## Questions ouvertes

- Adresse(s) des collecteurs (les comptes et leurs fournisseurs seront définis avec le serveur de collecte).
- Valeurs par défaut du consensus (`N = 3`, fenêtre 24 h) à confirmer sur un parc réel.
- Ce que l'abonnement débloque : recevoir le flux, ou seulement le recevoir plus vite et avec plus de types ? Une installation qui **partage** ses bans doit-elle garder un accès gratuit ? Le consensus (section 5) dépend du nombre de contributeurs : réserver la lecture aux payants sans contrepartie pour ceux qui rapportent risque d'appauvrir les données.
- Prestataire de paiement, tarification et facturation.
- Hébergement et coût d'un service public exposé (protection DDoS, sauvegarde du stockage).
