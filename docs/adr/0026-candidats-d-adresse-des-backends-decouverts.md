# ADR 0026 — Candidats d'adresse des backends découverts

**Statut :** accepté (livré : Agent 0.30.1, Edge 0.153.0) · **Date :** 2026-11

## Contexte

Un conteneur découvert par Portainer ou Arcane se joint de deux façons : son **IP interne et son port applicatif** (stable, jamais exposé, mais joignable seulement depuis le réseau Docker du conteneur) ou l'**hôte et le port publié** (joignable de partout sur le LAN, mais ce port est aléatoire quand le conteneur est publié en `:80` et change à chaque redémarrage).

L'Agent choisit aujourd'hui une seule adresse, d'après une règle fixe (hôte distant → port publié, hôte local → IP interne). Ça se trompe dès que la règle ne colle pas à la topologie : un conteneur de l'environnement « local » d'Arcane, qui n'est pas sur le réseau de la passerelle, reste rouge ; un réseau routable (macvlan, overlay, VPN) n'est pas exploité ; dans un groupe HA, deux passerelles sur des hôtes différents ne joignent pas les mêmes adresses. **Seule la passerelle sait ce qu'elle joint.**

## Décision

### L'Agent propose, la passerelle retient

La charge utile d'une route découverte gagne un champ optionnel `candidates` : les adresses du **même** conteneur, de la plus à la moins préférée.

1. IP interne du conteneur et port applicatif, pour chacun de ses réseaux ;
2. hôte (résolu en IP) et port publié.

`backends` reste l'adresse sûre d'aujourd'hui : une passerelle qui ne connaît pas `candidates` l'ignore et se comporte comme avant. Une étiquette `goproxify.backend` ou `goproxify.ip` désigne une seule adresse : pas de candidats, elle l'emporte comme toujours.

### Un backend porte ses candidats

`router.Backend` gagne `Candidates []string`. `URL` reste l'adresse **servie** : le chemin chaud du proxy ne change pas. À l'arrivée de la route, `URL` vaut `backends[0]` (l'adresse sûre) ; la sonde promeut ensuite un candidat préféré dès qu'il répond.

### Une sonde TCP par passerelle

Une boucle de la passerelle (toutes les 10 s, et tout de suite après l'arrivée d'une route à candidats) tente une connexion TCP vers chaque candidat (délai 1 s, au plus 32 sondes simultanées) :

- le **premier candidat joignable dans l'ordre de préférence** devient `URL` ;
- une **promotion** vers un candidat plus préféré est immédiate ;
- une **rétrogradation** (l'adresse servie ne répond plus) attend deux sondes ratées d'affilée, pour qu'une coupure de quelques secondes ne fasse pas basculer vers l'adresse publiée ;
- si **aucun** candidat ne répond, rien ne change : le conteneur est peut-être en train de redémarrer, et l'Agent republiera ses nouvelles adresses ;
- un candidat qui ne change pas ne réécrit pas la route : le choix de la passerelle survit aux réannonces de l'Agent (`mergeDiscoveryBackends`).

Chaque passerelle d'un groupe HA sonde pour elle-même : `core` peut servir l'IP interne et `backup` le port publié.

### Bornes

Au plus 8 candidats par backend. Seul TCP est sondé (pas de requête applicative : un 502 de l'application n'est pas une adresse injoignable). Les candidats ne sont pas équilibrés entre eux : un seul est servi à la fois, le pool à plusieurs conteneurs reste du ressort de l'équilibrage de charge existant.

### Portainer

Même règle pour un endpoint **distant** : `portainer.routable_networks` déclare les réseaux de conteneurs joignables ; le conteneur y propose son IP et son port applicatif avant son port publié. Un endpoint local garde la reprise du même hôte (passerelle connectée au réseau, IP interne servie). Une étiquette `backend` ou `ip`, et un conteneur à plusieurs routes, n'ont pas de candidats.

### Adresse de l'hôte : un port publié vaut mieux que l'IP interne pour un conteneur local

Un conteneur de l'hôte de l'Agent n'est pas forcément joint par son IP interne : celle-ci ne vaut que pour la passerelle de cet hôte, et dans un groupe HA les autres passerelles ne la joignent pas. Quand le conteneur **publie un port**, l'Agent le joint par **l'adresse de l'hôte et ce port**, atteignable par toutes les passerelles, sans étiquette `backend`. Sans port publié, l'IP interne reste (la passerelle de l'hôte rejoint le réseau).

L'Agent, dans son conteneur, ne voit que son adresse sur le réseau Docker. L'adresse de l'hôte vient de `host_address` (`GPX_HOST_ADDRESS`, IP ou nom) quand elle est configurée, sinon du nom de la machine que Docker rapporte (`GET /info`), résolu par le DNS (boucle locale et lien local écartés). Inconnue, l'IP interne est gardée. La règle vaut pour la découverte Docker locale, un endpoint Portainer local et l'environnement local d'Arcane ; elle ne touche ni une étiquette `backend` ou `ip`, ni un conteneur à plusieurs routes, ni une route TCP, et ignore un port publié sur la boucle locale seule.

### La passerelle de l'hôte est retrouvée seule

`network_management.edge_container_name` n'est plus nécessaire : le conteneur passerelle d'un hôte est celui qui porte l'adresse d'une passerelle de l'Agent, par son nom ou par l'IP qu'un nom ou un alias Docker désigne (une minute de cache : une passerelle recréée est retrouvée sans redémarrer l'Agent). Un nom configuré reste prioritaire. La connexion à un réseau est mémorisée par couple réseau et conteneur passerelle : une passerelle recréée est reconnectée.

### Arcane : rejoindre le réseau d'un conteneur de l'hôte de l'Agent

Quand le conteneur est sur le Docker de l'Agent (son identifiant y existe) et que la passerelle de l'hôte est connue (`network_management.edge_container_name`), l'Agent la **connecte au réseau Docker du conteneur**, comme il le fait pour Docker et pour un endpoint Portainer local. L'IP interne devient joignable par cette passerelle, et la sonde la retient.

## Conséquences

- Plus d'adresse à saisir pour les cas où l'IP interne est joignable (même hôte, réseau routable) : elle est retenue d'elle-même, et le port aléatoire n'a plus d'importance.
- Pour un hôte distant en réseau bridge classique, rien ne change : le port publié reste la seule voie, et l'Agent le rafraîchit à chaque sondage.
- Compatibilité : champ optionnel dans la charge utile et dans le backend ; une passerelle ancienne ignore `candidates`, un agent ancien n'en envoie pas. Rien à migrer.
- Coût : une connexion TCP par candidat et par backend toutes les 10 s depuis chaque passerelle ; avec 30 conteneurs à deux candidats, 60 connexions éphémères.

## Non retenu

- **Sonde faite par l'Agent** : il joint ce que *lui* joint, pas la passerelle (groupe HA sur plusieurs hôtes).
- **Plusieurs candidats servis comme un pool** : ils désignent le même conteneur, le trafic serait dupliqué entre deux chemins.
- **Rattrapage par échec de requête** (relire la source de l'Agent dès qu'un backend refuse) : utile, mais indépendant et plus intrusif dans le chemin chaud du proxy. À reprendre si l'intervalle de sondage de l'Agent ne suffit pas.
