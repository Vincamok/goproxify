# ADR-0006 — Autonomie des composants (passerelle, groupe HA, Agent)

**Statut :** Accepté  
**Date :** 2026-09-29  
**Complète :** ADR-004 (cache local de la passerelle), ADR-0005 (plan de contrôle WebSocket)

---

## Contexte

L'ADR-004 pose que la passerelle doit servir le **trafic** sans l'Administration, même après un redémarrage. Le principe n'était écrit ni pour les autres fonctions de la passerelle, ni pour les groupes HA, ni pour l'Agent.

Conséquence observée : la configuration du portail Access n'existe qu'en base Admin et en mémoire de la passerelle. Si une passerelle redémarre pendant une coupure de l'Admin, le portail ne redémarre pas, alors que ses comptes et ses coffres sont sur le disque.

---

## Décision

Chaque composant fonctionne seul avec ce qu'il a déjà reçu. Une coupure n'enlève que ce qui dépend directement du composant absent.

1. **Admin** : point de modification et de supervision, jamais point de passage du service. Tout ce qu'il envoie, la passerelle en garde une copie locale chiffrée.
2. **Passerelle** : fait tourner tout ce qui lui est confié (trafic, certificats, Sentinel, portail Access…) sans l'Admin, **y compris après un redémarrage pendant la coupure**. Rien de nécessaire au fonctionnement ne doit exister uniquement en base Admin ou en mémoire de la passerelle.
3. **Groupe HA** : les membres se connaissent et se synchronisent entre eux sans l'Admin (liste des pairs, clé de groupe, magasins répliqués), y compris après un redémarrage.
4. **Agent** : dépend uniquement de sa passerelle, jamais de l'Admin. Sa configuration, son jeton et son HMAC sont locaux. Ses fonctions locales (santé, redémarrage, scaling, mises à jour d'image) tournent sans passerelle ni Admin. S'il tombe, seules ses propres fonctions s'arrêtent : ses conteneurs continuent de recevoir le trafic.
5. **Reprise** : au retour d'un composant, la resynchronisation est complète et idempotente (full_sync Admin → passerelle, réannonce de tous les conteneurs Agent → passerelle), sans action manuelle.

**Test à appliquer à toute fonctionnalité :** « si X redémarre alors que Y est injoignable, qu'est-ce qui s'arrête ? ». La réponse doit être : uniquement ce que Y fait lui-même.

---

## Comportement attendu par coupure

| Coupure | Ce qui continue | Ce qui s'arrête (et seulement cela) |
|---|---|---|
| **Admin injoignable** | Trafic, certificats, Sentinel et bans, portail Access, découverte des conteneurs (l'Agent parle à la passerelle), réplication HA | Modifications de configuration, supervision et historique dans l'UI, approbation de nouveaux Agents, commandes vers les Agents (rescan, configuration, shell depuis l'Admin) |
| **Passerelle d'un Agent injoignable** | Conteneurs de l'hôte, fonctions locales de l'Agent (santé, scaling, mises à jour) ; les autres membres du groupe HA servent le trafic | Publication des changements de conteneurs, métriques du LB adaptatif, événements, logs, shell. Au retour : réannonce complète par l'Agent |
| **Agent arrêté** | La passerelle continue de router vers les conteneurs connus (routes conservées dans sa table et son cache) ; l'Agent est affiché hors ligne après 90 s | Découverte (conteneur ajouté ou arrêté non vu), scaling, redémarrage et mises à jour automatiques, métriques du LB adaptatif, logs, accès portail et shell aux conteneurs de cet hôte |
| **Un membre d'un groupe HA tombe** | Les autres membres servent le trafic et le portail (magasin répliqué) | La capacité de ce membre uniquement |

---

## État au 2026-09-29

### Conforme

- Routes (y compris celles découvertes par les Agents), certificats, snippets et fournisseurs d'authentification : cache chiffré `edge-cache.gpx`, rechargé au démarrage sans Admin.
- Bans, profils IP, listes de menaces, configuration CrowdSec et fail2ban, pages d'erreur : sur le disque de la passerelle.
- Réglages runtime (`push_settings` : anonymisation / pseudonymisation des IP, journalisation, tracing, URL publique) : copie chiffrée `edge-settings.gpx`, rechargée au démarrage (Edge `0.17.10`).
- Portail : comptes, coffres, catalogue et audit dans `portal.gpx` (chiffré, répliqué dans le groupe HA).
- HMAC des Agents approuvés persisté des deux côtés : un Agent se reconnecte à une passerelle redémarrée sans l'Admin.
- Agent : `agent.json`, `agent.token` et HMAC locaux ; santé, scaling et mises à jour sans passerelle ni Admin.
- Agent hors ligne : seul son statut change, ses routes restent actives.

### Écarts (suivis dans `suivi/roadmap-public.md`)

- **Portail Access** : configuration, politiques, accès temporaires et clé de groupe HA en mémoire seulement → portail arrêté après un redémarrage sans Admin.
- **Groupe HA** : liste des pairs de synchronisation (`push_gateway_peers`) et topologie Raft poussée par l'Admin (en l'absence de `cluster.peers` local) en mémoire seulement → plus de synchronisation entre pairs après un redémarrage sans Admin.
- **Agent** : un changement de conteneur survenu pendant une coupure de sa passerelle est perdu (envoi HTTP unique, pas de réannonce à la reconnexion) jusqu'au prochain rescan.
- **Agent rattaché à un groupe HA** : ne connaît qu'une adresse de passerelle (`control_plane.edge_endpoint`) ; le rattachement au groupe n'existe que côté Admin. Pas de bascule vers un autre membre, sauf si l'adresse est une IP virtuelle.
- **Challenges ACME HTTP-01 / TLS-ALPN-01** : posés par l'Admin en RAM sur la passerelle (15 min), jamais persistés ; l'émission et le renouvellement exigent l'Admin et une passerelle connectée, comme DNS-01. Un certificat déjà poussé reste servi sans l'Admin.
- **Clés ECH** : poussées par l'Admin et conservées dans le cache chiffré de chaque passerelle (fonctionnent sans l'Admin, après redémarrage) ; en revanche pas de réplication entre membres d'un groupe HA sans l'Admin.
- **Autres envois de l'Admin** (règles automatiques, tunnel L4, modèles du portail, configuration serveur) : persistance à vérifier un par un.

---

## Conséquences

- Toute nouvelle donnée envoyée par l'Admin à la passerelle doit préciser où elle est persistée côté passerelle et comment elle est rechargée au démarrage.
- La base Admin reste la source de modification ; la copie de la passerelle est une copie de fonctionnement, remplacée à chaque envoi de l'Admin.
- Les secrets conservés par la passerelle (clé de groupe HA, clés privées) sont chiffrés par sa clé maître.
