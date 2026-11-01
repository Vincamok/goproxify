# ADR 0022 — Annexe : droits par service, niveaux par service, profils d'équipe

**Statut :** accepté le 2026-11-01 (catalogue et seize décisions validés un par un avec le propriétaire) ; rien n'est mis en œuvre.
**Objet :** lister les services que GoProxify propose, définir pour **chacun** ses niveaux possibles, puis en déduire des profils d'équipe. Le portail Access n'était qu'un exemple : il n'est qu'un service parmi d'autres, et il se découpe lui-même en huit.

---

## 1. Principe

Un accès d'équipe est un **périmètre** (sur quoi) et, pour chaque service, un **niveau** (que peut-on y faire). Il n'y a **pas de niveau global** : « Lecture seule » ne veut rien dire tant qu'on ne dit pas de quoi (les proxys ? les logs ? le portail ?). Chaque service a sa propre échelle de niveaux.

```
Équipe « Exploitation prod »
  Accès 1 — périmètre : étiquette env=prod
      Proxys = Exploitation · Logs d'accès = Lecture · Alertes = Acquittement · Portail = Aucun · …
  Accès 2 — périmètre : passerelle interne
      Infrastructure = Lecture · …
```

- Les niveaux d'un service sont **cumulatifs** : chacun comprend les précédents. « Aucun » (par défaut) donne rien.
- Trois classes de permissions :
  1. **courante** : dans un niveau ;
  2. **destructive ordinaire** (supprimer un proxy, un domaine, un certificat, une destination) : dans le niveau le plus haut du service, « Gestion » ;
  3. **sensible** : *exécute* (lance une commande ou du code, ou pilote une exécution), *expose* (secret, clé, IP réelle, contenu de session) ou *coupe des clients légitimes en masse*. **Jamais dans un niveau** : case à cocher à part, audit de chaque usage.
- Un service est de **ressource** (le périmètre s'applique) ou de **plateforme** (aucun périmètre possible : ses niveaux ne se donnent qu'à l'administrateur ou comme capacité).

Deux faits du code guident la conception :

1. **Les passerelles ont déjà `region`, `environment` et `tags`** (`GET /nodes/meta/environments`, `/regions`). « Production » et « test » existent donc côté passerelle ; seuls les proxys n'ont pas d'étiquette.
2. **Plusieurs objets sont partagés entre des proxys de domaines différents** (snippets, profils IP, fournisseurs d'authentification, modèles de pages d'erreur, détecteurs, plugins). Modifier l'un change des proxys **hors** du périmètre de celui qui le fait : leur écriture reste à la plateforme (décision D5).

**Lecture du mot « passerelle » (D3).** Dans les colonnes « Périmètre » de ce document, le critère « passerelle » se lit **« groupe de passerelles »** : le droit se donne sur un groupe (nom ou attributs `environment`, `region`, `tags`) et vaut pour tous ses membres, présents et futurs. La passerelle (le membre) n'est que la cible des actions du service Infrastructure.

## 2. Niveaux par service

Légende : *cumulatifs de gauche à droite* ; **Explicites** = permissions sensibles à cocher à part.

### 2.1 Trafic

| Service | Périmètre | Niveaux | Explicites |
|---|---|---|---|
| **Proxys et routage** (HTTP, TCP, UDP) | domaine, nom, backend, passerelle, étiquette | **Lecture** : liste, détail, labels, révisions, test de chemin → **Exploitation** : créer, modifier, activer/désactiver, mode maintenance, purge du cache → **Gestion** : supprimer | import de configuration tierce *(crée en masse)* |
| **Proxys : affiner par section** *(option)* — la fenêtre de modification d'un proxy suit une requête en sept étapes : Entrée, Sécurité, Routage, Transformation, Backends, Résilience, Observabilité | celui du proxy | pour chaque section : **Lecture** → **Modification**. Par défaut, « Proxys = Exploitation » vaut Modification de toutes les sections ; « affiner » permet, par exemple, à l'équipe sécurité de modifier la section Sécurité (WAF, débit, authentification, filtre IP) sans toucher aux backends | plugins WASM d'une route *(exécute du code)* |
| **Conteneurs découverts** (Docker, K8s, annuaires) | domaine, backend, passerelle | **Lecture** → **Exploitation** : désactiver la route d'un hôte, convertir en proxy | — |
| **Surface applicative** (apprentissage, OpenAPI) | celui du proxy | **Lecture** : rapport, propositions, OpenAPI → **Apprentissage** : accepter des suggestions, réinitialiser | `surface:enforce` *(passage en block : peut couper des clients légitimes)* |
| **Domaines** | domaine | **Lecture** → **Gestion** : créer, modifier, renouveler, supprimer | `domains:delegate` *(crée des proxys implicites sur d'autres passerelles)* |
| **Certificats** | domaine (noms du certificat) | **Lecture** → **Gestion** : obtenir, importer, renouveler, supprimer | `certs:deploy` *(exécute : webhook, `ssh_exec`)* · `certs:export_key` *(expose : clé privée, jetons de récupération)* |
| **Surveillance des domaines** (certificat émis hors de GoProxify, CAA, noms pendants) | domaine | **Lecture** : constats → **Acquittement** : accepter un constat | `domain_watch:configure` *(envoie des noms de domaine à des services extérieurs)* |

### 2.2 Observabilité

| Service | Périmètre | Niveaux | Explicites |
|---|---|---|---|
| **Logs d'accès** | domaine, passerelle (chaque ligne porte `Domain` et `NodeName`) | **Lecture** : recherche, direct, histogramme, facettes, corrélation → **Export** : export du volume | — *(l'export expose les IP réelles si le mode de protection n'est pas actif : voir D1)* |
| **Logs système et conteneurs** | passerelle | **Lecture** | — |
| **Tableau de bord, Prism, métriques, carte** (la « Vue Proxy » en est la synthèse par proxy) | domaine, passerelle | **Lecture** → **Gestion** : régler l'objectif de disponibilité (SLO) | — |
| **Alertes** (règles, événements, sourdines) | domaine et passerelles (portés par la règle) | **Lecture** → **Acquittement** : acquitter, mettre en sourdine → **Gestion des règles** : créer, modifier, supprimer des règles | — |
| **Canaux de notification** (e-mail, Slack, webhook, PagerDuty, SMS…) | plateforme (adresses et jetons sortants) | **Lecture** (secrets masqués) → **Gestion** : créer, modifier, supprimer | `alert_channels:test` *(envoie un message vers l'extérieur)* |
| **Journal d'audit** | plateforme | **Lecture** | — |

### 2.3 Sécurité

| Service | Périmètre | Niveaux | Explicites |
|---|---|---|---|
| **Sécurité réseau** : bans, menaces, CVE, inventaire d'applications, rejets à l'entrée, score par proxy, carte des attaques, traçage d'IP | passerelle (`edge_name` sur bans, menaces, CVE), proxy, domaine | **Lecture** : bans, menaces, CVE, inventaire, rejets d'entrée, score, posture → **Analyse** : traçage d'IP, lancer une analyse de CVE → **Réponse** : bannir, débannir, liste blanche | `bans:import` *(en masse)* |
| **Moteurs adaptatifs** (WAF, Ephor) | passerelle ou groupe HA | **Lecture** → **Simulation** : rejouer, calibrer (lecture seule) → **Réglage** : modifier seuils et listes | `engines:enforce` *(passer un signal en block : bannit des clients)* |
| **Snippets** (préréglages WAF, débit, filtre IP, en-têtes, réutilisés par plusieurs proxys) | plateforme (partagés) | **Lecture** | écriture : plateforme seule (D5, D16) |
| **Profils IP** (GeoIP, réputation) | plateforme (partagés) | **Lecture** | écriture : plateforme seule (D5, D16) |
| **Fournisseurs d'authentification** (SSO, OIDC, SAML, LDAP) et **détecteurs** | plateforme (partagés, avec secrets) | **Lecture** (secrets masqués) | écriture : plateforme seule (D5) |
| **Modèles de pages d'erreur** | plateforme (partagés) | **Lecture** | écriture : plateforme seule (D5, D16) |

### 2.4 Plateforme

| Service | Périmètre | Niveaux | Explicites |
|---|---|---|---|
| **Infrastructure** (passerelles, Agents, topologie, événements) | passerelle, désignée par nom **ou** par `environment`, `region`, `tags` | **Lecture** → **Classement** : nom affiché, région, environnement, étiquettes, rescan | `nodes:approve` · `nodes:update` *(met à jour ou revient en arrière : exécute)* · `nodes:configure` · `nodes:tunnel` · `nodes:delete` · `enrol:create` *(billets d'enrôlement, secret d'appairage : expose)* · `tokens:manage` · `architecture:write` *(nœuds déclarés, assistant d'architecture, historique et restauration)* |
| **Périmètre des passerelles** (quelles routes chaque passerelle reçoit : `token_scopes`, jetons d'appairage) | passerelle | **Lecture** | `tokens:manage` *(décide ce qu'une passerelle sert)* · `tokens:rotate` |
| **Haute disponibilité** (groupes HA, pairs, quorum) | passerelle ou groupe | **Lecture** | écriture : plateforme seule |
| **Réglages de la passerelle** (général, délais HTTP, métriques, tunnel L4) | passerelle | **Lecture** → **Réglage** : réglages généraux et délais HTTP | `nodes:tunnel` *(tunnel mTLS entre passerelles)* |
| **Sources de découverte** (Docker, Kubernetes, Consul, Nomad, etcd, ECS) | passerelle, Agent | **Lecture** | `discovery:write` *(donne accès à un orchestrateur)* |
| **Automatisation** (flux, règles, planifications, playbooks) | plateforme | **Lecture** : voir, simuler → **Édition** : créer, modifier | `automation:run` *(exécute des actions)* · `automation:approve` *(décide une exécution en attente)* |

### 2.5 Portail Access, en huit sous-services

Chacun a sa propre échelle ; tous ont pour périmètre la passerelle, et, quand l'objet en porte, l'étiquette et le nom de la destination.

| Sous-service | Niveaux | Explicites |
|---|---|---|
| **Demandes d'accès temporaires** | **Lecture** → **Décision** : approuver, refuser | — |
| **Sessions en direct** | **Lecture** → **Coupure** : terminer une session | `portal_sessions:observe` *(expose : sortie du terminal en direct)* |
| **Enregistrements** | **Liste** | `portal_recordings:replay` *(expose le contenu)* · `portal_recordings:delete` |
| **Catalogue** (destinations, groupes de destinations) | **Lecture** → **Gestion** : créer, modifier, supprimer | — |
| **Utilisateurs et groupes du portail** | **Lecture** → **Gestion** : inviter, modifier, supprimer | — |
| **Politiques** (plages horaires, IP autorisées, inactivité) | **Lecture** → **Gestion** | — |
| **Audit du portail** | **Lecture** | — |
| **Modèles, réglages, poussée** | **Lecture** → **Gestion** : modifier, pousser aux passerelles | — |

### 2.6 Administration (plateforme, aucun périmètre)

| Service | Niveaux | Explicites |
|---|---|---|
| **Sauvegardes** | **Liste** | `backups:create` · `backups:restore` *(remplace tout)* |
| **Autorité de certification interne, ECH, fournisseurs ACME et clés DNS** | **Lecture** | `pki:write` *(clés de signature, identifiants DNS)* |
| **Plugins WASM** | **Lecture** | `plugins:write` *(exécute du code dans le plan de données)* |
| **Réglages des logs, SIEM** | **Lecture** | `logs_settings:write` · `siem:write` *(jetons et adresses internes)* |
| **Comptes, équipes, accès MCP** | **Lecture** | `users:write` · `teams:write` *(accorder des droits)* |
| **Paramètres** (MFA, SMTP, adresse publique, apparence) | **Lecture** | `settings:write` |
| **Libre-service de tout compte** | profil, mot de passe, MFA, appareils de confiance, ses propres jetons API | aucune permission nécessaire |

### 2.7 RGPD : quatre capacités (équipe intégrée « DPO »)

Ce ne sont pas des niveaux : chacune est une case, car elles portent sur des personnes et non sur des ressources.

| Capacité | Effet |
|---|---|
| `gdpr:reveal` | révéler l'IP réelle d'une ligne pseudonymisée (motif obligatoire) |
| `gdpr:export` | export d'accès et de portabilité (Art. 15 et 20) |
| `gdpr:erase` | effacement par IP ou par utilisateur (Art. 17), y compris sur les passerelles |
| `gdpr:hold` | gel légal et export signé de l'historique |

Aujourd'hui seul `gdpr:reveal` est une permission distincte : l'export et l'effacement relèvent de `logs:write`, donc d'un administrateur.

## 3. Profils d'équipe : des préréglages de la grille

Un profil n'est **pas** un niveau. C'est un point de départ qui remplit la grille (service → niveau) de la fenêtre d'équipe ; l'équipe créée est ordinaire et modifiable. Un profil se combine avec un périmètre (production, test, un domaine, une passerelle).

Le vague « Lecture seule » est remplacé par des profils qui disent ce qu'ils lisent :

| Profil | Niveaux préréglés | Pour qui |
|---|---|---|
| **Lecture du trafic** | Proxys, Conteneurs, Surface, Domaines, Certificats, Logs d'accès, Prism et métriques, Alertes = Lecture | direction, support niveau 1 |
| **Lecture de la sécurité** | Sécurité réseau, Moteurs adaptatifs, Surface, Logs d'accès = Lecture | analyste en lecture |
| **Lecture du portail** | les huit sous-services du portail = Lecture (enregistrements : Liste) | responsable conformité |
| **Lecture de toute la plateforme** | tous les services de ressource et de plateforme = Lecture, sauf comptes, équipes, sauvegardes et paramètres | audit interne |
| **Exploitation** | Proxys = Exploitation, Conteneurs = Exploitation, Surface = Apprentissage, Domaines et Certificats = Lecture, Logs d'accès et Prism = Lecture, Alertes = Acquittement | équipe d'un environnement ou d'un projet |
| **Propriétaire de domaine** | Proxys = Gestion, Conteneurs = Exploitation, Surface = Apprentissage, Domaines et Certificats = Gestion, Logs d'accès = Lecture, Prism = Lecture, Alertes = Gestion des règles | responsable d'un domaine complet |
| **Sécurité (SOC)** | Sécurité réseau = Réponse, Moteurs = Simulation, Logs d'accès = Lecture, Prism = Lecture, Surface = Lecture, Proxys = Lecture, Alertes = Acquittement | analystes sécurité |
| **Certificats et PKI** | Domaines = Gestion, Certificats = Gestion, Proxys = Lecture | équipe en charge des certificats |
| **Infrastructure** | Infrastructure = Classement, Logs système = Lecture, Prism = Lecture, Alertes = Acquittement | équipe réseau et système |
| **Astreinte** | Proxys, Logs d'accès, Prism, Infrastructure, Sécurité réseau = Lecture, Alertes = Acquittement | astreinte sans droit de modification |
| **Auditeur** | Journal d'audit = Lecture + Lecture de toute la plateforme | audit externe |
| **Portail : support** | Demandes = Décision, Sessions = Coupure, Catalogue, Utilisateurs, Audit du portail = Lecture | helpdesk qui approuve les accès temporaires |
| **Portail : gestion** | Catalogue, Utilisateurs, Politiques, Modèles et réglages = Gestion, Demandes = Décision, Sessions = Coupure, Enregistrements = Liste, Audit = Lecture | responsable du portail |
| **Approbateur d'automatisation** | Automatisation = Lecture + `automation:approve` | valide les exécutions à risque |
| **DPO** *(intégrée, ADR 0021)* | capacités `gdpr:reveal`, `gdpr:export`, `gdpr:erase`, `gdpr:hold` | délégué à la protection des données |
| **Équipe vide** | tout = Aucun | départ de zéro |

**Production et test** ne sont pas des profils mais deux périmètres : « Exploitation prod » = Exploitation × `env=prod`, « Exploitation test » = Exploitation × `env=test`.

## 4. Fenêtre d'équipe

Une grille : une ligne par service, un sélecteur de niveau (Aucun par défaut), les permissions explicites en cases à cocher sous la ligne concernée (marquées « sensible »). Les services sont regroupés comme le menu de l'Admin (Trafic, Observabilité, Sécurité, Plateforme, Portail, Administration). Chaque accès affiche son périmètre et la prévisualisation « couvre N proxys ». Le choix d'un profil remplit la grille.

## 5. Décisions (toutes tranchées le 2026-11-01, une à une avec le propriétaire)

| # | Décision |
|---|---|
| D1 | **Quatre capacités RGPD** : `gdpr:reveal`, `gdpr:export`, `gdpr:erase`, `gdpr:hold`, chacune se donne séparément ; l'équipe DPO les porte toutes. |
| D2 | **Trois classes de permissions** : courantes (dans un niveau), destructives ordinaires (dans « Gestion » du service), sensibles (case à part, usage audité). |
| D3 | **Le périmètre désigne des groupes de passerelles**, pas des passerelles : un droit sur un groupe vaut pour tous ses membres, présents et futurs (ADR 0014 : une passerelle isolée est un groupe d'un membre). Désignation **par nom (glob) ou par attributs du groupe** (`environment`, `region`, `tags`), combinables par ET. Les attributs se posent sur le groupe. Un périmètre sans groupe est une vue globale de l'Admin. La passerelle (le membre) reste l'objet des actions du service Infrastructure (mise à jour, jeton, suppression), limitées aux groupes du périmètre. |
| D4 | **Étiquettes des proxys** : toute équipe qui peut modifier un proxy peut poser ses étiquettes, sous la règle « dans le périmètre avant et après » ; chaque changement est audité. |
| D5 (+D16) | **Objets partagés** (snippets, profils IP, fournisseurs d'authentification, détecteurs, pages d'erreur, plugins) : lecture pour les équipes qui les utilisent, **écriture à la plateforme seule**. Pas de propriété par équipe pour l'instant. |
| D6 | **Séparation des tâches** : on ne peut pas approuver sa propre demande d'accès au portail, ni valider l'exécution d'un flux qu'on a déclenchée. |
| D7 | **Jetons API** : un jeton choisit des permissions du catalogue (les 26 scopes deviennent des groupes) ; pouvoir réel = permissions du jeton ∩ celles du compte, avec le **périmètre du compte** (pas de périmètre propre au jeton). |
| D8 | **Lectures de base supprimées pour un utilisateur** : un compte `user` sans accès ne voit rien, hormis son libre-service. Les administrateurs voient tout. |
| D9 | **Journal d'audit** : plateforme seule (permission « Audit : lecture » sans périmètre), filtrage par périmètre reporté. |
| D10 | **Garde CI** : toute route, tout outil MCP et toute commande CLI déclarent leur service, leur permission et, si besoin, leur descripteur de ressource, sinon la CI échoue ; la règle entre dans la liste de documentation obligatoire de `CLAUDE.md`. |
| D11 | **Niveaux propres à chaque service, cumulatifs**, « Aucun » par défaut ; aucun niveau global. Les profils ne sont que des préréglages de la grille. |
| D12 | **Le portail Access se découpe en huit sous-services**, chacun avec son échelle ; observer une session en direct et rejouer un enregistrement sont des cases sensibles. |
| D13 | **Fenêtre d'équipe : grille service × niveau et profils** comme préréglages, services regroupés comme le menu de l'Admin, permissions sensibles en cases sous la ligne. |
| D14 | **Plusieurs accès par équipe** : un accès = un périmètre + sa grille de niveaux ; les droits des accès s'additionnent. |
| D15 | **Droits par section d'un proxy, en option** : « Exploitation » couvre toutes les sections par défaut ; « affiner par section » permet Lecture ou Modification pour chacune (le rattachement des champs de configuration aux sections reste à établir). |
