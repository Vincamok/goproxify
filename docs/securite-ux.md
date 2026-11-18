# Menu Sécurité — refonte ergonomique : inventaire de parité et architecture

Ce document accompagne la refonte des interactions du menu **Sécurité** (Admin `0.272.0`, étendu en `0.273.0`). Il fait foi pour la règle de parité : **aucune fonctionnalité du menu n'a été retirée**. Il liste ce que fait chaque onglet, la mécanique d'interaction retenue, comment la fonction reste accessible, et où en est la refonte.

Périmètre : les sept onglets de l'Admin (Synthèse, Vulnérabilités, Bans, Traçage IP, Référentiel, Ephor, Score par proxy) et leurs variantes de passerelle (`edge-security*`, mêmes pages en mode `edge`), la fenêtre « Moteurs de sécurité » et les fenêtres ouvertes depuis Bans. Les règles d'automatisation (`security-rules`) appartiennent au menu Automatisation et ne sont pas touchées.

Maquette : `prive/maquettes/securite-ux.html` (non publiée) est une démonstration autonome (données d'exemple, sans serveur) de l'organisation du menu, et **l'interface réelle la reproduit** depuis l'Admin `0.274.0` : quatre espaces par intention — **Synthèse**, **Menaces** (Bans, Traçage IP, Référentiel), **Défenses** (Ephor, Moteurs), **Exposition** (Vulnérabilités, Score par proxy) — avec la palette `Ctrl+K`, l'annulation et le glisser-déposer. Chaque ligne de l'inventaire ci-dessous y a son équivalent. Les écarts avec la maquette sont listés en fin de document (§4).

Méthode : l'inventaire vient de la lecture de `security-synthese.js`, `security.js`, `bans.js`, `ip-trace.js`, `attack-ref.js` et `ephor.js` (fonctions, gestionnaires `window.*`, appels API). La colonne **Statut** distingue ce qui est refait dans cette livraison de ce qui est conservé tel quel.

## Principes d'interaction

| Principe | Application |
| --- | --- |
| Une IP est un objet | Partout où une IP s'affiche (Bans, Ephor, CrowdSec), elle se glisse vers une zone d'action, ou se clique (clavier : Entrée) pour ouvrir un menu d'actions. |
| Saisir plutôt que remplir | Une IP ou un CIDR et une durée se tapent d'un trait (`203.0.113.0/24 7j`) ; les durées acceptent `90min`, `36h`, `3j`, `2sem`, `perm`. |
| Pas de confirmation, une annulation | Lever, prolonger, rendre permanent, autoriser, corriger une CVE, changer un réglage d'Ephor : l'action s'applique et un toast propose **Annuler** (9 s), ou `Ctrl+Z`. La confirmation ne reste qu'au-delà de 20 bans d'un coup. |
| Éditer là où on lit | Une expiration, une valeur d'Ephor, le mode d'un signal se modifient dans la ligne ou le chip qui les affichent. |
| Divulgation progressive | Les formulaires complets restent, derrière « Plus d'options… » ou l'engrenage d'un chip. |
| Un point d'entrée unique | La palette `Ctrl+K` / `/` existante reçoit des **actions contextuelles** sur les pages Sécurité. |

## 1. Inventaire de parité

Statuts : **Refait** = nouvelle mécanique livrée et testée ; **Conservé** = fonction intacte, présente dans l'interface actuelle, refonte prévue ; **Étendu** = fonction intacte, avec une mécanique en plus.

### Transverse (toutes les pages Sécurité)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Palette de pages `Ctrl+K` | Inchangée | `Ctrl+K`, `/` | Conservé |
| Actions sur une IP depuis la palette | Coller une IP (+ durée) : Bannir (dernière durée, ou durée saisie), 1 h, 24 h, 7 j, à vie, Toujours autoriser, Lever le ban, Prolonger 24 h, Rendre permanent, Tracer, Historique, Prism | `Ctrl+K` puis coller | Nouveau |
| Actions de page depuis la palette | Nouveau ban, Importer, Liste blanche, ASN, Export CSV, Moteurs de sécurité (Synthèse), Réglages d'Ephor, Scan (Vulnérabilités), Référentiel, Actualiser | `Ctrl+K` puis taper le nom | Nouveau |
| Glisser une IP vers une action | Barre de dépôt : Bannir 1 h / 24 h / à vie, Toujours autoriser, Tracer. Un texte d'IP sélectionné se glisse aussi | Glisser une IP ou un texte | Nouveau |
| Menu d'actions d'une IP | Même liste, au clic ou à Entrée (tactile et clavier) | Cliquer l'IP | Nouveau |
| Annuler la dernière action | Toast + `Ctrl+Z` (10 min, 20 actions) | Toast, `Ctrl+Z` | Nouveau |
| Bandeau « passerelle » (mode edge), vue Admin / passerelle | Inchangé | — | Conservé |

### Synthèse (`security`, `edge-security`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Actualiser | Inchangé | Bouton ↺ ; palette « Actualiser la page » | Conservé |
| Ouvrir « Moteurs de sécurité » | Inchangé | Engrenage, carte Moteurs, palette | Étendu |
| Score de sécurité (anneau, 50 % CVE / 30 % en-têtes / 20 % certificats) et ses 3 repères | Inchangé | — | Conservé |
| 4 tuiles cliquables (bans actifs, menaces CrowdSec, CVE critiques, certificats) | Inchangé | Clic → Bans / Bans onglet CrowdSec / Vulnérabilités / Score par proxy | Conservé |
| Carte des moteurs (Ephor, WAF, Seuils multi-passerelles, CrowdSec, Règles) | Inchangé | Clic sur un moteur | Conservé |
| Carte des attaques : Direct on/off, mode Erreurs / IP bannies, style Zones / Villes / Régions, lien Prism | Inchangé | Boutons de la carte | Conservé |
| Top pays, détail pays / ville au clic, fermer le tiroir | Inchangé | Clic sur la carte ou le classement | Conservé |
| Flux en direct (regroupement ×N), masquer le trafic interne | Les IP du flux sont actionnables (le flux se fige pendant un glissement) | Interrupteur ; IP | Étendu |
| Activité 24 h (graphique, infobulle) | Inchangé | Survol | Conservé |
| Bans par source, Menaces principales, avec lien vers Bans | Inchangé ; l'IP d'une menace est actionnable | Liens de carte ; IP | Étendu |
| Classement passerelles / backends par risque CVE | Inchangé | Lien Vulnérabilités | Conservé |
| Posture (en-têtes, certificats valides / bientôt / expirés) | Inchangé | Lien Score par proxy | Conservé |
| Chronologie filtrable (Tous, Ban, Menace, CVE, Certificat) et « plus » | Inchangé ; l'IP d'un événement est actionnable | Puces ; IP | Étendu |

### Fenêtre « Moteurs de sécurité »

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Ephor : maître, 8 capacités (bloquer, listes IP / UA / path, débit, erreurs, limite globale, tarpit) ; une capacité numérique réactivée demande sa valeur (jamais devinée) | Une capacité numérique déjà active (débit, erreurs, limite globale) se modifie **sur place** (Entrée enregistre, Échap annule, annulable) ; la réactiver reste une saisie explicite | Fenêtre, onglet Ephor ; clic sur la valeur ; palette | Refait |
| Réglages détaillés d'Ephor | Les 12 sections sont les sous-entrées de l'entrée Ephor, à côté de l'aperçu des 8 capacités : un seul endroit pour allumer, régler et simuler Ephor | Moteurs › Ephor › Aperçu / sections | Refait |
| **Listes** (nouvelle entrée des moteurs) | Réunit ce qu'on confondait : **listes de référence** (IP connues, User-Agents, chemins : interrupteurs et rafraîchissement), **bloqués par Ephor** (IP, User-Agents, chemins, empreintes TLS : puces à ajouter, modifier sur place, retirer), **exceptions d'Ephor** (ce qu'il n'évalue jamais) et **liste blanche des bans** (adresses qu'aucun ban n'atteint). Chaque ajout s'applique tout de suite et s'annule ; les enregistrements du formulaire d'Ephor ne les touchent pas | Moteurs › Listes ; palette | Refait |
| WAF : maître, proxies protégés, requêtes signalées 24 h, top règles / domaines | Inchangé | Onglet WAF | Conservé |
| Seuils multi-passerelles : maître, XFF, ban permanent / durée, fenêtre fixe, formulaire avancé | La durée d'un ban temporaire (heures) se modifie **sur place** avec annulation ; activer une durée ou une limite éteinte demande toujours une valeur | Onglet Seuils ; clic sur la valeur | Refait |
| CrowdSec : maître, LAPI, formulaire avancé (URL, clé) | Inchangé | Onglet CrowdSec | Conservé |
| Règles : interrupteur par règle, lien vers Automatisation (Admin) | Inchangé | Onglet Règles | Conservé |
| Domaines : maître, 3 contrôles (CT, CAA, noms pendants), Analyser maintenant, constats à Reconnaître (Admin) | Inchangé | Onglet Domaines | Conservé |
| Scan : IP privées autorisées, SLA par gravité (4 champs) | Inchangé | Onglet Scan | Conservé |

### Vulnérabilités (`security-vulns`, `edge-security-vulns`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Lancer un scan, état « en cours », suivi de progression (mode passerelle) | Inchangé ; aussi dans la palette (page de passerelle) | Bouton ; palette | Étendu |
| 5 tuiles (critiques, KEV, élevées, ouvertes + retard SLA, passerelles / backends + risque) | Inchangé | — | Conservé |
| Vues Parc / Liste (mémorisée), recherche, filtre statut, filtre passerelle (Admin) | Inchangé | Barre d'outils | Conservé |
| Puces de gravité (Toutes, Critique, Élevée, Moyenne, Faible) et KEV | Inchangé | Puces | Conservé |
| Cartes du parc, dépliage d'une unité, liste des CVE | Inchangé ; chaque ligne de CVE se **glisse** vers Corrigée / Ignorée / Rouverte (annulable) et s'ouvre à Entrée | Clic ; glisser | Étendu |
| Tiroir d'une CVE (CVSS, statut, KEV, description, backend, application, EPSS, SLA, dates, lien NVD) | Inchangé | Clic sur une ligne | Conservé |
| Corriger / Ignorer / Rouvrir une CVE | Sans confirmation, avec **Annuler** (statut précédent remis) | Boutons du tiroir ; `Ctrl+Z` | Refait |
| Panneau du scanner : couverture, IP privées autorisées (mode passerelle) | Inchangé | Section dépliante | Conservé |

### Bans (`security-bans`, `edge-security-bans`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Créer un ban (IP / CIDR, domaine, motif, expiration, portée passerelle ou groupe HA, mesure d'impact) | **Barre d'ajout rapide** en tête : coller l'IP, durée en puces (1 h, 24 h, 7 j, 30 j, ∞, mémorisée) ou tapée (`7j`), mesure d'impact affichée en direct, Entrée bannit. Le formulaire complet reste à « Plus d'options… », prérempli | Barre ; bouton « + Ban » ; palette ; glisser une IP | Refait |
| Saisie assistée | Suggestions : IP des détections CrowdSec et des bans expirés | Champ de la barre | Nouveau |
| Mesure d'impact avant ban (trafic récent, réussites coupées, avertissements) | Sous la barre dès qu'une cible valide est saisie ; bouton d'aperçu du formulaire complet conservé | Automatique | Étendu |
| Lever un ban | Sans confirmation, **Annuler** recrée le ban (source, motif, domaine, expiration, portée) | Icône ; menu d'IP ; palette ; glisser | Refait |
| Prolonger de 24 h / rendre permanent | Icônes conservées ; l'expiration devient en plus **éditable sur place** | Icônes, ou clic sur la colonne « Restant » | Refait |
| Modifier l'expiration | Fenêtre sur la cellule : prolonger de 1 h / 24 h / 7 j / 30 j, « expire dans » libre (`36h`), permanent | Clic sur « Restant » | Nouveau |
| Sélection multiple, prolonger / permanent / lever en lot | Sans confirmation jusqu'à 20 bans, avec **Annuler** | Cases à cocher, barre de lot | Refait |
| Tuiles (actifs, expirent < 1 h, permanents, récidivistes, ratio déban / ban) filtrantes | Inchangé | Clic | Conservé |
| Analyses : bans par heure 48 h, origine géographique, par source, par passerelle / domaine, raisons fréquentes (filtrantes) | Inchangé | Clic sur un classement | Conservé |
| Onglets Actifs / Historique / CrowdSec avec compteurs | Inchangé | Onglets | Conservé |
| Recherche, filtre passerelle, puces Source, puces Durée (< 1 h, temporaires, permanents, récidivistes) | Inchangé | Barre | Conservé |
| Filtres enregistrés (appliquer, enregistrer, supprimer) | Le nom se saisit **sur place** au lieu d'une fenêtre `prompt()` | Sélecteur, bouton Enregistrer | Refait |
| Tri par colonne, « Afficher plus » | Inchangé | En-têtes | Conservé |
| Marqueurs de ligne : ×N récidives, Exempté, portée, signaux, User-Agent | Inchangé | — | Conservé |
| Voir dans Prism, Tracer, Historique de l'IP (chronologie + profil WAF Ephor + lien traçage) | Inchangé ; Tracer et Historique aussi dans le menu d'IP | Icônes ; menu d'IP | Étendu |
| Bandeau ASN (lever par ASN, afficher / masquer les plages) | Inchangé | Bandeau | Conservé |
| Bannir un ASN (recherche numéro / IP / nom, impact, motif, expiration, portée) | Inchangé | « + ASN » ; palette ; Traçage IP | Conservé |
| Importer une liste (bans ou liste blanche, texte / CSV / JSON, analyse à blanc, rejets / ignorés) | Inchangé | « Importer » ; palette | Conservé |
| Liste blanche (voir, retirer, ajouter avec commentaire) | Retirer sans confirmation, **annulable** (le commentaire revient) ; plus **Toujours autoriser** d'une IP en un geste | « Liste blanche » ; glisser ; menu ; palette | Refait |
| Export CSV | Inchangé | « Export CSV » ; palette | Conservé |
| Historique des bans expirés | Inchangé ; IP actionnables | Onglet Historique | Étendu |
| Onglet CrowdSec : recherche, tri (liste et colonnes), puces de type, tableau (IP + Tracer, scénario, origine, type, passerelle, occurrences, date) | Inchangé ; l'IP devient actionnable | Onglet | Étendu |
| Actualiser | Rechargement **sans écran de chargement** après une action ; bouton conservé | Bouton ↺ | Étendu |

### Traçage IP (`security-trace`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Cible IP / CIDR, bouton Analyser, ouverture depuis les autres pages (`openIPTrace`) | La cible accepte « adresse durée » (`203.0.113.7 7j`, `… 90j`, `… tout`) qui fixe la période ; **coller une adresse** sur la page lance le traçage ; l'IP du résultat est actionnable (bannir, autoriser) ; « Tracer » est dans tous les menus d'IP | Champ ; collage ; menu d'IP ; palette | Étendu |
| Filtre passerelle, période (24 h, 7 j, 30 j, 90 j, 1 an, tout, personnalisée) | Inchangé | Puces et segments | Conservé |
| Élargir à la plage, barre ASN (IP seule / ASN entier / bannir l'ASN) | Inchangé | Boutons du résultat | Conservé |
| Résumé, graphique par jour, chronologie, ordre, « charger plus » | Inchangé | — | Conservé |

### Référentiel (`security-attack-ref`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Lancer le passage, dernier passage, seuils, avertissement dégradé, suivi automatique | Inchangé ; aussi dans la palette | Bouton ; palette | Étendu |
| 3 tuiles (dossiers, candidats, rejetés) | Inchangé | — | Conservé |
| Entrées : filtres type et statut, tableau, Rejeter / Restaurer | Rejeter / Restaurer sans attente, annulable ; la ligne se **glisse** vers Rejeter / Restaurer | Segments, bouton de ligne, glisser | Refait |
| Dossiers : filtre de profil, tableau, dossier dépliable (profils, User-Agent, signaux, WAF, chemins) | Inchangé ; l'IP du dossier est actionnable (le clic dessus n'ouvre pas le dossier) | Clic sur la ligne ; IP | Étendu |

### Ephor (`security-ephor`, `edge-security-ephor`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| En-tête (actif, Block / Detect, groupe HA), bouton Réglages | Les étiquettes suivent les changements sur place | Bouton | Étendu |
| 4 tuiles, avertissement du mode detect | Inchangé | — | Conservé |
| Mode, Score seuil, Durée du ban, Débit par IP, Erreurs 4xx, Limite globale, Tarpit | **Édition sur place** : cliquer la valeur, Entrée enregistre, Échap annule, **Annuler** dans le toast. Mode et Tarpit basculent d'un clic. `7j` devient `168h`. L'engrenage ouvre la section complète | Chips de la vue d'ensemble | Refait |
| Score par IP (seuil, demi-vie) | Chip qui ouvre la section du tiroir | Chip | Conservé |
| Décisions récentes, IP récidivistes (IP actionnables), lien « Voir tous les bans » | Inchangé ; IP déplaçables | — | Étendu |
| Tableau des 13 détections avec « Régler » | Inchangé | Onglet Détections | Conservé |
| 16 signaux de comportement : mode | **Commutateur à trois positions** `off / detect / block` par signal, enregistré à chaque clic, annulable | Onglet Détections | Refait |
| Références du trafic, empreintes TLS proposées (« Ajouter à la liste »), références apprises, seuils proposés (« Appliquer ») | Inchangé | Onglet Détections | Conservé |
| Listes de référence, listes personnalisées, exceptions, profil WAF (passerelle) | **Fusionnés dans une seule entrée « Listes »** de la page Moteurs (voir plus bas) ; la vue d'ensemble d'Ephor n'en garde qu'un résumé avec « Gérer les listes » ; le profil WAF reste un lien dans ce résumé (passerelle) | Moteurs › Listes ; résumé de la vue d'ensemble | Refait |
| Réglages d'Ephor (12 sections : Général, Détection, Comportement, Défi, Seuils, Leurres, Hôte inconnu, Énumération, Empreintes TLS, Référence saisonnière, Anti-DDoS, Riposte), interrupteur d'activation, Simuler (1 h / 6 h / 24 h / 7 j), Enregistrer | **Le tiroir disparaît : ses réglages deviennent la page Moteurs › Ephor.** Une section à la fois (navigation à gauche), chacune avec sa phrase d'explication et ses champs sur deux colonnes ; une **barre collante** (Simuler, Annuler, Enregistrer) apparaît dès qu'un champ change ; l'enregistrement s'annule ; les chips de la vue d'ensemble et « Réglages » y mènent, la section visée ouverte | Page Moteurs › Ephor ; engrenage d'un chip ; palette | Refait |
| Profils WAF comportementaux (passerelle) | Inchangé | Liens depuis Ephor | Conservé |

### Score par proxy (`security-posture`, `edge-security-posture`)

| Fonction | Mécanique | Accès | Statut |
| --- | --- | --- | --- |
| Recherche, tri (5 critères), filtres (tous, incomplets, complets, faibles…) | Inchangé | Barre d'outils | Conservé |
| Cartes par proxy : note et contrôles, détail et correctif d'un en-tête, ouverture du proxy et de sa sécurité | Inchangé ; la **carte entière** ouvre la sécurité du proxy (Entrée au clavier) | Clic sur la carte | Étendu |

## 2. Architecture visuelle et composants

```
┌────────────────────────── Page Sécurité (onglets existants) ──────────────────────────┐
│  [Barre d'ajout rapide]   (Bans)                                                       │
│  Synthèse · Vulnérabilités · Bans · Traçage IP · Référentiel · Ephor · Score par proxy │
│  zone de travail : listes, tuiles, tiroirs (inchangés)                                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
 ░ Barre de dépôt (apparaît au glisser d'une IP) : 1 h · 24 h · à vie · autoriser · tracer
 ░ Toasts « Annuler »  ·  Menu d'IP / fenêtre d'expiration (flottants)  ·  Palette Ctrl+K
```

Le noyau est un seul fichier, `internal/admin/ui/src/js/shared/sec-ux.js`, qui expose `SecUX`. Les pages l'appellent ; il ne connaît aucune page, sauf pour se recharger (`refresh`).

| Composant (dans `SecUX`) | Rôle | Utilisé par |
| --- | --- | --- |
| `parseTarget`, `parseDur`, `durLabel`, `goDuration` | Validation d'une IP / d'un CIDR (IPv4 et IPv6), lecture d'une durée libre, durée au format Go pour Ephor | Barre rapide, palette, expiration, Ephor |
| `remember` + pile d'annulation | Toast avec **Annuler**, `Ctrl+Z`, 20 entrées sur 10 minutes | Toutes les actions |
| `ban`, `unban`, `setExpiry`, `extend`, `allow` | Actions sur `/security/bans` et `/security/bans/whitelist` ; chacune enregistre son annulation | Barre, menu, dépôt, palette, lignes |
| `ipHTML`, `ipMenu`, glisser-déposer | IP déplaçable et actionnable ; barre de dépôt ; menu | Bans, CrowdSec, Ephor |
| `expiryPop` | Fenêtre d'édition d'une expiration | Colonne « Restant » |
| `quickBanHTML` et `quick*` | Barre d'ajout rapide, mesure d'impact, suggestions | Page Bans |
| `editInline` | Remplace une valeur par un champ (Entrée enregistre, Échap annule) | Chips d'Ephor |
| `paletteProvider` via `window.gpxPaletteProviders` | Actions contextuelles dans `Ctrl+K` | Pages Sécurité |

Intégration dans l'existant :

| Fichier | Changement |
| --- | --- |
| `shared/sec-ux.js` (nouveau) | Le noyau. Chargé après `ban-signals.js` dans `index.html` |
| `core/search.js` | Point d'extension `gpxPaletteProviders` : les actions passent avant les pages ; une IP saisie ne montre que ses actions ; `searchOpen` exécute une action |
| `pages/bans.js` | Barre rapide, IP actionnables, colonne « Restant » éditable, lot et prolonger via `SecUX`, rechargement silencieux `bnQuietReload`, nom d'un filtre saisi sur place |
| `pages/security.js` | `deleteBan` et `makeBanPermanent` sans confirmation, annulables ; `openBanModal({ ip, ms })` prérempli ; `vsSetStatus` annulable ; IP CrowdSec actionnables |
| `pages/ephor.js` | Chips éditables, commutateur de signal, tiroir et en-tête resynchronisés, `sentPatch` |
| `css/components.css` | Styles `.secux-*` |
| `shared/i18n.js` | `search.scope.action` (4 langues) |

Aucune route, aucun outil MCP ni aucune commande CLI n'est ajouté : la refonte n'utilise que l'API existante (`POST/PATCH/DELETE /security/bans`, `/security/bans/whitelist`, `/security/bans/preview`, `PUT /security/threat-config`, `PATCH /security/cves/{id}`). Le catalogue de droits (`internal/admin/rbac/catalog.go`, `rights.go`) est inchangé : chaque action garde la permission de sa route.

Limites connues de l'annulation :

- Annuler un déban **recrée** le ban avec un nouvel identifiant ; l'historique garde le déban et le nouveau ban. Le compteur d'escalade d'Ephor remis à zéro par un déban manuel ne revient pas.
- Une annulation qui échoue (par exemple, la cible est maintenant en liste blanche) affiche l'erreur du serveur et ne change rien.
- Le glisser-déposer n'existe pas au toucher : le menu d'IP, la barre rapide et la palette couvrent les mêmes actions.

## 3. Ce qui reste

| Élément | Mécanique envisagée | Pourquoi pas encore |
| --- | --- | --- |
| Ephor, réglages | Sections les plus utilisées en chips sur la page | Les 12 sections sont déjà une page à part entière |
| Valeurs numériques des moteurs | Curseurs au lieu d'un champ | La saisie explicite évite de deviner une valeur perdue à la désactivation |
| Bannir ou lever un ASN | Lever un ASN sans confirmation | Annuler demanderait de rejouer motif, expiration et portée d'origine |
| Score par proxy : corriger par dépôt d'un profil | Déposer un profil sur une carte | Le correctif passe par la modale du proxy ; aucune route ne l'applique directement |
| Chronologie de la Synthèse, graphe du Traçage IP | Période par glissement sur le graphique | Pas de besoin exprimé ; à reprendre si la chronologie s'allonge |

## 4. Écarts entre la maquette et l'interface réelle

L'interface réelle est branchée sur le vrai serveur ; ces points diffèrent de la maquette, qui invente ses données.

| Maquette | Interface réelle | Raison |
| --- | --- | --- |
| Sélecteur de portée « Admin / passerelle » dans l'en-tête | Le rail latéral existant (Admin et une pastille par passerelle) | Le changement de portée y existe déjà et recharge toutes les pages |
| Traçage IP et Référentiel visibles dans les deux portées | Côté Admin seulement | Ces deux pages n'existent que dans l'Admin |
| Carte simplifiée en bulles | Carte Leaflet de Prism (zones, villes, régions, tiroir de détail) | Fonction existante, plus riche |
| Flux en direct : lignes dépliables avec signaux et points | Lignes du flux réel (pays, IP, domaine, type, compteur) avec actions au survol | Le flux ne porte pas les signaux de chaque IP |
| « Qui serait banni ? » : une barre par IP en points, ligne de seuil à tirer | Simulation du serveur sur 24 h (`POST /security/threat-config/simulate`) : barres de requêtes bloquées par IP, IP touchées en légitime en surbrillance, score seuil réglable en glissant le nombre | Le serveur ne publie pas les points par IP ; un seuil se règle sur le score seuil d'Ephor |
| Points de chaque signal réglables | Mode de chaque signal réglable, points affichés | Les points sont fixés par Ephor |
| Niveau de protection | Trois niveaux qui écrivent le mode, le score seuil (8, 8, 6) et le mode des 16 signaux (confiance 2 / 1 / 0) | Valeurs de départ proposées, à calibrer sur le trafic réel avant d'activer « Strict » ; « Observer » passe Ephor en `detect` |
| Contrôles du score : en-têtes de sécurité divers | Les 9 contrôles du moteur : TLS, HSTS, X-Frame-Options, masquage de Server, limite de débit, WAF, bots, filtrage IP, authentification | C'est ce que le serveur évalue |
| « Corriger » applique toujours le correctif | Applique et s'annule pour TLS, HSTS (1 an), X-Frame-Options (SAMEORIGIN), masquage de Server et WAF en détection ; ouvre la sécurité du proxy pour les quatre autres | Ces contrôles demandent des valeurs que rien ne doit deviner |
| Profils de protection | Les quatre profils appliquent les contrôles de la ligne précédente ; glisser-déposer sur un proxy ou clic puis clic | Même raison |
| Couleurs et typographie propres | Thèmes et skins de l'application | Cohérence avec le reste de l'Admin |
