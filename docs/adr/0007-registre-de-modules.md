# ADR 0007 — Registre de modules et manifestes

**Statut :** accepté (pilote : canaux de notification) · **Date :** 2026-10

## Contexte

Plusieurs familles de fonctions suivent le même schéma — « un type, une configuration, un comportement » — et sont câblées en dur : canaux de notification, fournisseurs d'authentification, détecteurs de sécurité, sources de découverte, fournisseurs DNS ACME, importeurs, cibles de déploiement de certificats. Le type d'un canal d'alerte était ainsi décrit à quatre endroits qui dérivaient : le `switch` Go (`channels.Build`), les tableaux du JavaScript, l'énumération du MCP et les docs. Conséquences constatées : la liste de secrets à masquer oubliait `webhook_url` (Slack, Teams), `bot_token` (Telegram) et `auth_token` (SMS), renvoyés en clair par `GET /alert-channels` ; modifier un canal effaçait ses secrets (le formulaire ne les préremplit pas et `PUT` remplaçait toute la configuration) ; le champ `port` de l'email partait en chaîne et était ignoré ; l'API acceptait n'importe quel type.

## Décision

Un paquet générique `internal/modules` fournit :

- **`Manifest`** : `type`, `label`, liste de `Field` (`key`, `label`, `placeholder`, `kind` ∈ text/password/number/list, `secret`, `required`).
- **`Registry[T]`** : enregistrement par `init()` d'un manifeste et d'une fabrique, ordre de déclaration conservé. Un manifeste invalide ou un type en double **panique au démarrage** (erreur de programmation, vue par les tests).
- **Opérations pilotées par le manifeste** : `Validate` (champs requis, clés inconnues), `Mask` (secrets → `••••••••`), `KeepSecrets` (un secret absent, vide ou égal au masque est conservé à la modification ; le masque n'est jamais stocké).

Chaque famille instancie son registre avec sa propre fabrique (`channels.Factory`). Ajouter un module = un fichier qui appelle `Register` ; l'API (`GET /alert-channel-types`), le masquage, la validation, le MCP (`list_alert_channel_types`), la CLI (`alert channels types`) et le formulaire de l'interface en découlent. L'interface garde ses icônes et libellés traduits pour les types connus et construit tout type inconnu depuis le manifeste.

## Règles

- **La validation ne s'applique qu'à la création et à la modification.** Une configuration déjà stockée (partielle, ancienne) se construit toujours : `Build` ne refuse jamais une config, il renvoie un `Sender` dont l'envoi échoue proprement.
- **Un champ n'est `required` que si l'expéditeur ne peut pas fonctionner sans lui** ; ceux qui ont une valeur par défaut (port SMTP, URL ntfy, GitLab, type d'issue Jira, groupe Zammad) restent facultatifs.
- **Tout identifiant (jeton, mot de passe, clé d'API, URL de webhook porteuse d'un jeton) est `secret`.** Un test le vérifie pour les types fournis.
- **Autonomie (ADR 0006)** : les canaux de notification sont exécutés par l'Admin, qui est leur point de supervision ; ils ne sont pas concernés par l'autonomie de la passerelle. Les familles qui tournent sur la passerelle (détecteurs, authentification) devront persister leurs modules et configurations dans le cache chiffré de la passerelle avant d'être migrées.

## Conséquences

- Les familles suivantes (`Importer`, `Discovery`, fournisseurs DNS, cibles de déploiement…) réutilisent `internal/modules` ; `AuthProvider` et `Detector` en dernier, après renforcement des tests, car ils touchent la sécurité.
- Un moteur d'exécution externe (WASM) pourra enregistrer des modules dans les mêmes registres : le registre est la couche commune, le moteur n'en est qu'une implémentation de fabrique.
- Changement de comportement assumé : `POST /alert-channels` refuse un type inconnu, un champ requis vide et une clé inconnue (`400`), alors qu'il acceptait tout.
