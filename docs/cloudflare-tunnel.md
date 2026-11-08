# GoProxify derrière Cloudflare Tunnel

Ce guide dit ce qui fonctionne quand le trafic public arrive à la passerelle par un tunnel `cloudflared` (Cloudflare Zero Trust), ce qui demande un réglage, et ce qui ne passe pas. Il a été établi à partir du code et de tests unitaires (`TestRealIPBehindCloudflareTunnel`, `TestRedirectHTTPSBehindCloudflareTunnel`), **pas sur un tunnel réel** : validez-le sur votre installation avant de compter dessus.

## Résumé

| Fonction | Derrière un tunnel | Remarque |
|---|---|---|
| Proxy HTTP / HTTPS, WebSocket, SSE, gRPC | oui | Cloudflare termine le TLS public |
| IP client (rate-limit, filtres IP, bans, journaux) | oui | `CF-Connecting-IP` lu d'un pair de confiance, voir ci-dessous |
| `redirect_https` | oui | `X-Forwarded-Proto: https` cru d'un pair de confiance, pas de boucle |
| WAF, Ephor, défi à preuve de travail | oui | ils s'appuient sur l'IP client |
| Certificats ACME | DNS-01 seulement | le fournisseur DNS Cloudflare est géré |
| ACME http-01 | à éviter | le nom passe par Cloudflare, pas par le port 80 de la passerelle |
| Admin et portail Access | oui | `GPX_ADMIN_PUBLIC_URL` à renseigner |
| mTLS par route | **non** | la poignée de main s'arrête chez Cloudflare |
| HTTP/3 vers la passerelle | **non** (inutile) | Cloudflare sert déjà HTTP/3 au visiteur |
| Routes TCP / UDP (L4) | **non** | demande `cloudflared access` chez chaque client |
| Délégation inter-Edge en Passthrough | **non** | tunnel TLS brut (SNI) |

## Montage recommandé

`cloudflared` et la passerelle dans le même réseau Docker (ou sur la même machine), le tunnel pointant vers le **port HTTP** de la passerelle (80 par défaut, `GPX_NETWORK_HTTP_PORT`) :

```yaml
# config.yml de cloudflared
ingress:
  - hostname: app.example.com
    service: http://goproxify-edge:80
  - hostname: "*.example.com"
    service: http://goproxify-edge:80
  - service: http_status:404
```

```yaml
# docker-compose : cloudflared à côté de la passerelle
  cloudflared:
    image: cloudflare/cloudflared:latest
    command: tunnel --no-autoupdate run
    environment:
      TUNNEL_TOKEN: ${CLOUDFLARE_TUNNEL_TOKEN}
    networks: [goproxify]
```

Dans l'Admin, créez les proxies comme d'habitude. Le DNS (CNAME vers le tunnel) reste chez Cloudflare.

### Pourquoi le port HTTP

Le TLS public est celui de Cloudflare. Viser le 443 de la passerelle oblige à `noTLSVerify` ou à un `originServerName` qui colle au certificat, et ajoute un second chiffrement sans gain si le trajet est local. Si le tunnel traverse un réseau que vous ne maîtrisez pas, visez `https://goproxify-edge:443` avec `originServerName: app.example.com` et laissez la vérification active.

## IP client : `GPX_TRUSTED_PROXIES`

La passerelle ne lit `CF-Connecting-IP`, `X-Forwarded-For` et `X-Real-IP` que d'un pair de confiance ([security.md](security.md#ip-client-et-proxies-de-confiance)). Par défaut sont de confiance le loopback et les réseaux privés.

- **`cloudflared` dans le même réseau Docker ou sur la même machine** : rien à faire, son adresse est privée.
- **`cloudflared` sur une autre machine, adresse publique** : ajoutez son adresse, sinon tout le trafic semble venir du tunnel et Ephor risque de bannir ce « visiteur » unique.

  ```
  GPX_TRUSTED_PROXIES=203.0.113.40
  ```
- **`GPX_TRUSTED_PROXIES=none`** (conseillé sur un LAN dont les postes ne sont pas fiables) retire aussi le tunnel privé : écrivez `none,172.18.0.4` pour ne croire que lui.

`CF-Connecting-IP` prime sur `X-Forwarded-For`, qu'un client peut pré-remplir avant Cloudflare.

## Certificats

- **Cloudflare termine le TLS** : la passerelle n'a pas besoin de certificat pour être joignable. Le certificat public est celui de Cloudflare.
- **Vous voulez quand même un certificat sur la passerelle** (trajet chiffré de bout en bout, accès direct de secours) : utilisez le défi **DNS-01** avec un fournisseur `cloudflare` (`/api/v1/acme/providers`). Le défi http-01 n'est pas fiable ici, le nom résout vers Cloudflare.
- Une route `tls_enabled` avec `redirect_https` reste servie : `X-Forwarded-Proto: https` annoncé par `cloudflared` évite la boucle de redirection. Avec « Toujours utiliser HTTPS » actif côté Cloudflare, la redirection de la passerelle est de toute façon redondante.

## Admin et portail Access

- Renseignez `GPX_ADMIN_PUBLIC_URL=https://admin.example.com` : les liens d'enrôlement et les pages d'erreur publiques en dépendent, et cette valeur ne se déduit jamais d'une requête.
- Les cookies de l'Admin passent `Secure` quand `X-Forwarded-Proto: https` arrive (appareil de confiance MFA, par exemple).
- L'Admin n'envoie pas `Strict-Transport-Security` derrière un proxy : activez-le chez Cloudflare.
- Le portail Access (SSH dans le navigateur) repose sur des WebSocket : ils traversent le tunnel.

## Ce qui ne passe pas

- **mTLS par route** : le certificat client est demandé pendant la poignée de main TLS, que Cloudflare arrête. Une route `mtls.enabled` ne peut pas fonctionner par tunnel.
- **HTTP/3 (443/udp) et `Alt-Svc`** : le tunnel est en HTTP/1.1 ou HTTP/2 jusqu'à la passerelle ; le visiteur obtient HTTP/3 de Cloudflare.
- **Routes TCP / UDP** : un tunnel public ne transporte que du HTTP vers un nom. Un service TCP demande `cloudflared access tcp` ou WARP chez chaque client.
- **Passthrough inter-Edge** : le SNI n'est pas lu par la passerelle d'entrée (Cloudflare l'a déjà terminé). Le mode **Terminate** reste possible.
- **Empreinte TLS du visiteur** : la passerelle voit celle de `cloudflared`.

## Dans l'autre sens : un backend derrière un tunnel

Une route peut viser un service exposé par un tunnel, avec une adresse `https://service.example.com` : la passerelle émet le SNI du nom de l'hôte envoyé. Il faut donc **désactiver `preserve_host`** sur cette route, sinon elle présente le nom public du proxy, que le tunnel ne connaît pas.

## Ce qui pourrait être rendu compatible

Rien de ceci n'est livré. À planifier selon le besoin :

| Piste | Gain | Effort | Remarque |
|---|---|---|---|
| Mot-clé `cloudflare` dans `GPX_TRUSTED_PROXIES` (plages officielles, rafraîchies) | Cloudflare « nuage orange » sans tunnel, dont l'origine reçoit les plages publiques de Cloudflare | faible | les plages sont déjà connues du moteur Ephor |
| Agent derrière un tunnel | un Agent sans port entrant ouvert vers la passerelle | faible, à valider | l'Agent accepte déjà `https://` et passe en `wss://` ; il faut n'exposer que `/ws/agent`, jamais l'API interne du 8000 |
| Certificat client transmis par Cloudflare | mTLS par route derrière Cloudflare | moyen | Cloudflare peut ajouter des en-têtes d'authentification TLS client (à vérifier chez eux) ; la passerelle devrait n'en croire que ceux d'un pair de confiance et ne jamais accepter un en-tête arrivé de l'extérieur |
| Authentification Cloudflare Access (`Cf-Access-Jwt-Assertion`) | SSO d'une route ou de l'Admin par Cloudflare Access | moyen | vérifier la signature du jeton contre les clés publiques du compte, et l'audience |
| Guide et assistant « derrière un tunnel » dans l'Admin | détecte l'IP du tunnel vue en pair et propose l'entrée `GPX_TRUSTED_PROXIES` | faible | évite le ban collectif quand l'adresse du tunnel n'est pas listée |
| ACME via Cloudflare Origin CA | certificat d'origine sans Let's Encrypt | moyen | utile seulement si le trajet tunnel-passerelle doit être chiffré |

**Impossible côté GoProxify** : le L4 public (TCP/UDP) par tunnel et le HTTP/3 entrant, qui tiennent au produit Cloudflare, pas à la passerelle.

## Vérifier

1. Depuis un navigateur, ouvrez le proxy : la réponse arrive, sans boucle de redirection.
2. Page **Journaux** : l'IP affichée est la vôtre, pas celle de `cloudflared`. Sinon, ajoutez le pair à `GPX_TRUSTED_PROXIES`.
3. Un test de rate-limit ou un ban manuel de votre IP (depuis un réseau de test) doit toucher cette IP seule.
