# Rapport de tests — GoProxify (2026-10-02)

Campagne de tests de sécurité, de résilience et de charge menée avec le labo `tests/lab/` (procédure : [tests-lab.md](tests-lab.md)) contre la stack de production distante (`<IP-passerelle>`), pilotée depuis un poste tiers sur le même LAN plutôt que déployée sur le daemon Docker de la stack elle-même.

## 1. Synthèse

| Domaine | Verdict |
|---|---|
| Sécurité (19 contrôles, `LAB_SAFE=1`) | **19 / 19 PASS** |
| Résilience (5 scénarios de panne réseau) | **5 / 5 PASS** : dégradation propre et reprise automatique |
| Charge (smoke) | **0 % d'erreur** sur 6 066 requêtes, 399 req/s |

Non exécutés : section « Admin API » d'`attacks.sh`, `moderate`/`saturation`/`spike`/`stress`/`baseline`/`soak`/`mixed`, ZAP/Nuclei/`lab-juice`, TLS — mêmes raisons qu'au [passage du 2026-09-24](rapport-tests-2026-09-24.md#7-tests-non-exécutés-et-pourquoi) : impact modéré à élevé sur une stack de production partagée, ou hors périmètre de ce passage.

## 2. Périmètre et environnement — écart notable

Contrairement à la procédure standard ([tests-lab.md](tests-lab.md)), le labo n'a **pas** été déployé sur le daemon Docker de la stack cible : il a tourné sur un poste Windows distinct, sur le même réseau local (`<réseau-LAN>`), ciblant l'Admin (`http://<IP-passerelle>:9443`) et la Passerelle (`http://<IP-passerelle>`) par IP.

Conséquence : `lab-backend` et `lab-toxiproxy` tournaient localement sur ce poste (IP `<IP-poste-de-test>`) plutôt que sur `goproxify_net`, avec leurs ports publiés (9000, 8666, 8474) et une règle de pare-feu entrante ouverte côté poste de test. Les routes `lab-*.lab.test` créées via l'API Admin pointaient vers cette IP au lieu des noms de conteneurs habituels (`lab-backend:9000`, `lab-toxiproxy:8666`). `attacks.sh` et `chaos.sh` ont tourné via les services « run » locaux (`--add-host` au lieu de la résolution DNS Docker de `hosts.sh`).

Cet écart valide que le Core route et se comporte correctement avec un backend externe au réseau Docker ; il ne reproduit pas exactement les conditions réseau internes (latence quasi nulle habituelle entre conteneurs). À réserver aux vérifications ponctuelles — la procédure normale (labo déployé sur le même daemon, §2 de [tests-lab.md](tests-lab.md)) reste la référence pour des mesures de charge ou une campagne complète.

| Élément | Valeur |
|---|---|
| Date | 2026-10-02, ~20:30 UTC |
| Cible | Admin + Passerelle GoProxify en production, `<IP-passerelle>` (version `0.71.2`) |
| Labo | `lab-backend` (Go 1.22), `lab-toxiproxy` 2.9.0, `goproxify-lab-tools` (Alpine 3.20, build local), `grafana/k6` — exécutés sur un poste tiers du LAN |
| Routes de test | `lab-fast`, `lab-waf-block`, `lab-waf-detect`, `lab-ratelimit`, `lab-chaos` (`*.lab.test`) |

## 3. Sécurité — 19 / 19 PASS

Script : `tests/lab/scripts/attacks.sh` avec `LAB_SAFE=1`.

| Groupe | Contrôle | Attendu | Obtenu |
|---|---|---|---|
| WAF (mode block) | SQLi `' OR 1=1` | 403 | 403 |
| | SQLi `UNION SELECT` | 403 | 403 |
| | XSS `<script>` | 403 | 403 |
| | Path traversal | rejet ou chemin nettoyé | 400 |
| | Traversal encodé (`..%2f`) | 403 | 403 |
| | Log4Shell (User-Agent) | 403 | 403 |
| | Injection de commande | 403 | 403 |
| | Trafic légitime | 200 | 200 |
| WAF (mode detect) | SQLi tolérée | 200 | 200 |
| IP / en-têtes | `X-Forwarded-For` complété par le Core | IP du pair en fin de chaîne | conforme (xff=<IP-poste-de-test>) |
| | En-tête hop-by-hop (`Connection:`) | retiré | retiré |
| Routage / Host | Host inconnu | 404 | 404 |
| | Host en double (requête brute) | 400 | 400 |
| | `TRACE` | 405 | 405 |
| | En-tête de 64 Ko | 431 | 431 |
| | Corps de 3 Mo avec `max_body_mb=1` | transmis intact | transmis intact |
| Smuggling | CL + TE | une seule réponse | 1 |
| Rate-limit | 120 requêtes en rafale (rps 10, burst 20) | des 429 | 90 / 120 en 429 |
| Slowloris | En-têtes incomplets | connexion coupée | coupée à 10 s |

## 4. Résilience — Toxiproxy entre le Core et le backend

Script : `tests/lab/scripts/chaos.sh` (n'agit que sur la route `lab-chaos`).

| Scénario | Résultat mesuré | Verdict |
|---|---|---|
| Latence +1,5 s (jitter 200 ms) | 200 en 1,52 s ; rétablissement | PASS |
| Backend coupé | 502 en **6,7 ms** ; reprise automatique au retour du backend | PASS |
| Connexion réinitialisée (RST) | 502 ; rétablissement | PASS |
| Backend muet | 502 après **30,0 s** (délai amont) ; rétablissement | PASS |
| Bande passante 50 Ko/s sur 1 Mo | 200 en 21,1 s (conforme au débit imposé) ; rétablissement | PASS |

## 5. Charge

Script : k6 (smoke uniquement), sur la route `lab-fast`.

| Scénario | Requêtes | Débit | Échecs | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| Smoke (2 VUs, 15 s) | 6 066 | 399/s | 0,00 % | 3,2 ms | 5,3 ms | 15,2 ms | 792,7 ms |

Pas de test de charge au-delà du smoke : la liaison passe par le LAN et un poste tiers plutôt que par le réseau Docker interne habituel, ce qui en ferait une mesure de ce lien plutôt que du Core.

## 6. Constats

Aucun défaut détecté. Néant à signaler par rapport au comportement attendu du Core `0.71.2`.

## 7. Nettoyage effectué

- Routes `lab-*.lab.test` supprimées via l'API Admin (204 chacune).
- Conteneurs locaux `lab-backend` / `lab-toxiproxy` et réseau Docker local supprimés.
- Règle de pare-feu entrante ouverte côté poste de test à retirer si plus utilisée (`GoProxify Lab`, ports 9000/8666/8474).
- PAT utilisé pour le seed à révoquer ou surveiller.

## 8. Reproduire

Procédure standard (labo déployé sur le même daemon que GoProxify) : [tests-lab.md](tests-lab.md). Pour reproduire la variante « poste tiers sur le LAN » utilisée ici : démarrer `lab-backend` et `lab-toxiproxy` localement avec leurs ports publiés, créer les routes `lab-*.lab.test` via l'API Admin avec l'IP LAN du poste comme backend (au lieu des noms de conteneurs), puis lancer `attacks.sh`/`chaos.sh`/k6 avec `EDGE_HOST`/`--add-host` pointant vers l'IP de la Passerelle distante.
