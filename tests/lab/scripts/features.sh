#!/usr/bin/env bash
# Suite fonctionnelle des proxies : une route *.lab.test par fonctionnalité, devant les applications simulées
# (lab-sim : boutique à 3 instances, canary, shadow, legacy, écho WebSocket). Verdict PASS/FAIL, code retour = nb d'échecs.
#
#   features.sh seed            crée les routes via l'API Admin (idempotent)
#   features.sh run [sections]  exécute les contrôles (ex. : run lb,cache,health) ; sans liste = toutes
#   features.sh                 seed + run
#
# Faible impact : uniquement des routes *.lab.test, une cinquantaine de requêtes par section, quelques rafales de 6 à 8
# requêtes concurrentes (backpressure, limit_conn). L'état des instances simulées est remis à zéro en sortie.
set -u
. /lab/scripts/hosts.sh
EDGE_HOST=${EDGE_HOST:-goproxify-edge}
SIM=${LAB_SIM_CTL:-http://lab-sim:9999}
ROUTES=/lab/scripts/feature-routes.json
PASSFILE=/tmp/lab-basic.pass
fail=0; npass=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; npass=$((npass+1)); }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
info() { printf '  info  %s\n' "$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
check() { # description got expected... (x local : le shell a une portée dynamique)
  local d=$1 got=$2 x; shift 2
  for x in "$@"; do [ "$got" = "$x" ] && { ok "$d ($got)"; return; }; done
  ko "$d : obtenu « $got », attendu « $* »"
}
ge() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>=b)}'; } # a >= b (réels)
u() { echo "http://lab-$1.lab.test"; }
ctl() { curl -s -o /dev/null --max-time 5 "$SIM/ctl/$1"; }
stats() { curl -s --max-time 5 "$SIM/ctl/stats"; }
rnd() { echo "$RANDOM$RANDOM"; }
wait_code() { # url attendu secondes [curl args...] : attend la propagation d'une config
  local url=$1 want=$2 n=$3; shift 3
  for _ in $(seq 1 "$n"); do [ "$(code "$@" "$url")" = "$want" ] && return 0; sleep 1; done; return 1
}
spread() { # url n [curl args] -> lignes "instance count" d'après X-Instance
  local url=$1 n=$2; shift 2
  for _ in $(seq 1 "$n"); do curl -s -o /dev/null -D- --max-time 10 "$@" "$url" | tr -d '\r' | awk 'tolower($1)=="x-instance:"{print $2}'; done | sort | uniq -c | awk '{print $2, $1}'
}
count_of() { echo "$1" | awk -v k="$2" '$1==k{print $2; f=1} END{if(!f)print 0}'; }
burst() { # url n [curl args] : requêtes concurrentes ; renseigne BURST_CODES, BURST_200, BURST_NON200, BURST_RA (appeler sans $(...))
  local url=$1 n=$2 i; shift 2
  local tmp; tmp=$(mktemp -d)
  for i in $(seq 1 "$n"); do ( curl -s -o /dev/null -D "$tmp/h$i" -w "%{http_code}\n" --max-time 20 "$@" "$url" > "$tmp/c$i" ) & done
  wait
  BURST_CODES=$(cat "$tmp"/c* | sort | uniq -c | awk '{printf "%s×%s ", $1, $2}')
  BURST_200=$(cat "$tmp"/c* | grep -c "^200$")
  BURST_NON200=$((n - BURST_200))
  BURST_RA=0; grep -qi "^retry-after" "$tmp"/h* && BURST_RA=1
  rm -rf "$tmp"
}
admin_id() { curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r --arg h "$1" '.[]? | select(.name==$h) | .id' | head -1; }

# ------------------------------------------------------------------ seed
seed() {
  . /lab/scripts/auth.sh
  [ -f "$PASSFILE" ] || openssl rand -hex 8 > "$PASSFILE"
  local pass have name body c n
  pass=$(cat "$PASSFILE")
  have=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | .name // empty')
  jq -c '.[]' "$ROUTES" | while read -r r; do
    name=$(echo "$r" | jq -r .host)
    if echo "$have" | grep -qx "$name"; then printf '%-32s déjà présent : ignoré\n' "$name"; continue; fi
    body=$(echo "$r" | jq -c '{config: (.config + {host: .host, type: "http", tls_enabled: false}) }' | sed "s/__BASIC_PASS__/$pass/g")
    if [ -n "${LAB_RUNNER_CIDR:-}" ]; then body=$(echo "$body" | jq -c --arg c "$LAB_RUNNER_CIDR" '.config.sentinel_whitelist = [$c]'); fi
    c=$(curl -s -o /tmp/fseed.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/proxies" \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body")
    printf '%-32s (%s)\n' "$name" "$c"
    case "$c" in 2*) ;; *) jq -r '(.dry_run.errors // [])[] | "  erreur : " + .' /tmp/fseed.out 2>/dev/null || head -c 300 /tmp/fseed.out; echo ;; esac
  done
  n=$(jq length "$ROUTES"); echo "Routes attendues : $n. Propagation vers la passerelle…"
  wait_code "$(u lb)/whoami" 200 60 && echo "lab-lb opérationnelle" || echo "ATTENTION : lab-lb ne répond pas encore (lab-sim démarré ? passerelle joignable ?)"
}

# ------------------------------------------------------------------ garde-fous
preflight() {
  [ "$(code "$SIM/ctl/stats")" = 200 ] || { echo "  FAIL lab-sim injoignable ($SIM) — stack lab déployée ? (compilation ~15 s au démarrage)"; exit 1; }
  ctl reset
  wait_code "$(u lb)/whoami" 200 60 || { echo "  FAIL lab-lb.lab.test indisponible après 60 s (features.sh seed fait ?) — arrêt"; exit 1; }
  # Les hôtes de routes.json doivent tous être résolus par hosts.sh, sinon les tests échoueraient pour une mauvaise raison.
  for h in $(jq -r '.[].host, (.[].config.aliases // [])[]' "$ROUTES"); do
    grep -q " $h\$" /etc/hosts || echo "  WARN  $h absent de /etc/hosts (hosts.sh à jour ?)"
  done
}

want() { [ -z "${SECTIONS:-}" ] && return 0; case ",$SECTIONS," in *",$1,"*) return 0;; esac; return 1; }
section() { want "$1" || return 1; echo "== $2 =="; return 0; }

# ------------------------------------------------------------------ sections
t_lb() { section lb "Équilibrage round-robin sur 3 instances + alias" || return
  local d; d=$(spread "$(u lb)/whoami" 30)
  for i in a b c; do
    n=$(count_of "$d" $i); [ "$n" -ge 5 ] && ok "instance $i reçoit sa part ($n/30)" || ko "instance $i sous-alimentée ($n/30)"
  done
  check "alias de domaine sur la même route" "$(code "http://lab-lb-alias.lab.test/whoami")" 200
}

t_weighted() { section weighted "Équilibrage pondéré (8/1/1)" || return
  local d n; d=$(spread "$(u weighted)/whoami" 60); n=$(count_of "$d" a)
  [ "$n" -ge 36 ] && ok "l'instance pondérée a reçoit $n/60 (≥ 36)" || ko "pondération non respectée : a=$n/60 ($(echo $d | tr '\n' ' '))"
}

t_sticky() { section sticky "Sessions collantes (cookie LABSID)" || return
  local jar=/tmp/lab-jar.$$ first n d
  rm -f $jar; first=$(curl -s -c $jar -o /dev/null -D- "$(u sticky)/whoami" | tr -d '\r' | awk 'tolower($1)=="x-instance:"{print $2}')
  grep -q LABSID $jar && ok "cookie LABSID posé" || ko "aucun cookie LABSID"
  d=$(for _ in $(seq 1 15); do curl -s -b $jar -o /dev/null -D- "$(u sticky)/whoami" | tr -d '\r' | awk 'tolower($1)=="x-instance:"{print $2}'; done | sort -u | tr '\n' ' ')
  check "15 requêtes avec cookie → toujours $first" "$d" "$first "
  n=$(spread "$(u sticky)/whoami" 20 | wc -l); [ "$n" -ge 2 ] && ok "sans cookie : répartition sur $n instances" || ko "sans cookie : une seule instance"
  rm -f $jar
}

t_health() { section health "Health check actif : éjection puis réintégration" || return
  local d codes
  ctl h1/health?up=0
  info "instance h1 rendue malsaine, attente de la sonde (≤ 6 s)"; sleep 6
  codes=$(for _ in $(seq 1 20); do code "$(u health)/whoami"; echo; done | sort | uniq -c | awk '{printf "%s×%s ", $1,$2}')
  d=$(spread "$(u health)/whoami" 20)
  [ "$(count_of "$d" h1)" = 0 ] && ok "aucune requête vers l'instance malsaine ($codes)" || ko "l'instance malsaine reçoit encore du trafic ($(echo $d | tr '\n' ' '))"
  ctl h1/health?up=1; sleep 6
  d=$(spread "$(u health)/whoami" 20)
  [ "$(count_of "$d" h1)" -ge 3 ] && ok "instance h1 réintégrée ($(echo $d | tr '\n' ' '))" || ko "instance h1 non réintégrée ($(echo $d | tr '\n' ' '))"
  ctl h1/health?up=0; ctl h2/health?up=0; sleep 6
  check "tous les backends malsains : la passerelle tente quand même (fail-open)" "$(code "$(u health)/whoami")" 200
  ctl reset; sleep 4
}

t_retry() { section retry "Failover et retry (un backend du pool est mort : port fermé)" || return
  local i o bad=0 max=0 t
  for i in 1 2 3 4 5 6 7 8; do
    o=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 20 "$(u retry)/whoami"); t=${o#* }
    [ "${o% *}" = 200 ] || bad=$((bad+1)); ge "$t" "$max" && max=$t
  done
  [ $bad = 0 ] && ok "avec retry : 8/8 réponses 200 malgré le backend mort" || ko "avec retry : $bad/8 erreurs"
  info "temps max observé $max s (attente de retry configurée : 0,4 s ; absente si le backend mort était déjà en quarantaine)"
  bad=0
  for i in 1 2 3 4 5 6 7 8; do [ "$(code "$(u noretry)/whoami")" = 200 ] || bad=$((bad+1)); done
  [ $bad = 0 ] && ok "sans retry : failover quand même (8/8 réponses 200)" || ko "sans retry : $bad/8 erreurs"
  info "une réponse 5xx du backend n'est ni retentée ni basculée : seules les pannes de transport (connexion refusée, coupée) déclenchent le failover"
}

t_cb() { section cb "Circuit breaker (seuil 3 échecs de transport, ouverture 8 s)" || return
  local hits
  ctl legacy/drop?n=100000
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do code "$(u cb)/whoami" >/dev/null; done
  hits=$(stats | jq '.legacy.hits')
  [ "$hits" -le 6 ] && ok "circuit ouvert : $hits requêtes seulement ont atteint le backend sur 12" || ko "le circuit ne s'ouvre pas : $hits/12 requêtes ont atteint le backend"
  ctl legacy/reset; sleep 9
  check "après l'ouverture et la guérison, le trafic reprend" "$(code "$(u cb)/whoami")" 200
}

t_transform() { section transform "Pipeline de transformation (réécriture, en-têtes)" || return
  local out hdr
  hdr=$(mktemp); out=$(curl -s -D "$hdr" -H 'X-Secret-Client: topsecret' "$(u transform)/shop/v1/products")
  check "réécriture /shop/v1 → /api" "$(echo "$out" | jq -r .path)" /api/products
  check "en-tête ajouté vers le backend" "$(echo "$out" | jq -r .marker)" via-proxy
  check "en-tête client retiré vers le backend" "$(echo "$out" | jq -r .secret)" ""
  grep -qi '^x-lab-resp: transformed' "$hdr" && ok "en-tête de réponse ajouté" || ko "X-Lab-Resp absent"
  grep -qi '^x-powered-by' "$hdr" && ko "X-Powered-By non retiré" || ok "en-tête de réponse retiré (X-Powered-By)"
  rm -f "$hdr"
}

t_paths() { section paths "Routage par chemin (locations)" || return
  check "location /legacy (strip_prefix) → instance legacy" "$(curl -s "$(u paths)/legacy/whoami")" legacy
  check "location regex avec réécriture \$1" "$(curl -s "$(u paths)/v3/items" | jq -r .path)" /api/version-3/items
  check "chemin par défaut → instance a" "$(curl -s "$(u paths)/whoami")" a
}

t_redirect() { section redirect "Réécriture Location et cookies (proxy_redirect, proxy_cookie_*)" || return
  local loc ck
  loc=$(curl -s -o /dev/null -D- "$(u redirect)/redirect" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
  check "proxy_redirect" "$loc" https://shop.lab.test/landing
  ck=$(curl -s -o /dev/null -D- "$(u redirect)/login" | tr -d '\r' | grep -i '^set-cookie:')
  case "$ck" in *"Domain=shop.lab.test"*) ok "cookie Domain réécrit";; *) ko "cookie Domain non réécrit : $ck";; esac
  case "$ck" in *"Path=/;"*|*"Path=/") ok "cookie Path réécrit";; *) ko "cookie Path non réécrit : $ck";; esac
}

t_subfilter() { section subfilter "Réécriture du corps de réponse (sub_filter)" || return
  local body
  body=$(curl -s --max-time 10 "$(u subfilter)/")
  [ -n "$body" ] || { ko "réponse vide ou tronquée (en-tête Content-Length périmé après réécriture ?)"; return; }
  case "$body" in *"https://shop.lab.test/products"*) ok "URL interne réécrite";; *) ko "URL interne non réécrite";; esac
  case "$body" in *PUBLIC-MARKER*) ok "texte remplacé";; *) ko "BACKEND-MARKER non remplacé";; esac
}

t_cors() { section cors "CORS" || return
  local h
  h=$(curl -s -o /dev/null -D- -X OPTIONS -H 'Origin: https://app.lab.test' -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type' "$(u cors)/api/x" | tr -d '\r')
  echo "$h" | grep -qi '^access-control-allow-origin: https://app.lab.test' && ok "preflight : origine autorisée" || ko "preflight : ACAO absent"
  echo "$h" | grep -qi '^access-control-max-age: 600' && ok "preflight : max-age 600" || ko "preflight : max-age absent"
  h=$(curl -s -o /dev/null -D- -X OPTIONS -H 'Origin: https://evil.test' -H 'Access-Control-Request-Method: POST' "$(u cors)/api/x" | tr -d '\r')
  echo "$h" | grep -qi '^access-control-allow-origin: https://evil.test' && ko "origine non autorisée acceptée" || ok "origine non autorisée refusée"
}

t_cache() { section cache "Cache disque (TTL, bypass, purge)" || return
  local p="/static/$(rnd).js" a b c d id
  hit() { curl -s -o /dev/null -D- "$@" | tr -d '\r' | awk 'tolower($1)=="x-origin-hit:"{print $2}'; }
  a=$(hit "$(u cache)$p"); b=$(hit "$(u cache)$p")
  [ -n "$a" ] && [ "$a" = "$b" ] && ok "2ᵉ GET servi par le cache (X-Origin-Hit=$a)" || ko "pas de cache : hit origine $a puis $b"
  c=$(hit -H 'X-No-Cache: 1' "$(u cache)$p")
  [ -n "$c" ] && [ "$c" != "$a" ] && ok "bypass par en-tête (origine $c)" || ko "bypass ignoré ($c)"
  id=$(admin_id lab-cache.lab.test)
  if [ -n "$id" ]; then
    curl -s -o /dev/null -X POST -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies/$id/cache/purge"
    sleep 1; d=$(hit "$(u cache)$p")
    [ -n "$d" ] && [ "$d" != "$a" ] && ok "purge via l'API : retour à l'origine ($d)" || ko "purge sans effet ($d)"
  else info "purge ignorée (jeton Admin absent)"; fi
}

t_ip() { section ip "Filtrage IP (allow / deny)" || return
  check "allow-list sans notre IP → refus" "$(code "$(u ipallow)/")" 403
  check "deny-list sans notre IP → accès" "$(code "$(u ipdeny)/")" 200
}

t_vars() { section vars "Variables de requête → en-tête (map nginx)" || return
  check "X-Plan: gold → premium" "$(curl -s -H 'X-Plan: gold' "$(u vars)/echo" | jq -r '.headers["X-Tier"][0]')" premium
  check "sans X-Plan → standard" "$(curl -s "$(u vars)/echo" | jq -r '.headers["X-Tier"][0]')" standard
}

t_backpressure() { section backpressure "Backpressure (max_inflight=2, sans file) et limit_conn (3/IP)" || return
  code "$(u backpressure)/whoami" >/dev/null; code "$(u limitconn)/whoami" >/dev/null  # amorce les handlers : à froid, des requêtes concurrentes créent chacune leur propre limiteur
  burst "$(u backpressure)/slow?ms=1500" 6
  [ "$BURST_NON200" -ge 1 ] && ok "excédent rejeté ($BURST_CODES)" || ko "aucun rejet ($BURST_CODES)"
  [ "$BURST_200" -ge 2 ] && ok "les requêtes dans la limite passent" || ko "trop peu de requêtes servies ($BURST_CODES)"
  [ "$BURST_RA" = 1 ] && ok "Retry-After présent" || ko "Retry-After absent"
  sleep 2
  burst "$(u limitconn)/slow?ms=1500" 8
  [ "$BURST_NON200" -ge 1 ] && [ "$BURST_200" -ge 3 ] && ok "limit_conn : excédent refusé ($BURST_CODES)" || ko "limit_conn sans effet ($BURST_CODES)"
}

t_canary() { section canary "Canary (en-tête, pourcentage)" || return
  local d n
  check "en-tête X-Canary → instance canary" "$(curl -s -H 'X-Canary: 1' "$(u canary)/whoami")" canary
  check "sans en-tête → instance a" "$(curl -s "$(u canary)/whoami")" a
  d=$(spread "$(u canary-pct)/whoami" 100); n=$(count_of "$d" canary)
  [ "$n" -ge 10 ] && [ "$n" -le 55 ] && ok "canary 30 % : $n/100 requêtes" || ko "canary hors fourchette 10–55 : $n/100"
}

t_shadow() { section shadow "Shadow mirror" || return
  local m="m-$(rnd)" got
  check "la réponse client vient du backend principal" "$(curl -s -H "X-Lab-Marker: $m" "$(u shadow)/whoami")" a
  sleep 1.5; got=$(stats | jq -r '.shadow.last_marker["/whoami"] // ""')
  check "le miroir a reçu la même requête" "$got" "$m"
}

t_cond() { section cond "Routage conditionnel (en-tête, query)" || return
  check "X-Device: mobile → legacy" "$(curl -s -H 'X-Device: mobile' "$(u cond)/whoami")" legacy
  check "?beta=1 → canary" "$(curl -s "$(u cond)/whoami?beta=1")" canary
  check "défaut → a" "$(curl -s "$(u cond)/whoami")" a
}

t_errpages() { section errpages "Page d'erreur personnalisée (backend injoignable)" || return
  local out; out=$(curl -s -w ' %{http_code}' "$(u errpages)/")
  case "$out" in *LAB-502-PAGE*) ok "page 502 personnalisée servie";; *) ko "page personnalisée absente : ${out:0:80}";; esac
  check "code conservé" "${out##* }" 502
}

ws_exchange() { # host -> sortie brute (première ligne + trames)
  local out=/tmp/ws.$$
  exec 3<>"/dev/tcp/$EDGE_HOST/80" || return 1
  printf 'GET /ws HTTP/1.1\r\nHost: lab-%s.lab.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' "$1" >&3
  sleep 0.5
  printf '\x81\x85\x00\x00\x00\x00hello' >&3
  timeout 2 cat <&3 > $out; exec 3>&-
  cat -v $out; rm -f $out
}
t_ws() { section ws "WebSocket (autorisé / interdit)" || return
  local o; o=$(ws_exchange ws)
  case "$o" in *"101 "*) ok "upgrade 101";; *) ko "pas d'upgrade : ${o:0:60}";; esac
  case "$o" in *"b:hello"*) ok "écho bidirectionnel via la passerelle";; *) ko "pas d'écho WebSocket";; esac
  o=$(ws_exchange nows)
  case "$o" in *"101 "*) ko "websocket:false n'empêche pas l'upgrade";; *) ok "upgrade refusé (websocket:false) : $(echo "$o" | head -1 | tr -d '\r')";; esac
}

t_body() { section body "Taille maximale du corps (1 Mo)" || return
  head -c 102400 /dev/zero > /tmp/lab-100k; head -c 2097152 /dev/zero > /tmp/lab-2m
  check "100 Ko acceptés" "$(code -X POST --data-binary @/tmp/lab-100k "$(u body)/upload")" 200
  check "2 Mo refusés (413)" "$(code -X POST --data-binary @/tmp/lab-2m "$(u body)/upload")" 413
  rm -f /tmp/lab-100k /tmp/lab-2m
}

t_secheaders() { section secheaders "En-têtes de sécurité" || return
  local h; h=$(curl -s -o /dev/null -D- "$(u secheaders)/api/x" | tr -d '\r')
  echo "$h" | grep -qi '^strict-transport-security: .*max-age=31536000' && ok "HSTS" || ko "HSTS absent"
  echo "$h" | grep -qi '^x-frame-options: DENY' && ok "X-Frame-Options" || ko "X-Frame-Options absent"
  echo "$h" | grep -qi "^content-security-policy: default-src 'self'" && ok "CSP personnalisée" || ko "CSP absente"
  echo "$h" | grep -qi '^x-lab-custom: 1' && ok "en-tête personnalisé" || ko "en-tête personnalisé absent"
  echo "$h" | grep -qi '^server: lab-sim' && ko "Server du backend exposé" || ok "empreinte Server masquée"
  echo "$h" | grep -qi '^x-powered-by' && ko "X-Powered-By exposé" || ok "X-Powered-By masqué"
}

t_timeout() { section timeout "Délai de réponse backend (1 s)" || return
  local o c t; o=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 15 "$(u timeout)/slow?ms=3000"); c=${o% *}; t=${o#* }
  case "$c" in 502|504) ok "backend trop lent → $c";; *) ko "attendu 502/504, obtenu $c";; esac
  ge 2.5 "$t" && ok "coupé à ${t}s (≪ 3 s)" || ko "pas de coupure rapide (${t}s)"
  check "requête rapide inchangée" "$(code "$(u timeout)/slow?ms=200")" 200
}

t_auth() { section auth "Authentification Basic" || return
  local pass; pass=$(cat "$PASSFILE" 2>/dev/null)
  [ -n "$pass" ] || { info "mot de passe du seed introuvable ($PASSFILE) : section ignorée"; return; }
  check "sans identifiants → 401" "$(code "$(u basicauth)/")" 401
  check "mauvais mot de passe → 401" "$(code -u lab:mauvais "$(u basicauth)/")" 401
  check "bons identifiants → 200" "$(code -u "lab:$pass" "$(u basicauth)/")" 200
}

t_bot() { section bot "Protection bot (liste noire d'User-Agent)" || return
  check "User-Agent LabBadBot → 403" "$(code -A LabBadBot "$(u bot)/")" 403
  check "navigateur normal → 200" "$(code -A 'Mozilla/5.0 (X11; Linux x86_64)' "$(u bot)/")" 200
}

t_wafcustom() { section wafcustom "Règle WAF personnalisée" || return
  check "motif interdit en query → 403" "$(code "$(u wafcustom)/?q=LAB-FORBIDDEN-WORD")" 403
  check "motif interdit dans le corps → 403" "$(code -X POST -d 'x=LAB-FORBIDDEN-WORD' "$(u wafcustom)/echo")" 403
  check "requête saine → 200" "$(code "$(u wafcustom)/?q=stylo")" 200
}

t_headers() { section headers "Host conservé / X-Request-ID / X-Forwarded-*" || return
  local a b hdr xff dup
  hdr=$(mktemp); a=$(curl -s -D "$hdr" "$(u lb)/echo")
  check "défaut : le backend voit le Host public" "$(echo "$a" | jq -r .host)" lab-lb.lab.test
  grep -qi '^x-request-id' "$hdr" && ok "X-Request-ID renvoyé au client" || ko "X-Request-ID absent par défaut"
  echo "$a" | jq -e '.headers["X-Forwarded-For"]' >/dev/null && ok "X-Forwarded-For transmis par défaut" || ko "X-Forwarded-For absent par défaut"
  xff=$(echo "$a" | jq -r '.headers["X-Forwarded-For"][0] // ""')
  dup=$(echo "$xff" | tr "," "\n" | tr -d " " | sort | uniq -d | wc -l)
  [ "$dup" = 0 ] && ok "X-Forwarded-For sans doublon ($xff)" || ko "X-Forwarded-For : IP du client en double ($xff)"
  b=$(curl -s -D "$hdr" "$(u nohost)/echo")
  check "preserve_host:false : le backend voit son propre Host" "$(echo "$b" | jq -r .host)" lab-sim:9001
  grep -qi '^x-request-id' "$hdr" && ko "request_id:false : X-Request-ID présent" || ok "request_id:false : pas de X-Request-ID"
  [ "$(echo "$b" | jq -r '[.headers["X-Forwarded-Host"], .headers["X-Forwarded-Proto"], .headers["X-Real-Ip"]] | map(select(. != null)) | length')" = 0 ] && ok "forwarded_headers vide : ni X-Forwarded-Host, -Proto ni X-Real-IP" || ko "forwarded_headers vide mais des en-têtes X-Forwarded-* / X-Real-IP sont transmis"
  [ "$(echo "$b" | jq -r '.headers["X-Forwarded-For"] // empty')" = "" ] && ok "forwarded_headers vide : pas de X-Forwarded-For (même pas celui du reverse proxy Go)" || ko "forwarded_headers vide mais X-Forwarded-For transmis : $(echo "$b" | jq -c '.headers["X-Forwarded-For"]')"
  rm -f "$hdr"
}

t_stream() { section stream "Streaming SSE et gros téléchargement" || return
  local o ttfb tot size
  o=$(curl -s -N -o /dev/null -w '%{time_starttransfer} %{time_total}' --max-time 15 "$(u lb)/sse?n=5&ms=500"); ttfb=${o% *}; tot=${o#* }
  ge 1.0 "$ttfb" && ge "$tot" 1.8 && ok "SSE non bufferisé : 1er événement à ${ttfb}s, fin à ${tot}s" || ko "SSE bufferisé ? ttfb=${ttfb}s total=${tot}s"
  size=$(curl -s -o /dev/null -w '%{size_download}' --max-time 30 "$(u lb)/bytes?n=5242880")
  check "téléchargement de 5 Mo intact" "$size" 5242880
}

t_toggle() { section toggle "Maintenance : désactiver / réactiver un proxy" || return
  local id; id=$(admin_id lab-toggle.lab.test)
  [ -n "$id" ] || { info "jeton Admin absent ou route introuvable : section ignorée"; return; }
  check "route active" "$(code "$(u toggle)/")" 200
  curl -s -o /dev/null -X PATCH -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"enabled":false}' "$LAB_ADMIN_URL/api/v1/proxies/$id"
  wait_code "$(u toggle)/" 404 20 && ok "désactivation propagée (404)" || { c=$(code "$(u toggle)/"); case "$c" in 502|503) ok "désactivation propagée ($c)";; *) ko "route toujours servie ($c)";; esac; }
  curl -s -o /dev/null -X PATCH -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d '{"enabled":true}' "$LAB_ADMIN_URL/api/v1/proxies/$id"
  wait_code "$(u toggle)/" 200 20 && ok "réactivation propagée" || ko "route non rétablie"
}

# ------------------------------------------------------------------ main
mode=${1:-all}; SECTIONS=${2:-}
case "$mode" in
  seed) seed; exit 0 ;;
  run|all) ;;
  *) echo "usage : features.sh [seed|run [sections]|all]"; exit 2 ;;
esac
[ "$mode" = all ] && seed
if [ -n "${LAB_ADMIN_TOKEN:-}${LAB_ADMIN_EMAIL:-}" ]; then . /lab/scripts/auth.sh; else token=""; fi
preflight
trap 'ctl reset' EXIT
for s in lb weighted sticky health retry cb transform paths redirect subfilter cors cache ip vars backpressure canary shadow cond errpages ws body secheaders timeout auth bot wafcustom headers stream toggle; do
  "t_$s"
done
echo; echo "Bilan : $npass PASS, $fail FAIL"
exit $fail
