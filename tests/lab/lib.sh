#!/usr/bin/env bash
# Fonctions communes à run-security.sh et run-load.sh (à sourcer, pas à lancer).
# Deux modes :
#   local  : labo jetable de docker-compose.local.yml, Admin et passerelle compilés depuis les sources ;
#   cible  : --target FICHIER, runners seuls (docker-compose.target.yml) face à une Admin et une passerelle existantes,
#            par exemple la production du LAN. Voir targets/exemple.env.

LAB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$LAB_DIR/../.." && pwd)
RESULTS=$LAB_DIR/results
STAMP=$(date +%Y%m%d-%H%M%S)
NOW_HUMAN=$(date '+%Y-%m-%d %H:%M:%S')
export MSYS_NO_PATHCONV=1   # Git Bash réécrirait /lab/scripts/... en chemin Windows
mkdir -p "$RESULTS"

TARGET=0; TARGET_NAME=; TARGET_FILE=; ASSUME_YES=0; KEEP=0
COMPOSE_FILE=docker-compose.local.yml
LAB_DIR_NATIVE=$(cd "$LAB_DIR" && { pwd -W 2>/dev/null || pwd; })   # docker.exe ne comprend pas /c/Users/...
dc()    { docker compose -f "$LAB_DIR_NATIVE/$COMPOSE_FILE" "$@"; }
tools() { dc exec -T lab-tools "$@"; }
strip_ansi() { sed $'s/\x1b\\[[0-9;]*m//g' | tr -d '\r'; }
say()   { printf '\033[1m[lab]\033[0m %s\n' "$*"; }
die()   { printf '\033[31m[lab] %s\033[0m\n' "$*" >&2; exit 2; }

command -v docker >/dev/null || die "docker introuvable"
docker info >/dev/null 2>&1 || die "le démon Docker ne répond pas"

# ------------------------------------------------------------------ mode cible
# load_target FICHIER : lit la cible ; un LAB_ADMIN_TOKEN déjà présent dans l'environnement l'emporte sur le fichier
load_target() {
  local env_token=${LAB_ADMIN_TOKEN:-} v
  [ -f "$1" ] || die "fichier de cible introuvable : $1 (modèle : tests/lab/targets/exemple.env)"
  set -a; . <(tr -d '\r' < "$1"); set +a
  [ -n "$env_token" ] && LAB_ADMIN_TOKEN=$env_token
  for v in LAB_TARGET_NAME LAB_ADMIN_URL LAB_ADMIN_TOKEN LAB_EDGE_IP LAB_BACKEND_HOST LAB_RUNNER_CIDR; do
    [ -n "${!v:-}" ] || die "$v manquant dans $1 (ou dans l'environnement)"
  done
  case "$LAB_ADMIN_TOKEN" in gpx_pat_*) ;; *) die "LAB_ADMIN_TOKEN doit être un jeton d'API (gpx_pat_…), pas un mot de passe" ;; esac
  export LAB_ADMIN_URL LAB_ADMIN_TOKEN LAB_EDGE_IP LAB_BACKEND_HOST LAB_RUNNER_CIDR LAB_ADMIN_INSECURE LAB_ALLOW_ACCOUNTS
  TARGET=1; TARGET_NAME=$LAB_TARGET_NAME; TARGET_FILE=$1; COMPOSE_FILE=docker-compose.target.yml
}

# confirm_target ACTION… : affiche la cible et ce qui va s'y passer, exige de retaper son nom (sauf --yes)
confirm_target() {
  local a
  echo
  say "CIBLE : $TARGET_NAME"
  printf '  Admin         %s\n  Passerelle    %s (ports 80 et 443)\n  Backends      %s (lab-backend et lab-sim publiés par cette machine : 9000-9008 et 9999)\n  Poste testé   %s (liste blanche Ephor des routes de test)\n  Ce passage :\n' \
    "$LAB_ADMIN_URL" "$LAB_EDGE_IP" "$LAB_BACKEND_HOST" "$LAB_RUNNER_CIDR"
  for a in "$@"; do printf '   - %s\n' "$a"; done
  echo
  [ "$ASSUME_YES" = 1 ] && return
  [ -t 0 ] || die "confirmation impossible sans terminal : relancer avec --yes si la cible est la bonne"
  read -r -p "Retaper le nom de la cible ($TARGET_NAME) pour continuer : " a
  [ "$a" = "$TARGET_NAME" ] || die "annulé"
}

# target_up : démarre les backends et runners, vérifie l'Admin et le jeton
target_up() {
  say "démarrage de lab-backend, lab-sim et des runners"
  dc up -d || die "docker compose up a échoué (LAB_BACKEND_HOST=$LAB_BACKEND_HOST est-il une IP de cette machine ?)"
  lab_ready
  local c
  c=$(tools bash -c '. /lab/scripts/auth.sh; curl -s -o /dev/null -w "%{http_code}" --max-time 20 -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies"')
  [ "$c" = 200 ] || die "l'Admin refuse le jeton ou ne répond pas ($c) : droits proxies:read/write/delete, expiration ?"
}

# target_cleanup : supprime les routes lab-* et le certificat de test de la cible (idempotent) ; sortie à journaliser
CLEANED=0
target_cleanup() {
  [ "$TARGET" = 1 ] && [ "$CLEANED" = 0 ] && [ "$KEEP" = 0 ] || return 0
  CLEANED=1
  echo "== nettoyage de la cible =="
  tools bash /lab/scripts/cleanup.sh 2>&1 | strip_ansi
}
target_teardown() {
  [ "$TARGET" = 1 ] && [ "$KEEP" = 0 ] || return 0
  dc down -v --remove-orphans >/dev/null 2>&1
}
# Sortie anormale (Ctrl-C, erreur) : ne jamais laisser les routes de test dans la cible
target_exit() { local rc=$?; target_cleanup >/dev/null 2>&1; target_teardown; exit $rc; }

# ------------------------------------------------------------------ mode local
# lab_up <fresh:0|1> <build:0|1>
lab_up() {
  local fresh=$1 build=$2 args=(-d)
  [ "$fresh" = 1 ] && { say "stack recréée de zéro"; dc down -v --remove-orphans >/dev/null 2>&1; }
  [ "$build" = 1 ] && args+=(--build)
  say "démarrage de la stack (la première compilation prend quelques minutes)"
  dc up "${args[@]}" || die "docker compose up a échoué"
  lab_ready
}

# lab_ready : runners prêts, scripts recopiés en LF, Admin et lab-sim joignables
lab_ready() {
  local i
  for i in $(seq 1 90); do tools bash -c 'command -v jq && command -v openssl' >/dev/null 2>&1 && break; sleep 2; done
  [ "$i" -lt 90 ] || die "lab-tools n'est pas prêt"
  # les scripts de scripts/ peuvent avoir changé ou être en CRLF depuis le démarrage du conteneur
  tools sh -c 'mkdir -p /lab/scripts; for f in /src/*; do tr -d "\r" < "$f" > "/lab/scripts/$(basename "$f")"; done'
  dc exec -T lab-k6 sh -c 'tr -d "\r" < /src/hosts.sh > /hosts.sh'

  say "attente de l'Admin"
  for i in $(seq 1 60); do tools bash -c 'curl -fs -o /dev/null --max-time 5 "$LAB_ADMIN_URL/api/v1/health"' && break; sleep 2; done
  [ "$i" -lt 60 ] || { dc logs --tail 30 2>/dev/null | tail -30; die "l'Admin ne répond pas ($([ "$TARGET" = 1 ] && echo "$LAB_ADMIN_URL" || echo goproxify-admin))"; }
  say "attente de lab-sim"
  for i in $(seq 1 60); do tools curl -fs -o /dev/null http://lab-sim:9999/ctl/stats && break; sleep 2; done
  [ "$i" -lt 60 ] || die "lab-sim ne répond pas"
}

# wait_route <url> : la passerelle applique une route créée par l'Admin avec un léger délai
wait_route() {
  local i
  for i in $(seq 1 "${LAB_ROUTE_WAIT:-40}"); do
    tools sh -c ". /lab/scripts/hosts.sh && curl -s -o /dev/null -w '%{http_code}' --max-time 5 '$1'" 2>/dev/null | grep -q '^200$' && return 0
    sleep 2
  done
  return 1
}

lab_info() { # lignes « clé | valeur » pour l'en-tête des rapports
  local commit dirty v_admin v_edge
  commit=$(git -C "$LAB_DIR_NATIVE" rev-parse --short HEAD 2>/dev/null || echo inconnu)
  [ -n "$(git -C "$LAB_DIR_NATIVE" status --porcelain --untracked-files=no 2>/dev/null)" ] && dirty=" (modifications locales non commitées)" || dirty=""
  v_admin=$(grep -o '"admin": *"[^"]*"' "$ROOT/versions.json" | cut -d'"' -f4)
  v_edge=$(grep -o '"edge": *"[^"]*"' "$ROOT/versions.json" | cut -d'"' -f4)
  printf '| Date | %s |\n' "$NOW_HUMAN"
  if [ "$TARGET" = 1 ]; then
    printf '| Cible | **%s** : Admin %s, passerelle %s, backends de test %s |\n' "$TARGET_NAME" "$LAB_ADMIN_URL" "$LAB_EDGE_IP" "$LAB_BACKEND_HOST"
    printf '| Scripts | commit %s%s (versions du dépôt : Admin %s, passerelle %s ; celles de la cible peuvent différer) |\n' "$commit" "$dirty" "$v_admin" "$v_edge"
  else
    printf '| Cible | labo local jetable, compilé depuis les sources |\n| Commit | %s%s |\n| Versions | Admin %s, Passerelle %s |\n' "$commit" "$dirty" "$v_admin" "$v_edge"
  fi
  printf '| Poste | %s, Docker %s |\n' "$(uname -s)" "$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
}

fmt_duration() { local s=$1; printf '%dm%02ds' $((s/60)) $((s%60)); }
