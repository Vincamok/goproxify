#!/usr/bin/env bash
# Régénère les services lab-tools / lab-k6 de docker-compose.lab.yml en y embarquant scripts/*.sh et load/*.js
# (aucun montage ni copie nécessaire sur le daemon distant). À relancer après toute modif de ces fichiers.
set -eu
cd "$(dirname "$0")"
F=docker-compose.lab.yml
emb() { # prefix file... -> variables d'environnement YAML (les $ sont doublés pour Compose)
  local p=$1; shift
  for f in "$@"; do
    printf '      %s%s: |\n' "$p" "$(basename "$f" | sed 's/\..*//; s/-/_/g')"
    tr -d '\r' < "$f" | sed 's/\$/$$/g; s/^\(.\)/        \1/'
  done
}
gen() {
cat <<'X'
  # >>> GENERATED (tests/lab/gen-compose.sh) — ne pas éditer à la main
  # Runners permanents pour `docker exec` : scripts embarqués, écrits au démarrage.
  lab-tools:
    image: alpine:3.20
    container_name: lab-tools
    restart: unless-stopped
    entrypoint:
      - sh
      - -c
      - |
        apk add --no-cache bash curl jq netcat-openbsd openssl coreutils >/dev/null
        mkdir -p /lab/scripts
        for f in seed attacks chaos hosts auth cleanup features security; do eval "printf %s \"\$$S_$$f\"" > /lab/scripts/$$f.sh; done
        printf %s "$$S_feature_routes" > /lab/scripts/feature-routes.json
        printf %s "$$S_security_routes" > /lab/scripts/security-routes.json
        exec sleep infinity
    networks: [goproxify_net]
    environment:
      LAB_ADMIN_URL: http://goproxify-admin:9443
X
emb S_ scripts/seed.sh scripts/attacks.sh scripts/chaos.sh scripts/hosts.sh scripts/auth.sh scripts/cleanup.sh scripts/features.sh scripts/feature-routes.json scripts/security.sh scripts/security-routes.json
cat <<'X'

  lab-k6:
    image: grafana/k6:latest
    container_name: lab-k6
    user: root
    restart: unless-stopped
    entrypoint:
      - sh
      - -c
      - |
        mkdir -p /scripts /results
        for f in common smoke moderate saturation baseline spike stress soak mixed realistic hosts; do eval "printf %s \"\$$K_$$f\"" > /scripts/$$f.js; done
        mv /scripts/hosts.js /hosts.sh
        exec sleep infinity
    networks: [goproxify_net]
    environment:
X
emb K_ load/common.js load/smoke.js load/moderate.js load/saturation.js load/baseline.js load/spike.js load/stress.js load/soak.js load/mixed.js load/realistic.js scripts/hosts.sh
echo
cat <<'X'

  # Applications simulées pour features.sh et realistic.js : boutique à 3 instances (9001-9003), canary (9004),
  # shadow (9005), legacy (9006), écho TCP (9100) ; pilotage de l'état sur 9999 (réseau interne uniquement, aucun port publié).
  lab-sim:
    image: golang:1.22-alpine
    container_name: lab-sim
    restart: unless-stopped
    working_dir: /app
    entrypoint: ["sh", "-c", "mkdir -p /app && printf %s \"$$SIM_main\" > /app/main.go && exec go run /app/main.go"]
    networks: [goproxify_net]
    environment:
X
emb SIM_ sim/main.go
echo
echo '  # <<< GENERATED'
}
s=$(grep -n '>>> GENERATED' $F | cut -d: -f1); e=$(grep -n '<<< GENERATED' $F | cut -d: -f1)
{ sed -n "1,$((s-1))p" $F; gen; sed -n "$((e+1)),\$p" $F; } > $F.new && mv $F.new $F
