#!/usr/bin/env bash
# Tests de charge de la passerelle en une commande : démarre le labo, crée les routes de test, enchaîne les scénarios k6
# et écrit un rapport horodaté (débit, latences, erreurs, seuils, CPU/mémoire de la passerelle). Deux modes : labo local
# jetable (défaut) ou cible distante (--target).
#
#   tests/lab/run-load.sh [options] [scénario...]
#
#   scénarios        smoke moderate saturation baseline spike stress mixed realistic soak (défaut : smoke moderate saturation, ~3 min)
#   --full           smoke moderate saturation baseline spike mixed realistic stress (~20 min ; soak, 30 min, reste à nommer)
#   --rate N         débit imposé en req/s de moderate et soak (défaut 300 en local, 50 sur une cible)
#   --duration D     durée de moderate, soak et realistic (ex. 2m ; défauts 1m, 30m et 3m)
#   --no-build       réutilise les images déjà compilées (par défaut Admin et passerelle sont recompilés ; le cache Docker rend le cas sans changement quasi instantané)
#   --fresh          repart d'une stack vierge (down -v puis up)
#   --down           arrête et supprime la stack après le test
#
# Cible distante (production du LAN…) :
#   --target FICHIER  cible décrite par un fichier d'après targets/exemple.env ; une seule route lab-fast.lab.test est créée puis supprimée.
#                     Plafonné pour ne pas gêner le trafic réel : smoke et moderate, 100 req/s, 2 min
#   --allow-heavy     lève ces plafonds (fenêtre de maintenance !) ; realistic reste réservé au labo local
#   --yes             ne demande pas de retaper le nom de la cible (indispensable hors terminal)
#   --keep            laisse la route de test et les conteneurs en place
#
# Rapport : tests/lab/results/charge-AAAAMMJJ-HHMMSS.md (+ .log brut, + JSON k6 dans charge-AAAAMMJJ-HHMMSS/) et charge-dernier.md.
# Code retour : 0 si tous les seuils sont tenus, 1 sinon, 2 si le labo n'a pas pu démarrer.
# Les chiffres d'un poste de développement (k6, passerelle et backend sur la même machine) ne sont pas comparables à docs/benchmark.md.
set -u -o pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

scenarios=(); build=1; fresh=0; down=0; rate=""; duration=""; target_file=""; heavy=0
while [ $# -gt 0 ]; do
  case $1 in
    --full) scenarios=(smoke moderate saturation baseline spike mixed realistic stress) ;;
    --rate) rate=${2:?débit attendu}; shift ;;
    --duration) duration=${2:?durée attendue}; shift ;;
    --no-build) build=0 ;;
    --fresh) fresh=1 ;;
    --down) down=1 ;;
    --target) target_file=${2:?fichier de cible attendu}; shift ;;
    --allow-heavy) heavy=1 ;;
    --yes) ASSUME_YES=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) die "option inconnue : $1 (--help)" ;;
    *) [ -f "$LAB_DIR/load/$1.js" ] || die "scénario inconnu : $1"; scenarios+=("$1") ;;
  esac
  shift
done
default_scen=0; [ ${#scenarios[@]} -gt 0 ] || { default_scen=1; scenarios=(smoke moderate saturation); }

REPORT=$RESULTS/charge-$STAMP.md
LOG=$RESULTS/charge-$STAMP.log
OUT=$RESULTS/charge-$STAMP
mkdir -p "$OUT"
start=$(date +%s)

if [ -n "$target_file" ]; then
  [ "$default_scen" = 1 ] && scenarios=(smoke moderate)
  case " ${scenarios[*]} " in *" realistic "*) die "realistic exige les routes de la boutique simulée : réservé au labo local" ;; esac
  if [ "$heavy" = 0 ]; then
    for s in "${scenarios[@]}"; do
      case $s in smoke|moderate) ;; *) die "scénario $s refusé sur une cible (charge lourde) : ajouter --allow-heavy en fenêtre de maintenance" ;; esac
    done
    [ -n "$rate" ] || rate=50
    [ "$rate" -le 100 ] 2>/dev/null || die "--rate $rate dépasse 100 req/s : ajouter --allow-heavy en fenêtre de maintenance"
    if [ -n "$duration" ]; then
      secs=$(case $duration in *m) echo $(( ${duration%m} * 60 ));; *s) echo "${duration%s}";; *) echo 9999;; esac)
      [ "$secs" -le 120 ] 2>/dev/null || die "--duration $duration dépasse 2m : ajouter --allow-heavy en fenêtre de maintenance"
    fi
  fi
  load_target "$target_file"
  confirm_target \
    "créer dans l'Admin la route lab-fast.lab.test (backend de test sur $LAB_BACKEND_HOST:9000)" \
    "envoyer du trafic de charge (${scenarios[*]}${rate:+, ${rate} req/s}${duration:+, $duration}) à la passerelle $LAB_EDGE_IP : elle le partage avec le trafic réel" \
    "supprimer ensuite la route de test$([ "$KEEP" = 1 ] && echo " (désactivé : --keep)")"
  trap target_exit EXIT
  target_up
else
  lab_up "$fresh" "$build"
fi

say "création des routes de test"
if [ "$TARGET" = 1 ]; then
  tools env LAB_SEED_ONLY=lab-fast.lab.test bash /lab/scripts/seed.sh 2>&1 | strip_ansi | tee "$LOG"
else
  tools bash /lab/scripts/seed.sh 2>&1 | strip_ansi | grep -v 'toxiproxy\|lab-chaos\|lab-juice' | tee "$LOG"
fi
case " ${scenarios[*]} " in *" realistic "*)
  say "création des routes de la boutique simulée (scénario realistic)"
  tools bash /lab/scripts/features.sh seed 2>&1 | strip_ansi | tail -3 | tee -a "$LOG" ;;
esac
wait_route http://lab-fast.lab.test/ || {
  c=$(tools sh -c ". /lab/scripts/hosts.sh && curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://lab-fast.lab.test/")
  d=$(tools curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${LAB_BACKEND_HOST:-lab-backend}:9000/")
  target_cleanup | tee -a "$LOG"
  die "lab-fast.lab.test ne répond pas 200 (via la passerelle : $c ; backend joint directement : $d). Backend 200 mais passerelle 502/504 : pare-feu entre la passerelle et le poste de test (ports 9000-9008 et 9999). 404 : route pas encore appliquée, relancer avec LAB_ROUTE_WAIT plus grand."
}
case " ${scenarios[*]} " in *" realistic "*) wait_route http://lab-realistic.lab.test/ || die "lab-realistic.lab.test ne répond pas 200" ;; esac

edge_id=$([ "$TARGET" = 1 ] || dc ps -q goproxify-edge)
# CPU et mémoire de la passerelle pendant le scénario courant, un échantillon toutes les ~3 s :
#   labo local  : docker stats du conteneur ;
#   cible       : CPU et mémoire (%) que les passerelles déclarent à l'Admin (GET /api/v1/nodes, scope nodes:read), valeur de l'hôte
sample() { # fichier
  while :; do docker stats --no-stream --format '{{.CPUPerc}};{{.MemUsage}}' "$edge_id" >> "$1" 2>/dev/null; sleep 1; done
}
sample_nodes() { # fichier
  while :; do
    tools bash -c 'curl -s --max-time 10 -H "Authorization: Bearer $LAB_ADMIN_TOKEN" "$LAB_ADMIN_URL/api/v1/nodes" | jq -r "[.[]? | select(.role == \"edge\")] | if length == 0 then empty else \"node;\(map(.cpu_pct // 0) | max);\(map(.mem_pct // 0) | max)\" end"' 2>/dev/null | tr -d '\r' >> "$1"
    sleep 3
  done
}
stats_max() { # fichier -> « cpu max % ; mémoire max Mo » (ou % de l'hôte pour une cible)
  [ -s "$1" ] || { printf "n/a%s" "$([ "$TARGET" = 1 ] && echo " (scope nodes:read ?)")"; return; }
  if head -1 "$1" | grep -q '^node;'; then
    awk -F';' '{ if ($2 + 0 > c) c = $2 + 0; if ($3 + 0 > m) m = $3 + 0 } END { printf "%.0f %% ; %.0f %% (hôte)", c, m }' "$1"
    return
  fi
  awk -F';' '
    { c = $1; sub(/%/, "", c); if (c + 0 > cpu) cpu = c + 0
      split($2, a, " "); m = a[1]; u = m; gsub(/[0-9.]/, "", u); sub(/[A-Za-z]+$/, "", m)
      if (u == "GiB") m *= 1024; else if (u == "KiB") m /= 1024; else if (u == "B") m /= 1048576
      if (m + 0 > mem) mem = m + 0 }
    END { printf "%.0f %% ; %.0f Mo", cpu, mem }' "$1" 2>/dev/null
}

declare -A rc dur
rows=()
# conditions du passage : deux passages ne se comparent que s'ils visent la même cible avec les mêmes réglages
echo "${TARGET_NAME:-local}|${rate:-}|${duration:-}|$heavy" > "$OUT/meta"

# Niveau de base de l'hôte de la passerelle avant toute charge : sans lui, un CPU à 80 % ne dit pas si c'est le test ou l'hôte.
# L'Agent déclare ses mesures toutes les 30 s : 35 s d'attente pour en voir au moins une.
if [ "$TARGET" = 1 ]; then
  say "mesure de la passerelle au repos (35 s)"
  : > "$OUT/idle.stats"
  sample_nodes "$OUT/idle.stats" & sp=$!
  sleep 35
  kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
fi
for s in "${scenarios[@]}"; do
  say "scénario $s"
  rm -f "$RESULTS/$s.json"
  env_args=""
  [ -n "$rate" ] && env_args="$env_args -e RATE=$rate"
  [ -n "$duration" ] && env_args="$env_args -e DURATION=$duration"
  [ "$TARGET" = 1 ] && [ "$heavy" = 0 ] && [ "$s" = smoke ] && env_args="$env_args -e PAUSE=0.1"
  [ "$s" = realistic ] && [ -n "$rate" ] && env_args="$env_args -e SHOP_RATE=$((rate / 15 > 0 ? rate / 15 : 1))"
  stats=$OUT/$s.stats; : > "$stats"
  sp=; if [ "$TARGET" = 1 ]; then sample_nodes "$stats" & sp=$!; else sample "$stats" & sp=$!; fi
  t0=$(date +%s)
  { echo; echo "== $s =="; dc exec -T lab-k6 sh -c "sh /hosts.sh && k6 run --quiet --no-color$env_args /scripts/$s.js" 2>&1 | strip_ansi; } | tee -a "$LOG"
  rc[$s]=${PIPESTATUS[0]}
  dur[$s]=$(( $(date +%s) - t0 ))
  [ -z "$sp" ] || { kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null; }
  [ -f "$RESULTS/$s.json" ] && mv "$RESULTS/$s.json" "$OUT/$s.json"
  sleep 5   # laisse la passerelle retomber avant le scénario suivant
done

if [ "$TARGET" = 1 ]; then
  say "nettoyage de la cible"
  target_cleanup > "$RESULTS/.cleanup-$STAMP"
  tee -a "$LOG" < "$RESULTS/.cleanup-$STAMP"; rm -f "$RESULTS/.cleanup-$STAMP"
fi

failed=0; for s in "${scenarios[@]}"; do [ "${rc[$s]}" -ne 0 ] && failed=$((failed+1)); done
total=$(( $(date +%s) - start ))
[ "$failed" -eq 0 ] && verdict="SUCCÈS" || verdict="ÉCHEC ($failed scénario(s) hors seuils)"

read -r -d "" jqcells <<'JQ' || true
def val(m; k): ((.metrics[m] // {}) | (.values // .)[k]) // null;
def n(x; d): if x == null then "-" else ((x * pow(10; d) | round) / pow(10; d) | tostring) end;
[ n(val("http_reqs"; "count"); 0), n(val("http_reqs"; "rate"); 0),
  (if val("http_req_failed"; "rate") == null then "-" else n(val("http_req_failed"; "rate") * 100; 2) + " %" end),
  n(val("http_req_duration"; "med"); 1), n(val("http_req_duration"; "p(95)"); 1),
  n(val("http_req_duration"; "p(99)"); 1), n(val("http_req_duration"; "max"); 0),
  n(val("vus"; "max"); 0), n(val("dropped_iterations"; "count") // 0; 0) ] | join(" | ")
JQ
# valeurs comparées d'un passage à l'autre : p95, p99, débit, taux d'échec (%)
read -r -d "" jqcmp <<'JQ' || true
def val(m; k): ((.metrics[m] // {}) | (.values // .)[k]) // 0;
[ val("http_req_duration"; "p(95)"), val("http_req_duration"; "p(99)"), val("http_reqs"; "rate"), val("http_req_failed"; "rate") * 100 ] | @tsv
JQ

# previous_run SCENARIO : dossier du passage précédent (mêmes conditions) qui contient ce scénario, sinon rien
previous_run() {
  local d
  for d in $(ls -1d "$RESULTS"/charge-*/ 2>/dev/null | sort -r); do
    d=${d%/}
    [ "$d" = "$OUT" ] && continue
    [ "$(cat "$d/meta" 2>/dev/null)" = "$(cat "$OUT/meta")" ] && [ -f "$d/$1.json" ] && { echo "$d"; return; }
  done
}
read -r -d "" jqthr <<'JQ' || true
.metrics | to_entries[] | .key as $m | (.value.thresholds // {}) | to_entries[]
| "\($m) : \(.key) → \(if (.value | type) == "object" then (if .value.ok then "tenu" else "NON TENU" end) else (if .value then "NON TENU" else "tenu" end) end)"
JQ

{
  echo "# Rapport de charge GoProxify — $NOW_HUMAN"
  echo
  echo "**Verdict : $verdict**"
  echo
  echo "| | |"; echo "|---|---|"
  lab_info
  echo "| Durée totale | $(fmt_duration "$total") |"
  echo "| Scénarios | ${scenarios[*]} |"
  echo
  echo "## Résultat par scénario"
  echo
  echo "| Scénario | Seuils | Durée | Requêtes | Req/s | Échecs | p50 ms | p95 ms | p99 ms | max ms | VUs actifs max | Itérations abandonnées | Passerelle (CPU max ; mém. max) |"
  echo "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|"
  for s in "${scenarios[@]}"; do
    [ "${rc[$s]}" -eq 0 ] && st="tenus" || st="**NON TENUS**"
    if [ -f "$OUT/$s.json" ]; then cells=$(tools jq -r "$jqcells" < "$OUT/$s.json" 2>/dev/null) || cells=""; fi
    [ -n "${cells:-}" ] || cells="- | - | - | - | - | - | - | - | -"
    echo "| $s | $st | $(fmt_duration "${dur[$s]}") | $cells | $(stats_max "$OUT/$s.stats") |"
    unset cells
  done
  echo
  if [ "$TARGET" = 1 ]; then
    echo "Hôte de la passerelle au repos (35 s avant le premier scénario) : $(stats_max "$OUT/idle.stats")"
    echo
  fi
  echo "## Évolution depuis le passage précédent"
  echo
  shown=0
  for s in "${scenarios[@]}"; do
    prev=$(previous_run "$s")
    [ -n "$prev" ] && [ -f "$OUT/$s.json" ] || continue
    a=$(tools jq -r "$jqcmp" < "$prev/$s.json" 2>/dev/null | tr -d '\r'); b=$(tools jq -r "$jqcmp" < "$OUT/$s.json" 2>/dev/null | tr -d '\r')
    [ -n "$a" ] && [ -n "$b" ] || continue
    if [ "$shown" = 0 ]; then
      echo "Comparaison avec le dernier passage de mêmes conditions (cible, débit, durée)."; echo
      echo "| Scénario | Passage précédent | p95 ms | p99 ms | Req/s | Échecs % | Alerte |"; echo "|---|---|---|---|---|---|---|"
      shown=1
    fi
    awk -v s="$s" -v d="$(basename "$prev" | sed 's/^charge-//')" -v a="$a" -v b="$b" 'BEGIN {
      split(a, x, "\t"); split(b, y, "\t")
      for (i = 1; i <= 3; i++) { p[i] = (x[i] > 0) ? (y[i] - x[i]) / x[i] * 100 : 0 }
      alert = ""
      if (y[1] > x[1] * 1.25 && y[1] - x[1] > 2) alert = "latence p95 en hausse"
      if (y[4] > x[4] + 0.5) alert = (alert == "" ? "" : alert ", ") "taux d échec en hausse"
      if (y[3] < x[3] * 0.8) alert = (alert == "" ? "" : alert ", ") "débit en baisse"
      printf "| %s | %s | %.1f → %.1f (%+.0f %%) | %.1f → %.1f (%+.0f %%) | %.0f → %.0f (%+.0f %%) | %.2f → %.2f | %s |\n", s, d, x[1], y[1], p[1], x[2], y[2], p[2], x[3], y[3], p[3], x[4], y[4], (alert == "" ? "-" : "**" alert "**") }'
  done
  [ "$shown" = 1 ] || echo "Premier passage dans ces conditions : rien à comparer."
  echo
  echo "## Seuils"
  echo
  for s in "${scenarios[@]}"; do
    echo "### $s"; echo
    if [ -f "$OUT/$s.json" ]; then tools jq -r "$jqthr" < "$OUT/$s.json" 2>/dev/null | tr -d '\r' | sed 's/^/- /'; else echo "- aucun résumé produit (le scénario a échoué avant la fin : voir le journal)"; fi
    echo
  done
  if [ "$TARGET" = 1 ]; then
    echo "> Cible distante : k6 et le backend de test tournent sur ce poste, la passerelle est celle de la cible ; la latence mesurée inclut donc ce poste et le réseau. Le débit est plafonné pour ne pas gêner le trafic réel : ces chiffres disent que la passerelle tient cette charge et permettent de suivre les régressions d'un passage à l'autre, pas de mesurer sa capacité. CPU et mémoire sont ceux de l'hôte de la passerelle déclarés à l'Admin (l'Agent les déclare toutes les 30 s : un scénario court n'en voit que un ou deux). Avant l'Agent 0.27.1 le CPU déclaré était un relevé de 200 ms, très bruité."
  else
    echo "> Poste de développement : k6, passerelle et backend se partagent la machine ; ces chiffres servent à suivre les régressions d'un passage à l'autre, pas à les comparer à \`docs/benchmark.md\`."
  fi
  echo "> Itérations abandonnées > 0 : le système n'a pas tenu le débit demandé. \`saturation\`, \`baseline\`, \`spike\`, \`stress\` et \`mixed\` ne fixent aucun seuil de débit : lire les req/s et les erreurs. « VUs actifs max » est le pic d'utilisateurs virtuels réellement occupés, pas le nombre préalloué."
  echo
  echo "<details><summary>Journal complet</summary>"
  echo
  echo '```'
  cat "$LOG"
  echo '```'
  echo
  echo "</details>"
} > "$REPORT"
cp "$REPORT" "$RESULTS/charge-dernier.md"

[ "$down" = 1 ] && { say "arrêt de la stack"; dc down -v --remove-orphans >/dev/null 2>&1; }

echo
say "$verdict en $(fmt_duration "$total")"
say "rapport : ${REPORT#"$ROOT"/}"
[ "$failed" -eq 0 ]
