#!/usr/bin/env bash
# Suite de sécurité de la passerelle en une commande : démarre le labo, crée les routes de test, lance les sections de
# scripts/security.sh et écrit un rapport horodaté. Deux modes : labo local jetable (défaut) ou cible distante (--target).
#
#   tests/lab/run-security.sh [options]
#
#   --sections a,b   sections au choix : trust acl ratelimit inject protocol waf cache ws jwt errleak admin spoof rights bans ephor tarpit decoys challenge ipcontrols geoip mtls asn http3 internal redirect tls (défaut : toutes)
#   --skip a,b       toutes les sections sauf celles-ci
#   --attacks        ajoute scripts/attacks.sh (WAF, smuggling, slowloris ~75 s, API Admin) ; labo local seulement
#   --brute          active le test anti brute-force du login Admin (verrouille le compte de test) ; labo local seulement
#   --no-build       réutilise les images déjà compilées (par défaut Admin et passerelle sont recompilés ; le cache Docker rend le cas sans changement quasi instantané)
#   --fresh          repart d'une stack vierge (down -v puis up)
#   --down           arrête et supprime la stack après le test
#   --no-strict-pass  ne rejoue pas trust, ratelimit, spoof et redirect avec GPX_TRUSTED_PROXIES=none après le premier passage (labo local)
#   --no-brute       ne joue pas le brute-force du login Admin (joué par défaut en local, jamais sur une cible)
#   --strict-ip      démarre Admin et passerelle avec GPX_TRUSTED_PROXIES=none (aucun réseau privé cru pour l'IP client) : les contrôles
#                    d'usurpation d'IP (X-Forwarded-For, rate-limit, journal d'audit), ignorés sinon depuis un poste du LAN, sont joués ;
#                    labo local seulement
#
# Cible distante (production du LAN…) :
#   --target FICHIER  cible décrite par un fichier d'après targets/exemple.env : aucune compilation, seuls des runners et les backends
#                     de test tournent ici ; les routes lab-sec-* sont créées dans l'Admin visé, testées, puis supprimées
#   --yes             ne demande pas de retaper le nom de la cible (indispensable hors terminal)
#   --keep            laisse routes de test et conteneurs en place (diagnostic ; nettoyage : docker compose -f tests/lab/docker-compose.target.yml ...)
#
# Rapport : tests/lab/results/securite-AAAAMMJJ-HHMMSS.md (+ .log brut) et securite-dernier.md. Code retour : 0 si aucun FAIL, 1 sinon, 2 si le labo n'a pas pu démarrer.
set -u
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

strict_ip=0; sections=""; skip_sections=""; attacks=0; brute=-1; build=1; fresh=0; down=0; target_file=""; strict_pass=1
while [ $# -gt 0 ]; do
  case $1 in
    --sections) sections=${2:?liste de sections attendue}; shift ;;
    --skip) skip_sections=${2:?liste de sections attendue}; shift ;;
    --attacks) attacks=1 ;;
    --brute) brute=1 ;;
    --no-brute) brute=0 ;;
    --no-strict-pass) strict_pass=0 ;;
    --no-build) build=0 ;;
    --fresh) fresh=1 ;;
    --down) down=1 ;;
    --strict-ip) strict_ip=1 ;;
    --target) target_file=${2:?fichier de cible attendu}; shift ;;
    --yes) ASSUME_YES=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "option inconnue : $1 (--help)" ;;
  esac
  shift
done

ALL_SECTIONS="trust acl ratelimit inject protocol waf cache ws jwt errleak admin spoof rights bans ephor tarpit decoys challenge ipcontrols geoip mtls asn http3 internal redirect tls"
if [ -n "$skip_sections" ]; then
  [ -z "$sections" ] || die "--sections et --skip sont exclusifs"
  for s in $ALL_SECTIONS; do
    case ",$skip_sections," in *",$s,"*) ;; *) sections=${sections:+$sections,}$s ;; esac
  done
fi
# Brute-force du login : par défaut joué sur le labo local (il vise un compte inexistant d'une stack jetable), jamais sur une cible
brute_asked=$brute
[ "$brute" = -1 ] && { [ -n "$target_file" ] && brute=0 || brute=1; }

# Un poste du LAN est un pair de confiance par défaut : trust, ratelimit (rotation de X-Forwarded-For), spoof et redirect
# (X-Forwarded-Proto) ne prouvent rien de plus dans ce mode. Sur le labo local, ces sections sont rejouées dans un second
# passage avec GPX_TRUSTED_PROXIES=none ; le premier passage laisse spoof au second.
STRICT_SECTIONS="trust ratelimit spoof redirect"
pass1=$sections; pass2=""; dual=0
if [ -z "$target_file" ] && [ "$strict_ip" = 0 ] && [ "$strict_pass" = 1 ]; then
  for s in $STRICT_SECTIONS; do
    if [ -z "$sections" ] || case ",$sections," in *",$s,"*) true ;; *) false ;; esac; then pass2=${pass2:+$pass2,}$s; fi
  done
  if [ -n "$pass2" ]; then
    dual=1
    base=${sections:-$(echo $ALL_SECTIONS | tr ' ' ',')}
    pass1=""; for s in ${base//,/ }; do [ "$s" = spoof ] || pass1=${pass1:+$pass1,}$s; done
  fi
fi

REPORT=$RESULTS/securite-$STAMP.md
LOG=$RESULTS/securite-$STAMP.log
start=$(date +%s)

if [ -n "$target_file" ]; then
  [ "$attacks" = 0 ] && [ "$brute_asked" != 1 ] || die "--attacks et --brute (brute-force du login, slowloris) sont réservés au labo local"
  [ "$strict_ip" = 0 ] || die "--strict-ip réglerait Admin et passerelle du labo local : sans objet sur une cible distante (positionner GPX_TRUSTED_PROXIES sur la cible)"
  load_target "$target_file"
  confirm_target \
    "créer dans l'Admin les routes lab-sec-*.lab.test (13, sans lab-sec-geo ni lab-sec-wl) et importer un certificat auto-signé *.lab.test" \
    "envoyer quelques centaines de requêtes d attaque simulées (WAF, smuggling, JWT forgés…) vers ces seules routes" \
    "poser puis retirer un ban sur 198.51.100.200 (section bans) et sur la plage 198.51.100.192/28 (section ipcontrols) ; plages de documentation, sans effet sur le trafic réel" \
    "$([ "${LAB_ALLOW_ACCOUNTS:-0}" = 1 ] && echo "créer puis supprimer un compte et une équipe de test (section rights)" || echo "ne créer aucun compte (LAB_ALLOW_ACCOUNTS=0)")" \
    "supprimer ensuite routes et certificat de test$([ "$KEEP" = 1 ] && echo " (désactivé : --keep)")"
  trap target_exit EXIT
  target_up
else
  [ "$strict_ip" = 1 ] && export GPX_TRUSTED_PROXIES=none
  # base GeoIP de test de MaxMind (adresses connues par pays), montée dans la passerelle du labo ; absente, la section geoip est ignorée
  mkdir -p "$LAB_DIR/fixtures"
  if [ ! -s "$LAB_DIR/fixtures/GeoIP2-Country-Test.mmdb" ]; then
    say "téléchargement de la base GeoIP de test de MaxMind"
    curl -fsSL --max-time 60 -o "$LAB_DIR/fixtures/GeoIP2-Country-Test.mmdb" \
      "https://github.com/maxmind/MaxMind-DB/raw/main/test-data/GeoIP2-Country-Test.mmdb" \
      || { rm -f "$LAB_DIR/fixtures/GeoIP2-Country-Test.mmdb"; say "base GeoIP indisponible : la section geoip sera ignorée"; }
  fi
  # mini-base ip2asn (format iptoasn.com : début, fin, ASN, pays, nom, séparés par des tabulations) : deux ASN de documentation sur
  # 198.51.100.0/24 en quatre plages non contiguës (deux par ASN : l'Admin fusionne les plages adjacentes d'un même ASN), lue par
  # l'Admin du labo à la place du jeu public de 9 Mo. Pas 203.0.113.0/24 : les profils IP publics que l'Admin active par défaut
  # (FireHOL…) la refusent dès qu'ils sont chargés, ce qui rend le résultat dépendant du moment où le labo a démarré.
  printf '198.51.100.208\t198.51.100.215\t64496\tZZ\tLAB-TEST-AS-A\n198.51.100.216\t198.51.100.223\t64497\tZZ\tLAB-TEST-AS-B\n198.51.100.232\t198.51.100.239\t64496\tZZ\tLAB-TEST-AS-A\n198.51.100.242\t198.51.100.249\t64497\tZZ\tLAB-TEST-AS-B\n' \
    | gzip -c > "$LAB_DIR/fixtures/ip2asn-lab.tsv.gz"
  # client HTTP/3 du labo (le curl d'Alpine n'a pas HTTP/3) : compilé avec le Go de ce poste ; absent, la section http3 est ignorée
  if command -v go >/dev/null 2>&1; then
    ( cd "$ROOT" && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$LAB_DIR/fixtures/h3probe" ./tests/lab/tools/h3probe ) \
      || { rm -f "$LAB_DIR/fixtures/h3probe"; say "compilation de la sonde HTTP/3 impossible : la section http3 sera ignorée"; }
  else rm -f "$LAB_DIR/fixtures/h3probe"; say "Go absent : la section http3 sera ignorée"; fi
  lab_up "$fresh" "$build"
fi

say "création des routes de test (lab-sec-*) et du certificat TLS"
tools bash /lab/scripts/security.sh seed 2>&1 | strip_ansi | tee "$LOG"

say "suite de sécurité"
tools env LAB_BRUTE="$brute" LAB_STRICT_PASS_FOLLOWS="$dual" bash /lab/scripts/security.sh run $pass1 2>&1 | strip_ansi | tee -a "$LOG"

passes=1
if [ "$dual" = 1 ]; then
  passes=2
  say "second passage, GPX_TRUSTED_PROXIES=none : $pass2"
  export GPX_TRUSTED_PROXIES=none
  dc up -d >/dev/null 2>&1 && lab_ready >/dev/null 2>&1
  { echo; echo "== second passage : Admin et passerelle avec GPX_TRUSTED_PROXIES=none =="; } | tee -a "$LOG"
  tools bash /lab/scripts/security.sh seed 2>&1 | strip_ansi >> "$LOG"
  tools env LAB_BRUTE=0 SECTION_PREFIX="[none] " bash /lab/scripts/security.sh run $pass2 2>&1 | strip_ansi | tee -a "$LOG"
  # la stack repart dans son état par défaut : un usage à la main ou un autre script ne doit pas hériter du mode strict
  unset GPX_TRUSTED_PROXIES
  dc up -d >/dev/null 2>&1 && lab_ready >/dev/null 2>&1
fi

if [ "$attacks" = 1 ]; then
  say "attaques ciblées (attacks.sh)"
  tools bash /lab/scripts/seed.sh 2>&1 | strip_ansi >> "$LOG"
  { echo; echo "== attacks.sh =="; tools bash /lab/scripts/attacks.sh 2>&1 | strip_ansi; } | tee -a "$LOG"
fi

if [ "$TARGET" = 1 ]; then
  say "nettoyage de la cible"
  target_cleanup > "$RESULTS/.cleanup-$STAMP"
  cat "$RESULTS/.cleanup-$STAMP" | tee -a "$LOG"; rm -f "$RESULTS/.cleanup-$STAMP"
fi


dur=$(( $(date +%s) - start ))
pass=$(grep -c '^  PASS ' "$LOG"); fail=$(grep -c '^  FAIL ' "$LOG"); skip=$(grep -c '^  skip ' "$LOG"); warn=$(grep -c '^  WARN ' "$LOG")
bilans=$(grep -c '^Bilan : ' "$LOG")
if [ "$bilans" -eq 0 ]; then ran=0; verdict="NON EXÉCUTÉE (la cible n'a pas répondu avant le premier contrôle : voir le diagnostic)"
elif [ "$bilans" -lt "$passes" ]; then ran=1; fail=$((fail+1)); verdict="INCOMPLÈTE (le second passage en mode strict n'a pas abouti : voir le journal)"
elif [ "$fail" -eq 0 ]; then ran=1; verdict="SUCCÈS"
else ran=1; verdict="ÉCHEC ($fail contrôle(s) en échec)"; fi

{
  echo "# Rapport de sécurité GoProxify — $NOW_HUMAN"
  echo
  echo "**Verdict : $verdict**"
  echo
  echo "| | |"; echo "|---|---|"
  lab_info
  echo "| Durée | $(fmt_duration "$dur") |"
  echo "| Périmètre | ${sections:-toutes les sections}$([ "$attacks" = 1 ] && echo ", attacks.sh")$([ "$dual" = 1 ] && echo " ; second passage avec GPX_TRUSTED_PROXIES=none : $pass2")$([ "$strict_ip" = 1 ] && echo " ; Admin et passerelle avec GPX_TRUSTED_PROXIES=none") |"
  echo
  echo "| PASS | FAIL | Ignorés | Avertissements |"; echo "|---:|---:|---:|---:|"
  echo "| $pass | $fail | $skip | $warn |"
  echo
  if [ "$ran" = 0 ]; then
    echo "## Diagnostic"
    echo
    echo "Aucune section n'a été jouée : les 0 PASS / 0 FAIL ci-dessus ne disent rien de la sécurité de la cible."
    echo
    grep -E '^(ATTENTION|  ABORT|  via |  backend |  ->)' "$LOG" | sed 's/^/    /'
    echo
  fi
  echo "## Résultat par section"
  echo
  echo "| Section | PASS | FAIL | Ignorés |"; echo "|---|---:|---:|---:|"
  awk '
    /^Bilan : / { if (name != "") printf "| %s | %d | %d | %d |\n", name, p, f, s; name = ""; next }
    /^== .* ==$/ { if (name != "") printf "| %s | %d | %d | %d |\n", name, p, f, s; name = substr($0, 4, length($0) - 6); p = f = s = 0
                   if (name ~ /^(nettoyage|second passage|attacks)/) name = ""; next }
    name != "" && /^  PASS / { p++ }
    name != "" && /^  FAIL / { f++ }
    name != "" && /^  skip / { s++ }
    END { if (name != "") printf "| %s | %d | %d | %d |\n", name, p, f, s }
  ' "$LOG"
  echo
  echo "## Échecs"
  echo
  if [ "$fail" -eq 0 ]; then echo "Aucun."; else
    awk '/^== .* ==$/ { sec = substr($0, 4, length($0) - 6) } /^  FAIL / { sub(/^  FAIL /, ""); printf "- **%s** — %s\n", (sec == "" ? "(hors section)" : sec), $0 }' "$LOG"
  fi
  echo
  if [ "$warn" -gt 0 ]; then
    echo "## Avertissements"; echo
    grep '^  WARN ' "$LOG" | sed 's/^  WARN */- /'
    echo
  fi
  echo "## Contrôles ignorés"
  echo
  if [ "$skip" -eq 0 ]; then echo "Aucun."; else grep '^  skip ' "$LOG" | sed 's/^  skip */- /'; fi
  echo
  if [ "$dual" = 1 ] || [ "$strict_ip" = 1 ]; then
    echo "> Un pair en réseau privé est un proxy de confiance par défaut : les contrôles d'usurpation d'IP sont joués dans un passage où GPX_TRUSTED_PROXIES=none (sections préfixées « [none] »). Les constats « info » et le détail de chaque contrôle sont dans le journal."
  else
    echo "> Un pair en réseau privé est un proxy de confiance par défaut : les contrôles d'usurpation d'IP sont ignorés depuis ce poste (section \`trust\`). Les constats « info » et le détail de chaque contrôle sont dans le journal."
  fi
  echo
  echo "<details><summary>Journal complet</summary>"
  echo
  echo '```'
  cat "$LOG"
  echo '```'
  echo
  echo "</details>"
} > "$REPORT"
cp "$REPORT" "$RESULTS/securite-dernier.md"

[ "$down" = 1 ] && { say "arrêt de la stack"; dc down -v --remove-orphans >/dev/null 2>&1; }

echo
say "$verdict : $pass PASS, $fail FAIL, $skip ignorés en $(fmt_duration "$dur")"
say "rapport : ${REPORT#"$ROOT"/}"
[ "$ran" = 1 ] || exit 2
[ "$fail" -eq 0 ]
