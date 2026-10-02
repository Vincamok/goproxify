#!/bin/sh
# Résout *.lab.test vers l'IP de la passerelle (trouvée par DNS Docker) : évite EDGE_IP et extra_hosts.
# La liste doit contenir tous les hôtes de feature-routes.json (features.sh le vérifie).
ip=$(getent hosts "${EDGE_HOST:-goproxify-edge}" | awk '{print $1; exit}')
[ -n "$ip" ] || { echo "goproxify-edge introuvable sur goproxify_net (stack principale démarrée ?)" >&2; exit 1; }
grep -v '\.lab\.test' /etc/hosts > /tmp/hosts.new
for h in lab-fast lab-waf-block lab-waf-detect lab-ratelimit lab-chaos lab-juice \
  lab-lb lab-lb-alias lab-weighted lab-sticky lab-health lab-retry lab-noretry lab-cb lab-transform lab-paths \
  lab-redirect lab-subfilter lab-cors lab-cache lab-ipallow lab-ipdeny lab-vars lab-backpressure lab-limitconn lab-canary \
  lab-canary-pct lab-shadow lab-cond lab-errpages lab-ws lab-nows lab-body lab-secheaders lab-timeout \
  lab-basicauth lab-bot lab-wafcustom lab-nohost lab-toggle lab-realistic; do
  echo "$ip $h.lab.test" >> /tmp/hosts.new
done
cat /tmp/hosts.new > /etc/hosts
