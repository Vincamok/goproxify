#!/usr/bin/env bash
# Supprime les routes lab-*.lab.test créées par les scripts du labo, ainsi que le certificat de test *.lab.test
# (à lancer après les tests ; run-security.sh et run-load.sh le font seuls en mode cible).
set -u
. /lab/scripts/auth.sh
ids=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | select((.name // "") | test("^lab-.*[.]lab[.]test$")) | "\(.id) \(.name)"')
if [ -z "$ids" ]; then echo "aucune route lab-*.lab.test"; else
  echo "$ids" | while read -r id name; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies/$id")
    printf '%-28s %s (%s)\n' "$name" "$id" "$code"
  done
fi
if curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/certs" | jq -e '.[]? | select(.domain == "*.lab.test")' >/dev/null 2>&1; then
  code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/certs/%2A.lab.test")
  printf '%-28s (%s)\n' "certificat *.lab.test" "$code"
fi
echo "Vérifier dans l'UI qu'il ne reste aucune route lab-* (révisions en attente comprises)."
