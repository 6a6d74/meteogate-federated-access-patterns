#!/usr/bin/env bash
# Probe every route and report what the gateway did with it.
#
# This is the fastest way to see the whole policy surface at once: which routes are
# open, which refuse an anonymous caller, and which quota each one applies.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
# shellcheck disable=SC1091
set -a; source .env; set +a

BASE="https://${DATA_HOST}"
CURL=(curl -s -o /dev/null --max-time 8)

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }

probe() {
  local label="$1" url="$2"; shift 2
  local out status limit remaining
  out=$(curl -s -D - -o /dev/null --max-time 8 "$@" "$url" 2>/dev/null)
  status=$(awk 'NR==1{print $2}' <<<"$out")
  limit=$(grep -i '^x-ratelimit-limit:' <<<"$out" | tr -d '\r' | awk '{print $2}')
  remaining=$(grep -i '^x-ratelimit-remaining:' <<<"$out" | tr -d '\r' | awk '{print $2}')

  local quota="—"
  [[ -n "${limit:-}" ]] && quota="${remaining:-?}/${limit}"

  local verdict
  case "${status:-000}" in
    200) verdict=$'\033[32mallowed\033[0m' ;;
    401) verdict=$'\033[33mrefused — no credential\033[0m' ;;
    403) verdict=$'\033[33mrefused — credential insufficient\033[0m' ;;
    429) verdict=$'\033[31mquota exhausted\033[0m' ;;
    302) verdict=$'\033[36mredirect to sign-in\033[0m' ;;
    500|503) verdict=$'\033[31mgateway cannot reach the control plane\033[0m' ;;
    000) verdict=$'\033[31mno answer\033[0m' ;;
    *)   verdict="$status" ;;
  esac
  printf '  %-34s %-5s %-9s %b\n' "$label" "${status:-—}" "$quota" "$verdict"
}

bold "Gateway at ${BASE}"
echo
printf '  %-34s %-5s %-9s %s\n' "ROUTE" "CODE" "QUOTA" "VERDICT"

probe "/api/birds (no token)"        "${BASE}/api/birds?q=finch&limit=1"
probe "/api/birds (junk token)"      "${BASE}/api/birds?q=finch&limit=1" -H "Authorization: Bearer not-a-token"
probe "/local/api/birds (no key)"    "${BASE}/local/api/birds?q=finch&limit=1"
probe "/local/api/birds (good key)"  "${BASE}/local/api/birds?q=finch&limit=1" -H "apikey: ${LOCAL_API_KEY_ACME}"
probe "/local/api/birds (bad key)"   "${BASE}/local/api/birds?q=finch&limit=1" -H "apikey: wrong"
probe "/open/api/birds"              "${BASE}/open/api/birds?q=finch&limit=1"
# 302 to Keycloak when the control plane is up; 500 when it is not, because the
# gateway cannot fetch the discovery document to know where to send you.
probe "/session/api/birds"           "${BASE}/session/api/birds?q=finch&limit=1"
probe "/openapi.json"                "${BASE}/openapi.json"
probe "/healthz"                     "${BASE}/healthz"
probe "/birds/ (web client)"         "${BASE}/birds/"
probe "/help/"                       "${BASE}/help/"

echo
bold "Human-readable error pages"
for accept in "application/json" "text/html"; do
  body=$(curl -s --max-time 8 -H "Accept: ${accept}" "${BASE}/api/birds?q=finch" | head -c 60 | tr '\n' ' ')
  printf '  Accept: %-20s → %s…\n' "$accept" "$body"
done

echo
bold "Quota, by exhausting it"
dim  "  partner_acme carries a 5/minute allowance; the sixth request should be refused"
for i in $(seq 1 6); do
  code=$("${CURL[@]}" -w '%{http_code}' -H "apikey: ${LOCAL_API_KEY_ACME}" \
         "${BASE}/local/api/birds?q=finch&limit=1")
  printf '    request %d → %s\n' "$i" "$code"
done
dim  "  Counted per consumer, so internal_dashboard's 120/minute is untouched by this."
dim  "  For the same thing on the federated route, with both refusal formats:"
dim  "    ./scripts/burn-quota.sh"

echo
# Generated files drift from .env silently: nothing fails, the gateway serves stale or
# placeholder values, and the first symptom is a sign-in button that sends you to a
# hostname that does not exist. Compare what is actually served against what .env says.
bold "Generated configuration matches .env"
served=$(curl -s --max-time 8 "${BASE}/birds/config.js")
drift=0
for pair in "issuer:${CONTROL_BASE_URL}/realms/${KC_REALM}" \
            "portal:${CONTROL_PORTAL_URL}" \
            "dataHost:${DATA_HOST}"; do
  field=${pair%%:*}; want=${pair#*:}
  got=$(sed -n "s/.*${field}: *\"\([^\"]*\)\".*/\1/p" <<<"$served")
  if [[ "$got" == "$want" ]]; then
    printf '  %-10s %s\n' "$field" "$got"
  else
    printf '  %-10s \033[31m%s\033[0m\n             expected \033[32m%s\033[0m\n' "$field" "${got:-<missing>}" "$want"
    drift=1
  fi
done
if [[ $drift -eq 1 ]]; then
  printf '\n  \033[31mThe served client configuration does not match .env. Run: make config\033[0m\n'
fi
echo

bold "Control plane reachability"
if curl -sf --max-time 8 "https://${CONTROL_HOST}/realms/${KC_REALM}/.well-known/openid-configuration" >/dev/null; then
  echo "  discovery document reachable at https://${CONTROL_HOST}/realms/${KC_REALM}"
else
  echo "  cannot reach https://${CONTROL_HOST} — federated routes will refuse everything"
fi
