#!/usr/bin/env bash
# Exhaust the quota on the federated search route and show what the gateway says.
#
# Two runs: one asking for JSON, one asking for HTML, so you can see the same refusal
# answered two different ways.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
# shellcheck disable=SC1091
set -a; source .env; set +a

URL="https://${DATA_HOST}/api/birds?q=finch&limit=1"
COUNT="${1:-8}"

command -v fed-token >/dev/null || {
  echo "fed-token is not on PATH — run testbed/cli/install.sh first." >&2; exit 2; }

TOKEN=$(fed-token) || exit 1

printf '\033[1mHammering %s\033[0m\n\n' "$URL"
for i in $(seq 1 "$COUNT"); do
  read -r code remaining reset < <(
    curl -s -o /dev/null -D - -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json' "$URL" \
    | awk 'BEGIN{c="?";r="?";t="?"}
           NR==1{c=$2}
           tolower($1)=="x-ratelimit-remaining:"{r=$2}
           tolower($1)=="x-ratelimit-reset:"{t=$2}
           END{gsub(/\r/,"",c);gsub(/\r/,"",r);gsub(/\r/,"",t);print c, r, t}')
  printf '  %2d  %s   remaining %-3s  reset in %ss\n' "$i" "$code" "$remaining" "$reset"
done

echo
printf '\033[1mThe same refusal, asked for as HTML\033[0m\n\n'
# One extraction per pass: the page is a single line, so a substitution that rewrites
# it leaves nothing for the next expression to match.
page=$(curl -s -H "Authorization: Bearer $TOKEN" -H 'Accept: text/html' "$URL")
for pair in 'badge:<span class="status">' 'heading:<h1>'; do
  label=${pair%%:*}
  printf '  %-9s %s\n' "$label" \
    "$(sed -n "s|.*${pair#*:}\([^<]*\)<.*|\1|p" <<<"$page")"
done
echo
echo "  Open it in a browser to see the whole page:"
echo "    $URL"
