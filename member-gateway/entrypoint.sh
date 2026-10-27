#!/usr/bin/env bash
# serve   generate APISIX's configuration from /config/gateway.yaml, then run APISIX
# check   generate it and print the route table, without serving
# routes  scripts/routes-helper.py, in the current directory (mount the package at /work)
# info    scripts/member-info.py, likewise
set -euo pipefail

HERE=/opt/member-gateway
CONFIG=${GATEWAY_CONFIG:-/config/gateway.yaml}
OUT=/usr/local/apisix/conf/apisix.yaml

generate() {
  [[ -f "$CONFIG" ]] || {
    echo "No $CONFIG. Run the routes helper first (see the README), and mount config/ at /config." >&2
    exit 1
  }
  # The generator insists on a session secret even when no route uses a session, and
  # member gateways have none, so a throwaway one per start is enough.
  if [[ -z "${SESSION_SECRET:-}" ]]; then
    SESSION_SECRET=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    export SESSION_SECRET
  fi
  python3 "$HERE/gen-apisix-config.py" "$CONFIG" -o "$1" --env /dev/null --print-routes
}

case "${1:-serve}" in
  serve)
    generate "$OUT"
    exec /docker-entrypoint.sh docker-start
    ;;
  check)
    generate /tmp/apisix.yaml
    ;;
  routes)
    shift; exec python3 "$HERE/routes-helper.py" "$@"
    ;;
  info)
    shift; exec python3 "$HERE/member-info.py" "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
