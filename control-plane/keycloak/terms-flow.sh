#!/usr/bin/env bash
# The terms-and-conditions step: a post-broker login flow, "federation terms", holding
# the fed-terms authenticator (providers/terms), set on every identity provider in the
# realm. Keycloak runs it after each sign-in through that provider, so the portal, the
# web clients, gateway sessions, device-flow approval and member sign-in doors all get
# it. Idempotent: rerun after changing any TERMS_* setting.
#
# Called by bootstrap.sh, which defines kc() and REALM. Run on its own, it needs KCADM
# (a kcadm.sh already signed in) and REALM.
#
#   TERMS_VERSION      shown, recorded on the user, and in the cookie; change it to ask again
#   TERMS_TEXT         the terms
#   TERMS_MODE         every-sign-in | once-per-version
#   TERMS_COOKIE_DAYS  0 offers no cookie
set -euo pipefail

if ! declare -F kc >/dev/null; then
  : "${KCADM:?set KCADM to a signed-in kcadm.sh, or run this from bootstrap.sh}"
  kc() { "$KCADM" "$@"; }
  say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fi
: "${REALM:?set REALM}"
FLOW="federation terms"
TERMS_VERSION="${TERMS_VERSION:-1}"
TERMS_TEXT="${TERMS_TEXT:-Try not to break the testbed.}"
TERMS_MODE="${TERMS_MODE:-every-sign-in}"
TERMS_COOKIE_DAYS="${TERMS_COOKIE_DAYS:-365}"
case "$TERMS_MODE" in every-sign-in|once-per-version) ;; *)
  echo "TERMS_MODE must be every-sign-in or once-per-version, not $TERMS_MODE" >&2; exit 1 ;;
esac

say "Terms and conditions after every sign-in (version $TERMS_VERSION, $TERMS_MODE)..."

# The flow, once.
if ! kc get authentication/flows -r "$REALM" --fields alias --format csv --noquotes </dev/null \
     | tr -d '\r' | grep -qx "$FLOW"; then
  kc create authentication/flows -r "$REALM" -s "alias=$FLOW" -s providerId=basic-flow \
    -s topLevel=true -s builtIn=false \
    -s "description=Terms and conditions, after every sign-in through an identity provider" </dev/null >/dev/null
  say "  created flow '$FLOW'"
fi
flow_path="authentication/flows/$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$FLOW")"

# Its one step, the authenticator, required.
execution=$(kc get "$flow_path/executions" -r "$REALM" --format json </dev/null | python3 -c '
import json, sys
for e in json.load(sys.stdin):
    if e.get("providerId") == "fed-terms":
        print(e["id"] + "\t" + (e.get("authenticationConfig") or "")); break
')
if [[ -z "$execution" ]]; then
  kc create "$flow_path/executions/execution" -r "$REALM" -s provider=fed-terms </dev/null >/dev/null
  execution=$(kc get "$flow_path/executions" -r "$REALM" --format json </dev/null | python3 -c '
import json, sys
for e in json.load(sys.stdin):
    if e.get("providerId") == "fed-terms":
        print(e["id"] + "\t" + (e.get("authenticationConfig") or "")); break
')
  say "  added the fed-terms step"
fi
execution_id="${execution%%	*}"
config_id="${execution#*	}"
[[ -n "$execution_id" ]] || { echo "could not add the fed-terms step: is the provider installed?" >&2; exit 1; }
kc update "$flow_path/executions" -r "$REALM" -b "{\"id\":\"$execution_id\",\"requirement\":\"REQUIRED\"}" </dev/null >/dev/null

# Its settings.
config=$(TERMS_VERSION="$TERMS_VERSION" TERMS_TEXT="$TERMS_TEXT" TERMS_MODE="$TERMS_MODE" \
         TERMS_COOKIE_DAYS="$TERMS_COOKIE_DAYS" python3 -c '
import json, os
print(json.dumps({"alias": "federation-terms", "config": {
    "terms_version": os.environ["TERMS_VERSION"], "terms_text": os.environ["TERMS_TEXT"],
    "terms_mode": os.environ["TERMS_MODE"], "cookie_days": os.environ["TERMS_COOKIE_DAYS"]}}))')
if [[ -z "$config_id" ]]; then
  kc create "authentication/executions/$execution_id/config" -r "$REALM" -f - <<<"$config" >/dev/null
else
  kc update "authentication/config/$config_id" -r "$REALM" -f - <<<"$config" >/dev/null
fi

# On every identity provider, and the theme that draws the page.
while read -r alias; do
  [[ -n "$alias" ]] || continue
  kc update "identity-provider/instances/$alias" -r "$REALM" -s "postBrokerLoginFlowAlias=$FLOW" </dev/null
  say "  after sign-in through $alias"
done < <(kc get identity-provider/instances -r "$REALM" --fields alias --format csv --noquotes </dev/null | tr -d '\r')
kc update "realms/$REALM" -s loginTheme=federation </dev/null
