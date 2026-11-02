#!/usr/bin/env bash
# Usage metrics and entitlements. Idempotent: rerun after changing any setting below.
#
#   * Events are kept for 35 days, so the exporter's 30-day active-user window is full
#     after a restart.
#   * fed-metrics-exporter, the exporter's confidential client: it may read events,
#     users and clients, and nothing else. FED_METRICS_EXPORTER_SECRET is its secret;
#     unset, the client stays disabled.
#   * FEDERATION_ENTITLEMENTS, {"<github login>": ["<entitlement>", ...]}, is written to
#     each person's eduperson_entitlement, which the federation scope puts in the
#     `entitlements` claim. It is authoritative: an entitlement not listed is removed.
#     Each person's credentials (portal-minted clients) get the same, as the portal
#     does when it mints or rotates one.
#
# Called by bootstrap.sh, which defines kc() and REALM. Run on its own, it needs KCADM
# (a kcadm.sh already signed in) and REALM.
set -euo pipefail

if ! declare -F kc >/dev/null; then
  : "${KCADM:?set KCADM to a signed-in kcadm.sh, or run this from bootstrap.sh}"
  kc() { "$KCADM" "$@"; }
  say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
  warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
fi
: "${REALM:?set REALM}"
EXPORTER=fed-metrics-exporter
EVENTS_DAYS=35
if [[ -z "${FEDERATION_ENTITLEMENTS:-}" ]]; then
  FEDERATION_ENTITLEMENTS='{}'
fi

say "Usage metrics: events kept $EVENTS_DAYS days, client $EXPORTER, entitlements..."

kc update "realms/$REALM" -s "eventsExpiration=$((EVENTS_DAYS * 86400))" </dev/null

# --- The exporter's client ----------------------------------------------------------
exporter_uuid() {
  kc get clients -r "$REALM" -q "clientId=$EXPORTER" --fields id,clientId --format json </dev/null 2>/dev/null \
    | python3 -c '
import json, sys
for c in json.load(sys.stdin):
    if c.get("clientId") == sys.argv[1]:
        print(c["id"]); break
' "$EXPORTER"
}
uuid=$(exporter_uuid)
if [[ -z "${FED_METRICS_EXPORTER_SECRET:-}" ]]; then
  warn "FED_METRICS_EXPORTER_SECRET is not set: $EXPORTER stays disabled, and the exporter cannot run"
  [[ -n "$uuid" ]] && kc update "clients/$uuid" -r "$REALM" -s enabled=false </dev/null
else
  if [[ -z "$uuid" ]]; then
    CLIENT_SECRET="$FED_METRICS_EXPORTER_SECRET" python3 -c '
import json, os, sys
print(json.dumps({
    "clientId": sys.argv[1],
    "name": "Usage metrics exporter",
    "description": "Reads events, users and clients for the per-service usage metrics. Never issues tokens to people.",
    "enabled": True, "publicClient": False, "secret": os.environ["CLIENT_SECRET"],
    "standardFlowEnabled": False, "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False, "serviceAccountsEnabled": True,
}))' "$EXPORTER" | kc create clients -r "$REALM" -f - >/dev/null
    say "  created $EXPORTER"
  else
    kc update "clients/$uuid" -r "$REALM" -s enabled=true -s "secret=$FED_METRICS_EXPORTER_SECRET" </dev/null
    say "  $EXPORTER present"
  fi
  # Read-only roles; view-events covers admin events too.
  kc add-roles -r "$REALM" --uusername "service-account-$EXPORTER" --cclientid realm-management \
    --rolename view-events --rolename view-users --rolename view-clients </dev/null >/dev/null 2>&1 || true
fi

# --- Entitlements -------------------------------------------------------------------
# One python3 works out what to change from three listings; kc applies it. Lines out:
#   user <id> <username> <json list>
grants=$(python3 -c '
import json, re, sys
try:
    wanted = json.loads(sys.argv[1])
except ValueError as exc:
    sys.exit(f"FEDERATION_ENTITLEMENTS is not JSON: {exc}")
if not isinstance(wanted, dict):
    sys.exit("FEDERATION_ENTITLEMENTS: an object, {\"login\": [\"entitlement\", ...]}")
for login, values in wanted.items():
    if not isinstance(values, list) or not all(isinstance(v, str) and re.fullmatch(r"\S+", v) for v in values):
        sys.exit(f"FEDERATION_ENTITLEMENTS: {login}: a list of entitlements, no spaces")
print(json.dumps({k.lower(): sorted(set(v)) for k, v in wanted.items()}))
' "$FEDERATION_ENTITLEMENTS") || { warn "FEDERATION_ENTITLEMENTS is invalid (above)"; exit 1; }

users_json=$(kc get users -r "$REALM" -q briefRepresentation=false -q max=100000 --format json </dev/null)
# The users listing leaves out service accounts, so each credential's is fetched: a
# credential is a client with fed_owner_sub, the owner's user id.
accounts_json=$(
  echo "["; sep=""
  while IFS=$'\t' read -r cuuid owner; do
    [[ -n "$cuuid" ]] || continue
    printf '%s{"owner": "%s", "account": ' "$sep" "$owner"
    kc get "clients/$cuuid/service-account-user" -r "$REALM" --format json </dev/null
    printf '}'; sep=","
  done < <(kc get clients -r "$REALM" --format json </dev/null | python3 -c '
import json, sys
for c in json.load(sys.stdin):
    owner = (c.get("attributes") or {}).get("fed_owner_sub")
    if owner and c.get("serviceAccountsEnabled"):
        print(c["id"] + "\t" + owner)
')
  echo "]")

# Who should hold what: people by username, credentials as their owner. Lines out:
#   absent <login>                      not signed in yet
#   set <user id> <username> <json>     change to this
plan=$(python3 -c '
import json, sys
wanted = json.loads(sys.argv[1])
users = json.load(open(sys.argv[2]))
accounts = json.load(open(sys.argv[3]))
ATTR = "eduperson_entitlement"
def has(u):
    return sorted((u.get("attributes") or {}).get(ATTR) or [])
target = {u["id"]: (u, wanted.get(u["username"].lower(), [])) for u in users
          if not u["username"].startswith("service-account-")}
found = {u["username"].lower() for u in users}
for login in wanted:
    if login not in found:
        print(f"absent\t{login}")
for a in accounts:
    owner = target.get(a["owner"])
    target[a["account"]["id"]] = (a["account"], owner[1] if owner else [])
for uid, (u, want) in target.items():
    if has(u) != want:
        name = u["username"]
        print(f"set\t{uid}\t{name}\t{json.dumps(want)}")
' "$grants" <(printf '%s' "$users_json") <(printf '%s' "$accounts_json"))

while IFS=$'\t' read -r what uid name want; do
  case "$what" in
    absent) warn "  $uid has not signed in yet: their entitlements wait for the next bootstrap" ;;
    set)
      kc update "users/$uid" -r "$REALM" -s "attributes.eduperson_entitlement=$want" </dev/null
      say "  $name → ${want}" ;;
  esac
done <<<"$plan"
