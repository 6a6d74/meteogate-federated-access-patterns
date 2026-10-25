#!/usr/bin/env bash
# Sweep the realm for expired machine credentials and disable them.
#
# The addendum's most urgent item is that a client secret decoupled from its owning
# identity never dies. Three controls answer it; this script is the one that has teeth:
#
#   * every minted client records fed_owner_sub and fed_owner_username  (portal)
#   * every minted client records fed_secret_expires                    (portal)
#   * this sweep disables clients past that date                        (here)
#
# Keycloak does not enforce the expiry itself — nothing in the product does. Enforcement
# is this sweep, so it only bites when it runs. Run it from cron on the control-plane host:
#
#   0 3 * * *  cd /path/to/control-plane && ./scripts/audit-credentials.sh --apply
#
# Without --apply it only reports. Add --purge-orphans to delete credentials whose
# owning account no longer exists.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# As in keycloak/bootstrap.sh: .env if there is one, otherwise the environment.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi
REALM="${KC_REALM:-federation}"

APPLY=0
PURGE=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --purge-orphans) PURGE=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# KCADM: see keycloak/bootstrap.sh.
if [[ -n "${KCADM:-}" ]]; then
  kc() { "$KCADM" "$@"; }
else
  kc() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
fi

kc config credentials --server http://localhost:8080 --realm master \
  --user "$KEYCLOAK_ADMIN" --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null

# Full representations, deliberately. `--fields ...,attributes` silently omits the
# attributes map, which is where every fact this script relies on is stored — the
# report then cheerfully finds nothing at all.
clients=$(kc get clients -r "$REALM" --format json)
users=$(kc get users -r "$REALM" -q max=10000 --format json)

# The user records carry a pointer back to their credential. A live secret that no
# user points at is unmanageable through the portal - the owner cannot rotate or
# revoke it, and may not know it exists. Worth naming separately from an orphan.
referenced=$(python3 -c '
import json, sys
pointers = set()
for user in json.loads(sys.argv[1]):
    for value in (user.get("attributes") or {}).get("fed_credential_client", []):
        pointers.add(value)
print(json.dumps(sorted(pointers)))
' "$users")

APPLY=$APPLY PURGE=$PURGE REALM=$REALM python3 - "$clients" "$users" "$referenced" <<'PY' > /tmp/fed-audit-actions
import json, os, sys
from datetime import datetime, timezone

clients = json.loads(sys.argv[1])
user_ids = {u["id"] for u in json.loads(sys.argv[2])}
referenced = set(json.loads(sys.argv[3]))
now = datetime.now(timezone.utc)

def attr(client, name):
    raw = (client.get("attributes") or {}).get(name)
    if raw is None:
        return None
    return raw[0] if isinstance(raw, list) else raw

rows, actions = [], []
for client in clients:
    owner = attr(client, "fed_owner_sub")
    if owner is None:
        continue                       # not a portal-minted credential
    expires_raw = attr(client, "fed_secret_expires") or ""
    try:
        expires = datetime.fromisoformat(expires_raw)
    except ValueError:
        expires = now                  # unparseable expiry counts as expired
    days = (expires - now).days
    orphaned = owner not in user_ids
    enabled = client.get("enabled", False)

    if orphaned:
        state = "ORPHANED"                      # the owning account is gone
        if os.environ["PURGE"] == "1":
            actions.append(f"delete {client['id']}")
    elif client["clientId"] not in referenced:
        state = "UNREFERENCED"                  # owner exists but cannot see it
    elif days < 0 and enabled:
        state = "EXPIRED"
        if os.environ["APPLY"] == "1":
            actions.append(f"disable {client['id']}")
    elif not enabled:
        state = "disabled"
    elif days <= 14:
        state = f"expiring in {days}d"
    else:
        state = f"ok, {days}d left"

    rows.append((client["clientId"], attr(client, "fed_owner_username") or "?", state))

width = max((len(r[0]) for r in rows), default=10)
print(f"{'CLIENT':<{width}}  {'OWNER':<20}  STATE", file=sys.stderr)
for client_id, owner, state in sorted(rows):
    print(f"{client_id:<{width}}  {owner:<20}  {state}", file=sys.stderr)
if not rows:
    print("(no portal-minted credentials in this realm)", file=sys.stderr)

print("\n".join(actions))
PY

while read -r verb uuid; do
  [[ -z "${verb:-}" ]] && continue
  case "$verb" in
    disable) echo "disabling $uuid"; kc update "clients/$uuid" -r "$REALM" -s "enabled=false" ;;
    delete)  echo "deleting $uuid";  kc delete "clients/$uuid" -r "$REALM" ;;
  esac
done < /tmp/fed-audit-actions
rm -f /tmp/fed-audit-actions

if [[ $APPLY -eq 0 ]]; then
  echo
  echo "Report only. Re-run with --apply to disable expired credentials,"
  echo "and --purge-orphans to delete those whose owner no longer exists."
fi

echo
echo "States: ok / expiring / EXPIRED       - expiry is enforced by this sweep, not by Keycloak"
echo "        ORPHANED      the owning account no longer exists (--purge-orphans deletes)"
echo "        UNREFERENCED  the owner exists but their record does not point here;"
echo "                      the portal reclaims these on the owner's next visit"
