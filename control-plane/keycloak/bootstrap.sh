#!/usr/bin/env bash
# Patch the imported realm with values that must not live in git.
#
# The realm structure is declared in realm-federation.json and imported by Keycloak on
# first start. Everything secret — the GitHub OAuth app credentials, the two confidential
# client secrets — carries a CHANGE_ME placeholder there and is injected here from .env.
#
# Also sets the browser flow's default identity provider to GitHub, so that every login
# lands on GitHub rather than on a username/password form that no account can satisfy.
#
# Idempotent: safe to re-run after changing .env, and re-run is how you rotate secrets.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# .env is where these values live on a Compose host. Where something else already puts
# them in the environment — a container platform injecting secrets, say — there is no
# .env, and that is fine.
if [[ -f .env ]]; then
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi

REALM="${KC_REALM:-federation}"

# kcadm.sh normally runs inside the Keycloak container, through Compose. KCADM names
# some other kcadm.sh to use instead — one installed beside this script, on a host
# where Keycloak runs without Compose — and it must be able to reach Keycloak at
# http://localhost:8080, the server named below.
if [[ -n "${KCADM:-}" ]]; then
  kc() { "$KCADM" "$@"; }
else
  kc() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }
fi

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

# Fail before touching the realm, not halfway through it with "unbound variable".
missing=()
for name in CONTROL_HOST DATA_HOST KEYCLOAK_ADMIN KEYCLOAK_ADMIN_PASSWORD \
            GATEWAY_CLIENT_SECRET PORTAL_ADMIN_SECRET; do
  [[ -n "${!name:-}" ]] || missing+=("$name")
done
(( ${#missing[@]} == 0 )) || die "Not set (in .env or the environment): ${missing[*]}"

# ---------------------------------------------------------------------------
# Wait for the realm to exist. Keycloak imports it during startup, so a container
# that is "up" is not necessarily a container that has finished importing.
# ---------------------------------------------------------------------------
say "Waiting for Keycloak to finish importing realm '$REALM'..."
for attempt in $(seq 1 60); do
  if kc config credentials \
        --server http://localhost:8080 \
        --realm master \
        --user "$KEYCLOAK_ADMIN" \
        --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null 2>&1 \
     && kc get "realms/$REALM" --fields realm >/dev/null 2>&1; then
    break
  fi
  [[ $attempt -eq 60 ]] && { warn "Keycloak did not become ready within 120s"; exit 1; }
  sleep 2
done
say "Keycloak is up and realm '$REALM' exists."

# ---------------------------------------------------------------------------
# GitHub identity provider credentials.
# ---------------------------------------------------------------------------
if [[ -z "${GITHUB_CLIENT_ID:-}" || "$GITHUB_CLIENT_ID" == CHANGE_ME* ]]; then
  warn "GITHUB_CLIENT_ID is unset in .env — GitHub login will not work until you set it."
else
  say "Configuring the GitHub identity provider..."
  kc update "identity-provider/instances/github" -r "$REALM" \
    -s "config.clientId=$GITHUB_CLIENT_ID" \
    -s "config.clientSecret=$GITHUB_CLIENT_SECRET"
fi

# ---------------------------------------------------------------------------
# Confidential client secrets.
#
# birds-gateway  — used by APISIX on the data-plane host for the session-cookie browser route
# portal-admin   — used by the portal backend to mint and revoke user credentials
# ---------------------------------------------------------------------------
set_client_secret() {
  local client_id="$1" secret="$2"
  local uuid
  uuid=$(kc get clients -r "$REALM" -q "clientId=$client_id" --fields id --format csv --noquotes | tr -d '\r')
  [[ -z "$uuid" ]] && { warn "client $client_id not found — skipping"; return; }
  kc update "clients/$uuid" -r "$REALM" -s "secret=$secret"
  say "Set secret for $client_id"
}

set_client_secret birds-gateway "$GATEWAY_CLIENT_SECRET"
set_client_secret portal-admin  "$PORTAL_ADMIN_SECRET"

# ---------------------------------------------------------------------------
# Redirect URIs and web origins.
#
# realm-federation.json ships neutral example.org hostnames, because a realm export
# checked into version control should not carry one deployment's addresses. The real
# ones live in .env and are applied here, so a fresh clone works from its own
# configuration rather than from whoever exported the realm last.
#
# Wildcards are used deliberately: the portal's own path moves when it is published
# behind a shared reverse proxy, and pinning the exact path would break that.
# ---------------------------------------------------------------------------
say "Setting redirect URIs from .env..."

set_client_urls() {
  local client_id="$1" host="$2"
  local uuid
  uuid=$(kc get clients -r "$REALM" -q "clientId=$client_id" --fields id --format csv --noquotes | tr -d '\r')
  [[ -z "$uuid" ]] && { warn "client $client_id not found — skipping"; return; }
  kc update "clients/$uuid" -r "$REALM" \
    -s "rootUrl=https://${host}" \
    -s "redirectUris=[\"https://${host}/*\"]" \
    -s "webOrigins=[\"https://${host}\"]" \
    -s "attributes.\"post.logout.redirect.uris\"=https://${host}/*"
  say "  $client_id → https://${host}"
}

set_client_urls federation-portal "$CONTROL_HOST"
set_client_urls birds-web         "$DATA_HOST"
set_client_urls birds-gateway     "$DATA_HOST"
# federation-cli and portal-admin have no browser redirect, so nothing to set.

# ---------------------------------------------------------------------------
# Unmanaged user attributes.
#
# Since Keycloak 24 the declarative user profile rejects any attribute it does not
# know about — and it does so silently. The write succeeds, returns 204, and stores
# nothing. Three things here depend on storing attributes Keycloak has never heard of:
#
#   * github_login, written by the identity provider mapper on every login
#   * fed_credential_client, the portal's pointer from a user to their credential
#   * eduperson_entitlement, the placeholder for AARC-G002 entitlements
#
# Without this, all three vanish without an error anywhere.
# ---------------------------------------------------------------------------
say "Adjusting the user profile..."
kc get "users/profile" -r "$REALM" --format json \
  | python3 -c '
import json, sys

profile = json.load(sys.stdin)
profile["unmanagedAttributePolicy"] = "ENABLED"

# firstName and lastName are required by default. A GitHub account with no public
# name set therefore cannot complete registration without being stopped at a
# "complete your profile" form. That form buys nothing: a self-asserted name from a
# social identity carries no assurance and is used for no authorisation decision
# anywhere in this federation. Requiring it would be friction in exchange for a field
# we have already agreed not to trust.
#
# If institutional IdPs are added later, their attributes ARE worth requiring — but
# that is a per-IdP decision, not a blanket one.
for attribute in profile.get("attributes", []):
    if attribute.get("name") in ("firstName", "lastName"):
        attribute["required"] = None
        attribute.pop("required", None)

json.dump(profile, sys.stdout)
' \
  | kc update "users/profile" -r "$REALM" -f - >/dev/null \
  && say "  unmanaged attributes enabled; firstName/lastName no longer required"

# ---------------------------------------------------------------------------
# The `federation` client scope.
#
# Carries what every federation token says about its holder — the `entitlements`
# claim — and nothing about where the token may be used. That is each service's own
# scope, below. (It once added a shared audience, `federation-services`, which let a
# token for one service be replayed at any other; the migration step removes it.)
#
# It is created here rather than in realm-federation.json for a specific reason:
# supplying a `clientScopes` array in a realm import makes Keycloak skip creating its
# own built-in scopes entirely — no `profile`, no `email`, no `offline_access`. That
# costs you preferred_username, the user's email, and the ability to ask for an
# offline token, which is most of what the realm is for. Adding the scope afterwards
# leaves the built-ins alone.
# ---------------------------------------------------------------------------
say "Ensuring the 'federation' client scope exists..."

scope_id_of() {
  kc get client-scopes -r "$REALM" --format json 2>/dev/null | python3 -c '
import json, sys
for scope in json.load(sys.stdin):
    if scope.get("name") == sys.argv[1]:
        print(scope["id"]); break
' "$1"
}

scope_id=$(scope_id_of federation)

if [[ -z "$scope_id" ]]; then
  kc create client-scopes -r "$REALM" -f - <<'JSON'
{
  "name": "federation",
  "description": "What a federation token says about its holder. Where it may be used is each service's own scope.",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "false"
  },
  "protocolMappers": [
    {
      "name": "federation-entitlements",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-usermodel-attribute-mapper",
      "consentRequired": false,
      "config": {
        "user.attribute": "eduperson_entitlement",
        "claim.name": "entitlements",
        "jsonType.label": "String",
        "multivalued": "true",
        "id.token.claim": "false",
        "access.token.claim": "true",
        "userinfo.token.claim": "true"
      }
    }
  ]
}
JSON
  scope_id=$(scope_id_of federation)
  say "Created client scope 'federation' ($scope_id)"
else
  say "Client scope 'federation' already present ($scope_id)"
fi

[[ -n "$scope_id" ]] || die "could not create or find the 'federation' client scope"

# Migration: the shared audience. A realm bootstrapped before per-service audiences
# still has it, and while it is there every token opens every service.
legacy_mapper=$(kc get "client-scopes/$scope_id/protocol-mappers/models" -r "$REALM" --format json 2>/dev/null \
  | python3 -c '
import json, sys
for m in json.load(sys.stdin):
    if m.get("name") == "federation-audience":
        print(m["id"]); break
')
if [[ -n "$legacy_mapper" ]]; then
  kc delete "client-scopes/$scope_id/protocol-mappers/models/$legacy_mapper" -r "$REALM"
  kc update "client-scopes/$scope_id" -r "$REALM" -s 'attributes."display.on.consent.screen"=false'
  say "  removed the shared audience 'federation-services' from the 'federation' scope"
fi

client_uuid() {
  kc get clients -r "$REALM" -q "clientId=$1" --fields id,clientId --format json 2>/dev/null \
    | python3 -c '
import json, sys
for c in json.load(sys.stdin):
    if c.get("clientId") == sys.argv[1]:
        print(c["id"]); break
' "$1"
}

# Attach it to every client that issues tokens for people. portal-admin is excluded on
# purpose: it talks to the Keycloak admin API, not to the federation.
for client_id in federation-portal birds-web federation-cli birds-gateway; do
  uuid=$(client_uuid "$client_id")
  if [[ -z "$uuid" ]]; then
    warn "client $client_id not found — skipping scope attachment"
    continue
  fi
  kc update "clients/$uuid/default-client-scopes/$scope_id" -r "$REALM" >/dev/null 2>&1 \
    && say "  federation scope → $client_id" \
    || say "  federation scope → $client_id (already attached)"
done

# ---------------------------------------------------------------------------
# One client scope per member service: `service:<audience>` puts `aud: <audience>` in
# a token, and that service's gateway accepts nothing else.
#
# So a token is good at one service only. A service that is sent a token — every
# service is, by every caller — cannot replay it at another member. And a service
# joins the federation by being listed here: one that is not never receives a token
# minted for it.
#
# FEDERATION_SERVICES is the member list, a JSON array:
#   [{"audience": "birds", "name": "Avian Visitors"}, ...]
#
# The scopes are optional on federation-cli and on every portal-minted credential, so
# a token carries a service's audience only when that service is asked for — one at a
# time; fed-token narrows on each refresh. The testbed's own clients, birds-web and
# birds-gateway, talk to one service, so they get its scope by default.
#
# A service dropped from the list loses its scope, and with it every token's ability
# to reach it: removal takes effect as soon as tokens already issued expire.
# ---------------------------------------------------------------------------
# (Not ${FEDERATION_SERVICES:-…}: the first } in a JSON default would end the expansion.)
if [[ -z "${FEDERATION_SERVICES:-}" ]]; then
  FEDERATION_SERVICES='[{"audience": "birds", "name": "Avian Visitors"}]'
fi
BIRDS_AUDIENCE="${BIRDS_AUDIENCE:-birds}"

services=$(python3 -c '
import json, re, sys
try:
    services = json.loads(sys.argv[1])
except json.JSONDecodeError as exc:
    sys.exit(f"FEDERATION_SERVICES is not JSON: {exc}")
seen = set()
for s in services:
    aud, name = s.get("audience", ""), s.get("name", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", aud):
        sys.exit(f"FEDERATION_SERVICES: audience {aud!r}: use a-z, 0-9 and -")
    if aud in seen:
        sys.exit(f"FEDERATION_SERVICES: {aud} appears twice")
    seen.add(aud)
    print(aud + "\t" + (name.replace("\t", " ") or aud))
' "$FEDERATION_SERVICES") || die "FEDERATION_SERVICES is invalid (above)"

grep -q "^${BIRDS_AUDIENCE}	" <<<"$services" \
  || warn "BIRDS_AUDIENCE=$BIRDS_AUDIENCE is not in FEDERATION_SERVICES: the testbed's own web client will get no audience"

say "Ensuring one client scope per member service..."
service_scope_ids=()
while IFS=$'\t' read -r audience name; do
  [[ -n "$audience" ]] || continue
  sid=$(scope_id_of "service:$audience")
  if [[ -z "$sid" ]]; then
    python3 -c '
import json, sys
aud, name = sys.argv[1], sys.argv[2]
print(json.dumps({
    "name": f"service:{aud}",
    "description": f"Tokens for {name}, and nothing else.",
    "protocol": "openid-connect",
    "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "true",
                   "consent.screen.text": f"Use {name}"},
    "protocolMappers": [{
        "name": "audience", "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
        "config": {"included.custom.audience": aud, "access.token.claim": "true",
                   "id.token.claim": "false", "introspection.token.claim": "true"},
    }],
}))' "$audience" "$name" | kc create client-scopes -r "$REALM" -f - >/dev/null
    sid=$(scope_id_of "service:$audience")
    say "  created service:$audience ($name)"
  else
    kc update "client-scopes/$sid" -r "$REALM" \
      -s "description=Tokens for $name, and nothing else." \
      -s "attributes.\"consent.screen.text\"=Use $name"
    say "  service:$audience ($name) present"
  fi
  [[ -n "$sid" ]] || die "could not create client scope service:$audience"
  service_scope_ids+=("$sid")

  if [[ "$audience" == "$BIRDS_AUDIENCE" ]]; then
    for client_id in birds-web birds-gateway; do
      uuid=$(client_uuid "$client_id")
      [[ -n "$uuid" ]] && kc update "clients/$uuid/default-client-scopes/$sid" -r "$REALM" >/dev/null 2>&1 || true
    done
    say "    default on birds-web and birds-gateway"
  fi
done <<<"$services"

# Optional on the CLI client and on every credential the portal has minted (svc-*):
# present in a token only when asked for.
optional_on=(federation-cli)
while read -r minted; do
  [[ -n "$minted" ]] && optional_on+=("$minted")
done < <(kc get clients -r "$REALM" -q "clientId=svc-" -q search=true --fields clientId --format csv --noquotes 2>/dev/null \
         | tr -d '\r' | grep '^svc-' || true)
for client_id in "${optional_on[@]}"; do
  uuid=$(client_uuid "$client_id")
  [[ -n "$uuid" ]] || continue
  for sid in "${service_scope_ids[@]}"; do
    kc update "clients/$uuid/optional-client-scopes/$sid" -r "$REALM" >/dev/null 2>&1 || true
  done
done
say "  optional on federation-cli and $(( ${#optional_on[@]} - 1 )) minted credential(s)"

# Services no longer listed: delete their scopes, which detaches them everywhere.
while IFS=$'\t' read -r sid name; do
  [[ -n "$sid" ]] || continue
  grep -q "^${name#service:}	" <<<"$services" && continue
  kc delete "client-scopes/$sid" -r "$REALM"
  say "  removed $name: no longer a member"
done < <(kc get client-scopes -r "$REALM" --format json 2>/dev/null | python3 -c '
import json, sys
for s in json.load(sys.stdin):
    if s.get("name", "").startswith("service:"):
        print(s["id"] + "\t" + s["name"])
')

# ---------------------------------------------------------------------------
# The portal backend acts on the user's behalf against the admin API: it mints a
# per-user client, rotates its secret, and deletes the registration outright. Those
# need realm-management roles on the service account.
#
# Deliberately NOT granted: realm-admin. The portal should not be able to reconfigure
# the realm, only to manage users and clients.
# ---------------------------------------------------------------------------
say "Granting realm-management roles to the portal service account..."
kc add-roles -r "$REALM" \
  --uusername service-account-portal-admin \
  --cclientid realm-management \
  --rolename manage-users \
  --rolename view-users \
  --rolename manage-clients \
  --rolename view-clients \
  --rolename query-users \
  --rolename query-clients 2>/dev/null || say "(roles already granted)"

# ---------------------------------------------------------------------------
# Send every browser login straight to GitHub.
#
# Direct registration is refused and no account has a local password, so the default
# login form is a dead end. Setting defaultProvider on the identity-provider-redirector
# execution skips it. This also fixes the device-flow verification page, which is
# Keycloak's own screen and would otherwise present the same dead-end form.
# ---------------------------------------------------------------------------
say "Pointing the browser flow at GitHub by default..."
redirector=$(kc get "authentication/flows/browser/executions" -r "$REALM" --format json \
  | python3 -c '
import json, sys
for ex in json.load(sys.stdin):
    if ex.get("providerId") == "identity-provider-redirector":
        print(ex["id"], ex.get("authenticationConfig", ""))
        break
')
exec_id=$(awk "{print \$1}" <<<"$redirector")
have_config=$(awk "{print \$2}" <<<"$redirector")

if [[ -z "$exec_id" ]]; then
  warn "identity-provider-redirector execution not found — skipping default provider"
elif [[ -n "$have_config" ]]; then
  kc update "authentication/config/$have_config" -r "$REALM" \
    -s "alias=github-default" \
    -s "config.defaultProvider=github"
  say "Updated existing default-provider config."
else
  kc create "authentication/executions/$exec_id/config" -r "$REALM" \
    -s "alias=github-default" \
    -s "config.defaultProvider=github"
  say "Created default-provider config."
fi

# ---------------------------------------------------------------------------
# Report the endpoints the data plane needs.
# ---------------------------------------------------------------------------
cat <<EOF

$(say "Realm '$REALM' configured.")

  Issuer      https://${CONTROL_HOST}/realms/${REALM}
  JWKS        https://${CONTROL_HOST}/realms/${REALM}/protocol/openid-connect/certs
  Discovery   https://${CONTROL_HOST}/realms/${REALM}/.well-known/openid-configuration
  Device auth https://${CONTROL_HOST}/realms/${REALM}/protocol/openid-connect/auth/device
  Portal      https://${CONTROL_HOST}${PORTAL_PATH:-/}
  Admin       https://${CONTROL_HOST}/admin/  (realm: master, user: ${KEYCLOAK_ADMIN})

EOF
