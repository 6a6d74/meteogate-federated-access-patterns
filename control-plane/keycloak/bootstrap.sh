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

# shellcheck disable=SC1091
set -a; source .env; set +a

REALM="${KC_REALM:-federation}"
kc() { docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh "$@"; }

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

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
# This is what puts `aud: federation-services` into an access token, and it is what
# every data service in the federation checks. A token minted for some unrelated
# client does not carry it and will not open a federated route.
#
# It is created here rather than in realm-federation.json for a specific reason:
# supplying a `clientScopes` array in a realm import makes Keycloak skip creating its
# own built-in scopes entirely — no `profile`, no `email`, no `offline_access`. That
# costs you preferred_username, the user's email, and the ability to ask for an
# offline token, which is most of what the realm is for. Adding the scope afterwards
# leaves the built-ins alone.
# ---------------------------------------------------------------------------
say "Ensuring the 'federation' client scope exists..."

scope_id=$(kc get client-scopes -r "$REALM" --format json 2>/dev/null | python3 -c '
import json, sys
for scope in json.load(sys.stdin):
    if scope.get("name") == "federation":
        print(scope["id"]); break
')

if [[ -z "$scope_id" ]]; then
  kc create client-scopes -r "$REALM" -f - <<'JSON'
{
  "name": "federation",
  "description": "Marks a token as valid across the federation's data services.",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "Access data services across the MeteoGate federation"
  },
  "protocolMappers": [
    {
      "name": "federation-audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "consentRequired": false,
      "config": {
        "included.custom.audience": "federation-services",
        "id.token.claim": "false",
        "access.token.claim": "true"
      }
    },
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
  scope_id=$(kc get client-scopes -r "$REALM" --format json 2>/dev/null | python3 -c '
import json, sys
for scope in json.load(sys.stdin):
    if scope.get("name") == "federation":
        print(scope["id"]); break
')
  say "Created client scope 'federation' ($scope_id)"
else
  say "Client scope 'federation' already present ($scope_id)"
fi

[[ -n "$scope_id" ]] || die "could not create or find the 'federation' client scope"

# Attach it to every client that issues tokens for data services. portal-admin is
# excluded on purpose: it talks to the Keycloak admin API, not to the federation, and
# a credential should not carry an audience it has no business presenting.
for client_id in federation-portal birds-web federation-cli birds-gateway; do
  uuid=$(kc get clients -r "$REALM" -q "clientId=$client_id" --fields id --format csv --noquotes | tr -d '\r')
  if [[ -z "$uuid" ]]; then
    warn "client $client_id not found — skipping scope attachment"
    continue
  fi
  kc update "clients/$uuid/default-client-scopes/$scope_id" -r "$REALM" >/dev/null 2>&1 \
    && say "  federation scope → $client_id" \
    || say "  federation scope → $client_id (already attached)"
done

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
