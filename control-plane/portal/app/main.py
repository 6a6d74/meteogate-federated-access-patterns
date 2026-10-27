"""Federation portal — registration and credential management.

Runs beside Keycloak on the control plane. Two jobs:

  1. Serve the single-page UI where a user, having registered through GitHub, can see
     their identity, mint and rotate a machine credential, revoke their CLI sessions,
     and delete their registration outright.

  2. Act on the Keycloak admin API on the user's behalf — but only ever on themselves.
     Every mutating endpoint derives the subject from the validated bearer token and
     ignores anything the client says about who it is.

The portal is control plane. It never sees data-service traffic.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any

import httpx
import jwt
import segno
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from jwt import PyJWKClient
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------

CONTROL_HOST = os.environ["CONTROL_HOST"]
REALM = os.getenv("KC_REALM", "federation")

# Two base URLs for the same Keycloak. Server-to-server calls take the internal one and
# skip Traefik; anything a browser or CLI must reach has to be the public one, and the
# issuer in a token is always the public one.
KC_INTERNAL = os.getenv("KC_INTERNAL_URL", "http://keycloak:8080").rstrip("/")
KC_PUBLIC = os.getenv("KC_PUBLIC_URL", f"https://{CONTROL_HOST}").rstrip("/")

ISSUER = f"{KC_PUBLIC}/realms/{REALM}"
JWKS_URL = f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/certs"
ADMIN_BASE = f"{KC_INTERNAL}/admin/realms/{REALM}"

PORTAL_CLIENT_ID = os.getenv("PORTAL_CLIENT_ID", "federation-portal")
ADMIN_CLIENT_ID = os.getenv("PORTAL_ADMIN_CLIENT_ID", "portal-admin")
ADMIN_SECRET = os.environ["PORTAL_ADMIN_SECRET"]
CLI_CLIENT_ID = os.getenv("CLI_CLIENT_ID", "federation-cli")

CREDENTIAL_TTL_DAYS = int(os.getenv("CREDENTIAL_TTL_DAYS", "90"))
DATA_SERVICE_URL = os.getenv("DATA_SERVICE_URL", "https://data.example.org")

# The member services, as bootstrap.sh reads them: one client scope, service:<audience>,
# each. A token carries one service's audience at a time, so the commands this portal
# shows ask for the one they are about to call.
SERVICES = [
    {"audience": s["audience"], "name": s.get("name") or s["audience"],
     "scope": f"service:{s['audience']}"}
    for s in json.loads(os.getenv("FEDERATION_SERVICES")
                        or '[{"audience": "birds", "name": "Avian Visitors"}]')
]
BIRDS_AUDIENCE = os.getenv("BIRDS_AUDIENCE", "birds")

STATIC_DIR = Path(__file__).parent / "static"

# Attribute names. Kept together because they are the contract between this file, the
# audit script, and anyone reading the realm in the admin console.
ATTR_USER_CREDENTIAL = "fed_credential_client"   # on the user: which client is theirs
ATTR_OWNER_SUB = "fed_owner_sub"                 # on the client: who owns it
ATTR_OWNER_NAME = "fed_owner_username"
ATTR_EXPIRES = "fed_secret_expires"              # ISO-8601 date, enforced by the sweep


# --------------------------------------------------------------------------------------
# Keycloak admin client
# --------------------------------------------------------------------------------------

class AdminClient:
    """Thin wrapper over the Keycloak admin REST API, using the portal's service account.

    Holds one access token and renews it a little before expiry rather than on failure,
    so a long-running request does not die mid-flight.
    """

    def __init__(self, http: httpx.AsyncClient):
        self._http = http
        self._token: str | None = None
        self._expires_at: float = 0.0

    async def _bearer(self) -> str:
        if self._token and time.monotonic() < self._expires_at:
            return self._token
        resp = await self._http.post(
            f"{KC_INTERNAL}/realms/{REALM}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": ADMIN_CLIENT_ID,
                "client_secret": ADMIN_SECRET,
            },
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._expires_at = time.monotonic() + max(body.get("expires_in", 60) - 15, 10)
        return self._token

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = kwargs.pop("headers", {}) | {"Authorization": f"Bearer {await self._bearer()}"}
        resp = await self._http.request(method, f"{ADMIN_BASE}{path}", headers=headers, **kwargs)
        if resp.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail=f"Keycloak admin API {method} {path} returned {resp.status_code}: {resp.text[:400]}",
            )
        return resp

    async def get(self, path: str, **kw: Any) -> Any:
        resp = await self.request("GET", path, **kw)
        return resp.json() if resp.content else None

    async def post(self, path: str, **kw: Any) -> httpx.Response:
        return await self.request("POST", path, **kw)

    async def put(self, path: str, **kw: Any) -> httpx.Response:
        return await self.request("PUT", path, **kw)

    async def delete(self, path: str, **kw: Any) -> httpx.Response:
        return await self.request("DELETE", path, **kw)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient(timeout=15.0) as http:
        app.state.http = http
        app.state.admin = AdminClient(http)
        # PyJWKClient caches keys and refetches on an unknown kid, which is exactly the
        # "periodic JWKS fetch, no per-request call to the centre" behaviour we want.
        app.state.jwks = PyJWKClient(JWKS_URL, cache_keys=True, lifespan=600)
        yield


app = FastAPI(
    title="Federation Portal",
    version="1.0.0",
    summary="Registration and credential management for the MeteoGate federation testbed.",
    lifespan=lifespan,
)


def admin(request: Request) -> AdminClient:
    return request.app.state.admin


# --------------------------------------------------------------------------------------
# Token validation
# --------------------------------------------------------------------------------------

class Principal(BaseModel):
    sub: str
    username: str
    email: str | None = None
    name: str | None = None
    github_login: str | None = None


async def current_user(request: Request) -> Principal:
    """Validate the bearer token against Keycloak's JWKS and return who it belongs to.

    Signature, issuer and expiry only. The audience is deliberately not checked here:
    the portal is the token's own issuer's neighbour, and the SPA presents a token
    issued to federation-portal. Data services are the ones that care about `aud`.
    """
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = header[7:].strip()

    try:
        key = request.app.state.jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256", "ES256"],
            issuer=ISSUER,
            options={"verify_aud": False, "require": ["exp", "iat", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired") from None
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"Token rejected: {exc}") from None

    return Principal(
        sub=claims["sub"],
        username=claims.get("preferred_username") or claims["sub"],
        email=claims.get("email"),
        name=claims.get("name"),
    )


User = Annotated[Principal, Depends(current_user)]
Admin = Annotated[AdminClient, Depends(admin)]


# --------------------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------------------

class Credential(BaseModel):
    clientId: str
    created: str
    expires: str
    daysRemaining: int
    enabled: bool
    secret: str | None = Field(
        default=None,
        description="Present only in the response that created or rotated it. Never retrievable again.",
    )


class Registration(BaseModel):
    sub: str
    username: str
    email: str | None
    name: str | None
    githubLogin: str | None
    identityProviders: list[str]
    createdAt: str | None
    credential: Credential | None
    offlineSessions: int
    activeSessions: int


class PortalConfig(BaseModel):
    """Everything the SPA needs to start an OIDC flow. All of it is public."""

    issuer: str
    realm: str
    clientId: str
    cliClientId: str
    authorizationEndpoint: str
    tokenEndpoint: str
    endSessionEndpoint: str
    deviceEndpoint: str
    accountConsole: str
    dataServiceUrl: str
    dataServiceScope: str
    services: list[dict[str, str]]
    credentialTtlDays: int


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def _attr(obj: dict[str, Any], name: str) -> str | None:
    """Read a single-valued attribute out of a Keycloak user or client representation."""
    raw = (obj.get("attributes") or {}).get(name)
    if raw is None:
        return None
    return raw[0] if isinstance(raw, list) else raw


async def _find_client(kc: AdminClient, client_id: str) -> dict[str, Any] | None:
    found = await kc.get("/clients", params={"clientId": client_id, "max": 1})
    return found[0] if found else None


async def _cli_client_uuid(kc: AdminClient) -> str | None:
    client = await _find_client(kc, CLI_CLIENT_ID)
    return client["id"] if client else None


CREDENTIAL_PREFIX = "svc-"


async def _find_owned_client(kc: AdminClient, sub: str) -> dict[str, Any] | None:
    """Find a minted credential by its recorded owner, ignoring the user's pointer.

    The pointer on the user record is the fast path, but it can go missing — an admin
    editing the user in the console, or a failed write. A live client secret whose owner
    nobody can see is exactly the thing the architecture addendum warns about, so the
    authoritative link is the fed_owner_sub attribute on the client, and this is the
    scan that uses it.

    Linear in the number of svc- clients. Keycloak can index attributes for search, but
    that needs realm SPI configuration; for a federation of this size the scan is
    cheaper than the configuration.
    """
    candidates = await kc.get(
        "/clients", params={"clientId": CREDENTIAL_PREFIX, "search": "true", "max": 500}
    ) or []
    for client in candidates:
        if _attr(client, ATTR_OWNER_SUB) == sub:
            return client
    return None


async def _load_credential(kc: AdminClient, user: dict[str, Any]) -> Credential | None:
    client_id = _attr(user, ATTR_USER_CREDENTIAL)
    client = await _find_client(kc, client_id) if client_id else None

    if client is None:
        # Either there was no pointer, or it pointed at a client that has since been
        # deleted. Fall back to the ownership attribute before concluding there is none:
        # showing "no credential" while a working secret exists in their name is the
        # worst possible answer.
        client = await _find_owned_client(kc, user["id"])
    if client is None:
        return None

    expires_raw = _attr(client, ATTR_EXPIRES) or ""
    try:
        expires = datetime.fromisoformat(expires_raw)
    except ValueError:
        expires = datetime.now(timezone.utc)
    remaining = (expires - datetime.now(timezone.utc)).days

    return Credential(
        clientId=client["clientId"],
        created=_attr(client, "fed_created") or "unknown",
        expires=expires_raw,
        daysRemaining=remaining,
        enabled=client.get("enabled", False),
    )


async def _user_record(kc: AdminClient, sub: str) -> dict[str, Any]:
    user = await kc.get(f"/users/{sub}")
    if not user:
        raise HTTPException(status_code=404, detail="No such registration")
    return user


# Fields Keycloak owns and will reject or ignore on the way back in.
_SERVER_OWNED_USER_FIELDS = frozenset({
    "id", "createdTimestamp", "access", "self", "origin",
    "disableableCredentialTypes", "federationLink", "serviceAccountClientId",
})


async def _set_user_attributes(kc: AdminClient, record: dict[str, Any],
                               changes: dict[str, str | None]) -> None:
    """Change some of a user's attributes without losing the rest of the account.

    `PUT /users/{id}` is a full replace, not a patch. A request body carrying only
    `attributes` therefore erases the user's email, first name and last name — which for
    a brokered account means erasing everything GitHub told us about them. Merge into the
    representation already read instead, and send it back whole.

    Note also that unmanaged attributes must be enabled on the realm's user profile or
    Keycloak accepts this request and silently stores nothing. bootstrap.sh does that.
    """
    payload = {k: v for k, v in record.items() if k not in _SERVER_OWNED_USER_FIELDS}
    attributes = dict(record.get("attributes") or {})
    for key, value in changes.items():
        if value is None:
            attributes.pop(key, None)
        else:
            attributes[key] = [value]
    payload["attributes"] = attributes
    await kc.put(f"/users/{record['id']}", json=payload)
    record["attributes"] = attributes


# --------------------------------------------------------------------------------------
# Public endpoints
# --------------------------------------------------------------------------------------

@app.get("/api/config", response_model=PortalConfig, tags=["public"])
def portal_config() -> PortalConfig:
    """Discovery for the SPA. Mirrors the well-known document, minus what we don't use."""
    base = f"{KC_PUBLIC}/realms/{REALM}/protocol/openid-connect"
    return PortalConfig(
        issuer=ISSUER,
        realm=REALM,
        clientId=PORTAL_CLIENT_ID,
        cliClientId=CLI_CLIENT_ID,
        authorizationEndpoint=f"{base}/auth",
        tokenEndpoint=f"{base}/token",
        endSessionEndpoint=f"{base}/logout",
        deviceEndpoint=f"{base}/auth/device",
        accountConsole=f"{KC_PUBLIC}/realms/{REALM}/account/",
        dataServiceUrl=DATA_SERVICE_URL,
        dataServiceScope=f"service:{BIRDS_AUDIENCE}",
        services=SERVICES,
        credentialTtlDays=CREDENTIAL_TTL_DAYS,
    )


@app.get("/api/qr", tags=["public"], summary="Render a QR code")
def qr_code(
    data: Annotated[str, Query(max_length=512, description="The text to encode.")],
    format: Annotated[str, Query(pattern="^(svg|txt)$")] = "svg",
) -> Response:
    """QR rendering, so no client needs a QR library of its own.

    `format=txt` returns a block-character rendering that prints directly in a terminal —
    that is how the device-flow CLI shows a scannable code without installing anything.

    A device flow's `verification_uri_complete` embeds the user code, so a QR code is a
    one-scan approval. Convenient, and also the primary phishing vector: never send one
    to someone else. Rendering it in your own terminal, for a flow you just started, is
    the safe case.
    """
    code = segno.make(data, error="m")
    if format == "txt":
        import io

        buf = io.StringIO()
        code.terminal(out=buf, compact=True, border=2)
        return Response(buf.getvalue(), media_type="text/plain; charset=utf-8")

    import io

    buf = io.BytesIO()
    # Opaque black-on-white, always. The SVG is loaded through an <img>, which is a
    # separate document — CSS from the host page cannot reach inside it, so there is no
    # way to make the code follow the viewer's theme. A code that inherited a dark
    # foreground onto a dark background would simply not scan. White quiet zone included.
    code.save(buf, kind="svg", scale=6, border=3, dark="#000000", light="#ffffff")
    return Response(
        buf.getvalue(),
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/healthz", tags=["ops"])
async def healthz(request: Request) -> dict[str, Any]:
    try:
        resp = await request.app.state.http.get(
            f"{KC_INTERNAL}/realms/{REALM}/.well-known/openid-configuration", timeout=5.0
        )
        keycloak_ok = resp.status_code == 200
    except httpx.HTTPError:
        keycloak_ok = False
    return {"status": "ok" if keycloak_ok else "degraded", "keycloak": keycloak_ok}


# --------------------------------------------------------------------------------------
# Authenticated endpoints — all scoped to the caller
# --------------------------------------------------------------------------------------

@app.get("/api/me", response_model=Registration, tags=["registration"])
async def whoami(user: User, kc: Admin) -> Registration:
    """Everything the portal shows about the signed-in registration."""
    record = await _user_record(kc, user.sub)
    links = await kc.get(f"/users/{user.sub}/federated-identity") or []

    sessions = await kc.get(f"/users/{user.sub}/sessions") or []

    offline = 0
    cli_uuid = await _cli_client_uuid(kc)
    if cli_uuid:
        offline_sessions = await kc.get(f"/users/{user.sub}/offline-sessions/{cli_uuid}") or []
        offline = len(offline_sessions)

    created_ms = record.get("createdTimestamp")
    created = (
        datetime.fromtimestamp(created_ms / 1000, timezone.utc).isoformat()
        if created_ms
        else None
    )

    return Registration(
        sub=user.sub,
        username=record.get("username", user.username),
        email=record.get("email"),
        name=" ".join(filter(None, [record.get("firstName"), record.get("lastName")])) or None,
        githubLogin=_attr(record, "github_login"),
        identityProviders=[link["identityProvider"] for link in links],
        createdAt=created,
        credential=await _load_credential(kc, record),
        offlineSessions=offline,
        activeSessions=len(sessions),
    )


@app.post("/api/credential", response_model=Credential, tags=["credential"], status_code=201)
async def mint_credential(user: User, kc: Admin) -> Credential:
    """Mint the caller's machine credential, or rotate the secret if one already exists.

    This is the `client_credentials` path from the architecture document — a client id
    and secret that behave like an API key. The addendum's objection to it is that such a
    secret is normally decoupled from the identity that created it, so nothing revokes it
    when that identity goes away. Three things here answer that directly:

      * the owning subject and username are recorded on the client;
      * the secret carries an expiry, after which the sweep disables it;
      * deleting the registration deletes the client (see delete_registration below).

    What this does *not* give you is revocation when the upstream GitHub account is
    disabled. Keycloak never learns that. The expiry is the backstop, and that is the
    honest limit of the mechanism.
    """
    record = await _user_record(kc, user.sub)
    existing_id = _attr(record, ATTR_USER_CREDENTIAL)
    now = datetime.now(timezone.utc)
    expires = (now + timedelta(days=CREDENTIAL_TTL_DAYS)).replace(microsecond=0)

    client = await _find_client(kc, existing_id) if existing_id else None
    if client is None:
        # Adopt rather than duplicate. Minting a second credential while the first is
        # still live would leave a working secret nobody is tracking.
        client = await _find_owned_client(kc, user.sub)

    if client is None:
        client_id = f"{CREDENTIAL_PREFIX}{record.get('username', user.sub)}-{secrets.token_hex(3)}"
        payload = {
            "clientId": client_id,
            "name": f"Federation credential for {record.get('username', user.sub)}",
            "description": "Machine credential minted through the federation portal.",
            "enabled": True,
            "publicClient": False,
            "standardFlowEnabled": False,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True,
            "defaultClientScopes": ["basic", "roles", "federation"],
            # Optional, so a token names one service only when asked:
            # `-d scope=service:birds`. Credentials minted before a service joined get
            # its scope from bootstrap.sh at the next start.
            "optionalClientScopes": [service["scope"] for service in SERVICES],
            "attributes": {
                ATTR_OWNER_SUB: user.sub,
                ATTR_OWNER_NAME: record.get("username", ""),
                ATTR_EXPIRES: expires.isoformat(),
                "fed_created": now.replace(microsecond=0).isoformat(),
            },
            "protocolMappers": [
                {
                    # So a data service can see whose credential this is without a call
                    # back to the centre — the whole point of self-contained tokens.
                    "name": "fed-owner",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "config": {
                        "claim.name": "fed_owner",
                        "claim.value": record.get("username", user.sub),
                        "jsonType.label": "String",
                        "access.token.claim": "true",
                        "id.token.claim": "false",
                    },
                }
            ],
        }
        await kc.post("/clients", json=payload)
        client = await _find_client(kc, client_id)
        if client is None:
            raise HTTPException(status_code=502, detail="Client was created but cannot be read back")

        await _set_user_attributes(kc, record, {ATTR_USER_CREDENTIAL: client_id})
    else:
        # Rotation: same client id, new secret, expiry clock restarted. Re-attestation
        # is the act of clicking the button, which requires a live brokered login.
        client_id = client["clientId"]
        attributes = (client.get("attributes") or {}) | {ATTR_EXPIRES: expires.isoformat()}
        await kc.put(f"/clients/{client['id']}", json={"attributes": attributes, "enabled": True})

    secret_resp = await kc.post(f"/clients/{client['id']}/client-secret")
    secret = secret_resp.json()["value"]

    return Credential(
        clientId=client_id,
        created=_attr(client, "fed_created") or now.replace(microsecond=0).isoformat(),
        expires=expires.isoformat(),
        daysRemaining=CREDENTIAL_TTL_DAYS,
        enabled=True,
        secret=secret,
    )


@app.delete("/api/credential", status_code=204, tags=["credential"])
async def revoke_credential(user: User, kc: Admin) -> Response:
    """Delete the caller's machine credential. Tokens already issued survive to expiry."""
    record = await _user_record(kc, user.sub)
    client_id = _attr(record, ATTR_USER_CREDENTIAL)
    client = await _find_client(kc, client_id) if client_id else None
    if client is None:
        client = await _find_owned_client(kc, user.sub)
    if client is None:
        raise HTTPException(status_code=404, detail="No credential to revoke")

    if client is not None:
        _assert_owned(client, user.sub)
        await kc.delete(f"/clients/{client['id']}")

    await _set_user_attributes(kc, record, {ATTR_USER_CREDENTIAL: None})
    return Response(status_code=204)


@app.post("/api/sessions/revoke", status_code=204, tags=["credential"])
async def revoke_sessions(user: User, kc: Admin) -> Response:
    """Revoke every CLI grant and log the user out everywhere.

    Removing the consent for federation-cli is what actually kills an offline token: it
    drops the offline session with it. A plain logout would leave offline tokens working,
    which is the whole point of offline tokens.
    """
    consents = await kc.get(f"/users/{user.sub}/consents") or []
    for consent in consents:
        await kc.delete(f"/users/{user.sub}/consents/{consent['clientId']}")
    await kc.post(f"/users/{user.sub}/logout")
    return Response(status_code=204)


@app.delete("/api/registration", status_code=204, tags=["registration"])
async def delete_registration(user: User, kc: Admin) -> Response:
    """Delete the registration entirely: credential, grants, then the account itself.

    Ordered so that a failure part-way through never leaves an orphaned credential that
    outlives the account it belonged to.
    """
    record = await _user_record(kc, user.sub)

    client_id = _attr(record, ATTR_USER_CREDENTIAL)
    client = await _find_client(kc, client_id) if client_id else None
    if client is None:
        client = await _find_owned_client(kc, user.sub)
    if client is not None:
        _assert_owned(client, user.sub)
        await kc.delete(f"/clients/{client['id']}")

    for consent in await kc.get(f"/users/{user.sub}/consents") or []:
        await kc.delete(f"/users/{user.sub}/consents/{consent['clientId']}")

    await kc.delete(f"/users/{user.sub}")
    return Response(status_code=204)


def _assert_owned(client: dict[str, Any], sub: str) -> None:
    """Refuse to touch a client that is not the caller's, whatever the pointer said."""
    if _attr(client, ATTR_OWNER_SUB) != sub:
        raise HTTPException(status_code=403, detail="That credential belongs to someone else")


@app.exception_handler(httpx.HTTPError)
async def upstream_error(_: Request, exc: httpx.HTTPError) -> JSONResponse:
    return JSONResponse(status_code=503, content={"detail": f"Keycloak unreachable: {exc}"})


# Mounted last so it cannot shadow the API routes above.
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="ui")
