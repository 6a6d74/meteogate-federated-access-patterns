# Federated Access Testbed — Architecture

A working implementation of the control-plane/data-plane separation set out in the
MeteoGate design notes. It exists to answer one question with running code rather than
prose: **can a federation issue one credential per user, valid at every member service,
without ever standing between that user and the data?**

> **This file is the complete reference.** It carries the implementation detail —
> plugin field names, exact configuration, commands — and it sits beside the code.

---

## 0. Terms and source documents

### The three documents referred to throughout

This testbed implements a set of MeteoGate design notes that are not published here.
They are referred to by short name throughout, and summarised below so that nothing in
this document depends on having read them.

| Referred to as | What it argues |
|---|---|
| **the architecture note** | *Federated Data Sharing — Authentication & Access Control Architecture.* That the federation's central infrastructure should handle identity only, with data flowing directly from users to each member service. Proposes a reusable gateway package for operators who cannot modify their own service, and a simplified configuration layer for it. |
| **the brokering review** | The closing section of that same note. That identities should be brokered from each participating institution's own identity provider rather than from commercial providers such as GitHub. Source of two arguments this document returns to repeatedly: that a personal social account cannot be withdrawn by the institution someone is leaving, and that a client secret unconnected to the identity that created it never expires on its own. |
| **the device-flow note** | *Device Authorization Grant (RFC 8628) for MeteoGate CLI and Programmatic Access.* That a command line needs this particular grant, that device-code phishing is a real risk requiring specific mitigations, and — correcting the architecture note — that browser access needs a session cookie rather than a token in a query string. |

The brokering review is the closing part of the architecture note rather than a separate
file. It is named separately here because the two make materially different arguments:
the note designs the system, the review questions whose identities it should be built on.

### Terms and abbreviations

| Term | Meaning |
|---|---|
| **API** | Application Programming Interface. An *API key* is a static secret a service issues to a caller; Keycloak's *Admin API* is the interface the Federation Portal uses to manage users and credentials. |
| **Access token** | A short-lived credential presented with each request. Here it is a JSON Web Token valid for five minutes. |
| **Bearer token** | Any token where possession alone is sufficient — there is no accompanying proof of identity. All the tokens here are bearer tokens. |
| **CIBA** | Client-Initiated Backchannel Authentication. An OpenID Connect flow in which the service asks the user's registered device to approve a request out of band. |
| **Client credentials grant** | An OAuth 2.0 flow in which an application presents an identifier and a secret, with no user and no browser involved. |
| **Device authorization grant** | The OAuth 2.0 flow defined in RFC 8628, in which a device or command line displays a short code that a person approves in a browser elsewhere. |
| **IdP** | Identity provider. The service that authenticates a person and asserts who they are. |
| **JWKS** | JSON Web Key Set. The set of public keys an issuer publishes so that anyone can verify the tokens it signs, without contacting it per request. |
| **JWT** | JSON Web Token. A signed, self-contained token: the claims travel inside it, so a recipient with the issuer's public key can verify it locally. |
| **OIDC** | OpenID Connect. The identity layer built on OAuth 2.0 that all of this uses. |
| **PKCE** | Proof Key for Code Exchange, RFC 7636. Binds an authorization code to the client that requested it, so an intercepted code is useless on its own. |
| **Realm** | Keycloak's unit of isolation: its own users, clients, keys and policies. This testbed uses one, named `federation`. |
| **Refresh token** | A longer-lived credential used to obtain fresh access tokens without the user re-authenticating. An **offline token** is a refresh token that survives the end of the browser session. |
| **Scope** and **audience** | A scope is what a token is permitted to do; the audience (`aud`) claim names who it is meant for. A service checks the audience to reject tokens issued for somebody else. |
| **TLS** | Transport Layer Security, the encryption underneath HTTPS. Both machines serve genuine Let's Encrypt certificates obtained through Tailscale. |
| **Tailnet** | The private Tailscale network these two machines are on. Nothing here is exposed publicly. |

### The claims this system depends on

`iss` and `aud` are registered JWT claims from RFC 7519 §4.1 — *claims*, not properties or
fields, since they are entries in the token's payload. The ones that carry weight here:

| Claim | Meaning | Value in this federation |
|---|---|---|
| `iss` | Issuer — who minted the token | `https://identity.example.org/realms/federation` |
| `aud` | Audience — who it is intended for | `federation-services` |
| `sub` | Subject — the account it was minted for | an opaque Keycloak user id, stable per account |
| `azp` | Authorized party — the client that requested it | e.g. `federation-cli`, or a minted `fed-<user>-<hex>` |
| `exp`, `iat` | Expiry and issue time | five-minute lifetime in this realm |
| `fed_owner` | Custom: the person behind a machine credential | added by a protocol mapper at mint |

`iss` and `aud` are the two halves of the trust decision a gateway makes locally. `iss`
says *I recognise the authority that signed this*, and determines which JWKS verifies it.
`aud` says *and it was minted for me*. Checking the signature without checking the audience
is the classic mistake: it accepts a validly signed token issued for some entirely
different service in the same realm. That is exactly what the `portal-admin` test in
*Checking the audience* demonstrates — right issuer, valid signature, refused.

Two details matter when porting this to another gateway:

- **`aud` may be a string or an array.** RFC 7519 permits either, and Keycloak emits an
  array as soon as more than one audience mapper applies. Treat "is my audience present in
  `aud`" as a membership test, never string equality.
- **`azp` is not `aud`.** The authorized party identifies the *credential*; the audience
  identifies the intended *recipient*. Authorising on `azp` would require every service to
  know individual client ids, which is the coupling the audience claim exists to remove.

And `exp`/`iat` are why neither the raw `Authorization` header nor a userinfo blob can key
a quota: both change on every refresh. See *How the quota is keyed*.

### A note on spelling

Protocol names, header fields and configuration keys keep their specification spelling —
the `Authorization` header, the authorization code grant, `authorizationEndpoint`.
Ordinary prose uses British spelling: authorisation, organisation, recognised. Where the
two sit in the same sentence the inconsistency is deliberate, because renaming a header
field to suit a house style would be worse.

---

## 1. The shape of it

Two machines, deliberately. Running both halves on one host would let a mistake go
unnoticed — the whole point of the architecture is that the halves are separable.

```
                          ┌──────────────────────────────────────────────┐
                          │  CONTROL PLANE            identity.example.org       │
   ┌──── register ───────▶│                                              │
   │                      │  Traefik :443                                │
   │  ┌─ get a token ────▶│    ├── /realms/*  ──▶ Keycloak ──▶ Postgres  │
   │  │                   │    └── /*         ──▶ Portal                 │
   │  │                   │                                              │
   │  │   ┌─ keys, once ─▶│  Issues: tokens signed by the realm key      │
   │  │   │  then cached  │  Publishes: public keys, discovery document  │
   │  │   │               └──────────────────────────────────────────────┘
   │  │   │                                    ▲
   │  │   │                                    │  GitHub sign-in (browser only)
   │  │   │                                    ▼
   │  │   │                             [ github.com ]
   │  │   │
 ┌─┴──┴───┴──┐                    ┌──────────────────────────────────────┐
 │   User    │                    │  DATA PLANE               data.example.org│
 │  browser  │                    │                                      │
 │  curl     │═══ data ══════════▶│  APISIX :443                         │
 │  phone    │◀══ (direct) ═══════│    ├── validates tokens locally      │
 └───────────┘                    │    ├── counts quota per user         │
                                  │    └──▶ FastAPI birds service        │
                                  └──────────────────────────────────────┘
```

The double line is the only path data ever takes. The centre sees a token request once
per session, and a fetch of its public keys once per key rotation. It never sees a byte
of bird data.

**What that buys.** If the control-plane host is switched off right now, the gateway carries on serving federated
requests until the cached keys expire. Nothing about a data request consults the centre.
That is not a resilience feature added afterwards — it follows directly from using
self-contained signed tokens instead of a lookup.

**What it does not buy, and the distinction is easy to lose.** *Holding* a token is
independent of the centre; *obtaining* one is not. Access tokens live 300 seconds, so a
client whose token is still valid keeps working, and one whose token has expired cannot
refresh — `fed-token` calls the token endpoint and fails. The blast radius of a centre
outage is therefore "no new sessions, and no refreshes after the current token expires",
not "no data". Worth being precise about when demonstrating it, because a `cannot reach
…/realms/federation` from the command line looks at first glance like the very dependency
the architecture claims not to have. It is the client that reached for the centre, on the
user's own machine, before any request left for the gateway.

---

## 2. Components

| Where | Component | Role |
|---|---|---|
| control | Keycloak 26.4 | Identity provider and broker. Issues tokens, publishes the public keys used to verify them. |
| control | PostgreSQL 16 | Registrations, offline sessions, issued credentials. |
| control | Federation Portal (FastAPI) | Registration and credential management, as a web page and an API. |
| control | Traefik 3.3 | Terminates TLS; separates Keycloak's paths from the Federation Portal's. |
| data | APISIX 3.13 | The gateway. Validates tokens, enforces quota, explains refusals. |
| data | FastAPI birds service | The service being protected. **Unmodified.** |
| data | nginx | Serves the web client and the help pages. |
| anywhere | `oidc-agent`, or the bundled scripts | Command-line access via the device authorization grant. |

The birds service is built from its own repository and knows nothing about any of this.
That is the case the architecture note cares most about: an operator who *cannot* modify
their service still gets federated access control.

**The control plane can share a host that already runs a reverse proxy.** The default is
self-sufficient — its own Traefik, its own certificate, nothing external required — and
that property is deliberate, because a federation whose member package depends on
somebody else's infrastructure is not a package a member can deploy. Where the host
already has a proxy, an optional overlay
(`control-plane/docker-compose.shared-traefik.yml`) publishes Keycloak and the portal
through it instead, declaring routes as container labels and touching none of the
existing installation's files. Keycloak keeps its own paths, because they appear inside
the issuer URL in every token; the portal is the part that moves, to a path prefix, and
its single-page client resolves everything relative to wherever it was served from so it
needs no rebuild.

---

## 3. Identity: brokered, never local

Direct registration is refused (`registrationAllowed: false`). There is no password
store, no reset process, and no credential lifecycle for human users at all. Every
account arrives through GitHub, and the browser flow's `identity-provider-redirector` is
configured with `defaultProvider: github`, so the username and password form — which no
account here could satisfy — is never shown.

This mirrors MeteoGate's deployed state: it is already an identity broker. Adding
institutional identity providers later is configuration within a Keycloak already doing
exactly this job, not a change of architecture.

### What this does and does not give you

| | Status |
|---|---|
| Authentication federation | Yes |
| Withdrawal of access when someone leaves an institution | **No.** A personal GitHub account is not the institution's to close, and Keycloak is never told it was. |
| Verified institutional affiliation | No. Social identities carry none. |
| Level of assurance | Self-asserted, uniform, low. |

The backstop for the second row is Keycloak's `Offline Session Max`, set here to **seven
days**. After that a command-line credential stops renewing and the person must
authenticate again — at which point a closed GitHub account fails at source. It is set
deliberately rather than left at its default, because it is the only signal the social
path has.

`firstName` and `lastName` are made optional. A GitHub account with no public name would
otherwise be stopped at a "complete your profile" form, and a self-asserted name from a
social identity informs no authorisation decision anywhere here. Requiring it would add
friction in exchange for a field already agreed not to be trusted.

---

## 4. Credentials: four kinds of user, four ways in

Four ways to obtain a *federation* credential, one for each kind of user, following the
table in the device-flow note.

| Who | How they authenticate | Where the credential is kept |
|---|---|---|
| Someone at a browser | Authorization code with PKCE, run in JavaScript by the web client | Browser memory (`sessionStorage`) |
| Someone pasting URLs into the address bar | Authorization code with PKCE, run by the gateway | A session cookie |
| Someone at a terminal | Device authorization grant, yielding an offline token | Encrypted in `oidc-agent`, or a file for the bundled scripts |
| A job that runs unattended | Client credentials grant, using a credential issued by the Federation Portal | Wherever the operator puts it |

### Why three of the four share a route

Three of them end in the same thing — an `Authorization: Bearer <token>` header — so all
three use `/api/birds`, and **the gateway cannot tell them apart.** It verifies a
signature. It has no way of knowing whether the token behind it came from a browser, a
device flow, or an unattended job, and it does not need to.

Only the second needs a route of its own, and the browser forces that. A URL typed into
the address bar cannot carry a header, so its credential has to be a cookie instead;
`/session/api/birds` exists to run the sign-in and read that cookie back. It is the one
real division, and it is imposed rather than chosen.

### The fourth case: jobs that run unattended

A scheduled task, an ingest pipeline, a server process — anything that runs when nobody
is at a keyboard. It needs separate treatment because the device authorization grant
**requires a person at least once**: somebody has to open a browser and approve. A
machine nobody ever signs in to cannot do that. It needs either an offline token created
during setup by a person, or a client credentials credential registered to an
institution rather than an individual.

Client-Initiated Backchannel Authentication is sometimes proposed for this, and Keycloak
supports it, but it assumes each user has a registered authentication device and so does
not fit the case.

### The device authorization grant

The client credentials grant **cannot be brokered.** It contains no browser redirect, so
there is nowhere to insert the hop to GitHub — or, later, to an institutional identity
provider. The device authorization grant is the only standard grant that gives a command
line a brokered identity:

```
CLI                          Keycloak                      Browser (any device)
 ├─ POST /auth/device ─────────▶│
 │◀─ user_code "UFQA-LZSQ",     │
 │   verification_uri, interval │
 │  [prints code + QR code]     │◀─ user opens the URI ──────┤
 ├─ POST /token ───────────────▶│   enters the code          │
 │◀─ authorization_pending      │   → straight to GitHub     │
 ├─ POST /token ───────────────▶│   → consent screen         │
 │◀─ access + refresh token     │◀───── approved ────────────┤
```

Verified working, including the `slow_down` response when a client polls faster than the
interval it was given.

The QR code encodes `verification_uri_complete`, which embeds the user code so there is
nothing to type. It is rendered by the portal (`GET /api/qr?format=txt`), so the command
line needs no QR library of its own — it prints what it is handed.

That path is relative to wherever the portal is mounted, which the issuer URL does not
record: standalone the portal owns the root of the control-plane host, but published
through a proxy the host already runs it sits under `PORTAL_PATH` (`/portal` by default)
and the root belongs to that host. `fed-login` tries both and remembers what answered;
`FED_PORTAL` in `~/.federation/config` settles it outright. A QR is a convenience, so its
absence degrades to the code and URL rather than failing the login.

**The phishing mitigations set out in the device-flow note are implemented.** The
command-line client requires a consent screen even though it is first-party; the device
code lifespan is left at ten minutes; refresh token rotation is on with no reuse
permitted; and both the command line and the Federation Portal warn, in as many words, never to
approve a code you did not start yourself.

### What the Portal actually mints

Not an API key in any bespoke sense: a **Keycloak client**, with every flow switched off
except one.

```python
"publicClient": False,                 # confidential — it has a secret
"standardFlowEnabled": False,          # no browser redirect
"implicitFlowEnabled": False,
"directAccessGrantsEnabled": False,    # no username/password grant
"serviceAccountsEnabled": True,        # client_credentials, and only that
"defaultClientScopes": ["basic", "roles", "federation"],
```

The credential can do exactly one thing: present its id and secret at the token endpoint
for `grant_type=client_credentials`. It cannot be used to sign a person in, and it cannot
be replayed through a browser. The secret is returned exactly once, at mint or rotation.

Two details turn a Keycloak client into a *federation* credential:

- **`federation` in the default client scopes.** That scope carries an audience mapper
  emitting `federation-services`, which is the claim every data service checks. This is
  the whole of what makes the credential portable: a gateway that has never heard of this
  client, at an institution that was not consulted, accepts the token because the audience
  is right and the signature verifies. It is also why the scope is deliberately withheld
  from `portal-admin`, which talks to the admin API — a credential should not carry an
  audience it has no business presenting.
- **A hardcoded `fed_owner` claim** naming the person who minted it, so a service can see
  whose credential is calling without asking the centre.

The resulting access token therefore carries `iss`, `aud: federation-services`, `sub` (the
service account's own user id, stable for the life of the credential), `azp` (the client
id), and `fed_owner`. A service sees a machine that is traceable to a person, in the token
itself.

Minting twice **adopts** the existing credential rather than issuing a second one. That is
deliberate and worth stating: a second live secret that nothing is tracking is exactly the
failure the next section is about. Rotation keeps the client id, replaces the secret, and
restarts the expiry clock; the re-attestation is the act of clicking the button, which
requires a live brokered login.

### The client-secret lifecycle problem, and how far this gets

A job that runs unattended is issued a client identifier and secret by the Federation
Portal. That
secret behaves like an API key: anyone holding it can obtain federation tokens, at every
service in the federation, with no browser and no person involved.

The brokering review calls the lifecycle of that secret the most urgent unresolved
concern. It is clearer as a scenario than as a principle:

> Someone registers, is issued a credential, and wires it into a pipeline. A year later
> they leave. Their GitHub account is closed, so they can no longer sign in — but the
> secret is a separate object in Keycloak that was never linked to their account.
> Nothing connects the two events. The person is gone; the secret keeps working,
> indefinitely, for anyone who ever had a copy of it.

That is why such a secret never expires on its own. Four controls address different parts
of it.

| Control | Which part of the problem it addresses |
|---|---|
| `fed_owner_sub` and `fed_owner_username`, recorded on the credential when it is issued | Establishes whose secret this is. Nothing else here is possible without it: you cannot withdraw a secret by owner if no owner was ever written down. |
| `fed_secret_expires`, ninety days by default | Gives it a finite life even when nobody is paying attention. The only control that works with no person and no signal at all. |
| A `fed_owner` claim added to every token issued for that credential | Lets a data service see whose credential is calling, from the token alone, without asking the centre. |
| Deletion alongside the registration | Deleting an account deletes its secret in the same operation, so the two cannot drift apart. |

The first is load-bearing. *"Every client secret must have a recorded owning identity"*
is the brokering review's own first minimum measure, and every other control depends on
there being an answer to *whose is this?*

`control-plane/scripts/audit-credentials.sh`, run on the control-plane machine, is
the part with teeth. Keycloak does not enforce the
expiry — nothing in the product does — so a scheduled sweep does:

```
CLIENT                 OWNER        STATE
svc-alice-3f1a2b       alice        ok, 89d left
svc-bob-77c104         bob          expiring in 9d
svc-carol-2ea9f1       carol        EXPIRED         → disabled by --apply
svc-dave-004b1c        (gone)       ORPHANED        → deleted by --purge-orphans
svc-erin-91ba7d        erin         UNREFERENCED    → reclaimed on erin's next visit
```

Two limits.

**The sweep acts when it runs, not when a secret expires.** Between the expiry date and
the next run, an expired secret still works. Run it from cron; the interval chosen is the
real exposure window.

**None of this closes the scenario above.** The failure there was a GitHub account being
closed, and Keycloak is never told that. No commercial identity provider sends a "this
person has gone" signal, so not one of the four controls can act on the event that
actually matters. What the expiry does is bound how long a secret outlives its owner —
ninety days rather than indefinitely. That is a real improvement on indefinite validity,
and it is not revocation.

The only genuine fix is an upstream identity that *can* be closed at source. That is the
brokering review's central argument for institutional brokering, and it is not something
a testbed built on GitHub sign-ins can demonstrate.

### Choosing a command-line client

Two are installed side by side, and the realm cannot distinguish them: same public
client, same user, same tokens.

- **`oidc-agent`** (Karlsruhe Institute of Technology) is the one to recommend. It keeps
  the credential encrypted and hands out tokens over an agent socket, on the
  `ssh-agent` model. It is also the standard tool across EGI and EOSC, so users arriving
  from those communities will already have it.
- **`fed-login` and `fed-curl`**, bundled here, exist to make RFC 8628 legible: the whole
  grant is about eighty readable lines. They leave the refresh token in a file, which is
  worse. Keep them for demonstrating; do not recommend them for use.

`docs/cli-clients.md` compares the two in full.

### Two routes that are not federation credentials

Neither belongs in the table above; both exist for contrast.

| Route | Credential | Why it exists |
|---|---|---|
| `/local/api/birds` | The operator's own API key, in an `apikey` header | To show that joining a federation does not mean giving up the ability to issue your own credentials. Two consumers are configured with different allowances — five and 120 requests a minute — because the operator still sets their own policy. |
| `/open/api/birds*` | None | The comparison: the same data with no gateway policy at all, so protected and unprotected can be put side by side. **Delete this route and the point is made** — it is a demonstration aid, not something a real operator would run. |

---

## 5. The gateway

### Why standalone APISIX rather than APISIX with etcd

The architecture note's packaging sketch runs etcd alongside APISIX. For a package
distributed to operators that is the wrong default. Standalone mode, configured from a
file, gives:

- no etcd, no Admin API, and no control-plane database to operate;
- configuration that is a file — readable, diffable, and kept in version control;
- reload within a second of that file changing, with no restart.

Nothing in a single-node gateway needs a distributed key-value store.

### The simplified configuration layer

This is the deliverable the architecture note asks for: operators never touch the APISIX
Admin API or learn its plugin schemas. They write this —

```yaml
service:
  name: Avian Visitors
  upstream: http://api:8000

auth:
  provider: keycloak
  discovery: ${CONTROL_BASE_URL}/realms/${KC_REALM}/.well-known/openid-configuration
  issuer:    ${CONTROL_BASE_URL}/realms/${KC_REALM}
  audience:  federation-services

rate_limiting:
  requests_per_minute: 5

routes:
  - name: birds-search
    path: /api/birds
    methods: [GET]
    auth: federated
```

— and `make config` produces fourteen APISIX routes, two upstreams, two consumers, the
TLS material, the global HTTP-to-HTTPS rule, the plugin chains, the route priorities, and
an OIDC callback route the operator never asked for and should not have to know about.
(The TLS material and the redirect rule are dropped when the operator leaves `listen.tls`
out, for a gateway behind a load balancer or CDN that terminates TLS itself.)
`${VARS}` are resolved from `.env` when the configuration is generated, so no secret
reaches version control.

That last item is the telling one. Session-cookie routes need a fixed callback endpoint
with a route of its own, because a path prefix that gets rewritten breaks the plugin's
default behaviour. An operator should never have to know that; concealing it is most of
what the layer is for.

Concretely, one four-line route entry becomes:

```
serverless-pre-function (10000) → extract the token's subject into a header
openid-connect          (2599)  → verify signature against cached keys, check issuer
                                  and audience
limit-count             (1002)  → count the request against that subject
friendly-errors         (50)    → if it went wrong, explain it in the right language
proxy-rewrite / upstream        → hand off to the backend
```

### How the quota is keyed, and why it needed care

The two obvious approaches both fail, and fail invisibly.

- **`X-Userinfo`**, which the `openid-connect` plugin helpfully sets, contains `iat` and
  `exp`. It changes with every token, so a user would get a fresh allowance each time
  they refreshed.
- **The `Authorization` header** has exactly the same problem.

So a `serverless-pre-function` runs in the *rewrite* phase, decodes the token's payload
without verifying it, and pins the subject into `X-Fed-Subject`. Two things make reading
an unverified token safe here:

1. It **always** overwrites the header, so a client cannot supply its own value and
   charge its requests to somebody else's quota.
2. `openid-connect` (priority 2599) rejects an invalid token before `limit-count`
   (priority 1002) ever reads the header. By the time the value is used, the token it
   came from has been verified against the federation's published keys.

Verified: two users making requests on the same route in the same second get independent
counters.

Session routes cannot use any of this. There is no bearer token on the request, and the
subject only becomes known after `openid-connect` has run — too late for `limit-count`.
They are keyed on `cookie_session` instead, which is the session cookie itself: correct
per browser session, but it resets when that session does. See *Three sessions* below.

### Checking the audience

The `openid-connect` plugin has no "expected audience" setting. It has exactly one
audience control — `claim_validator.audience.match_with_client_id`, which compares the
token's `aud` claim against the plugin's own `client_id`. So on bearer-token routes the
`client_id` is set to `federation-services`: not a client at all, but the federation's
audience name. No secret is used on that path, because verification is entirely local
against the cached keys.

Verified: a token issued for `portal-admin`, which lacks the `federation` client scope,
is refused with `403 mismatched audience`.

### Porting this to another gateway

Nothing above is APISIX-shaped, and it is worth separating the requirements from the
product that happens to implement them here. **A federation gateway validates tokens; it
does not manage credentials.** The gateway never sees a client secret — the client
exchanges its secret for a token at the centre, and the gateway only ever sees the token.
The whole lifecycle in section 4 happens somewhere the gateway cannot observe. That is
precisely what makes the model portable.

Five requirements, then, and everything else is detail:

| # | Requirement | Why it matters |
|---|---|---|
| 1 | Discover and **cache the JWKS**, refreshing on rotation | This is the property that keeps the centre out of the data path |
| 2 | Validate `iss` against an **allowlist** | Otherwise a token from any issuer with a valid signature works |
| 3 | Validate `aud` against the federation audience | The credential was minted for the federation, not for you |
| 4 | **Pin the signing algorithm**; reject `none` and HMAC | Prevents algorithm confusion against a public key |
| 5 | Project a verified claim into something **policy can key on** | Quotas, logging, per-user rules |

How that maps onto other products:

| Tool | JWKS | `iss` / `aud` | Subject projection |
|---|---|---|---|
| Envoy `jwt_authn` | `remote_jwks` with `cache_duration` | `issuer` and `audiences` — both first-class | `forward_payload_header`, then RBAC or rate-limit descriptors |
| NGINX Plus | `auth_jwt_key_request` | manual, via `map` on `$jwt_claim_*` | `$jwt_claim_sub` straight into `limit_req_zone` |
| Kong | `openid-connect` plugin | native issuer and audience settings | claim to header, then rate-limit key |
| AWS API Gateway (HTTP API) | automatic from the issuer | JWT authorizer takes `issuer` and `audience` | claims into the authorizer context |
| Apigee | `VerifyJWT` policy | explicit issuer and audience elements | claims to flow variables |

Editions matter more than the table suggests: Kong's OIDC plugin and Traefik's JWT support
sit behind commercial tiers, and Kong OSS's `jwt` plugin is per-consumer, which does not
fit JWKS-based federation at all. Traefik Proxy has no built-in JWT middleware, which is
why it terminates TLS here and does not do token validation.

Envoy is the closest structural match, and porting to it would *remove* code rather than
add it: `issuer` and `audiences` are first-class fields, so the `client_id` double-duty
described above disappears, and so does the placeholder client secret.

The one requirement no gateway grants for free is the fifth. Keying a quota on the raw
`Authorization` header, or on a userinfo blob, silently hands every user a fresh allowance
on each token refresh — both contain `iat` and `exp`. Whatever the product, the subject has
to be extracted deliberately and the extraction has to run after verification. That is a
design decision to carry across, not an implementation detail to rediscover.

### Refusals a person can read

A gateway refusing a request has to answer two audiences with one status code. A script
wants JSON and a non-zero exit. Somebody who has just pasted a URL into a browser wants
to know what went wrong and what to do about it.

`friendly-errors` is a small custom APISIX plugin that negotiates on the error path, in
**both** directions. If the client's `Accept` header names `text/html`, or
`Sec-Fetch-Dest: document` indicates a person navigating, the body is replaced with a
page naming the problem and linking to the fix. If the client wants anything *but* HTML
and the body would be HTML anyway, it is replaced with JSON instead.

The second direction is the one easily forgotten, and it matters more. When
`openid-connect` refuses a request it sets `WWW-Authenticate` and exits without writing a
body, so nginx supplies its own error page — which is HTML. Without this, a script asking
for JSON receives a `<title>` tag. A body another plugin has already written as JSON is
left alone.

```
$ curl 'https://data.example.org/api/birds?q=finch'
{"error":"unauthorized", "detail":"No valid federation credential was presented…"}

$ curl -H 'Accept: text/html' 'https://data.example.org/api/birds?q=finch'
→ "You need a credential to read this", with a link to the Federation Portal,
  the setup
  command, and the exact curl for the URL that was tried
```

The quotes are not decoration. In zsh — the default shell on macOS — `?` is a glob
character, and a glob that matches nothing is a hard error rather than a literal string,
so an unquoted URL with a query string never reaches curl at all. `&` breaks in every
shell, by backgrounding the command. Every example in this repository quotes its URLs
for that reason.

The 429 page reads `X-RateLimit-Limit` and `X-RateLimit-Reset` from the response, so it
states how many seconds remain rather than restating policy.

Three of the gateway's refusals default to HTML and all three had to be pinned: the two
above, and `limit-count`, which without an explicit `rejected_msg` falls through to
nginx's stock 429 page.

Every code snippet on these pages carries a copy button. On the gateway's error pages the
script is inlined rather than loaded from the web container, because an error page is
what a reader sees when that container is unreachable.

### What the gateway logs, and what it refuses to log

One JSON object per request, on standard output. It carries the request, the status, the
latency, the rate-limit headers, and the authenticated subject — the last of these only
because the gateway sets `X-Fed-Subject` on the request itself, so it is available to
nginx as an ordinary header.

It carries **no credential**. Not the bearer token, not the API key, not the session
cookie — only a single word naming which kind was presented. All three are usable by
whoever reads the log, and log files travel further than the systems that produce them:
into aggregators, backups, and support tickets. This is the same argument that makes the
gateway refuse a `?token=` query parameter, applied one layer down.

Two things about the format are worth recording because both cost time to discover:

- **APISIX's `$route_name` and `$consumer_name` are not nginx variables.** They are
  Lua-side context that its own logger plugins can read; putting one in an nginx
  `log_format` makes the process refuse to start. Anything the access log needs must
  either be a real nginx variable or a header the gateway sets for itself.
- **`access_log_buffer: 1`** — an attempt to flush every line for a live view — starts
  cleanly and then resets every TLS connection. Log lines lag up to three seconds on
  nginx's flush timer, and that is the floor.

`scripts/watch-traffic.py` formats that stream into one readable line per request, which
is what makes the gateway's decisions demonstrable rather than merely described.

### Routes

| Path | Credential | Quota per minute | Purpose |
|---|---|---|---|
| `/api/birds` | Federation token | 5 | The documented URL. A small quota, deliberately. |
| `/api/birds/*` | Federation token | 60 | Illustrations — cheap, and one page pulls several. |
| `/session/api/birds` | Gateway session cookie | 5 | For pasting into the address bar. |
| `/local/api/birds` | The operator's API key | Per consumer | Not federated. |
| `/open/api/birds*` | None | 60 | The comparison. |
| `/birds/*`, `/help/*`, `/openapi.json`, `/healthz` | None | None | Discovery and user interface. |

Splitting the quota by *cost* rather than only by user is what makes a five-a-minute
search allowance usable at all. Discovery is deliberately unmetered: a client that cannot
read the OpenAPI document cannot find out how to authenticate in the first place.

---

## 6. Two things the browser forces

**An `<img src>` sends no `Authorization` header.** The web client therefore fetches each
illustration with `fetch()` and turns the bytes into a blob URL. This is not a
workaround; it is the constraint that makes a web client or a gateway session necessary
in the first place, made visible.

**The address bar cannot set headers at all.** That is what the `/session/` routes are
for: an ordinary authorization code flow with PKCE at the gateway, and a session cookie
the browser *will* send. It is the mechanism the device-flow note's correction identifies
as the right answer, and the reason no `?token=` query parameter is offered here — tokens
in query strings end up in server logs, browser history, and `Referer` headers.

### Three sessions, and why the demonstration often looks like nothing happened

The session routes make a protected URL work when it is typed, and the cost of that is a
piece of state most descriptions of the flow leave out: the gateway keeps a session of its
own. APISIX runs `openid-connect` with `bearer_only: false` and `unauth_action: auth`, and
on success sets a `session` cookie with `cookie_lifetime: 3600`.

So the redirect chain is **per gateway session, not per request** — which means the same URL
produces three different network traces depending on what already exists. Three sessions are
in play, they are created at different moments, and they end independently:

| Session | Set by | Ended by |
|---|---|---|
| The gateway's `session` cookie | APISIX, on callback | one hour, `/session/logout`, or deleting the cookie |
| Keycloak's SSO session | Keycloak, on brokered login | `/session/logout`, or Keycloak's own logout |
| GitHub's | GitHub | signing out of GitHub |

| Already in place | Trace |
|---|---|
| Nothing | four redirects, and GitHub's sign-in screen |
| GitHub only | four redirects, all silent, then `200` |
| GitHub + Keycloak | two redirects — Keycloak issues a code immediately, no GitHub hop |
| GitHub + Keycloak + the gateway cookie | a single `200` |

The last row is the ordinary case on any second visit inside the hour, and it is easy to
read as a failure: the redirects that the walkthrough promises simply are not there, and
reloading does not bring them back. They are absent because the gateway does not need them.
Verified cold, with no cookie jar, the first hop is real:

```
gateway/session/api/birds…            302 → identity/realms/…/protocol/openid-connect/auth
identity/realms/…/auth                303 → identity/realms/…/broker/github/login
identity/realms/…/broker/github/login 303 → github.com/login/oauth/authorize
github.com/…                          302 → back to Keycloak, then to gateway/session/callback
```

Two consequences worth holding onto. The gateway session is the thing that makes the
address bar work, so it is also the thing to end when demonstrating the flow — hence
`logout_path: /session/logout`, which clears the cookie and Keycloak's session together.
And because the quota on these routes is keyed on `cookie_session` (see *How the quota is
keyed*), ending the gateway session also resets that route's allowance: the same person
returns as a new counter. That is a deliberate trade — there is no verified subject
available at `limit-count` time on a session route — but it means the session routes are
not where to demonstrate that a quota cannot be escaped.

---

## 7. Verified behaviour

Everything below was exercised against the running two-machine deployment, with a real
GitHub-brokered identity.

| Test | Result |
|---|---|
| Valid federation token | 200 |
| No token | 401, with the right body for the client |
| Signature corrupted | 401 |
| Payload corrupted, signature kept | 401 |
| Signature stripped | 401 |
| Subject forged, original signature kept | 401 |
| `alg: none` | 401 |
| Token for the wrong audience | 403 `mismatched audience` |
| Quota exhausted | 429 on the sixth of five, as JSON or HTML as asked |
| Two users, same route, same second | Independent counters |
| Illustrations on a separate allowance | Still 200 after the search quota is spent |
| Operator API key: valid / absent / wrong | 200 / 401 / 401 |
| Per-consumer quota override | Five a minute for one partner, 120 for another |
| 401 to a client wanting JSON | JSON, with an actionable `detail` field |
| 401 to a browser | A readable HTML page |
| 200 responses | Untouched by the plugin |
| Device flow | Code issued, `authorization_pending`, `slow_down` |
| Issue → rotate → present the old secret | Rejected immediately |
| Delete registration | Account and credential both gone |
| Whole chain end to end | Device flow through GitHub → offline token → Federation Portal → issued client credential carrying `aud: federation-services` and a `fed_owner` claim → gateway returns 200 |

### Six failures that give no useful error

Recorded because none of them produces a diagnostic worth the name: each does the wrong
thing and reports success, or dies with no output at all.

Three were found while building:

- **Keycloak's `PUT /users/{id}` is a full replace, not a partial update.** A request
  body carrying only `attributes` erases the user's email address and name — which for a
  brokered account means erasing everything GitHub told us about them.
- **Since Keycloak 24, user attributes the realm does not declare are rejected by
  default,** and rejected silently: the write returns success and stores nothing. This
  affects `github_login` written by the identity provider mapper, the Portal's pointer to
  a user's credential, and the entitlements placeholder. `unmanagedAttributePolicy:
  ENABLED` is now set during bootstrap.
- **Supplying a `clientScopes` array in a realm import *replaces* Keycloak's built-in
  scopes** rather than adding to them. The realm came up with no `profile`, no `email`
  and no `offline_access` — so no username in tokens, and no way to request an offline
  token at all. The `federation` scope is created during bootstrap instead.

Three more appeared only on deploying to the second machine, and none of them is in this
code:

- **A Secure Shell (SSH) command run as `ssh host 'command'` gets a non-login shell**, which on macOS skips `path_helper`.
  `/usr/local/bin` is therefore absent, and Docker Desktop's command-line tool appears
  not to be installed rather than merely not found. The deploy script now uses a login
  shell, and starts the Docker daemon itself rather than telling you to.
- **The Tailscale command-line tool is sandboxed on macOS.** Started over SSH it cannot
  create files in an arbitrary directory, and fails with `operation not permitted` on its
  own temporary file — which reads like a fault in whatever called it. `gen-certs.sh` now
  takes the certificate and key on standard output and splits them, so every file is
  created by the script itself.
- **`cryptography` 50.x wheels for 64-bit ARM use instructions that older Docker Desktop
  virtual machines do not expose.** The import is killed by the illegal-instruction signal
  `SIGILL` and prints *nothing*, so the container restarts in a silent loop. Pinned to `>=44,<47`; the pin can be lifted
  once Docker Desktop on that host is updated.

---

## 8. The source documents' open questions, as they stand here

**Federation-wide quota.** Not attempted. Quotas here are per service, keyed on the
token's subject, using APISIX's local counter. Collective enforcement needs a shared
counter store — `limit-count` supports Redis, so it is configuration rather than
redesign — but that puts a shared dependency back into the data path, which is the thing
this architecture exists to avoid.

**Token lifetime.** Largely dissolved, as the device-flow note predicted. Access tokens
last five minutes and nobody notices, because renewal is automatic on all four paths.

**The audience claim.** Implemented as a single federation-wide audience,
`federation-services`, carried by a client scope rather than issued per service. An
`entitlements` claim is wired in as a placeholder for the entitlement format defined by
AARC-G002 — a guideline from Authentication and Authorisation for Research and
Collaboration describing how to express group membership and role as a Uniform Resource
Name (URN) — reading a user attribute that nothing yet
populates. That is where an attribute authority would connect.

**A central gateway.** There is none. The centre is Keycloak and the Federation Portal; the only
APISIX instance is the operator's own, in front of the operator's own data.

**Advertising security schemes in OpenAPI.** Not done. The birds service is deliberately
unmodified and its OpenAPI document is generated by FastAPI, so advertising the gateway's
security schemes would mean either editing the service or rewriting the document in
flight. Worth doing; not done here.

---

## 9. What this testbed does not show

Stated plainly, because a demonstration that overstates itself is worse than none.

- **One service, not thirty.** The claim "one credential, every service" is structurally
  supported — a second service would validate the same tokens against the same published
  keys using the same configuration layer — but it is not demonstrated.
- **No institutional brokering.** GitHub only. Adding an identity provider reached
  through eduGAIN, the international interfederation service for research and education,
  or a Microsoft Entra ID tenant, is realm configuration; the brokering review's whole
  argument is that this is incremental. That too is untested here.
- **No attribute authority.** The `entitlements` claim exists and is always empty. This
  is the largest genuinely new component the brokering review identifies, and here it is
  a placeholder.
- **No assurance framework.** Nothing from the assurance framework published by REFEDS
  (Research and Education FEDerations), nothing from Sirtfi — the Security Incident Response Trust Framework for Federated Identity — and no
  entity categories governing attribute release.
- **Withdrawal of access is still unsolved,** and cannot be solved on the social path.
  The seven-day offline session maximum is a backstop, not a fix.
- **Tailnet only.** Everything is bound to Tailscale addresses. No public exposure, no
  realistic load, and no adversary.
