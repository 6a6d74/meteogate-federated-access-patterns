# Federated Access Testbed

A working implementation of the control-plane/data-plane separation set out in a set of
MeteoGate design notes. Those notes are not published here; `docs/architecture.md` §0
summarises what each argues, and nothing in this repository depends on having read them.

One credential per user, issued centrally, valid at every member service — with the
centre never in the data path.

- **`docs/architecture.md`** — what was built, why, and what it does *not* show.
  The complete reference, and the authoritative one.
- **`docs/demo.md`** — a walkthrough you can follow in about ten minutes.
- **`docs/cli-clients.md`** — the bespoke CLI vs `oidc-agent`, and why the
  difference is entirely in how the token is stored.

```
identity.example.org          data.example.org
┌────────────────────────────┐         ┌────────────────────────────┐
│ CONTROL PLANE              │         │ DATA PLANE                 │
│  Keycloak  — identity      │◀─JWKS───│  APISIX    — the gateway   │
│  Portal    — credentials   │  once   │  FastAPI   — the birds     │
│  Postgres                  │         │  nginx     — web client    │
└────────────────────────────┘         └────────────────────────────┘
                                                    ▲
                    all data flows here ────────────┘
```

---

## Prerequisites

- Docker with Compose v2, on both machines
- Tailscale on both, logged in, with HTTPS certificates enabled
- SSH from `the data-plane host` to `the control-plane host` (the deploy script tells you how if it is not set up)
- A **GitHub OAuth App** — see below
- `python3` on the data-plane host (for the config generator; it falls back to a container if PyYAML
  is missing)

### The GitHub OAuth App

At <https://github.com/settings/developers> → **New OAuth App**:

| Field | Value |
|---|---|
| Application name | anything, e.g. `MeteoGate Federation (test)` |
| Homepage URL | `https://identity.example.org/` |
| Authorization callback URL | `https://identity.example.org/realms/federation/broker/github/endpoint` |

Generate a client secret and keep both values. GitHub's servers never call that URL —
only your browser does — so a tailnet-only host works fine.

---

## Bringing it up

```bash
# ── 1. Control plane, on the control-plane host ──────────────────────────────────────────
cd control-plane
make secrets                 # writes .env with generated passwords
$EDITOR .env                 # paste GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET

cd ../
./scripts/deploy-control-plane.sh    # rsync to the control-plane host, build, start, configure realm

# ── 2. Data plane, on the data-plane host ─────────────────────────────────────────────
cd data-plane
make secrets                 # writes .env, generates the operator's own API keys
# copy GATEWAY_CLIENT_SECRET from control-plane/.env into data-plane/.env
make up                      # certs, generate APISIX config, build, start, verify

# ── 3. The CLI, anywhere on the tailnet ────────────────────────────────
cd ../cli
./install.sh                 # symlinks fed-login, fed-curl, fed-token, fed-logout
./oidc-agent-setup.sh        # optional: the standard client, alongside the bespoke one
```

That host may already run the standalone `avian-visitors` stack on port 443. Stop it first —
the gateway takes that port:

```bash
(cd ../../avian-visitors-simple-web-service && docker compose down)
```

Nothing in that repository is modified. The gateway builds the same service from the
same source and puts a front door in front of it.

---

## Using it

| | |
|---|---|
| Web client | <https://data.example.org/birds/> |
| How access works | <https://data.example.org/help/> |
| Federation Portal | <https://identity.example.org/portal/> |
| Keycloak admin | <https://identity.example.org/admin/> (realm `master`) |

```bash
# The standard client — recommended for actual use. Keeps the token encrypted
# and hands it out over an agent socket rather than leaving it in a file.
oidc-agent-setup.sh                                    # device flow, once
curl --oauth2-bearer "$(oidc-token meteogate)" \
  'https://data.example.org/api/birds?q=finch&limit=3'

# The bespoke scripts — kept because they make RFC 8628 legible in ~80 lines.
# Same realm, same client, same user; the token lands in a file instead.
fed-login                                              # device flow, once
fed-curl 'https://data.example.org/api/birds?q=finch&limit=3'
fed-token --status                                     # what am I holding?
fed-logout                                             # revoke it centrally
```

See [`docs/cli-clients.md`](docs/cli-clients.md) for why the difference is entirely in
how the token is stored.

---

## Everyday commands

### Control plane (`control-plane/`, run on the control-plane host)

| Command | What |
|---|---|
| `make up` | Start everything and configure the realm |
| `make bootstrap` | Re-apply realm configuration (idempotent; how you rotate secrets) |
| `make check` | Probe discovery and the Federation Portal |
| `make audit` | Report on minted credentials |
| `make audit ARGS=--apply` | Disable expired credentials |
| `make logs` / `make ps` | The usual |
| `make nuke` | Stop and **delete the database** — every registration goes |

From `the data-plane host`, `./scripts/deploy-control-plane.sh` does the sync-build-start-verify cycle
remotely. Re-run it after any change under `control-plane/`.

### Data plane (`data-plane/`, run on the data-plane host)

| Command | What |
|---|---|
| `make up` | Generate config, build, start, verify |
| `make config` | Regenerate APISIX config from the operator YAML |
| `make routes` | Show the route table the YAML produces |
| `make reload` | Regenerate; APISIX picks it up within a second, no restart |
| `make check` | Probe every route and report what each one did |
| `./scripts/burn-quota.sh` | Exhaust the quota and show both refusal formats |

---

## Layout

```
control-plane/                    runs on the control-plane host
├── keycloak/
│   ├── realm-federation.json     realm structure — no secrets
│   └── bootstrap.sh              secrets, client scope, user profile, GitHub default
├── portal/                       FastAPI + single-page UI
├── traefik/                      TLS, and the /realms vs /* split
├── scripts/
│   ├── gen-secrets.py            .env from .env.example
│   ├── gen-certs.sh              tailscale cert, self-signed fallback
│   └── audit-credentials.sh      the expiry sweep — the part with teeth
└── Makefile

data-plane/                       runs on the data-plane host
├── gateway-config/
│   └── avian-visitors.yaml       ★ the whole of what an operator writes
├── scripts/
│   ├── gen-apisix-config.py      ★ the simplified→native translator
│   ├── check.sh                  probe every route
│   └── burn-quota.sh             exhaust the quota, show both formats
├── apisix/
│   ├── config.yaml               static config: standalone mode, plugin list
│   ├── plugins/friendly-errors.lua   ★ human-readable refusals
│   └── conf/apisix.yaml          GENERATED — do not edit
├── web/html/birds/               OAuth-aware copy of the bird client, and copy.js
├── web/html/help/                what a user is sent to when refused
└── Makefile

cli/                              fed-login, fed-token, fed-curl, fed-logout
└── oidc-agent-setup.sh           the standard client, set up against this realm
scripts/deploy-control-plane.sh   data plane → control plane
docs/architecture.md              ★ the design, and its limits
docs/cli-clients.md               oidc-agent vs the bundled scripts
docs/demo.md                      a ten-minute walkthrough
```

Files marked ★ are the ones worth reading first.

---

## Things worth knowing

**Generated files are git-ignored, and two of them hold secrets.**
`data-plane/apisix/conf/apisix.yaml` embeds the TLS private key, because APISIX in
standalone mode keeps certificates in the same document as the routes.

**Certificates last 90 days.** `make certs` (with `--force` to renew) on each machine.
They are real Let's Encrypt certificates from `tailscale cert`, which matters more than
usual here: Keycloak's issuer URL ends up in every token, and the gateway verifies the
control plane's certificate when it fetches JWKS.

**`make bootstrap` is how you rotate.** Change a secret in `control-plane/.env` and
re-run it. Everything it does is idempotent.

**The quota is deliberately tiny** — five searches a minute — so you can exhaust it in
five seconds. Change `rate_limiting` in `gateway-config/avian-visitors.yaml` and
`make reload`.
