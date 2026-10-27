# Member gateway

Put your own web service behind the federation. This is the testbed's data-plane
gateway as a single container that you can run anywhere: APISIX, the federation's
friendly-errors plugin, and the generator that turns a short YAML file into APISIX's
configuration.

```
user ──▶ member gateway ──▶ your service          (unchanged; it never sees a token check)
              │
              └─ fetches the federation's public signing keys once, then checks
                 every token locally. No request goes to the federation.
```

Each path you protect, a *target*, can have up to three front doors, each with its own
quota:

| Door | Credential | Default path | Quota counted per |
|---|---|---|---|
| federated | a token from the federation (`Authorization: Bearer …`) | `/api/obs` | user |
| API key | a key you issue (`apikey: …` header) | `/local/api/obs` | key |
| open | none | `/open/api/obs` | client address |

One switch turns every open route off. Switched off, open routes stay in your answers,
so turning them back on loses nothing, but they are left out of the gateway's
configuration entirely.

## What you need

- Docker (or anything that runs a container: see [Running it elsewhere](#running-it-elsewhere)).
- **`federation.env`**, from the federation's operator. It holds the federation's
  public URLs. `federation.env.example` shows its shape.
- A public hostname for the gateway, with TLS terminated either by a load balancer or
  CDN in front of it, or by the gateway itself (`certs/server.crt` and `certs/server.key`).

## Setting it up

From this directory:

```sh
make build       # the image: docker build -f Dockerfile -t member-gateway:latest ..
cp ~/Downloads/federation.env .        # from the federation's operator

make routes      # choose targets, doors and quotas
make info        # collect what the federation's operator needs
make check       # show the route table APISIX will get
make up          # start it
```

`make routes` and `make info` run the helpers inside the image, so you don't need
Python. Each asks questions. The defaults in brackets are what you'd usually want, and
rerunning either one starts from your earlier answers.

**`make routes`** writes:

| File | What it is |
|---|---|
| `config/targets.yaml` | Your answers. Edit it by hand if you like, then run `make render`. |
| `config/gateway.yaml` | The gateway's configuration, generated from `targets.yaml`. Don't edit it. |
| `gateway.env` | A random key for each API-key holder. Hand each key over privately. |

**`make info`** checks that this machine can reach the federation's identity provider,
and writes `member-registration.json`. **Send that file to the federation's operator.**
It names you, the gateway and its routes, and the GitHub accounts that need a
federation credential. It holds no secrets. The operator adds those accounts to the
federation's allow-list. Your gateway needs nothing else from them: tokens are checked
against the federation's published keys.

## Trying it

```sh
curl -i https://gw.example.org/api/obs                              # 401, with how to get a token
curl -i --oauth2-bearer "$(oidc-token meteogate)" https://gw.example.org/api/obs   # 200
curl -i -H "apikey: $KEY" https://gw.example.org/local/api/obs      # 200
```

The command-line clients for getting a token are described in
[docs/cli-clients.md](../docs/cli-clients.md). A browser that hits a refusal gets a
page explaining what to do. A script gets JSON.

`make logs` shows one JSON line per request, with the user, the kind of credential
and the quota left. It never logs the credential itself.

## Changing things

| To | Do |
|---|---|
| change routes or quotas | `make routes` (or edit `config/targets.yaml` and run `make render`), then `make restart` |
| add an API key | `make routes`, then `make restart`. The new key is in `gateway.env`. |
| replace a key | delete its line from `gateway.env`, run `make render`, then `make restart` |
| remove a key holder | `make routes`, answering no to keeping that key, then `make restart` |

A key's own quota, if you give it one, replaces the route's quota on every API-key route.

## Running it elsewhere

The image is the whole gateway. Whatever runs it needs to provide:

| | |
|---|---|
| **Ports** | 9080 (HTTP) and 9443 (HTTPS, only if the gateway holds the certificate). |
| **Mounts** | `config/` at `/config`, read-only; `certs/` at `/certs` if the gateway terminates TLS. |
| **Environment** | Everything in `federation.env` and `gateway.env`. |
| **Health** | `GET :7085/status` returns 200 while it runs. The image's own `HEALTHCHECK` uses it. |
| **Logs** | stdout and stderr. |

Configuration is generated each time the container starts, so a change takes effect
when you restart it. Kubernetes: a ConfigMap for `gateway.yaml`, Secrets for the keys,
and `/status` on port 7085 as the liveness probe. ECS, Nomad and the like work the
same way.

**Behind a load balancer**, every request appears to come from the balancer, so open
routes' per-address quotas are shared by everyone. Federated and API-key quotas are
unaffected.

**Your service on the same machine** is `http://host.docker.internal:PORT`. The compose
file maps that name on Linux too.

## Tests

```sh
make test        # the helpers (needs pytest and PyYAML)
make e2e         # the built image against a stand-in identity provider and service
```

The end-to-end test signs real RS256 tokens and checks that the gateway accepts a good
one and refuses one that's expired, has the wrong audience or issuer, or is forged.
It also checks the quotas, the API keys, and that disabled open routes are not served.
