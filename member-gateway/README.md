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

A federation token names one service, its *audience*, and only that service's gateway
accepts it, so a service you send a token to cannot replay it at another member. You
choose your service's audience (`make routes` asks; something short like `fmi-obs`), and
the federation's operator registers it. Until they do, no token names it.

Each path you protect, a *target*, can have up to three front doors, each with its own
quota:

| Door | Credential | Default path | Quota counted per |
|---|---|---|---|
| federated | a token from the federation (`Authorization: Bearer …`) | `/api/obs` | user |
| API key | a key you issue (`apikey: …` header) | `/local/api/obs` | key |
| open | none |
| session (sign-in door) | as federated: `X-Fed-Subject`, `X-Fed-Username`, `X-Userinfo` | `/open/api/obs` | client address |

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
It names you, the gateway, its audience and routes, and the GitHub accounts that need a
federation credential. It holds no secrets. The operator registers the audience and adds
those accounts to the federation's allow-list. Your gateway needs nothing else from
them: tokens are checked against the federation's published keys.

## Trying it

```sh
curl -i https://gw.example.org/api/obs                              # 401, with how to get a token
curl -i --oauth2-bearer "$(fed-token fmi-obs)" https://gw.example.org/api/obs   # 200
fed-curl https://gw.example.org/api/obs                             # the same: it asks the gateway which token
curl -i -H "apikey: $KEY" https://gw.example.org/local/api/obs      # 200
```

The command-line clients for getting a token are described in
[docs/cli-clients.md](../docs/cli-clients.md). A browser that hits a refusal gets a
page explaining what to do. A script gets JSON, and a `WWW-Authenticate` header naming
the scope to ask for: `scope="service:fmi-obs"`.

An API key can also go in the query string, `?apikey=$KEY`, for clients that can't set
a header, such as map tiles in a browser.

`make logs` shows one JSON line per request, with the user or key holder, the kind of
credential and the quota left. It never logs the credential itself. A key in the query
string is logged as `apikey=-`. The error log (stderr) can't be masked: nginx adds the
request line to each entry. It records only real faults, but a fault on a request that
carries `?apikey=` will show that key there. Prefer the header where a client allows it.

## A sign-in door for browsers

The federated door wants a bearer token, which a browser doesn't send when it follows a
link. To let people browse your service's pages, give it a **sign-in door** on a hostname
of its own. People sign in with the federation once, and the gateway keeps a session
cookie. Your service's own paths and links work there unchanged.

`make routes` asks for the door's hostname, and which targets it serves. In
`config/targets.yaml`:

```yaml
session:
  host: web.obs.example.org             # its own hostname; point it at this gateway too
  after_logout: https://web.obs.example.org/   # optional; the door's home page if unset
targets:
  - name: obs
    path: /api/obs
    session: {quota: 60}                # per person, as on the federated door
```

The door needs a client from the federation's operator. `make info` puts the two
addresses they need in `member-registration.json`, under `web`. They send back an id and
a secret: put them in `gateway.env` as `SESSION_CLIENT_ID` and `SESSION_CLIENT_SECRET`,
and `make restart`. Until both are set, the gateway won't start. `gateway.env` also holds
`SESSION_SECRET`, which encrypts the cookies. It's kept, so a restart doesn't sign
anyone out.

**Changing `session.host` or `after_logout` later needs the operator too.** The client
accepts only the addresses it was registered with: the callback on `session.host`, and
`after_logout` as the page after sign-out. Change either and the identity provider
refuses the redirect, so sign-in or sign-out stops on its error page. Run `make info`
again and send the operator the new `web` block. Once they've updated the client, it
works again. On their side it's a change to the `web` block in the member list, then a
deploy.

What happens there:
- **Signing in:** someone without a session is sent to the federation's sign-in, and
  comes back to the page they asked for.
- **Tokens:** the session's token is asked for with `service:<audience>`, and must name
  your service, the same rule as the federated door. It isn't passed on: your service
  gets `X-Fed-Subject`, `X-Fed-Username` and `X-Userinfo`, as on the federated door.
- **Quotas:** one per person, however often they sign in.
- **Renewal:** tokens are renewed as they expire, while the session lasts (an hour by
  default).
- **Signing out:** `https://<door>/session/logout` ends the session here and at the
  federation, then returns to `after_logout`.

The door has no CORS: its cookie is for the browser's own pages. A web app on another
site uses the federated door with a token instead.

## What your service receives

The gateway checks the credential and keeps it: neither the API key (header or query
string) nor the bearer token is passed on. The service learns who called from headers
the gateway sets:

| Door | Headers |
|---|---|
| federated | `X-Fed-Subject` (the user's stable ID), `X-Fed-Username`, `X-Userinfo` (the verified token claims, base64 JSON) |
| API key | `X-Consumer-Username` (the key holder's name in `targets.yaml`) |
| open | none |

Every door also sends `X-Forwarded-Host`, the hostname the request came to (a client's
own is replaced). The API-key and open doors send `X-Forwarded-Prefix`, the prefix the
gateway strips (`/local`, `/open`), so a service that honours it can build links that
lead back through the same door. On the federated door a client's own is removed.

The gateway removes these headers from anything a client sends, so they can be trusted.
A service that needs the raw bearer token itself sets `forward_token: true` under
`service` in `targets.yaml`. Removing a key from the query string can change the order
of the other parameters.

## Changing things

| To | Do |
|---|---|
| change routes or quotas | `make routes` (or edit `config/targets.yaml` and run `make render`), then `make restart` |
| add an API key | `make routes`, then `make restart`. The new key is in `gateway.env`. |
| let web pages on other sites call the gateway | Allowed from any site by default: a page still needs a token or a key, and these doors use no cookies. To allow only some, `make routes` asks, or set `service.cors_origins` in `config/targets.yaml` to a list such as `[https://maps.example.org]`, or `[]` for none; then `make render` and `make restart`. Preflights are answered without a credential, and refusals carry the CORS headers too, so the page can show why it was refused. |
| wait longer for a slow service | `make routes` asks how long to wait (30 s unless you change it), or set `service.timeout.read` in `config/targets.yaml` and run `make render`; then `make restart`. If your service has its own deadline, go a few seconds past it, so a slow request ends with its answer rather than the gateway's 504. `connect` (3 s) and `send` (30 s) can be set the same way. |
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

**Behind a reverse proxy or load balancer**, every request appears to come from the
proxy. Open routes' per-address quotas are then one quota for everyone, and the log shows
the proxy's address. Tell the gateway which proxies to believe: `make routes` asks, or
set it in `config/targets.yaml`:

```yaml
listen:
  trusted_proxies: [10.0.0.0/8]            # the proxies' addresses or networks
  client_address_header: X-Forwarded-For   # or X-Real-IP, whichever your proxy sets
```

The gateway then takes the client's address from that header, but only on requests from
those addresses. With `X-Forwarded-For` it takes the rightmost address that isn't a
trusted proxy, so a client can't get past its quota by adding its own entries on the left.

**List only a proxy that overwrites or strips the header** on the requests it passes on.
Traefik sets `X-Real-IP` itself, and most load balancers append to `X-Forwarded-For`.
A proxy that passes a client's header through untouched lets the client choose its own
address. Federated and API-key quotas don't depend on addresses, so they're unaffected
either way.

**Your service on the same machine** is `http://host.docker.internal:PORT`. The compose
file maps that name on Linux too.

## Tests

```sh
make test        # the helpers (needs pytest and PyYAML)
make e2e         # the built image against a stand-in identity provider and service
make e2e-session # the sign-in door against a real Keycloak and a scripted browser
```

The end-to-end test signs real RS256 tokens and checks that the gateway accepts a good
one and refuses one that's expired, forged, from the wrong issuer, or for another
service — including one carrying the old shared audience.
It also checks the quotas, the API keys, and that disabled open routes are not served.
