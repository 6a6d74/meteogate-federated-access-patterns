# Working on this project

## Generated files are not sources — regenerate them

Four files are produced from a template plus `.env`. They are git-ignored, so a fresh
clone never has them, and they are the files the running system actually reads.

| Generated file | Produced from | By |
|---|---|---|
| `data-plane/apisix/conf/apisix.yaml` | `gateway-config/*.yaml` + `.env` | `make -C data-plane config` |
| `data-plane/web/html/birds/config.js` | `web/html/birds/config.js.tmpl` + `.env` | same |
| `control-plane/traefik/dynamic/routes.yml` | `traefik/dynamic/routes.yml.tmpl` + `.env` | `make -C control-plane render` (standalone only) |
| `*/certs/server.{crt,key}` | `tailscale cert`, or self-signed | `make certs` |

**After any bulk edit — a find-and-replace, a rename, a scrub, a merge — run
`make -C data-plane config` and then `make -C data-plane check`.**

This is not a style preference. It has already caused one live bug: a search-and-replace
across the tree rewrote `config.js` along with the sources, nothing was regenerated, and
the web client's Sign In button sent users to a hostname that does not exist. Every
source file was correct. The one file the browser loads was not.

The failure mode is silent by construction: no command errors, the gateway serves the
stale copy quite happily, and the first symptom appears in someone's browser. `make check`
now compares the *served* client configuration against `.env` and reports drift, so run it
rather than trusting that the sources look right.

## Verify the artefact, not the input

Related, and the recurring theme of this project's bugs. Checking that a source file says
the right thing is not evidence that the running system does.

- Changed a plugin? Restart APISIX and `curl` the endpoint.
- Changed the realm? Re-run `bootstrap.sh` and fetch a token.
- Changed a page? Fetch it through the gateway, not from disk.
- Changed something on the control plane? Re-deploy — editing on the remote host works
  until the next `rsync --delete` overwrites it.

## Hostnames and addresses live only in `.env`

Every source file uses neutral placeholders (`identity.example.org`, `data.example.org`,
`100.64.0.x`). Real values belong in `.env`, which is git-ignored, and in nothing else.
`realm-federation.json` ships placeholder redirect URIs on purpose; `bootstrap.sh` sets the
real ones from `.env` at deploy time.

If a real hostname ever appears in a tracked file, that is a bug, not a shortcut.

## The two planes are deployed differently

`data-plane` runs wherever you are working. `control-plane` is pushed to another host by
`scripts/deploy-control-plane.sh`, which rsyncs with `--delete` and runs `make up`
remotely. Editing files directly on that host is temporary.

`certs/` is excluded from that sync deliberately: the certificate is issued for the remote
host's own name and can only be requested there.

## Site-local adaptations stay optional

`control-plane/docker-compose.shared-traefik.yml` publishes through a reverse proxy the
host already runs, and is enabled by `COMPOSE_FILE` in `.env`. The base compose must
remain self-sufficient — a member of a federation has to be able to stand up their own
infrastructure without depending on anyone else's. Do not fold site-local assumptions
into the base files.
