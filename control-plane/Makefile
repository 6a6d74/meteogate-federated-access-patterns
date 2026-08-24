SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

.PHONY: help secrets render certs up down restart rebuild bootstrap logs ps audit nuke check

help:            ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk -F':.*?## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.env:
	@test -f .env || { \
	  echo "No .env — copy .env.example to .env and fill it in, or run 'make secrets'."; \
	  exit 1; }

secrets:         ## Create .env from the example, generating the random secrets
	@./scripts/gen-secrets.py

render: .env     ## Render Traefik routes from the template using .env
	@set -a; source .env; set +a; \
	sed -e "s|__CONTROL_HOST__|$$CONTROL_HOST|g" \
	    -e "s|__CONTROL_IP__|$$CONTROL_IP|g" \
	    traefik/dynamic/routes.yml.tmpl > traefik/dynamic/routes.yml
	@echo "Rendered traefik/dynamic/routes.yml"

certs: .env      ## Obtain the TLS certificate (idempotent; --force to renew)
	@./scripts/gen-certs.sh

# In shared-proxy mode the host's reverse proxy terminates TLS and owns the routing,
# so this stack needs neither a certificate nor a Traefik route file. Detect it from
# .env rather than asking, so `make up` is the same command either way.
SHARED := $(shell grep -qs 'shared-traefik' .env && echo yes)

up: .env             ## Build if needed, start, and configure the realm
ifneq ($(SHARED),yes)
	@$(MAKE) --no-print-directory render certs
else
	@echo "Shared-proxy mode: skipping certificate and route generation."
	@echo "TLS and routing belong to the host's existing reverse proxy."
endif
	docker compose up -d --build
	@$(MAKE) --no-print-directory bootstrap

bootstrap: .env  ## Inject secrets into the realm and wire up GitHub (idempotent)
	@./keycloak/bootstrap.sh

down:            ## Stop and remove the containers, keeping the database
	docker compose down

restart:         ## Restart without rebuilding
	docker compose restart

rebuild:         ## Force a clean image rebuild, then start
	docker compose build --no-cache
	docker compose up -d

logs:            ## Follow logs from all containers
	docker compose logs -f

ps:              ## Show container status
	docker compose ps

audit:           ## Report on minted credentials (add ARGS=--apply to enforce expiry)
	@./scripts/audit-credentials.sh $(ARGS)

check: .env      ## Probe the running control plane
	@set -a; source .env; set +a; \
	echo "-- discovery"; \
	curl -sf "https://$$CONTROL_HOST/realms/$$KC_REALM/.well-known/openid-configuration" \
	  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" issuer:", d["issuer"]); print(" device:", d["device_authorization_endpoint"]); print(" grants:", ", ".join(d["grant_types_supported"]))'; \
	echo "-- portal"; \
	curl -sf "https://$$CONTROL_HOST/healthz"; echo

nuke:            ## Stop everything and DELETE the database — all registrations go
	@read -p "Delete all registrations and credentials? [y/N] " ok; [[ $$ok == y ]]
	docker compose down -v --remove-orphans
