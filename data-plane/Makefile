SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

GATEWAY_CONFIG := gateway-config/avian-visitors.yaml
GENERATED      := apisix/conf/apisix.yaml

# The generator needs PyYAML. Use the host's python3 if it has it, otherwise borrow a
# container — an operator deploying this package should not have to set up a virtualenv.
PYYAML := $(shell python3 -c 'import yaml' 2>/dev/null && echo host || echo docker)
ifeq ($(PYYAML),host)
  GEN := python3
else
  GEN := docker run --rm -v "$(CURDIR)":/w -w /w python:3.12-slim \
           sh -c 'pip install --quiet pyyaml && exec python3 "$$@"' --
endif

.PHONY: help secrets certs config up down restart rebuild logs ps check routes reload

help:            ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk -F':.*?## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.env:
	@test -f .env || { echo "No .env — run 'make secrets' first."; exit 1; }

secrets:         ## Create .env from the example, generating the random secrets
	@./scripts/gen-secrets.py

certs: .env      ## Obtain the TLS certificate (idempotent; --force to renew)
	@./scripts/gen-certs.sh

config: .env certs  ## Regenerate APISIX configuration from the operator YAML
	@set -a; source .env; set +a; \
	sed -e "s|__CONTROL_HOST__|$$CONTROL_HOST|g" \
	    -e "s|__KC_REALM__|$$KC_REALM|g" \
	    -e "s|__DATA_HOST__|$$DATA_HOST|g" \
	    web/html/birds/config.js.tmpl > web/html/birds/config.js
	@$(GEN) scripts/gen-apisix-config.py $(GATEWAY_CONFIG) -o $(GENERATED) --print-routes

routes: config   ## Show the route table the operator YAML produces

up: config       ## Build if needed, generate configuration, and start
	docker compose up -d --build
	@echo
	@$(MAKE) --no-print-directory check || true

reload: config   ## Regenerate configuration; APISIX picks it up within a second
	@echo "APISIX rereads apisix.yaml about once a second — no restart needed."

down:            ## Stop and remove the containers
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

check: .env      ## Probe every route and report what each one does
	@./scripts/check.sh
