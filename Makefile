SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# Top-level convenience. The two planes are independently deployable — that is the
# point of the architecture — so each has its own Makefile and its own .env. This file
# only orchestrates; it never hides which machine something runs on.

.PHONY: help status deploy-control up-data check demo-urls install-cli stop-legacy

help:                ## Show this help
	@echo
	@echo "  Federated access testbed"
	@echo
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk -F':.*?## ' '{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "  Per-plane targets:  make -C control-plane help"
	@echo "                      make -C data-plane help"
	@echo

stop-legacy:         ## Stop the standalone avian-visitors stack, which holds port 443
	-@cd ../../avian-visitors-simple-web-service && docker compose down

deploy-control:      ## Sync, build, start and verify the control plane on the control-plane host
	@./scripts/deploy-control-plane.sh

up-data: stop-legacy ## Generate configuration and start the data plane here on the data-plane host
	@$(MAKE) -C data-plane up

install-cli:         ## Symlink fed-login and friends into ~/.local/bin
	@./cli/install.sh

status:              ## Where does each half think it is, and is it answering?
	@set -a; source data-plane/.env; set +a; \
	printf '\n\033[1mControl plane\033[0m  %s\n' "$$CONTROL_BASE_URL"; \
	if curl -sf --max-time 5 "$$CONTROL_BASE_URL/realms/$$KC_REALM/.well-known/openid-configuration" >/dev/null; then \
	  echo "  discovery   reachable"; \
	  curl -s "$$CONTROL_BASE_URL/realms/$$KC_REALM/.well-known/openid-configuration" \
	    | python3 -c 'import json,sys; d=json.load(sys.stdin); print("  issuer     ", d["issuer"]); print("  device      ", "advertised" if "urn:ietf:params:oauth:grant-type:device_code" in d["grant_types_supported"] else "NOT ADVERTISED")'; \
	else echo "  discovery   UNREACHABLE — federated routes will refuse everything"; fi; \
	printf '\n\033[1mData plane\033[0m     https://%s\n' "$$DATA_HOST"; \
	for path in /healthz /birds/ /help/ /openapi.json; do \
	  printf '  %-14s %s\n' "$$path" "$$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 https://$$DATA_HOST$$path)"; \
	done; \
	printf '  %-14s %s (401 expected without a token)\n' "/api/birds" "$$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 'https://'$$DATA_HOST'/api/birds?q=finch')"; \
	echo

check:               ## Probe every gateway route and report what each one did
	@$(MAKE) -C data-plane check

watch:               ## Follow gateway traffic live — run in a second window
	@$(MAKE) -C data-plane watch ARGS="$(ARGS)"

demo-urls:           ## Print the URLs for the walkthrough in docs/demo.md
	@set -a; source data-plane/.env; set +a; \
	printf '\n  %-22s %s\n' "Web client"       "https://$$DATA_HOST/birds/"; \
	printf '  %-22s %s\n'   "How access works" "https://$$DATA_HOST/help/"; \
	printf '  %-22s %s\n'   "Refused, in a browser" "https://$$DATA_HOST/api/birds?q=finch&limit=3"; \
	printf '  %-22s %s\n'   "Address-bar route" "https://$$DATA_HOST/session/api/birds?q=finch&limit=3"; \
	printf '  %-22s %s\n'   "Unprotected"      "https://$$DATA_HOST/open/api/birds?q=finch&limit=3"; \
	printf '  %-22s %s\n'   "Portal"           "$$CONTROL_BASE_URL/"; \
	printf '  %-22s %s\n\n' "Keycloak admin"   "$$CONTROL_BASE_URL/admin/"
