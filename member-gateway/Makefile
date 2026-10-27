SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

IMAGE ?= member-gateway:latest
# The helpers run inside the image, as you, on this directory: no Python needed here.
HELPER := docker run --rm -it --user "$$(id -u):$$(id -g)" -v "$(CURDIR)":/work -w /work $(IMAGE)

.PHONY: help build info routes render check up down restart logs ps test e2e

help:            ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	 | awk -F':.*?## ' '{printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

federation.env:
	@echo "No federation.env. Ask the federation's operator for it (federation.env.example shows its shape)."; exit 1

build:           ## Build the gateway image
	docker build -f Dockerfile -t $(IMAGE) ..

info: federation.env  ## Collect what the federation operator needs: writes member-registration.json
	$(HELPER) info

routes:          ## Choose routes and quotas: writes config/targets.yaml, config/gateway.yaml, gateway.env
	$(HELPER) routes

render:          ## Regenerate config/gateway.yaml after editing config/targets.yaml by hand
	$(HELPER) routes --render

check: federation.env  ## Generate APISIX's configuration and show the route table, without serving
	docker run --rm --env-file federation.env --env-file gateway.env -v "$(CURDIR)/config":/config:ro $(IMAGE) check

up: federation.env  ## Start the gateway (after build and routes)
	docker compose up -d --force-recreate

down:            ## Stop it
	docker compose down

restart: up      ## Apply a changed configuration

logs:            ## Follow the gateway's logs: one JSON line per request
	docker compose logs -f

ps:              ## Show whether it is running and healthy
	docker compose ps

test:            ## The helpers' unit tests (needs pytest and PyYAML here)
	cd .. && python3 -m pytest -q member-gateway/tests

e2e: build       ## End to end: this image, a stand-in identity provider and service
	cd .. && python3 member-gateway/tests/e2e.py --image $(IMAGE)
