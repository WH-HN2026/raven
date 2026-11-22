# RAVEN developer commands. See AGENTS.md "Commands".
SHELL := /bin/bash
NPM ?= npm
SQLC := go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
# web/node_modules can contain Go packages, so never use ./... here.
GO_PKGS := ./cmd/... ./internal/... ./web
INFRA_SERVICES := raven-db nginx uwsgi celeryworker celerybeat initializer postgres valkey

.PHONY: dev check check-go check-web gen build manual infra-up infra-down db-new test-integration test-scale lab-up lab-down cve-db

## dev: Go server (rebuilt on change) + Vite dev server, using .env.local (run scripts/wt-env.sh first)
dev: web/node_modules
	scripts/dev.sh

## check: everything CI runs; needs no Docker or database
check: check-web check-go

check-go:
	@unformatted=$$(gofmt -l $$(git ls-files --cached --others --exclude-standard '*.go' | grep -v '^internal/db/gen/')); \
	  if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	go vet $(GO_PKGS)
	go test $(GO_PKGS)

check-web: web/node_modules
	cd web && $(NPM) run typecheck && $(NPM) run lint && $(NPM) test && $(NPM) run build

web/node_modules: web/package-lock.json
	cd web && $(NPM) ci
	@touch web/node_modules

## gen: sqlc + openapi-typescript (commit the output)
gen: web/node_modules
	$(SQLC) generate
	cd web && $(NPM) run gen

## build: web build embedded into bin/raven
build: web/node_modules
	cd web && $(NPM) run build
	CGO_ENABLED=0 go build -trimpath -o bin/raven ./cmd/raven

## manual: render docs/manual/raven-manual.tex to docs/RAVEN-instrukcja.pdf with tectonic
manual:
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	  tectonic --outdir "$$tmp" docs/manual/raven-manual.tex && \
	  cp "$$tmp/raven-manual.pdf" docs/RAVEN-instrukcja.pdf && \
	  echo "built docs/RAVEN-instrukcja.pdf"

## infra-up: shared Postgres (5433) + DefectDojo (18080), everything except raven
infra-up:
	scripts/shared-env.sh
	docker compose up -d $(INFRA_SERVICES)

infra-down:
	docker compose stop $(INFRA_SERVICES)

## db-new name=add_foo: new timestamped goose migration
db-new:
	@test -n "$(name)" || { echo "usage: make db-new name=add_foo"; exit 1; }
	@f=internal/db/migrations/$$(date -u +%Y%m%d%H%M%S)_$(name).sql; \
	  printf -- '-- +goose Up\n\n-- +goose Down\n' > $$f; echo "created $$f"

## test-integration: DB/Dojo tests; needs `make infra-up` and .env.local (scripts/wt-env.sh)
test-integration:
	set -a; [ -f .env.local ] && . ./.env.local; set +a; go test -count=1 -tags integration $(GO_PKGS)

## test-scale: 16k and 65k host fake-scanner load test; needs `make infra-up` and .env.local (scripts/wt-env.sh)
test-scale:
	set -a; [ -f .env.local ] && . ./.env.local; set +a; go test -v -count=1 -timeout 30m -tags scaletest ./internal/scaletest

## cve-db: regenerate internal/cve/data/cve.json.gz from NVD (products.txt), CISA KEV and EPSS.
## Dev machine only (≈15 min without NVD_API_KEY); commit the output. Build and runtime never download.
cve-db:
	go run ./internal/cve/gen

## Labs (docs/development/lab.md): one lab at a time, and one organizers' stack at a time.
##   LAB=ours (default): our fixtures, compose.lab.yml on the internal network raven_lab (172.30.0.0/24).
##   LAB=organizers STACK=quickstart|custom-network|modern|modern-proxy|vulnerable: the organizers'
##   files in lab/organizers, run as-is with their own commands (STACK=quickstart, the default, is
##   their ./quickstart.sh). RAVEN reaches them at 172.17.0.1: add that target, then run Default or Aggressive.
LAB ?= ours
STACK ?= quickstart
ORG_STACKS := quickstart custom-network modern modern-proxy vulnerable
ORG_UP_quickstart := bash quickstart.sh up
ORG_DOWN_quickstart := bash quickstart.sh down
ORG_UP_modern-proxy := cp -n .env.example .env && docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d
ORG_DOWN_modern-proxy := cp -n .env.example .env && docker compose --env-file .env -f docker-compose-modern-proxy.yml down
ORG_UP = $(or $(ORG_UP_$(STACK)),docker compose -f docker-compose-$(STACK).yml up -d)
ORG_DOWN = $(or $(ORG_DOWN_$(STACK)),docker compose -f docker-compose-$(STACK).yml down)

.PHONY: lab-check lab-change lab-verify

lab-check:
	@case "$(LAB)" in \
	  ours) ;; \
	  organizers) case " $(ORG_STACKS) " in *" $(STACK) "*) ;; \
	    *) echo "invalid STACK=$(STACK); use one of: $(ORG_STACKS)" >&2; exit 1;; esac;; \
	  *) echo "invalid LAB=$(LAB); use LAB=ours or LAB=organizers" >&2; exit 1;; \
	esac

## lab-up [LAB=ours|organizers] [STACK=…]: start a lab
lab-up: lab-check
ifeq ($(LAB),organizers)
	@$(MAKE) --no-print-directory lab-verify
	cd lab/organizers && $(ORG_UP)
	@gw=$$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'); \
	  echo "Docker host bridge address (docker0 gateway): $$gw"; \
	  if [ "$$gw" != 172.17.0.1 ]; then \
	    echo "WARNING: the gateway is $$gw, not 172.17.0.1; add target $$gw instead of 172.17.0.1" >&2; \
	  fi; \
	  echo "Next: in RAVEN, add target $$gw in Targets, then start a run of the profile \"Default\" (or \"Aggressive\")"
else
	docker compose -f compose.lab.yml up -d --build --wait
endif

## lab-down [LAB=ours|organizers] [STACK=…]: stop a lab
lab-down: lab-check
ifeq ($(LAB),organizers)
	cd lab/organizers && $(ORG_DOWN)
else
	docker compose -f compose.lab.yml down
endif

## lab-change: the organizers' quickstart step 3 (= ./quickstart.sh change, stops the service on 8787)
lab-change:
	cd lab/organizers && bash quickstart.sh change

## lab-verify: check that lab/organizers still holds the organizers' files byte for byte (SHA256SUMS)
lab-verify:
	cd lab/organizers && sha256sum -c --quiet SHA256SUMS
	@echo "lab/organizers: verbatim (SHA256SUMS OK)"
