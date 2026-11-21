# ASI developer commands. See AGENTS.md "Commands".
SHELL := /bin/bash
NPM ?= npm
SQLC := go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
# web/node_modules can contain Go packages, so never use ./... here.
GO_PKGS := ./cmd/... ./internal/... ./web
INFRA_SERVICES := asi-db nginx uwsgi celeryworker celerybeat initializer postgres valkey

.PHONY: dev check check-go check-web gen build infra-up infra-down db-new test-integration lab-up lab-down

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

## build: web build embedded into bin/asi
build: web/node_modules
	cd web && $(NPM) run build
	CGO_ENABLED=0 go build -trimpath -o bin/asi ./cmd/asi

## infra-up: shared Postgres (5433) + DefectDojo (8080), everything except asi
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

lab-up:
	docker compose -f compose.lab.yml up -d

lab-down:
	docker compose -f compose.lab.yml down
