# RAVEN developer commands. See AGENTS.md "Commands".
SHELL := /bin/bash
NPM ?= npm
SQLC := go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
# web/node_modules can contain Go packages, so never use ./... here.
GO_PKGS := ./cmd/... ./internal/... ./web
INFRA_SERVICES := raven-db nginx uwsgi celeryworker celerybeat initializer postgres valkey

.PHONY: dev check check-go check-web gen build infra-up infra-down db-new test-integration test-scale lab-up lab-down cve-db

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

## infra-up: shared Postgres (5433) + DefectDojo (8080), everything except raven
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

lab-up:
	docker compose -f compose.lab.yml up -d --build --wait

lab-down:
	docker compose -f compose.lab.yml down

## vuln lab (docs/vuln-lab.md): organizers' stacks on the internal raven_vlab network, 10.77.0.0/16
VLAB := docker compose -f compose.vlab.yml
.PHONY: vlab-pull vlab-up vlab-down vlab-ps

## vlab-pull: pull the vuln lab images that are missing, retrying on Docker Hub rate limits (docker login helps)
vlab-pull:
	@for i in 1 2 3 4 5 6; do \
	  missing=$$($(VLAB) --profile scenario --profile init config --images | sort -u | while read -r img; do \
	    docker image inspect "$$img" >/dev/null 2>&1 || echo "$$img"; done); \
	  [ -z "$$missing" ] && { echo "vlab-pull: all images present"; exit 0; }; \
	  for img in $$missing; do docker pull -q "$$img" || true; done; \
	  [ $$i -lt 6 ] && { echo "vlab-pull: attempt $$i incomplete, retrying in 120 s (docker login raises the Docker Hub pull limit)"; sleep 120; }; \
	done; echo "vlab-pull: images still missing" >&2; exit 1

## vlab-up: start the vuln lab, wait for health, install the WordPress sites and the Toxiproxy proxy
vlab-up:
	lab/vuln/preflight.sh
	$(VLAB) up -d --wait
	$(VLAB) run --rm vlab-init

## vlab-down: detach other containers (e.g. RAVEN) from raven_vlab, then stop the lab; volumes are kept
vlab-down:
	@for c in $$(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' raven_vlab 2>/dev/null); do \
	  case $$c in raven-vlab-*) ;; *) echo "disconnect $$c"; docker network disconnect -f raven_vlab $$c;; esac; \
	done
	$(VLAB) --profile scenario --profile tools --profile init down

vlab-ps:
	$(VLAB) --profile scenario --profile tools ps

## one-command demo (docs/vuln-lab.md §6): RAVEN + DefectDojo + vuln lab, seeded; ARGS="--scale[=N] --l1 --no-run"
.PHONY: demo demo-down demo-reset
demo:
	scripts/demo.sh up $(ARGS)

## demo-down: stop RAVEN, DefectDojo and the labs; data kept
demo-down:
	scripts/demo.sh down

## demo-reset: delete RAVEN/Dojo/lab volumes and .demo-credentials, keep .env (asks first; CONFIRM=1 skips)
demo-reset:
	CONFIRM=$(CONFIRM) scripts/demo.sh reset

## vuln lab scale layer (docs/vuln-lab.md §5): N hosts in 10.77.64.0/18, e.g. make vlab-scale-up N=1024
.PHONY: vlab-scale-up vlab-scale-down
vlab-scale-up:
	scripts/vlab-scale.sh up $(N)

## vlab-scale-down: remove the scale layer (run it before vlab-down)
vlab-scale-down:
	scripts/vlab-scale.sh down
