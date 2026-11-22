# AGENTS.md — RAVEN (Recon of Assets, Versions, Exposures & Networks)

Hackathon prototype for AGH CBI: a web app that runs safe, recurring discovery scans of large networks (nmap + nuclei), fingerprints services and web technologies, tracks changes between runs, and uses **DefectDojo 3.5 (API v2)** as its dedup and finding-lifecycle engine. Go backend, React SPA, Postgres 18.

Read before working:
- [`docs/architecture.md`](docs/architecture.md): decisions D1–D10, data flow, Dojo mapping, schema, RBAC, safety rules.
- [`docs/roadmap.md`](docs/roadmap.md): tasks, dependencies, status.
- [`docs/challenge.md`](docs/challenge.md): the brief (Polish) and the organizers' notes.
- [`docs/design/`](docs/design/README.md): **UI design reference.** Tokens, layout rules, one `.dc.html` mockup per screen, AGH logo and squares assets. Any UI task starts here.
- DefectDojo source is checked out at `../django-DefectDojo` (parsers: `dojo/tools/<name>/parser.py`, API: `dojo/*/api/`). Read it instead of guessing API behaviour.

## Ground rules

- **Hackathon: choose the simplest thing that works.** No compat layers, no speculative config, no new infra. Decisions in architecture §1 are settled; don't re-open them in code.
- **Newest DefectDojo only** (3.5.x, API v2, Locations, Asset naming).
- **Safety is a scored criterion. Never break it** (full rules: [architecture §9](docs/architecture.md#9-safety-scored-criterion-non-negotiable)):
  - **Always (every workflow):** scan only the profile's in-scope targets with the global blacklist applied. Scan targets (dev machines): only (1) our lab (`make lab-up`, raven_lab 172.30.0.0/24), (2) the organizers' stacks from lab/organizers/, reached at the Docker host's bridge address (172.17.0.1) as target 172.17.0.1 with the Default (or Aggressive) profile, or (3) the organizers' lab at the event. Never the internet, other hosts on the LAN, the host's LAN address, or AGH ranges. Scanner flags come only from the allowlists in `internal/scanner/*`. Rate limit and time cap on every tool; no login attempts or credential brute-forcing, no DoS, no interactsh/OAST, no external APIs.
  - **Organizers' files are verbatim.** Never edit anything in lab/organizers/ (`make lab-verify` checks SHA256SUMS). Adapt RAVEN around them (ports, profiles, networks), never the other way round.
  - **Default workflow** (nmap → httpx → nuclei): no intrusive scripts or templates, GET-only probes, signatures from the safe-subset validator.
  - **Aggressive stages** (active nuclei, nikto, wpscan, ZAP) only in profiles using the **Aggressive preset**: explicit opt-in, admin-only (`scan:aggressive`), never the default, still under the "Always" rules.
- **No secrets in git.** Use `.env.local`, which is gitignored; keep `.env.example` up to date when you add a variable.

## Workflow (Orca coordinator + workers, no human review)

Repo: https://github.com/WH-HN2026/raven. One roadmap task = one worktree = one branch = one PR. There are no human reviews. Rules (by convention: the org is on GitHub Free, so branch protection isn't available on this private repo):
- the CI check `check` (`.github/workflows/check.yml`, which runs `make check`) must be green before merging;
- squash merge only, and the remote branch is deleted automatically after merge (both are repo settings);
- **never push to `main` directly.**

Each person runs one **coordinator** agent. The coordinator doesn't write feature code itself: it dispatches **workers** through Orca orchestration, each in its own child worktree, then **verifies** each worker's PR and merges it. Working solo without a coordinator is also allowed; then follow the worker steps and merge yourself after the verification checklist.

Orca CLI: use `$ORCA_CLI_COMMAND` if it is set, otherwise `orca` inside Orca terminals. Never run bare `orca` outside Orca on Linux (that's the GNOME screen reader). Load the version-matched guide **once per session** before the first orchestration command: `orca skills get orchestration`. The flags below come from it; if they disagree, the guide wins.

### Coordinator (the main agent, in the main checkout on `main`)

The coordinator's checkout stays on `main` and only runs `git pull`. It never edits code; every change, docs included, goes through a worker PR.

1. **Turn the request into tasks.** If the user names a roadmap ID, use it. Otherwise find the matching roadmap task, or add a new roadmap line in the worker's spec. Before dispatching, check `gh pr list --state open`: an open PR titled `<ID>: …` means someone else has the task.
2. **Write a self-contained spec** (template below) and start the worker in a new child worktree:
   ```
   orca orchestration worker-start --worktree new-child --name t-<id>-<slug> --agent <agent> --spec "<spec>"
   ```
   `<agent>` = the agent you run as, unless the user names another. Up to ~4 workers at once, only for tasks whose dependencies are `[x]` and that don't touch the same files. Start parallel workers from one shell command (see the guide's `references/parallel-start.md`). Then **end your turn**: Orca wakes you when a worker asks something or reports. Don't poll and don't type into worker terminals.
3. **Answer questions** with `orchestration reply` when the spec or this file answers them; otherwise ask the user.
4. **Verify** each `worker_done` against the checklist below. If anything fails, send a concrete list of fixes to the same worker (`orca orchestration send --to dispatch:<id> --subject "fixes" --body "…"`) and end your turn. Repeat until it passes.
5. **Merge:** `gh pr merge <n> --squash`, then `git pull` on `main`. If the merge conflicts because `main` moved, send the worker "rebase on origin/main, re-run make check, push" and verify again (CI green + a quick diff look).
6. **Clean up:** after the merge, remove the worker's worktree with the Orca CLI (`orca worktree --help`). Report to the user per task: PR link, what was verified and how, follow-ups.

**Verification checklist** (the coordinator does all of it; CI only covers the first item):
- [ ] `gh pr checks <n>` is green, and the PR is ready (not draft) and rebased on current `main`.
- [ ] `gh pr diff <n>` does what the spec asked, and nothing outside its scope. No unrelated refactors, no hand-edited generated files, no edits to merged migrations, no secrets or `.env*` files.
- [ ] AGENTS.md rules are followed:
  - every new route has `auth.Require`, and mutations write `audit_log`;
  - sensitive fields use `_enc`;
  - scanner flags come from the allowlists;
  - aggressive stages stay gated (`scan:aggressive`, start confirmation, badge, `audit_log`; never default), see architecture §9;
  - scans only write scan-owned columns;
  - deploy files (`compose.yml`, `deploy/Dockerfile`, `.env.example`) are updated if the task needs it;
  - the task is marked `[x]` in the roadmap.
- [ ] The worker's evidence is real and matches the claims: test names and output, the URL and pages it checked in the browser, scan output.
- [ ] **One hands-on check by the coordinator itself**, picked to hit the riskiest claim:
  - backend: run the most relevant test package in the worker's worktree (`go test ./internal/<pkg>/...`);
  - UI: open the worker's URL in the Orca browser and click through the changed pages as `admin` and `viewer`;
  - scanning/Dojo: run one lab scan or the integration test and look at the result in our DB or Dojo.

**Worker spec template** (paste it, fill it in; a worker can't see your conversation):
```
Task <ID>: <task name>  — repo raven, read AGENTS.md and docs/architecture.md first.
Goal: <the roadmap text for the task, plus anything the user added>.
In scope: <packages/dirs the worker may edit>. Out of scope: <what not to touch>.
Contract: <API paths / tables / interfaces it must provide or use>.
Done when: <concrete, checkable evidence, e.g. "go test ./internal/scanner/nmap passes with fixtures
from testdata/; /api/targets accepts the CSV in testdata and returns 4 entries; page /targets shows them">.
Follow the worker steps in AGENTS.md; stop after the PR is ready with green CI. Do NOT merge.
Report with worker_done: PR URL, summary, evidence (commands + results), known gaps.
```

### Worker (dispatched by a coordinator, or a solo session)

1. **Branch:** you start in a fresh child worktree. Rename the branch to `t/<id>-<slug>` (`git branch -m t/<id>-<slug>`), and make sure it's based on current `origin/main` (`git fetch origin && git rebase origin/main`).
2. **Claim it with a draft PR right away.** Don't edit the roadmap for the claim; the draft PR *is* the claim.
   `git commit --allow-empty -m "<ID>: start" && git push -u origin HEAD && gh pr create --draft --title "<ID>: <task name>" --body "Roadmap task <ID>."`
   If another open PR for the same ID already exists, stop and tell your coordinator (`ask`), or the user if you're solo.
3. **Set up the env:** `scripts/wt-env.sh`. It writes `.env.local` with a per-worktree database (`raven_<slug>`) and free ports for the Go server and Vite, then prints the URLs. Put those URLs in your report.
4. **Work in small commits:** `<ID>: <what>` (e.g. `S2: parse nmap service versions`). Push often. Stay inside the spec's scope; if the task needs more, `ask` before widening it.
5. **Verify your own work** as described in "Verify your change" below, and save the evidence (commands, output, pages visited).
6. **Finish:**
   ```bash
   # mark the task [x] in docs/roadmap.md, commit
   git fetch origin && git rebase origin/main   # resolve conflicts (table below)
   make check                                   # must pass locally
   git push --force-with-lease
   gh pr ready
   gh pr checks --watch --fail-fast             # must end green; if red, fix and push again
   ```
   Fill in the PR body: what changed, how it was verified, known gaps.
   - **Dispatched worker:** report with `worker_done` (PR URL + evidence) and **don't merge**; the coordinator verifies and merges. If you get fixes via `send`, apply them on the same branch, repeat step 6, and report again.
   - **Solo:** go through the verification checklist above yourself, then `gh pr merge --squash`.
7. If a task grows too big, finish a mergeable part (behind a disabled button or an unused code path if needed) and propose a new roadmap line for the rest in your report. **Something should merge at least once per day.**

### Avoiding / resolving conflicts

| Hotspot | Rule |
|---|---|
| DB migrations | Create them only with `make db-new name=<x>`, which gives a timestamped filename. **Never edit a migration that is on `main`**; add a new one. |
| `api/openapi.yaml` | Add paths and schemas inside your area's section (they're grouped by tag). On conflict keep both sides, then run `make gen`. |
| Generated code (`internal/db/gen`, `web/src/api/schema.d.ts`) | Never hand-edit. On conflict take either side, then run `make gen`. |
| `internal/httpapi/router.go`, `web/src/routes.tsx` | One line per area. Your code lives in your own files. |
| `docs/roadmap.md` | Only flip your task to `[x]` (in the finishing commit), and add new tasks at the end of a track. Adjacent-line conflicts here are expected: keep both sides. |
| Shared deps (`go.mod`, `web/package.json`) | On conflict keep both, then run `go mod tidy` / `npm install`. |

### Parallel worktrees, shared infra

- Start the infra **once** from any checkout: `make infra-up`. It runs the root `compose.yml` without the `raven` service, giving Postgres on 5433 and DefectDojo on http://localhost:18080 (admin credentials in `.env`).
- Every worktree uses its **own database** on the shared Postgres (created by `scripts/wt-env.sh`, migrated on startup) and its own ports. Don't hardcode ports.
- DefectDojo is **shared**: don't assume it's empty, and don't delete other people's data. Integration tests create uniquely named objects (e.g. with the branch slug as a tag).
- The labs (one at a time): ours with `make lab-up`; the organizers' with `make lab-up LAB=organizers STACK=…` (architecture §10, "Lab scenarios").

## Commands

```bash
make dev          # Go server (with reload) + Vite dev server, using .env.local
make check        # gofmt, go vet, go test ./..., web: tsc --noEmit, eslint, vitest, build
make gen          # sqlc + openapi-typescript
make build        # web build → embedded into bin/raven
make db-new name=add_foo        # new timestamped goose migration
make test-integration           # go test -tags integration ./... (needs infra-up)
make infra-up / infra-down
make lab-up / lab-down                      # our lab (LAB=ours, compose.lab.yml)
make lab-up LAB=organizers STACK=quickstart # organizers' stack, verbatim; STACK=quickstart|custom-network|modern|modern-proxy|vulnerable
make lab-down LAB=organizers STACK=…        # stop that stack
make lab-change                             # their ./quickstart.sh change
make lab-verify                             # lab/organizers/ matches SHA256SUMS
scripts/gen-env.sh && docker compose up -d --build   # full deployment, what the jury runs
```

**Deployment is Docker Compose** (architecture §10). It must work from a clean clone with only `scripts/gen-env.sh` and `docker compose up -d --build`. If your change needs a new env var, a new service, a volume or a binary in the image, update `compose.yml`, `deploy/Dockerfile` and `.env.example` in the same branch, and run the full compose up once before merging.

## Verify your change

- **Go:** table-driven unit tests next to the code. Parser tests use real tool output saved in `testdata/`. Test Dojo interactions with `-tags integration` against the shared Dojo.
- **UI:** open the worktree's Vite URL in the **Orca browser** and click through the changed pages. Check with at least an `admin` and a `viewer` user: viewers must not see mutation controls, and the API must reject their requests with 403. Check the browser console for errors.
- **Scanning:** run a real scan against the lab only, then check our DB and the Dojo UI/API for the expected Assets and findings.
- **Done** = `make check` passes, the behaviour has been seen working (test, browser or real scan), the PR is squash-merged into `main` with green CI, and the task is marked `[x]`.

## Code conventions

**Go** (module root = repo root, Go ≥ 1.25)
- Libraries: chi (HTTP), pgx/v5 + sqlc (DB), goose (migrations), River (jobs), `log/slog`, the standard library for everything else. Ask before adding another dependency, or just don't.
- Package per domain in `internal/` (see architecture §7). HTTP handlers stay thin, in `internal/httpapi/<area>.go`: parse → call the domain package → write JSON. The MCP server (last task) calls the same domain functions, so put no business logic in handlers.
- Every handler declares its permission with `auth.Require(auth.Perm…)`. Every mutation writes `audit_log`.
- Pass `context.Context` everywhere; scanner processes are started with `exec.CommandContext`, so cancelling ctx kills them (time windows depend on this).
- Wrap errors: `fmt.Errorf("dojo reimport %s: %w", ip, err)`. No panics outside `main`.
- Sensitive fields: `_enc bytea` columns written with `raven_enc(@x)` and read with `raven_dec(col)` (see architecture §5). Never log their plaintext.
- Scans write only scan-owned columns. User-owned columns and `overrides` are written only by user edits.

**Web** (`web/`)
- React + TS strict, TanStack Query for server state, React Router, Tailwind.
- Follow [`docs/design/README.md`](docs/design/README.md) and the matching `docs/design/canvas/<Screen>.dc.html` mockup: square corners, AGH black/red, Roboto, the shared page frame.
- Use colours only through the theme tokens in `web/src/theme.css` (copied from `docs/design/README.md`). No raw hex in components.
- API types come only from the generated `web/src/api/schema.d.ts`, via the small client in `web/src/api/client.ts`.
- Pages live in `web/src/pages/<area>/` and export their routes. Use `useCan(perm)` to hide controls the role can't use.
- UI language: English.
- **UI copy is data, labels and actions only.** No sentences explaining how the system works (encryption, write-back to Dojo, re-probing, scheduling rules); those belong in `docs/`.

## Don'ts

- Don't call Dojo from request handlers to render pages; read the mirror tables (`dojo_*`). Writes (triage edits) go to Dojo and then update the mirror.
- Don't reimport a host that didn't respond in this run, because `close_old_findings` would close everything on it (see architecture §3.8).
- Don't reimport a tool's Test for a stage that didn't run in this run, for the same reason (see architecture §3.11).
- Don't make a new profile, or the seeded Default profile, aggressive; the seeded **Aggressive** profile is the only aggressive seed. Don't let a non-admin save or change an aggressive profile.
- Don't add Dojo version checks, fallbacks for v1/old Endpoints, or alternative storage backends.
- Don't modify `../django-DefectDojo`. It's reference material, not part of this repo.
