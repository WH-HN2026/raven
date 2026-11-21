# AGENTS.md — ASI (Attack Surface Intelligence)

Hackathon prototype for AGH CBI: a web app that runs safe, recurring discovery scans of large networks (nmap + nuclei), fingerprints services and web technologies, tracks changes between runs, and uses **DefectDojo 3.5 (API v2)** as its dedup and finding-lifecycle engine. Go backend, React SPA, Postgres 18.

Read before working:
- [`docs/architecture.md`](docs/architecture.md): decisions D1–D10, data flow, Dojo mapping, schema, RBAC, safety rules.
- [`docs/roadmap.md`](docs/roadmap.md): tasks, dependencies, status.
- [`docs/challenge.md`](docs/challenge.md): the brief (Polish) and the organizers' notes.
- DefectDojo source is checked out at `../django-DefectDojo` (parsers: `dojo/tools/<name>/parser.py`, API: `dojo/*/api/`). Read it instead of guessing API behaviour.

## Ground rules

- **Hackathon: choose the simplest thing that works.** No compat layers, no speculative config, no new infra. Decisions in architecture §1 are settled; don't re-open them in code.
- **Newest DefectDojo only** (3.5.x, API v2, Locations, Asset naming).
- **Safety is a scored criterion. Never break it:**
  - Scan **only** the local lab network (`compose.lab.yml`) or the organizers' lab. Never scan the internet, the host network, or AGH ranges from a dev machine.
  - nmap and nuclei flags come only from the allowlists in `internal/scanner/*`. No intrusive scripts or templates, no login attempts, rate limits always set.
- **No secrets in git.** Use `.env.local`, which is gitignored; keep `.env.example` up to date when you add a variable.

## Workflow (Orca worktrees, no human review)

Repo: https://github.com/WH-HN2026/zadanie-agh-asi. One roadmap task = one worktree = one branch = one PR, and **you merge your own PR**; there are no human reviews. Rules (by convention: the org is on GitHub Free, so branch protection isn't available on this private repo):
- the CI check `check` (`.github/workflows/check.yml`, which runs `make check`) must be green before merging; the merge command below waits for it;
- squash merge only (repo setting), and the remote branch is deleted automatically after merge (repo setting);
- **never push to `main` directly.**

1. **Pick a task** in `docs/roadmap.md` whose dependencies are `[x]`. Run `gh pr list --state open` first; an open PR titled `<ID>: …` means the task is taken.
2. **Create the worktree** from up-to-date `origin/main`. Branch name: `t/<id>-<slug>`, e.g. `t/s2-nmap`.
3. **Claim it immediately** with a draft PR: make an empty commit, push, open the PR. Don't edit the roadmap for the claim; the draft PR *is* the claim.
   `git commit --allow-empty -m "<ID>: start" && git push -u origin HEAD && gh pr create --draft --title "<ID>: <task name>" --body "Roadmap task <ID>."`
   If someone else's PR for the same ID appeared in the meantime, close yours and pick another task.
4. **Set up the env:** `scripts/wt-env.sh`. It writes `.env.local` with a per-worktree database (`asi_<slug>`) and free ports for the Go server and Vite, then prints the URLs.
5. **Work in small commits:** `<ID>: <what>` (e.g. `S2: parse nmap service versions`). Push often.
6. **Finish:**
   ```bash
   # mark the task [x] in docs/roadmap.md, commit
   git fetch origin && git rebase origin/main   # resolve conflicts (table below)
   make check                                   # must pass locally too
   git push --force-with-lease
   gh pr ready
   gh pr checks --watch --fail-fast && gh pr merge --squash   # remote branch auto-deleted by repo setting
   ```
   Fill in the PR body: what changed, how it was verified (test / browser / real scan), and any follow-ups. `gh pr checks --watch` exits non-zero if CI fails, so the merge only runs on green. **If CI fails, fix it on the same branch and run the last line again**; never merge red, and never leave a PR red and walk away. If `gh pr merge` reports a conflict because `main` moved, rebase again and repeat.
7. If a task grows too big, merge what works (behind a disabled button or an unused code path if needed) and add a new roadmap line for the rest. **Merge at least once per day.**
8. After the merge, remove the worktree and its local branch (`git worktree remove …`, `git branch -D t/…`). The next task starts from a fresh `origin/main`.

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

- Start the infra **once** from any checkout: `make infra-up`. It runs the root `compose.yml` without the `asi` service, giving Postgres on 5433 and DefectDojo on http://localhost:8080 (admin credentials in `.env`).
- Every worktree uses its **own database** on the shared Postgres (created by `scripts/wt-env.sh`, migrated on startup) and its own ports. Don't hardcode ports.
- DefectDojo is **shared**: don't assume it's empty, and don't delete other people's data. Integration tests create uniquely named objects (e.g. with the branch slug as a tag).
- The lab: `make lab-up` (after task L1).

## Commands

```bash
make dev          # Go server (with reload) + Vite dev server, using .env.local
make check        # gofmt, go vet, go test ./..., web: tsc --noEmit, eslint, vitest, build
make gen          # sqlc + openapi-typescript
make build        # web build → embedded into bin/asi
make db-new name=add_foo        # new timestamped goose migration
make test-integration           # go test -tags integration ./... (needs infra-up)
make infra-up / infra-down / lab-up / lab-down
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
- Sensitive fields: `_enc bytea` columns written with `asi_enc(@x)` and read with `asi_dec(col)` (see architecture §5). Never log their plaintext.
- Scans write only scan-owned columns. User-owned columns and `overrides` are written only by user edits.

**Web** (`web/`)
- React + TS strict, TanStack Query for server state, React Router, Tailwind.
- Use colours only through the theme tokens in `web/src/theme.css` (AGH palette). No raw hex in components.
- API types come only from the generated `web/src/api/schema.d.ts`, via the small client in `web/src/api/client.ts`.
- Pages live in `web/src/pages/<area>/` and export their routes. Use `useCan(perm)` to hide controls the role can't use.
- UI language: English.

## Don'ts

- Don't call Dojo from request handlers to render pages; read the mirror tables (`dojo_*`). Writes (triage edits) go to Dojo and then update the mirror.
- Don't reimport a host that didn't respond in this run, because `close_old_findings` would close everything on it (see architecture §3.7).
- Don't add Dojo version checks, fallbacks for v1/old Endpoints, or alternative storage backends.
- Don't modify `../django-DefectDojo`. It's reference material, not part of this repo.
