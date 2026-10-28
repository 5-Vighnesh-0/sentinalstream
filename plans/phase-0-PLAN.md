# Phase 0 Plan — Docs and scaffolding

## Tasks

1. Record available skills/plugins in PROGRESS.md.
2. `git init` (branch `main`), `.gitignore`, empty directories with `.gitkeep`.
3. Write README.md (overview, architecture placeholder, quick-start placeholder, Results placeholder).
4. Write docs/PRD.md, docs/ARCHITECTURE.md, docs/DATA_MODEL.md, docs/API_SPEC.md.
5. Write docs/PHASES.md, docs/EVALUATION.md, docs/LIMITATIONS.md.
6. Write AGENTS.md and PROGRESS.md.
7. Cross-check names, ports, env vars, paths, tables and message schemas across all docs.
8. Confirm no `.py`, `.ts`, `.tsx` files exist.

## Files

| Action | Path |
|---|---|
| create | README.md, AGENTS.md, PROGRESS.md, .gitignore |
| create | docs/PRD.md, docs/ARCHITECTURE.md, docs/DATA_MODEL.md, docs/API_SPEC.md, docs/PHASES.md, docs/EVALUATION.md, docs/LIMITATIONS.md |
| create | plans/phase-0-PLAN.md (this file) |
| create (empty) | backend/, frontend/, ml/, simulator/, data/, tests/, models/, plans/ (each with `.gitkeep`) |

## Acceptance gate (from docs/PHASES.md)

> All files exist and are consistent with each other, no logic code exists. Present the file tree plus a one-paragraph summary, then wait for "documentation approved".

## Checks

```bash
find . -path ./.git -prune -o -type f \( -name '*.py' -o -name '*.ts' -o -name '*.tsx' \) -print   # expect no output
find . -path ./.git -prune -o -print | sort
```
