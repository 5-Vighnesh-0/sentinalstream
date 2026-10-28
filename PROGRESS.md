# Progress

Current phase: **Phase 0 — awaiting `documentation approved`**

## Environment (recorded 2026-10-28)

| Tool | Version |
|---|---|
| OS | Linux 7.0.0-38-generic |
| Python | 3.14.4 (project requires 3.11+; Docker image will use 3.12-slim) |
| Node | v26.11.1 |
| Docker | 29.1.3 |
| git | 2.53.0 |

## Available skills and plugins

Checked at the start of Phase 0. Skill used per area:

| Area | Matching skills found | Use |
|---|---|---|
| Documentation | `engineering:documentation`, `agent-skills:documentation-and-adrs` | `engineering:documentation` used for Phase 0 |
| FastAPI | `fastapi`, `fastapi-templates` | Phase 3 |
| React / Vite | `vite`, `frontend-design`, `agent-skills:frontend-ui-engineering` | Phase 4 |
| Charts | `dataviz` | Phase 4 (TrafficChart, AttackDistribution) |
| Docker | `multi-stage-dockerfile` | Phase 7 |
| Testing | `python-testing-patterns`, `vitest`, `webapp-testing`, `superpowers:test-driven-development` | Phases 1–7 |
| CI | `agent-skills:ci-cd-and-automation` | Phase 7 |
| Security | `security-and-hardening` | Phase 3 (upload route), Phase 6 (simulator target check) |

Plugins: the GitHub MCP connector (`plugin:engineering:github`) is installed but not authorised in this session; `gh` CLI is logged in and can be used instead. No packet-capture or ML-specific skill exists, so Scapy and scikit-learn work is done manually.

## Decisions made with the human (Phase 0)

| Question | Answer |
|---|---|
| Git | Use the existing GitHub repo `sentinelstream`. Local repo initialised on `main`; remote not added yet (see open questions). |
| Phase 1 benign training data | CICIDS2017 MachineLearningCSV.zip (~225 MB) — ask before downloading in Phase 1, with exact size. Sample PCAP is synthetic (Scapy). |
| Extra dependencies | Approved: python-multipart, httpx, uvicorn[standard], ruff, @testing-library/react, jsdom. |
| Alerts ↔ flows link | Add nullable `alerts.flow_id` → `flows.id`. |

## Open questions

1. GitHub remote URL: `gh repo view sentinelstream` under account `5-Vighnesh-0` found no repo by that name. Need the exact `owner/name` or URL before the first push.

---

## Phase 0 — Docs and scaffolding

Plan: [plans/phase-0-PLAN.md](plans/phase-0-PLAN.md)

### Tasks completed

- [x] Skills/plugins recorded (above)
- [x] `git init -b main`, `.gitignore`, empty dirs with `.gitkeep`
- [x] README.md
- [x] docs/PRD.md, docs/ARCHITECTURE.md, docs/DATA_MODEL.md, docs/API_SPEC.md
- [x] docs/PHASES.md, docs/EVALUATION.md, docs/LIMITATIONS.md
- [x] AGENTS.md, PROGRESS.md
- [x] Consistency check and no-logic-code check (evidence below)

### Blockers

None.

### Evidence

```text
$ find . -path ./.git -prune -o -type f \( -name "*.py" -o -name "*.ts" -o -name "*.tsx" \) -print
(no output = no logic code)

$ find . -path ./.git -prune -o -print | sort
.
./AGENTS.md
./backend
./backend/.gitkeep
./data
./data/.gitkeep
./docs
./docs/API_SPEC.md
./docs/ARCHITECTURE.md
./docs/DATA_MODEL.md
./docs/EVALUATION.md
./docs/LIMITATIONS.md
./docs/PHASES.md
./docs/PRD.md
./frontend
./frontend/.gitkeep
./.gitignore
./ml
./ml/.gitkeep
./models
./models/.gitkeep
./plans
./plans/.gitkeep
./plans/phase-0-PLAN.md
./PROGRESS.md
./README.md
./simulator
./simulator/.gitkeep
./tests
./tests/.gitkeep

$ grep -c for shared contract terms per doc (feature_set.py / flow_id / 50 MB / 3000 / 8000)
README.md              feature_set=0 flow_id=0 50MB=0 port3000=1 port8000=0
AGENTS.md              feature_set=1 flow_id=0 50MB=1 port3000=1 port8000=1
docs/API_SPEC.md       feature_set=0 flow_id=1 50MB=1 port3000=1 port8000=1
docs/ARCHITECTURE.md   feature_set=1 flow_id=0 50MB=1 port3000=5 port8000=3
docs/DATA_MODEL.md     feature_set=3 flow_id=1 50MB=0 port3000=0 port8000=0
docs/EVALUATION.md     feature_set=0 flow_id=0 50MB=0 port3000=0 port8000=0
docs/LIMITATIONS.md    feature_set=0 flow_id=0 50MB=0 port3000=0 port8000=1
docs/PHASES.md         feature_set=1 flow_id=0 50MB=0 port3000=1 port8000=0
docs/PRD.md            feature_set=0 flow_id=0 50MB=0 port3000=1 port8000=1

$ grep -rhoE "SENTINEL_[A-Z_]+" --include=*.md . | sort | uniq -c
      3 SENTINEL_DB_PATH
      4 SENTINEL_IFACE
      2 SENTINEL_MODEL_PATH

$ grep -rn "critical" docs AGENTS.md README.md   # severity enum is low|medium|high only
docs/API_SPEC.md:66:**422** invalid parameter (e.g. `severity=critical`, `limit=0`).
```

The only `critical` hit is the API_SPEC example of an *invalid* severity value, as intended.
