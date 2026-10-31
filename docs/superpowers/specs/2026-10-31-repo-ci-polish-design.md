# Sub-project 2: Repo + CI polish — design

Roadmap: [2026-10-29-security-hardening-design.md](2026-10-29-security-hardening-design.md), row 2. Approved by the human on 2026-10-31.

## Goal

`main` is protected by checks that prove the product works end to end and that its dependencies have no known fixable vulnerabilities; dependency updates arrive as tested PRs; the repo presents itself (description, topics, screenshot, security policy) and ships `v1.0.0`.

## Decisions (human-approved)

| Question | Decision |
|---|---|
| Scope | All four roadmap groups: supply-chain checks, end-to-end demo test, repo presentation, Trivy |
| Trivy noise | Fail only on HIGH/CRITICAL with a fix available (`ignore-unfixed`) |
| Python lock layout | Rename to pip-compile's convention so Dependabot regenerates the hashed lock |
| New CI tools | pip-audit (exact version) and `aquasecurity/trivy-action` (commit SHA) approved |
| Branch protection | PRs only, required checks green, branch up to date, no review requirement, admin override kept |
| Workflow shape | Extend the single `ci.yml`; add a weekly schedule so new CVEs surface without a code change |

## Part 1: code and CI (one PR)

1. **Dependencies.** `git mv requirements.txt requirements.in`, `git mv requirements.lock requirements.txt`; the lock header's command names the new files. `backend/Dockerfile` and `ci.yml` install `requirements.txt` with `--require-hashes`. `docs/DEMO.md`'s `pip install -r requirements.txt` stays valid (it now installs the hashed lock). Historical evidence files are not edited.
2. **`.github/dependabot.yml`.** Weekly; ecosystems `pip` (`/`), `npm` (`/frontend`), `github-actions` (`/`), `docker` (`/backend`, `/frontend`). Minor and patch updates grouped per ecosystem; majors as their own PRs.
3. **CI jobs** added to `ci.yml` (existing `python`, `frontend`, `docker` unchanged apart from the file rename):
   - `audit`: `pip-audit --strict --require-hashes -r requirements.txt`; `npm audit --audit-level=high` in `frontend/`.
   - `trivy`: build both images; scan each with severity `HIGH,CRITICAL`, `ignore-unfixed: true`, `exit-code: 1`.
   - `e2e`: run `scripts/e2e-demo.sh`.
   - Triggers: push to `main`, pull requests, weekly `schedule`. Permissions stay `contents: read`; every action pinned by SHA.
4. **`scripts/e2e-demo.sh`** (runnable locally): `docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d`; wait for backend health (timeout); read the token from the backend container's `/app/data/api-token` into a variable, never printed; run the simulator's port scan; poll `GET /alerts` with the token until an alert with `attack_type == "PortScan"` and `severity == "high"` appears (60 s timeout); assert `curl -sI http://localhost:3000/` has `Content-Security-Policy`; `trap` tears the stack down (`down -v`) on every exit. Exit non-zero with a one-line reason on any failure.
5. **`SECURITY.md`.** Private reporting through GitHub's private vulnerability reporting; supported version: latest 1.x; scope (local demo, dashboard token, PCAP upload, model loading); known accepted risks link to `docs/LIMITATIONS.md`.
6. **README screenshot.** `docs/images/dashboard.png`: a fresh 1440×900 capture of the live dashboard (loopback demo traffic only, no token visible), embedded under the README title with alt text.

## Part 2: after the PR merges (human-approved outward-facing actions, via `gh`)

1. Branch protection on `main`: required status checks `python`, `frontend`, `docker`, `audit`, `trivy`, `e2e`; strict (up to date); PR required, 0 approvals; `enforce_admins: false`.
2. Enable private vulnerability reporting.
3. Description: "Real-time network intrusion detection on one laptop CPU: Scapy capture, Random Forest + Isolation Forest + port-scan rule, FastAPI/WebSocket API and a React dashboard. Offline, no cloud." Topics: intrusion-detection, network-security, cybersecurity, machine-learning, scikit-learn, scapy, fastapi, react, websocket, cicids2017.
4. Tag `v1.0.0` on the resulting `main` commit and publish a GitHub release: what it is, how to run (link `docs/DEMO.md`), security hardening, known limits (link `docs/LIMITATIONS.md`), results by link to the README table only (no new numbers), no binary assets.

## Verification

- The PR's CI runs all six jobs green, including `e2e` on a GitHub runner.
- `scripts/e2e-demo.sh` passes locally; `pip-audit` and `npm audit` run locally with the same flags.
- If `audit` or `trivy` finds a real issue on first run: fix by upgrading the pin when a fixed version exists; otherwise stop and ask (no blanket ignores).
- After Part 2: `gh api .../branches/main/protection` shows the six checks; `gh repo view` shows description and topics; `gh release view v1.0.0` exists.
- Evidence appended to PROGRESS.md under "Post-v1 sub-project 2: repo + CI polish".

## Out of scope

Signed commits, CODEOWNERS, SBOM generation, release artifacts, coverage gates, Trivy filesystem/IaC scans.
