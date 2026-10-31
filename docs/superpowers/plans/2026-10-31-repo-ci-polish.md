# Repo + CI polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Protect `main` with checks that prove the product works and its dependencies are clean, automate dependency updates, present the repo, and ship `v1.0.0`.

**Architecture:** One `ci.yml` gains `audit`, `trivy` and `e2e` jobs plus a weekly schedule; `scripts/e2e-demo.sh` runs the Docker demo and asserts a High PortScan alert over the API; Dependabot updates pip (pip-compile layout), npm, actions and Docker digests. Repo settings and the release are applied with `gh` after merge.

**Tech Stack:** GitHub Actions, Dependabot, pip-audit 2.10.1, aquasecurity/trivy-action v0.36.0, Docker Compose, bash, gh.

Spec: [docs/superpowers/specs/2026-10-31-repo-ci-polish-design.md](../specs/2026-10-31-repo-ci-polish-design.md)

## Global Constraints

- Every action pinned by full commit SHA with a `# vX.Y.Z` comment; workflow `permissions: contents: read`; `persist-credentials: false` on checkout.
- pip-audit pinned `==2.10.1`; trivy-action `ed142fd0673e97e23eac54620cfb913e5ce36c25  # v0.36.0`.
- Trivy: `severity: HIGH,CRITICAL`, `ignore-unfixed: true`, `exit-code: "1"`.
- No blanket vulnerability ignores; a finding with no fixed version → stop and ask the human.
- The dashboard token is never printed (CI logs are public).
- Required check names: `python`, `frontend`, `docker`, `audit`, `trivy`, `e2e`.
- Historical evidence files (PROGRESS.md earlier sections, docs/PHASE1_RESULTS.md) are not edited.

---

### Task 1: Rename the Python requirements to pip-compile's layout

**Files:**
- Rename: `requirements.txt` → `requirements.in`; `requirements.lock` → `requirements.txt`
- Modify: `requirements.txt` header (the `pip-compile` command line), `backend/Dockerfile:11-12`, `.github/workflows/ci.yml:22`

- [ ] **Step 1: Rename with history**

```bash
git mv requirements.txt requirements.in
git mv requirements.lock requirements.txt
```

- [ ] **Step 2: Fix the lock header** so Dependabot and humans regenerate it correctly. In `requirements.txt` replace the command line with:

```
#    pip-compile --allow-unsafe --generate-hashes --output-file=requirements.txt --strip-extras requirements.in
```

- [ ] **Step 3: Point the Dockerfile and CI at the lock**

`backend/Dockerfile`:
```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
```
`.github/workflows/ci.yml` python job:
```yaml
      - run: pip install --require-hashes -r requirements.txt
```

- [ ] **Step 4: Verify** — `grep -rn "requirements.lock" --exclude-dir=.git . | grep -v "docs/superpowers\|PROGRESS.md"` prints nothing; `docker build -f backend/Dockerfile -t sentinelstream-backend .` succeeds.

- [ ] **Step 5: Commit** — `git commit -m "Rename Python requirements to pip-compile's .in/.txt layout"`

### Task 2: Dependabot

**Files:** Create `.github/dependabot.yml`

- [ ] **Step 1: Write the config**

```yaml
# Weekly dependency PRs; minor/patch grouped per ecosystem so a week brings a few PRs, not dozens.
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule: { interval: weekly }
    groups: { python-minor: { update-types: [minor, patch] } }
  - package-ecosystem: npm
    directory: "/frontend"
    schedule: { interval: weekly }
    groups: { npm-minor: { update-types: [minor, patch] } }
  - package-ecosystem: github-actions
    directory: "/"
    schedule: { interval: weekly }
    groups: { actions-minor: { update-types: [minor, patch] } }
  - package-ecosystem: docker
    directories: ["/backend", "/frontend"]
    schedule: { interval: weekly }
```

- [ ] **Step 2: Verify** — `.venv/bin/python -c "import yaml,sys; yaml.safe_load(open('.github/dependabot.yml'))"` (or `python3` with PyYAML); GitHub validates it on push (Insights → Dependency graph → Dependabot shows no config error).

- [ ] **Step 3: Commit** — `git commit -m "Dependabot: weekly pip, npm, actions and Docker digest updates"`

### Task 3: `audit` job

**Files:** Modify `.github/workflows/ci.yml`

- [ ] **Step 1: Run both audits locally first** (a failing audit must be fixed in this task, not discovered in CI):

```bash
python3 -m venv /tmp/pa && /tmp/pa/bin/pip install -q pip-audit==2.10.1
/tmp/pa/bin/pip-audit --strict --require-hashes -r requirements.txt
npm --prefix frontend audit --audit-level=high
```
Expected: `No known vulnerabilities found` and `found 0 vulnerabilities` (or none at high+). If a finding has a fixed version, bump it (npm: `npm --prefix frontend install <pkg>@<fixed>` and pin exact; pip: edit `requirements.in`, relock with pip-tools in a throwaway `python:3.12-slim` container as in PROGRESS.md Phase 7). If no fix exists: stop and ask.

- [ ] **Step 2: Add the job**

```yaml
  audit:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0
        with:
          python-version: "3.12"
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1  # v7.1.0
        with:
          node-version: "24"
      - run: pip install pip-audit==2.10.1
      - run: pip-audit --strict --require-hashes -r requirements.txt
      - run: npm audit --audit-level=high
        working-directory: frontend
```

- [ ] **Step 3: Commit** — `git commit -m "CI: pip-audit and npm audit"`

### Task 4: `trivy` job

**Files:** Modify `.github/workflows/ci.yml`

- [ ] **Step 1: Add the job**

```yaml
  trivy:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
      - run: docker build -f backend/Dockerfile -t sentinelstream-backend .
      - run: docker build -t sentinelstream-frontend frontend
      # Fail only on HIGH/CRITICAL that have a fix: unfixable upstream CVEs would turn CI red with nothing to do.
      - uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25  # v0.36.0
        with:
          image-ref: sentinelstream-backend
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"
      - uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25  # v0.36.0
        with:
          image-ref: sentinelstream-frontend
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"
          skip-setup-trivy: true
```

- [ ] **Step 2: Verify in CI** (Task 7). A finding with a fixed version is fixed by a base-image digest bump or package pin; otherwise stop and ask.

- [ ] **Step 3: Commit** — `git commit -m "CI: Trivy scan of both images (fixable HIGH/CRITICAL)"`

### Task 5: End-to-end demo script and `e2e` job

**Files:** Create `scripts/e2e-demo.sh` (executable); modify `.github/workflows/ci.yml`

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# End-to-end demo check: the Docker demo must turn a loopback port scan into a High PortScan alert over the API.
# Run from the repo root. Never prints the dashboard token (CI logs are public).
set -euo pipefail
compose=(docker compose -f docker-compose.yml -f docker-compose.demo.yml)
trap '"${compose[@]}" down -v >/dev/null 2>&1' EXIT
fail() { echo "e2e: FAIL: $*" >&2; "${compose[@]}" logs --tail 40 backend >&2 || true; exit 1; }

"${compose[@]}" up --build -d
for _ in $(seq 60); do curl -fs http://127.0.0.1:8000/health >/dev/null && break; sleep 2; done
curl -fs http://127.0.0.1:8000/health >/dev/null || fail "backend not healthy after 120 s"

token=$("${compose[@]}" exec -T backend cat /app/data/api-token)
[ -n "$token" ] || fail "no dashboard token"

# The demo's simulator service runs one port scan as soon as the backend is healthy.
for _ in $(seq 30); do
  if curl -fs -H "Authorization: Bearer $token" "http://127.0.0.1:8000/alerts?limit=200" \
    | python3 -c 'import json,sys; sys.exit(not any(a["attack_type"]=="PortScan" and a["severity"]=="high" for a in json.load(sys.stdin)["items"]))'; then
    found=1; break
  fi
  sleep 2
done
[ "${found:-}" = 1 ] || fail "no High PortScan alert within 60 s"

curl -fsI http://localhost:3000/ | grep -qi '^content-security-policy:' || fail "dashboard served without a CSP"
echo "e2e: PASS (High PortScan alert over the API; dashboard CSP present)"
```

- [ ] **Step 2: Run it locally and see it pass**: `chmod +x scripts/e2e-demo.sh && scripts/e2e-demo.sh` → last line `e2e: PASS …`. Then prove it can fail: temporarily change `"PortScan"` to `"NoSuchAttack"`, run → `e2e: FAIL: no High PortScan alert within 60 s`; revert.

- [ ] **Step 3: Add the job and the weekly schedule** (`on:` gains `schedule: [{ cron: "0 6 * * 1" }]`):

```yaml
  e2e:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
      - run: scripts/e2e-demo.sh
```

- [ ] **Step 4: Commit** — `git commit -m "CI: end-to-end Docker demo check and weekly run"`

### Task 6: SECURITY.md and README screenshot

**Files:** Create `SECURITY.md`, `docs/images/dashboard.png`; modify `README.md` (under the title)

- [ ] **Step 1: SECURITY.md**

```markdown
# Security policy

## Reporting a vulnerability

Please report privately through GitHub: **Security → Report a vulnerability** on this repository. Do not open a public issue. Expect an acknowledgement within a week.

## Supported versions

Only the latest 1.x release gets fixes.

## Scope

SentinelStream is a local tool: the backend binds 127.0.0.1 only and the dashboard is meant for one machine. In scope:

- the API and WebSocket (dashboard token, Host and Origin checks, CORS)
- PCAP upload parsing (size and type checks, the sandboxed parser)
- model loading (sha256 pins) and the least-privilege capture setup
- the Docker images and the dashboard's browser security headers

Known, accepted risks (single shared token, local-only design, detector blind spots) are listed in [docs/LIMITATIONS.md](docs/LIMITATIONS.md); reports about them are welcome but are not treated as vulnerabilities.
```

- [ ] **Step 2: Screenshot** — run the demo (`docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d`), wait for the PortScan alert, capture the dashboard's 1440×900 first viewport with headless Chrome (token seeded into localStorage, never shown) to `docs/images/dashboard.png`; check the image shows only loopback traffic and no token; keep it under 400 KB.

- [ ] **Step 3: README** — directly under the `# SentinelStream` paragraph:

```markdown
![SentinelStream dashboard: the "In effect now" strip shows one High alert, above a live feed of loopback alerts with per-detector evidence, a packets-per-second chart and attack-type counts](docs/images/dashboard.png)
```

- [ ] **Step 4: Commit** — `git commit -m "SECURITY.md and README screenshot"`

### Task 7: PR, green CI, merge

- [ ] **Step 1:** `npm --prefix frontend test`, `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check .` all pass locally.
- [ ] **Step 2:** Push `repo-ci-polish`, open the PR, bind it; all six jobs (`python`, `frontend`, `docker`, `audit`, `trivy`, `e2e`) green. Fix any red job per the Global Constraints.
- [ ] **Step 3:** Ask the human before merging; merge with a merge commit.

### Task 8: Repo settings, evidence, `v1.0.0`

- [ ] **Step 1: Branch protection** (human-approved):

```bash
gh api -X PUT repos/5-Vighnesh-0/sentinalstream/branches/main/protection --input - <<'EOF'
{"required_status_checks":{"strict":true,"checks":[{"context":"python"},{"context":"frontend"},{"context":"docker"},{"context":"audit"},{"context":"trivy"},{"context":"e2e"}]},
 "enforce_admins":false,
 "required_pull_request_reviews":{"required_approving_review_count":0},
 "restrictions":null}
EOF
```

- [ ] **Step 2: Private vulnerability reporting** — `gh api -X PUT repos/5-Vighnesh-0/sentinalstream/private-vulnerability-reporting`
- [ ] **Step 3: Description and topics**

```bash
gh repo edit 5-Vighnesh-0/sentinalstream \
  --description "Real-time network intrusion detection on one laptop CPU: Scapy capture, Random Forest + Isolation Forest + port-scan rule, FastAPI/WebSocket API and a React dashboard. Offline, no cloud." \
  --add-topic intrusion-detection,network-security,cybersecurity,machine-learning,scikit-learn,scapy,fastapi,react,websocket,cicids2017
```

- [ ] **Step 4: Evidence PR** — on a branch `progress-subproject-2`, append "## Post-v1 sub-project 2: repo + CI polish" to PROGRESS.md with: the six CI job results, local `e2e: PASS` output, audit outputs, and the `gh api` / `gh repo view` outputs proving Steps 1–3. Open a PR; it must wait for the six required checks (this proves protection works); merge.
- [ ] **Step 5: Release** — on the merged `main` commit:

```bash
git tag -a v1.0.0 -m "SentinelStream 1.0.0" && git push origin v1.0.0
gh release create v1.0.0 --title "SentinelStream 1.0.0" --notes-file <notes>
```
Notes: what it is (README first paragraph); run it (`docs/DEMO.md`); measured results: link to the README's results table (no numbers restated); security hardening summary (least-privilege capture, dashboard token, pinned models, CSP, CI scanning); known limits (`docs/LIMITATIONS.md`).
- [ ] **Step 6: Verify** — `gh api repos/5-Vighnesh-0/sentinalstream/branches/main/protection --jq '[.required_status_checks.checks[].context]'` lists the six; `gh repo view --json description,repositoryTopics`; `gh release view v1.0.0`.
