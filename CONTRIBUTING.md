# Contributing

Read [AGENTS.md](AGENTS.md) first: it holds the rules every change follows (phase gates, no unmeasured numbers, which dependencies are approved, what to ask before doing).

## Set up

Linux, Python 3.11+, Node.js 20.19+ (or 22.12+):

```bash
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.lock
npm --prefix frontend ci --ignore-scripts
```

## Before you open a pull request

The same checks CI runs:

```bash
.venv/bin/ruff check backend tests simulator
.venv/bin/pytest -q
npm --prefix frontend test
npm --prefix frontend run build
docker build -f backend/Dockerfile .
docker build frontend
```

None of these need root or the CICIDS2017 dataset: the trained models and the PCAP fixtures are committed.

## Changing things that have contracts

- **API or database:** change [docs/API_SPEC.md](docs/API_SPEC.md) or [docs/DATA_MODEL.md](docs/DATA_MODEL.md) in the same pull request. The SQLite schema is frozen; schema changes need the maintainer's approval first.
- **Features or models:** the feature order lives only in `backend/features/feature_set.py`. Retrain with `backend/ml/train_supervised.py`, re-run `backend/evaluation/benchmark.py`, and update the numbers in README.md and docs/EVALUATION.md from its output. Never edit numbers by hand.
- **Dependencies:** add the pin to `requirements.txt`, then regenerate the hashed lock in the same image the backend uses:

```bash
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src python:3.12-slim \
  sh -c 'python -m venv /tmp/v && /tmp/v/bin/pip install -q pip-tools && /tmp/v/bin/pip-compile --quiet --generate-hashes --strip-extras --allow-unsafe --output-file requirements.lock requirements.txt'
```

- **Live capture:** anything that changes capture or flow-building needs a run on `lo` with `sudo` (see docs/PHASE2_RESULTS.md for the method), not only the unit tests.

## Security

The API has no authentication and binds 127.0.0.1 only. Don't change bind addresses, CORS origins or the upload checks without reading the trust-boundary section of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Report vulnerabilities privately to the maintainer rather than in a public issue.
