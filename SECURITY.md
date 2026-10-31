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
