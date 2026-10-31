# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: a junior SOC analyst or IT admin at a small organisation who keeps one browser tab of live alerts open while doing other work, and glances at it, or reacts when something serious arrives. Secondary: a reviewer (recruiter, hiring manager) evaluating this portfolio project in a minute or two while the owner runs the attack simulator. The design serves the analyst first; that is what makes it credible to the reviewer.

## Product Purpose

Real-time network intrusion detection on one laptop CPU: capture live traffic (or read an uploaded PCAP), group packets into flows, score each flow with detectors, and stream alerts to the dashboard over WebSocket. Success: the analyst sees what is happening now, can tell a serious alert from noise at a glance, and can trust every number shown.

## Positioning

Three detectors with different kinds of evidence, shown honestly side by side: a port-scan rule (a rule fired, nothing measured), a Random Forest trained on CICIDS2017 (names the attack, gives a class probability), and an Isolation Forest (cannot name an attack; says how unusual a flow is against normal training traffic). Fully offline: no cloud, paid APIs, GPU or telemetry.

## Operating Context

- Live view: alerts arrive continuously; repeats of the same source, destination and type within 30 s aggregate into one alert with a count. Severity is high, medium or low.
- Upload view: a .pcap/.pcapng up to 50 MB is parsed in a sandbox; its alerts show in their own view with capture times.
- Demo mode captures loopback only, so alerts come from programs on the same computer; `simulator/simulate_attack.py` generates port scans and floods.
- Access needs a dashboard token pasted once (printed by the backend, stored in `data/api-token`).
- Packets-per-second stats arrive every second.

## Capabilities and Constraints

- React 18, Vite, Tailwind CSS v4, Recharts. Approved additions for the redesign: self-hosted font packages and lucide-react.
- No dark mode (AGENTS.md).
- Strict CSP in production: everything self-hosted, no external fonts or scripts.
- The API and data contracts are fixed (docs/API_SPEC.md, docs/DATA_MODEL.md); the redesign is frontend-only.
- Known detection limits are documented in docs/LIMITATIONS.md (e.g. the classifier mislabels some scan flows).

## Brand Commitments

- Name: SentinelStream.
- Voice: plain, precise, honest; says what is and isn't known (e.g. "Demo mode: capturing loopback traffic only, so alerts come from programs on this computer.").

## Evidence on Hand

Real alerts from the running backend and simulator; benchmark results from `backend/evaluation/benchmark.py` (README). There are no customers, testimonials or deployments: never invent them.

## Product Principles

1. No unmeasured numbers: every figure shown must mean what it says, per detector.
2. Severity first: a High alert must be unmistakable at a glance; colour is never the only signal.
3. Live means live: when data stops, the screen says so.
4. Honest about limits: demo mode, detector blind spots and missing models are stated, not hidden.

## Accessibility & Inclusion

WCAG 2.2 AA: text contrast, keyboard operation, screen-reader announcements for new high-severity alerts and connection changes, and reduced-motion support.
