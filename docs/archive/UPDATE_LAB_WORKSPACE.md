> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

# Docker lab assessment workspace

Replace backend/scan_api.py and frontend/scanner_ui.py in your current working project. Keep .env beside compose.yaml. No environment changes required.

```powershell
docker compose up -d --build backend frontend
```

The session form now requires operator authorization acknowledgment. The backend requires a strict boolean authorization_confirmed=true and permits only AUTOSHIELD_LAB_ORIGINS (default http://proxy). This is a local lab restriction, not a SaaS authentication or ownership-verification system. Existing history and exports remain readable.

Tabs: Reconnaissance (saved pages, parameter names and forms), Vulnerabilities (findings/evidence/AI review), Payloads & Probes (two supported query probes and their recorded findings), Testing Session (scope, options, timestamps, progress and errors), Reports (JSON/HTML exports and comparisons). Stop scan remains above tabs while running.

No arbitrary payload runner, automatic exploitation, DNS verification, port scanning, technology fingerprinting, raw response viewer or complete probe execution log is claimed or implemented. Active mode runs the existing reflection and database-error probes within existing eligibility/limits; passive mode does not.

SaaS ownership checks and approved target/test scope are future work. Buying a domain does not authorize testing arbitrary infrastructure.

Validation: 37 scanner/AI/report/comparison/authorization tests passed. Frontend syntax checked; interactive tab layout requires local verification.
