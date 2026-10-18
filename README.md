# AutoShield-AI

**Policy-enforced web assessment, constrained WAF rule compilation and auditable MCP tools.**

AutoShield uses a FastAPI backend, React/Vite dashboard, SQLite evidence store and ArmorIQ-gated MCP scanner. Its separate WAF lab turns supported SQL injection log findings into trusted ModSecurity rule templates; AI review remains advisory.

## Start the demo

Install Docker Desktop and use Linux containers. In PowerShell, from this directory:

```powershell
.\start-demo.ps1
```

The launcher creates `.env` only if absent, asks for a missing ArmorIQ key without displaying it, validates all four Compose files, builds the stack, waits for service readiness and opens [the dashboard](http://localhost:8502). A key still needs matching console policies; startup does not claim live cloud authorization. Optional Groq/Gemini keys can be added to `.env` before launch.

```powershell
.\start-demo.ps1 -CheckOnly    # Validate config without starting containers
.\start-demo.ps1 -NoBuild      # Reuse previously built images
.\start-demo.ps1 -Stop         # Stop the project; retain evidence volumes
```

| Component | Local address |
| --- | --- |
| React dashboard | http://localhost:8502 |
| API / rule compilation endpoints | http://127.0.0.1:8010/docs |
| Streamlit scanner | http://127.0.0.1:8501 |
| Synthetic fixture | http://127.0.0.1:8090 |
| Juice Shop monitoring proxy | http://127.0.0.1:8080 |
| Baseline / candidate / enforcement WAF | Ports 8081 / 8082 / 8083 |

For the first scan, select **Session**, target `http://fixture-lab:8090/`, active mode, 5 pages, 25 requests and 120 seconds. Confirm authorization. **Activity** records scanner policy outcomes; **MCP Gateway** is a separate DevOps lab.

## What the project demonstrates

- Bounded HTTP(S) crawling with same-origin scope, DNS pinning, public TLS validation and ArmorIQ authorization for every target GET.
- Evidence-linked observations, two optional query probes, advisory AI review, comparison reports and exports.
- WAF log finding → trusted proposal → deterministic rule compilation. Candidate validation and explicit promotion are separate steps.
- MCP capability allowlists, SQL canonicalization, untrusted-log handling and durable ALLOW/BLOCK evidence.

A reflected marker is not proof of XSS. A database-error signature is not proof of exploitable SQL injection. Coverage is selected OWASP 2021 heuristics, not a complete Top 10 audit. A compiled rule is not a deployed patch. This is a local, single-operator lab.

## Documentation and checks

- [Setup, policies and troubleshooting](docs/SETUP.md)
- [3-minute demo checklist and exact WAF commands](docs/DEMO_SCRIPT.md)
- [Architecture and component boundaries](docs/ARCHITECTURE.md)
- [Portability, tests and patch notes](docs/FINAL_REVIEW.md)
- [Documentation index and historical updates](docs/README.md)

```text
python -m pip install -r requirements-dev.txt -r backend/requirements-mcp.txt
python -m unittest discover -s tests -v
```

Native Windows executor tests need Git for Windows (Git Bash); production tools execute inside Linux containers. Docker-dependent WAF tests live separately in `tests/integration`. Keep `.env` and generated databases out of Git.
