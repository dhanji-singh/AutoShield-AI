# Public HTTP/HTTPS scanner with required ArmorIQ enforcement

This update replaces the scanner API's lab-only target gate. Public HTTP/HTTPS targets no longer need entries in `.env`. Every target GET initiated by the scanner API now travels over a persistent official MCP stdio connection to a dedicated scanner gateway process. Only that process performs the HTTP request, after explicit ArmorIQ approval. There is no direct-network fallback in the scanner API worker.

## Update without replacing .env

Extract this ZIP separately. In PowerShell, from its `AutoShield-AI` directory, run:

```powershell
.\scripts\Apply-Update.ps1 -ProjectPath "C:\path\to\your\existing\AutoShield-AI"
```

The script copies only changed/new files, backs up files it replaces, and leaves `.env`, your compose port mappings, stored Docker volumes, and unrelated files alone. Alternatively merge the changed files listed in `docs/manifests/SCANNER_GATEWAY_UPDATE.json` manually.

## Configure ArmorIQ once

In your existing project's `.env`, keep your actual key:

```dotenv
ARMORIQ_API_KEY=your_actual_key
```

Do not paste the key in frontend files. The backend already loads the project's `.env` through Docker `env_file`. The scanner requires ArmorIQ regardless of the legacy `MCP_ARMORIQ_MODE` setting; `disabled` does not bypass scanner enforcement.

In your ArmorIQ console, configure a matching policy for:

| Field | Exact scanner value |
| --- | --- |
| Agent identity | `autoshield-scanner` |
| Operator/user identity | `local-scan-operator` |
| MCP name | `autoshield_scanner` |
| Tool action | `autoshield_scanner__http_get` |

The policy check receives `url`, `method` (`GET`), `mode` (`passive` or `active`), `purpose` (`page_fetch`, `reflection`, or `sql_error`), `origin` and `verify_ssl`. Configure your policy to allow the operations you intend, and block those outside your scope. For example, allow passive `page_fetch` and deny active probes until you explicitly enable them. A captured plan is not an allow decision: `session.check()` must return both `allowed=True` and action `allow`.

The old DevOps lab agent is `autoshield-lab-agent`; its policy does not automatically cover this new scanner identity. Your console's policy editor and permissions determine how rules are entered. This project does not create or activate cloud policies automatically.

## Start (Windows PowerShell or Ubuntu terminal)

Run from the existing directory containing `.env` and `compose.yaml`:

```text
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml config --quiet
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml up -d --build
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml ps
```

Open `http://localhost:8502` (or your existing custom UI port). In Session, enter the full public HTTPS URL, choose Passive, leave TLS verification on, and acknowledge that the target is in your authorized scope. Start with a few pages while validating your cloud policy. Activity shows gateway attribution, action and reason. The saved scan JSON/HTML includes the same evidence.

No `.env` change is required for each public domain. Private addresses still require an explicit `AUTOSHIELD_LAB_ORIGINS` entry, such as the existing Docker lab presets. Public TLS certificate validation stays enabled. Same-origin scope, URL credential exclusion, DNS pinning, private/reserved-address protection, request/page/time limits, and cancellation remain in force. Each same-origin redirect destination gets its own MCP/ArmorIQ decision. Cross-origin redirects are skipped: start a new scan at the final canonical HTTPS origin instead.

## Decisions and troubleshooting

- `ARMORIQ_KEY_MISSING`: key is absent from backend environment; add it to the existing `.env` and recreate backend.
- `no_matching_policy`: cloud policy did not match this scanner agent/tool/arguments.
- `ARMORIQ_DENIED_OR_HELD` / `policy_hold` / `policy_denied`: provider denied, held, or returned an unsupported action. Request was not sent.
- `ARMORIQ_UNAVAILABLE`: SDK initialization, plan capture or cloud check failed. No local allow fallback.
- `MCP_STARTUP_FAILED` / `MCP_PROTOCOL_FAILED`: rebuild backend with the added MCP dependencies and modules.
- `SCOPE_OR_ADDRESS_POLICY`: wrong origin, unsafe URL, disallowed mode/purpose, or private/reserved DNS result for a public target. Cloud ALLOW cannot override these local network protections.
- TLS errors: use a valid certificate or trusted CA for public targets. Explicit insecure verification remains available only for configured labs.

The scan stops at the first policy denial, retaining earlier findings if any. An unavailable cloud policy cannot yield a successful empty scan.

## Implementation

- `scan_mcp_client.py`: synchronous crawler bridge to one official SDK stdio connection per scan; MCP initialize, tools/list, tools/call; cancellation marker; sanitized failures.
- `scan_mcp_server.py`: dedicated scanner gateway; fixed GET operation, scope/mode enforcement, required cloud check, then existing pinned transport.
- `scan_gateway_policy.py`: official ArmorIQ SDK sessions in `sdk` mode. Because discovered URLs are unknown at startup, each concrete request gets its own short-lived plan and policy check. Successful results are reported as hashes, not response bodies; reporting/completion is best effort and is not claimed as confirmed cloud acknowledgment.
- `scan_api.py`: public target acceptance and mandatory MCP transport for scanner workers.
- `scan_engine.py`: gateway telemetry and block reasons in the scan timeline/check evidence.

The low-level `assess(..., transport_factory=...)` library remains injectable for offline tests. Production scanner API workers always supply MCP transport. The existing DevOps MCP server and UI stay separate and unchanged; scanner decisions appear in Scanner Activity, not the older DevOps replay feed. AI advisory reviews are separate provider requests, not target scan requests.

This is an operator-run local deployment, not multi-tenant SaaS authentication or proof of domain ownership. The user authorization acknowledgment records the operator's assertion; ArmorIQ evaluates tool policy. Neither establishes legal ownership of a website. Scan output contains untrusted page data; it is never executed as instructions.

## Validation and performance

Current verification: 111 Python unit tests, 4 fixture tests and 6 frontend tests passed; the frontend production build passed. The launcher and updater were exercised using PowerShell 7.4.6, and actual Docker Compose CLI configuration validation passed. See [FINAL_REVIEW.md](FINAL_REVIEW.md) for precise coverage and remaining live checks.

Unit coverage includes public API acceptance, authorization acknowledgment, TLS restrictions, real MCP stdio calls, fail-closed behavior, deny/hold cases, DNS restrictions, cancellation, budgets and local fixture HTTP execution. Cloud decisions are stubbed only in tests. Production exposes no simulated-allow switch. No live ArmorIQ ALLOW/BLOCK or full Docker Engine/WAF run was performed here.

Cloud checks add latency and consume provider quota. MCP is persistent for each scan; cloud decisions are never cached as blanket allows. Larger crawls may stop at the configured time budget. Page limit 0 means no page cap, not unlimited requests/time. JavaScript execution, authenticated session crawling and full exploit testing are outside this scanner's scope.

```text
python -m pip install -r requirements-dev.txt -r backend/requirements-mcp.txt
python -m unittest discover -s tests -p "test_scanner*.py"
python -m unittest discover -s tests -p "test_scan_*.py"
python -m unittest discover -s tests -p "test_detector.py"
python -m unittest discover -s tests -p "test_mcp_gateway.py"
```

The HTTPS fixture regression generates an ephemeral certificate with Python cryptography; no OpenSSL CLI is required. The WAF integration suites still need their existing running lab services.
