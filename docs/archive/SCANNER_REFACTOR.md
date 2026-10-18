> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

> Public target and gateway behavior has been updated. Read PUBLIC_SCANNER_MCP.md first; older lab-only/direct-transport instructions below are historical.

# Scanner refactor

## Update your existing project (PowerShell)

Keep your current project folder and its `.env`. Extract this archive into a separate folder, then merge the updated files listed below into your existing project. The archive contains no `.env` and no API keys. Do not delete your existing project or Docker volumes.

Changed files: `backend/scan_engine.py`, `scan_api.py`, `scan_store.py`, `scan_report.py`, `scan_compare.py`, `Dockerfile`; new `backend/scan_settings.py`, `scan_identity.py`, `scan_checks.py`; `frontend/scanner_ui.py`; `motion-ui/src/main.jsx`; `compose.yaml` (lab-origin environment override); `tests/test_scanner.py`, new `tests/test_scanner_refactor.py`.

From the existing project's root, with Docker Desktop running:

```powershell
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml config --quiet
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml up -d --build
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml ps
```

Keep your existing port mappings if you changed them locally. `compose.mcp.yaml`, the MCP adapter, and MCP dependencies were not modified. No new Python runtime dependency is needed.

## Configuration

Add or edit these entries in your existing `.env` only if you want different defaults:

```dotenv
SCANNER_MAX_PAGES=200
SCANNER_VERIFY_SSL=true
```

`SCANNER_MAX_PAGES=0` (also `none`, `null`, `unlimited`) disables only the page cap. API `max_pages: 0` or `null` does the same. Omitted `max_pages` uses the environment default, otherwise 200. Explicit per-scan settings, including those sent by either UI, override environment defaults. The UIs initially display 200.

Request budget defaults to 1000 (range 1–10000), time budget to 900 seconds (range 1–86400). Depth remains 0–4, default 2, and the API minimum delay remains 0.25 seconds. These independent limits and cancellation remain effective even when pages are unlimited. Adjust request/time limits for larger scans. Only discovered same-origin links are crawled; JavaScript is not run. Bodies remain bounded at 256 KiB.

Example scan JSON:

```json
{
  "target": "https://your-configured-lab.example/",
  "mode": "passive",
  "max_pages": 200,
  "max_requests": 1000,
  "max_seconds": 900,
  "max_depth": 2,
  "delay_seconds": 0.5,
  "verify_ssl": true,
  "authorization_confirmed": true
}
```

## HTTPS and lab certificates

Targets without a scheme default to HTTPS. Explicit HTTP is preserved. Same-origin scope includes scheme and port; HTTP-to-HTTPS redirects are intentionally not followed across origins. Start with the HTTPS target and configure that exact lab origin.

Set `AUTOSHIELD_LAB_ORIGINS` to your explicitly authorized lab origins. The base compose file now respects this variable. `compose.fixture.yaml` still has its own explicit lab-origin list; extend that list if using the fixture overlay with additional HTTPS labs.

Verification is on by default. Prefer installing/mounting your lab CA and setting `SSL_CERT_FILE`. For self-signed lab testing, explicitly select `verify_ssl: false` (or uncheck the UI control). Disabling verification requires a configured lab origin. There is no silent insecure retry. Verification failures and other TLS errors produce safe recorded errors; verification mode is included in report coverage. The scanner uses stdlib `http.client`/`ssl`, not requests/urllib3, so it generates no InsecureRequestWarning and does not globally suppress warnings.

## Findings and coverage

Every valid scanner observation has a SHA-256 fingerprint over check type, canonical original URL, parameter and HTTP method. Probe findings use baseline URLs, so random markers do not change identity. Host/default ports, fragments, unreserved URL escapes and query-key ordering normalize deterministically. Query values, different paths, methods and parameters remain distinct. First matching evidence is retained; IDs are preserved. Incomplete legacy records without URLs are preserved rather than incorrectly merged. Deduplication applies to live findings, storage/API JSON, HTML exports and comparison grouping.

Checks use the **OWASP 2021** labels requested in this task:

- A01: directory listing, file-content and traversal-input heuristics. No role/ownership bypass claim.
- A02: cleartext HTTP, existing mixed-content checks, private-key/credential-material patterns. Matched secret values are not stored.
- A03: existing opt-in active reflection and differential SQL-error probes, now modular. Reflection is not confirmed XSS; SQL errors are suspected injection only.
- A05: CSP, HSTS on HTTPS HTML, X-Frame-Options (CSP frame-ancestors accepted as an alternative), X-Content-Type-Options; stack-trace leakage.
- A07: Basic-auth challenges and discovered common login/admin paths. No login attempts, default-password guesses or authentication-bypass claims.
- A09: discovered public log-content heuristic. Logging capture, alerting, integrity and retention require server-side/manual validation. Stack traces belong primarily to A05 and do not establish A09 failure.

These are partial heuristics, not complete OWASP Top 10 coverage. Passive mode sends no query probes or extra guessed-path requests. Existing lab authorization, DNS pinning, same-origin controls and cancellation are preserved.

## Verification

Local validation: 82 unit/regression tests; real HTTP crawling beyond 30 pages; explicit and unlimited page settings; real self-signed TLS rejection, explicit insecure lab mode, trusted lab CA success; deterministic identities and exports; OWASP heuristics; existing MCP boundary tests. Frontend production build and 4 frontend tests.

```powershell
python -m pip install -r requirements-dev.txt -r backend/requirements-mcp.txt
python -m unittest discover -s tests -p "test_scanner*.py"
python -m unittest discover -s tests -p "test_scan_*.py"
python -m unittest discover -s tests -p "test_detector.py"
python -m unittest discover -s tests -p "test_mcp_gateway.py"
cd motion-ui
npm ci
npm run build
node --test src/api.test.js
```

The real TLS regression test uses `openssl` on PATH to generate an ephemeral test certificate. It never reuses project keys.

Docker was unavailable in the editing environment. Compose YAML and Docker COPY sources were checked, but image builds and the pre-existing live WAF integration tests (`test_waf_baseline.py`, `test_candidate_waf.py`) require your running Docker lab and were not validated here. They were left unchanged. The scanner request-budget validation test now checks 10001 (above the new 10000 maximum) instead of the old boundary 101.

References: https://docs.python.org/3.12/library/ssl.html and https://top10.owasp.org/2021/ .
