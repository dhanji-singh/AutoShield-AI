> Public target and gateway behavior has been updated. Read PUBLIC_SCANNER_MCP.md first; older lab-only/direct-transport instructions below are historical.

# AutoShield AI 0.4 — automated web assessment

This release adds a working, bounded HTTP scanner to the existing virtual-patching
lab. The deterministic engine discovers linked pages, checks response configuration,
and optionally runs lightweight query probes. Groq or Gemini can review the saved results.
The model does not generate or execute tests. This is an initial web assessment
release, not a complete autonomous penetration-testing agent.

## Start in Windows / VS Code

Extract this ZIP into a new folder. Keep your previous working folder and Docker
volumes until you have verified the new version. Do not overwrite your existing
`.env` or live WAF configuration with the defaults from this release.

With Docker Desktop running, open the new project folder in VS Code:

```powershell
Copy-Item .env.example .env
docker compose up --build -d
```

Open http://127.0.0.1:8501 and select **Scanner**. If the previous stack is running,
stop it from its original directory with `docker compose down` first to free the
ports. Do not add `-v`; that deletes named volumes.

The default target, `http://proxy/rest/products/search?q=apple`, is the local
Juice Shop route as seen from the backend container. Choose **active** to run
reflection and database-error probes against that query parameter. Choose
**passive** for crawling and response checks only. Passive mode still makes HTTP
requests; it is not an offline analysis.

For your authorized website, replace the target with:

```text
https://dhanji-singh.github.io
```

No scan of this website was run during development. Start with crawl/response
checks. A static site may have no query parameters to test. The scanner follows
only the exact selected scheme, hostname and port. An HTTP-to-HTTPS or cross-domain
redirect is recorded but not followed; use the intended final URL as the target.

## What is implemented

- Same-origin linked-page discovery; form metadata is recorded, never submitted.
- HTTP transport, absent CSP / nosniff / HSTS headers, mixed-resource references,
  and cookie-attribute observations.
- Optional unique-marker reflection and single-quote database-error comparison
  on discovered query parameters (up to five per page, one set per path/name).
- A baseline and mutated response are compared before reporting a new database
  error. A marker reflection is explicitly inconclusive for XSS.
- Start, stop, progress, recent history, restart interruption handling, and JSON
  evidence download.
- Optional automatic AI review after a finished/partial scan, and a manual
  review/retry button. Successful reviews are cached per immutable finished scan.

The report distinguishes **confirmed observations**, **suspected issues**, and
**inconclusive leads**. Missing headers do not establish exploitation. No findings
does not establish that a target is secure. Severities are conservative check
labels, not CVSS calculations.

## AI setup

Scanning works without AI credentials. Scanner review supports Groq or Gemini.
For Groq create a key at https://console.groq.com/keys and set these in `.env`:

```dotenv
AI_PROVIDER=groq
GROQ_API_KEY=your-own-key-here
GROQ_MODEL=openai/gpt-oss-20b
```

Preserve your existing `.env`. When updating from the earlier release, copy these
files from this archive into your existing project folder:
- backend/scan_ai.py
- backend/scan_api.py
- backend/ai_check.py
- backend/Dockerfile
- frontend/scanner_ui.py

Then run from the folder containing compose.yaml:

```powershell
docker compose up -d --build backend frontend
docker compose exec backend python ai_check.py
```

Expected: `AI check OK: groq / openai/gpt-oss-20b`. The check makes one small
request with synthetic data, never website evidence. Reload the dashboard and
use Scanner → AI review → Generate / retrieve AI review. Switching provider or
model generates a fresh review; an identical provider/model reuses a saved result.
API usage is subject to your provider account limits and billing.

Only Scanner review uses AI_PROVIDER. Legacy WAF explanations and proposals still
use GEMINI_API_KEY/GEMINI_MODEL. To use Gemini for Scanner too, set AI_PROVIDER=gemini
and a currently available GEMINI_MODEL, then recreate the backend.

The scanner sends up to 10 finding summaries and coverage information to your
selected provider. It excludes raw bodies, cookies, form values, and URL queries.
AI output is plain text and cannot change verdicts or launch requests. No automatic
provider fallback occurs. Errors do not invalidate the scan. HTTP 401/403 indicates
credentials or access issues; 404 can indicate model availability; 429/503 needs a
later retry and a quota/status check. Provider error bodies and keys are not logged.

This update passed 37 local tests, including mocked Groq/Gemini responses, error
handling, and provider cache switching. Live provider connectivity and Docker
rebuild were not tested here; run ai_check.py on your machine to verify your account.

## Scope and operating limits

Only one scan runs at a time in one backend process. Do not launch multiple Uvicorn
workers. Maximums: 30 fetched pages, 100 HTTP requests, depth 4, and a 180-second
cooperative scan deadline. Each connection/read has a five-second timeout; stop
requests take effect between operations. System DNS lookup may outlast the scan
deadline. Response capture is capped at 256 KiB, with a truncation flag.

Public targets may not resolve to private/reserved addresses. Every request is
resolved and checked, then connected to that exact address to prevent a second
DNS lookup from changing the destination. HTTPS retains certificate and hostname
verification. No system HTTP proxy is used.

The Docker backend allows the exact local origin `http://proxy` through the
operator-controlled `AUTOSHIELD_LAB_ORIGINS` setting. To test another local app,
explicitly add its exact origin in Compose and recreate the backend. Do not set
this list from user input or expose the backend publicly. The API is a localhost
development service without user authentication.

The crawler skips common state-changing-looking paths and sensitive query
parameters. It sends only GET requests, does not carry sessions or submit forms,
and does not promise that a poorly designed application's GET routes are harmless.
Use a test environment where possible.

## Limitations and next milestones

- No JavaScript/browser execution: SPA routes and dynamically discovered APIs
  may be missed. Start at a known endpoint when necessary.
- No authenticated, role-based, business-logic or multi-step workflow testing.
- No confirmed XSS execution, boolean/time-based SQLi, traversal, SSRF, uploads,
  network-port scans, or external scanner integrations yet.
- No automatic WAF deployment from scan findings. Existing WAF features remain a
  separate local workflow using the original detector's findings.
- No retention scheduler or full-history pagination yet (latest 100 scans via API).
- AI is currently a result reviewer; a constrained test planner is a later step.

Next milestones: browser/API discovery, independently verified checks, authenticated
test-account workflows, and optional scanner adapters with scope enforcement.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/scans` | Start a bounded scan |
| GET | `/scans` | Recent scan history |
| GET | `/scans/{id}` | Status, progress, evidence and AI review |
| POST | `/scans/{id}/cancel` | Request cancellation |
| POST | `/scans/{id}/ai-review` | Generate/retrieve advisory review |
| GET | `/scans/{id}/report` | JSON download |

## Development without Docker

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
$env:AUTOSHIELD_DB_PATH = "$PWD\data\autoshield.db"
python -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In a second activated terminal:

```powershell
$env:API_BASE = "http://127.0.0.1:8000"
python -m streamlit run frontend/app.py
```

The older monitoring collector reports a missing log until Nginx logs are
available; this does not prevent the Scanner from operating. The Docker-specific
default target `http://proxy` will not resolve outside Docker. Supply a reachable
target, and configure `AUTOSHIELD_LAB_ORIGINS` before backend startup for a local
fixture. Local Python does not automatically read `.env`; export AI provider variables
in the backend terminal if using AI outside Docker.

## Tests

```powershell
python -m unittest discover -s tests -p "test_scanner.py" -v
python -m unittest discover -s tests -p "test_detector.py" -v
```

The scanner tests start an ephemeral local HTTP server. They do not contact the
website supplied in chat or call external AI providers. WAF integration tests require Docker:

```powershell
python -m unittest discover -s tests/integration -p "test_waf_baseline.py" -v
python -m unittest discover -s tests/integration -p "test_candidate_waf.py" -v
```

## Existing WAF workflow

The packaged candidate and enforcement files now start at baseline CRS. Previous
state/configuration/evidence samples are retained under
`examples/previous-lab-state/`; they are historical samples, not current proof.
Regenerate candidate bytes directly from the compiler response rather than
manually editing whitespace, then load/reload and verify them in the WAF lab.
The dashboard's evidence command now correctly points into `tests/`.

Promotion and rollback remain manual host-controller actions. Neither the new
scanner nor the AI reviewer edits your WAF or your target website.


## Structured AI review update

Update backend/scan_ai.py and backend/scan_api.py together, preserving your .env.
Run `docker compose up -d --build backend`. No frontend change or new dependency
is needed. Run `docker compose exec backend python ai_check.py` for one live
synthetic request. Select a finished scan and press Generate / retrieve AI review.
Old text-only reviews regenerate on demand; a new target scan is unnecessary.

The model returns JSON with exactly one ID, explanation and remediation per
supplied finding. Local validation rejects extra/missing/duplicate IDs, extra
fields (including model-provided severity/verdict), duplicate JSON keys, wrong
types, empty/oversized text, incomplete generations and tool-call responses.
Scan facts, coverage, severity, verdict, title and recorded remediation are
rendered from saved scanner records. AI explanations remain explicitly unverified;
structural validation cannot establish truthfulness of free-form text.

AI reviews the first 10 findings to bound output size; every scanner finding stays
in the evidence report. The display states reviewed/total count. The JSON export
adds ai_review.structured, review_version, input_sha256 and validation metadata.
Provider/model, review version and minimized input fingerprint determine cache
reuse, including changes to lab classification. Saved scan evidence is unchanged
when AI output is rejected; its review status is unavailable and can be retried.

37 local tests passed (23 scanner/AI/API tests and 14 detector tests), including
mocked provider responses. This structured format has not been live-tested with
your Groq account. Review factual accuracy of model prose before sharing reports.


## HTML report export

Rebuild backend and frontend after applying this update:

```powershell
docker compose up -d --build backend frontend
```

Select a saved scan, then click **Prepare HTML / PDF report** and **Download report (HTML)**. Open the HTML in a browser and use Ctrl+P → Save as PDF. PDF conversion uses your browser; there is no server PDF dependency. Re-prepare after updating a scan or AI review; the download is a saved snapshot.

The offline report includes all recorded findings, evidence, coverage, settings, discovered pages and the saved AI review. It makes no target or model calls. Untrusted values are HTML-escaped; scripts and external assets are blocked. Partial/running scans are labelled; AI prose remains unverified. Older plain-text AI reviews also work.

API: `GET /scans/{scan_id}/report.html`. Existing JSON exports are unchanged.

Changed files: `backend/scan_report.py` (new), `backend/scan_api.py`, `backend/Dockerfile`, `frontend/scanner_ui.py`. Regression tests: `tests/test_scan_report.py`. Scanner/AI/report suite: 26 tests passing. Browser print appearance still needs checking on your machine.
