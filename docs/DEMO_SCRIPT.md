# Three-minute demo: scanner, compiler and MCP guard

## Before recording

- [ ] Run `start-demo.ps1` before recording; do not spend video time on image downloads.
- [ ] Configure ArmorIQ policies for **both** scanner and DevOps agent identities; keep `MCP_ARMORIQ_MODE=required`.
- [ ] Rehearse an allowed scan and a cloud-denied first request. Record actual cloud outcomes, never a mocked cloud check.
- [ ] Open React at port 8502, API docs at port 8010, and the relevant ArmorIQ console view. Streamlit at 8501 is also a scanner, not a rule-compilation UI.
- [ ] Keep API keys, `.env`, unrelated windows and private account details off screen.
- [ ] Prepare one real WAF log finding using the local-only steps below. If using a pre-existing finding, identify it as a previously collected lab event.
- [ ] Prebuild the candidate WAF; rehearse syntax and benign cases. If an application regression remains, disclose it.
- [ ] Use a 16:9 recording, readable zoom, mic check and notifications off. Check the saved video duration and playback before submission.

## Recording timeline (180 seconds)

| Time | Show | Say / prove |
| --- | --- | --- |
| 0:00–0:15 | Dashboard + architecture | “AutoShield bounds assessment requests, compiles trusted candidate rules and records tool-policy decisions.” |
| 0:15–1:00 | New live authorized fixture scan; Activity | Start at `http://fixture-lab:8090/`, active mode, 5 pages, 25 requests, 120 seconds. Show a real MCP/ArmorIQ decision, progress and one observation with evidence. The fixture SQL error is synthetic; reflection is not proof of XSS. |
| 1:00–1:55 | WAF log finding → proposal API → compiled artifact | Show the finding/request ID, call the proposal endpoint and compiler, then display rule ID, route scope and SHA-256. This is automatic **trusted-template compilation**, not LLM-written rules or automatic deployment. If rehearsed, show actual candidate syntax/attributed blocking evidence. |
| 1:55–2:45 | DevOps MCP lab replay or live agent; cloud-deny scan | Show one allowed safe tool, one blocked secret/destructive proposal, and `NOT EXECUTED` with its audit call ID. Local deterministic blocks may precede the cloud check; label the attribution. Show a separately prepared denied-first-request scanner run with zero target requests and correlate with the ArmorIQ console. |
| 2:45–3:00 | Exported report and scope | Export actual evidence. State selected checks, local lab scope, advisory AI and the distinction between compiled, validated and deployed. |

If cloud latency exceeds the recording window, show a clearly labeled earlier real run alongside the live run. Do not present a replay as a compromised LLM, or local policy as a cloud decision. Do not edit an unfinished request to imply success.

## Exact WAF compilation rehearsal (PowerShell)

Run from the project root. These commands send one known test string only to your local Juice Shop proxy. The web-scanner fixture findings are a separate data model and do **not** feed this compiler automatically.

```powershell
$api = 'http://127.0.0.1:8010'
$marker = 'autoshield-demo-' + [guid]::NewGuid().ToString('N')
$query = [uri]::EscapeDataString("' OR 1=1-- " + $marker)
try {
    $null = Invoke-WebRequest -UseBasicParsing -Uri ("http://127.0.0.1:8080/rest/products/search?q=" + $query) -TimeoutSec 10
} catch {
    # An HTTP 4xx/5xx is still a response. A network failure must stop rehearsal.
    if ($null -eq $_.Exception.Response) { throw }
}

# Collection and finding generation run in the backend background worker.
$finding = $null
for ($attempt = 0; $attempt -lt 15; $attempt++) {
    $page = Invoke-RestMethod -Uri "$api/findings?limit=100" -TimeoutSec 10
    $finding = $page.findings | Where-Object { $_.request.query_evidence -like "*$marker*" } | Select-Object -First 1
    if ($finding) { break }
    Start-Sleep -Seconds 1
}
if (-not $finding) { throw 'Fresh lab finding was not collected; inspect proxy/backend health.' }
$finding | Select-Object id, event_id, matched_rules

$proposal = Invoke-RestMethod -Method Post -Uri "$api/findings/$($finding.id)/proposal" -TimeoutSec 10
$proposalId = $proposal.proposal.id
$compiled = Invoke-RestMethod -Uri "$api/proposals/$proposalId/compiled" -TimeoutSec 10
$compiled | Select-Object proposal_id, compile_status, validation_status, deployment_status, rule_ids, sha256
$compiled.content
```

The last two calls are the generation/compilation automation to show on camera. The compiler deliberately reports `not_run` validation and `not_deployed` deployment. AI review cannot inject executable rule text.

## Optional candidate installation and proof

Do this before recording if you want to show actual candidate blocking. It changes only the lab candidate rule file; it does not promote the rule into the enforcement WAF.

```powershell
# Continue in the same shell so $compiled and $proposalId refer to that run.
$ruleFile = Join-Path (Get-Location) 'candidate/autoshield.conf'
[IO.File]::WriteAllText($ruleFile, $compiled.content, (New-Object Text.UTF8Encoding($false)))
$compose = @('-f', 'compose.yaml', '-f', 'compose.fixture.yaml', '-f', 'compose.motion.yaml', '-f', 'compose.mcp.yaml')
& docker compose @compose exec -T candidate-waf nginx -t
if ($LASTEXITCODE -ne 0) { throw 'Candidate syntax check failed; do not reload.' }
& docker compose @compose exec -T candidate-waf nginx -s reload
if ($LASTEXITCODE -ne 0) { throw 'Candidate reload failed.' }
$validation = Invoke-RestMethod -Method Post -Uri "$api/proposals/$proposalId/validate-http" -TimeoutSec 120
$validation
python tests/verify_candidate_evidence.py $proposalId
if ($LASTEXITCODE -ne 0) { throw 'Candidate attribution check failed.' }
```

This Python evidence helper needs host Python and Docker CLI. It verifies loaded rule hashes, syntax and an exact blocking transaction containing the candidate rule ID. The HTTP validation status normally remains `review_required`; it is not a production approval. Review known benign application errors rather than hiding them. Baseline CRS may already block these inputs, so do not claim added coverage from a 403 alone.

Promotion is intentionally explicit and out of scope for the short compilation segment. Only if separately rehearsed, review the validation, attach its matching evidence and use `deploy_lab.py promote --run-id <actual-id> --lab-demo`. The controller checks eligibility and records rollback state. Never substitute a proposal ID for a validation run ID.

## Submission proof checklist

- [ ] Live scan: target/scope, actual decision and response evidence are visible.
- [ ] Compiler: finding ID → proposal ID → deterministic scoped rules and hash are visible.
- [ ] Enforcement: allowed tool success and blocked tool non-execution have distinct audit records.
- [ ] ArmorIQ: the console event matches the agent/tool and actual run; historical events are labeled.
- [ ] Report: exported findings, request limits and coverage limitations are readable.
- [ ] Claims: no full Top 10, confirmed exploit, automatic production patching or policy learning claim beyond recorded evidence.
