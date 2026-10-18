# Setup and troubleshooting

## One command

Use Windows PowerShell 5.1+ or PowerShell 7. Install Docker Desktop, enable Linux containers, then run from the extracted project:

```powershell
.\start-demo.ps1
```

No Python or Node installation is required on the host for the Docker demo. Native Python unit tests need the dependencies listed in README and Git Bash on Windows.

The script resolves paths from its own directory, so a project path containing spaces is supported. It uses the same four Compose files for validation, start and stop. It checks the engine, required ArmorIQ configuration, Compose wait support and local service endpoints. Startup does not scan a target or call ArmorIQ.

First launch copies `.env.example` if `.env` is absent and asks for a missing ArmorIQ key using hidden input. It appends the entered key to `.env` without replacing existing settings. Keys are never passed as command-line arguments or printed. Configure your cloud policies before recording.

```powershell
.\start-demo.ps1 -CheckOnly
.\start-demo.ps1 -NonInteractive -NoBrowser
.\start-demo.ps1 -NoBuild -WaitTimeoutSeconds 300
.\start-demo.ps1 -Stop
```

`-CheckOnly` performs actual Compose configuration validation without starting containers or asking for secrets. If `.env` is absent, it uses a temporary template copy and removes that copy afterward. `-NonInteractive` fails clearly if the key is missing. `-Stop` retains named volumes. Compose must support `up --wait --wait-timeout`.

If local execution policy blocks this downloaded script, inspect it and run a single process with `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\start-demo.ps1`; this does not change the machine's persistent execution policy. On Linux with PowerShell installed, use `pwsh -File ./start-demo.ps1 -NoBrowser`.

## ArmorIQ policy identities

| Flow | Agent | User | Tool name |
| --- | --- | --- | --- |
| Scanner | `autoshield-scanner` | `local-scan-operator` | `autoshield_scanner__http_get` |
| DevOps MCP lab | `autoshield-lab-agent` | `local-lab-operator` | `autoshield__read_system_metrics`, `autoshield__read_lab_file`, `autoshield__query_database`, `autoshield__run_system_command`, `autoshield__invoke_lab_api` |

Scanner arguments are `url`, `method`, `mode`, `purpose`, `origin`, `verify_ssl`. Allow only the intended lab origin and probe purposes. Local scope restrictions still apply after a cloud allow. DevOps uses the fixed operator-defined plan in `backend/mcp_policy.py`.

Keep `MCP_ARMORIQ_MODE=required`. Explicit `disabled` is a local-policy-only DevOps mode; it never disables scanner ArmorIQ enforcement. Groq live-agent execution needs `GROQ_API_KEY`. Optional `MCP_SEMANTIC_MODE=required` also needs working Groq configuration. Gemini is used for optional legacy WAF proposal review; no LLM writes executable rule text.

## Compose wiring verified

| File | Responsibility |
| --- | --- |
| `compose.yaml` | Backend/data/logs, proxy, isolated Juice Shop, Streamlit scanner, three WAF paths |
| `compose.fixture.yaml` | Fixture service and configurable lab-origin list |
| `compose.motion.yaml` | React build/Nginx on loopback port 8502 |
| `compose.mcp.yaml` | Restricted gateway, writable audit volume, fixture health dependency, UI gateway dependency |

Use all four together for the complete demo. `compose.mcp.yaml` is an overlay and depends on the fixture and motion overlays. The Linux gateway uses `/workspace`; native Windows Python uses an existing operator-configured `MCP_WORKSPACE` or the bundled lab directory. The vulnerable Juice Shop is on the internal lab network. Exposed service ports remain bound to loopback.

## Manual diagnostics

```powershell
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml ps
docker compose -f compose.yaml -f compose.fixture.yaml -f compose.motion.yaml -f compose.mcp.yaml logs --tail=80 backend mcp-gateway motion-ui fixture-lab
```

The launcher uses default published ports. Preserve the supplied port mappings for the recording. If you customize the UI port, update gateway trusted Host/Origin checks and launcher HTTP probes together.

- Missing key: update `.env` and recreate backend and gateway. Readiness never proves key validity.
- Policy hold/deny/unavailable: inspect the actual policy outcome; never enable a blanket fallback for the recording.
- Port occupied: stop the other local deployment before starting this one.
- Slow first build: prebuild before recording; increase the wait timeout if needed.
- WAF integration failures: inspect candidate content, `nginx -t` and exact audit rule IDs. An HTTP 403 alone does not prove the AutoShield rule matched.
- Existing setup: the full ZIP contains current Compose wiring. `scripts/Apply-Update.ps1` preserves custom Compose and `.env`; compare the accompanying patch before using the new launcher with an older installation.

Official references: [Compose installation](https://docs.docker.com/compose/install/), [Compose up options](https://docs.docker.com/reference/cli/docker/compose/up/), [PowerShell installation](https://learn.microsoft.com/powershell/scripting/install/install-powershell).
