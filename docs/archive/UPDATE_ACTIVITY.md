> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

# Activity update

Copy these files into your EXISTING project folder:

- backend/scan_engine.py
- backend/scan_store.py
- motion-ui/src/main.jsx
- motion-ui/src/style.css
- tests/test_scan_activity.py (optional, for development)

Keep your existing .env and compose files, including your host-port 8010 change.
Do not create a new project folder or remove Docker volumes.

Run from the folder containing compose.yaml:

```powershell
docker compose -f compose.yaml -f compose.motion.yaml up -d --build backend proxy motion-ui
```

Open http://localhost:8502 and press Ctrl+F5. Start a new authorized lab scan.
Activity shows persisted events refreshed every three seconds, operation status,
response fingerprints, baseline evidence and linked finding IDs. Existing scans
have no historical activity data; no events are invented for them.

Response configuration is currently logged as a grouped operation. Reflection
and database-error probes have individual records. No observation is not a pass.
Stopped operations can have no response when budget/cancellation prevented execution.
Raw response bodies and cookie values are not stored. JSON report exports include
activity; the existing HTML summary does not yet render the activity log.

Failures now show a stop reason above the tabs. DNS failures explain the Docker
lab startup requirement. Backend restarts mark pending operations interrupted/stopped.

Validation: production UI build; six deterministic activity/recovery tests;
frontend API test command. Full backend HTTP tests were blocked in this execution
environment by missing FastAPI and socket permissions. Docker/browser end-to-end
validation is still required locally.

This update is the first milestone: execution visibility and evidence logging.
Modular check registry, targeted retesting and evidence graph are future milestones.
