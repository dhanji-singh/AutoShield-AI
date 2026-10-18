> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

# Final touches

Implemented:

- Blank mandatory ArmorIQ key setting and explicit enforcement modes in `.env.example`.
- DevOps MCP lab defaults to required ArmorIQ; explicit disabled mode remains clearly local-policy-only. Scanner enforcement remains mandatory.
- Read-only `/scans/readiness` endpoint: installed MCP/SDK packages, key presence, optional AI configuration and last recorded ArmorIQ gate outcome. It never sends cloud or target requests and never returns keys.
- Session readiness panel distinguishes prerequisites from verified cloud permission. Starting from the React dashboard requires configured prerequisites.
- Backend reachability badge no longer implies a functioning scanner/cloud connection.
- DevOps lab and scanner evidence views explicitly labeled as separate flows.
- React groups repeated header observations while preserving per-response evidence and exported finding IDs.
- Corrected README ports, one recommended startup path, architecture and concrete demo script.
- Updater manifest includes new files while preserving existing `.env` and Compose customizations.

Verified in this environment:

- 96 Python tests passed: scanner suites (64), detector (14), MCP gateway (18).
- 6 frontend tests passed, including evidence-preserving header grouping.
- React production build passed.

Operator checks still needed:

- Docker Compose build and service health; WAF integration and promotion.
- Real ArmorIQ ALLOW/BLOCK and corresponding cloud console evidence.
- Browser visual review, mobile layout and actual recording.
- PowerShell updater execution on Windows.

For existing installs, add `ARMORIQ_API_KEY` and `MCP_ARMORIQ_MODE=required` to your own `.env`; the updater preserves it and your Compose files. Rebuild backend and motion UI, and recreate mcp-gateway after configuration changes. Existing stored scan evidence remains readable. No keys, runtime database, node_modules or generated test state are included in the release ZIP.
