> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

# AutoShield motion interface

A React interface inspired by the reference video's full-screen composition, bold type and interaction-driven scenes. Original AutoShield artwork uses CSS; no reference-site media or branding is copied.

## Install into your EXISTING project

Copy only these additions from this ZIP into the project folder where compose.yaml and your working .env already live:

- motion-ui/ (entire folder)
- compose.motion.yaml

Do not replace .env or create a new project folder. This update does not change backend code, saved database volumes or the existing Streamlit frontend. It expects the latest lab authorization and comparison endpoints already installed in the project.

Run from the folder containing compose.yaml:

```powershell
docker compose -f compose.yaml -f compose.motion.yaml up -d --build motion-ui
```

Open http://localhost:8502. Existing Streamlit remains at http://localhost:8501. If the Docker target itself is stopped, start it using `docker compose up -d proxy` and wait for its health checks before scanning.

To stop only the new interface:

```powershell
docker compose -f compose.yaml -f compose.motion.yaml stop motion-ui
```

## Included

- Pointer-reactive orbital introduction with a keyboard-accessible Enter workspace button.
- Animated section entrances, hover/focus feedback, and a motion toggle; reduced-motion preference respected.
- Session configuration and authorization acknowledgment, saved scan selection, three-second polling and Stop scan.
- Clickable map of up to 12 observed pages; full page evidence remains in the list.
- Filterable findings and expandable evidence, supported probes and recorded probe findings.
- Configured-provider AI review (same backend keys); no browser API key entry/storage.
- Existing JSON/HTML report downloads, comparisons and print-to-PDF workflow.
- Responsive CSS for desktop and small screens. All React data is rendered as text; provider content is never injected as HTML.

The intro artwork is decorative, not a scan-progress indicator. Counters show saved backend data. A connected badge means the scans API responded, not that the target is reachable or that the system is secure. This remains a local Docker lab application, not a production SaaS release. No domain verification or autonomous exploitation was added.

## Validation and limits

- Production Vite build passed.
- Four frontend API-helper tests passed (request shape, same-origin path, backend error handling).
- Existing 37 scanner/AI/report/comparison/authorization tests passed.
- Browser preview was blocked from accessing localhost in the development environment, so live visual behavior, mobile layout and Docker/Nginx integration require local verification. No successful visual or end-to-end Docker test is claimed.

## Local development (optional)

With a compatible Node.js installation and backend on port 8000:

```text
cd motion-ui
npm ci
npm run dev
```

Vite proxies /api to the local backend during development. Docker uses Nginx to proxy only scanner and health API paths to backend:8000. package-lock.json locks the resolved frontend dependencies.
