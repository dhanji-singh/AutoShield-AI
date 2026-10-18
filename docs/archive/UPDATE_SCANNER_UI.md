> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

# Scanner-only interface

Replace only frontend/app.py in your existing project. Keep your current .env and project folder.

```powershell
docker compose up -d --build frontend
```

Refresh the dashboard. Scanner is now the only workspace. Scan history, evidence, AI review, comparison and exports remain in Scanner. The old WAF-related UI pages are removed; backend lab services are retained for compatibility.

Validation: Python syntax checked; old page routing removed. Browser appearance needs local verification.
