> Historical migration note. Use [current setup](../SETUP.md) and the root README for this release.

# Update your existing project

This update is based on your uploaded AutoShield-AI (3).zip. That archive did not contain a .env file. No credentials were added or replaced.

1. Keep your current VS Code project folder.
2. Extract this ZIP into a temporary folder.
3. Copy backend/scan_report.py, backend/scan_api.py and frontend/scanner_ui.py into the corresponding folders of your EXISTING project, replacing those three files.
4. Your existing .env stays beside compose.yaml. Do not delete or replace your working project folder.
5. Run from the folder containing compose.yaml:

```powershell
docker compose up -d --build backend frontend
```

Scanner → select Current scan → Compare saved scans → choose Baseline → Compare scans → Prepare comparison HTML / PDF → Download comparison (HTML). Open the HTML and print to PDF with A4 and browser headers/footers disabled.

New: comparison HTML export with both scans' evidence, recorded severity/verdict, coverage warnings and interpretation limits. Comparison JSON and individual scan exports remain available.

The complete project is included for recovery, but only the three application files above need replacing. Tests/test_scan_compare.py and tests/test_scan_report.py contain regression checks.

Validation: 35 scanner/AI/report/comparison tests passed locally. Frontend syntax checked. Browser print layout for the new comparison export still requires local review.
