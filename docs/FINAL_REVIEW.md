# Final review and patch notes

## Implemented changes

- Root contains README, launcher, Compose files and source/configuration. Auxiliary Markdown lives under `docs/`; older update notes live under `docs/archive/`; manifests live under `docs/manifests/`.
- Moved the backup-preserving merge script to `scripts/Apply-Update.ps1` and adjusted its project-root/manifest resolution.
- Added `start-demo.ps1`: PowerShell 5.1-compatible syntax, path-safe invocation, hidden missing-key input, four-file Compose validation, Linux-engine check, health waiting, local API/UI checks, stop/config-only modes and noninteractive failures.
- Compose passes ArmorIQ consistently to scanner/gateway, respects configured lab origins in the fixture overlay, and waits for fixture health before starting the DevOps gateway.
- Executor resolves Linux Bash or Git for Windows Bash. It rejects a WSL launcher fallback, preserves only required Windows OS environment, does not inherit provider keys or Bash startup hooks, and shell-quotes the operator workspace for the fixed disk command. Container workspace remains `/workspace`; native development defaults to the bundled lab directory.
- Windows uptime uses `GetTickCount64`; Linux uses `/proc/uptime`. Native cwd comparisons normalize filesystem paths. Actual Windows execution still needs validation on Windows.
- ArmorIQ normalizes string/enum actions, requires strict `allowed=True` plus action `allow`, treats blank keys as unavailable, and closes failed sessions safely and idempotently.
- HTTPS tests generate ephemeral localhost certificates with Python cryptography (already an SDK dependency), removing OpenSSL CLI and Git Bash argument-conversion dependencies.
- WAF integration suites moved to `tests/integration/`; plain unit-test discovery no longer requires live WAF ports.
- Corrected host API port 8000 → 8010 in deployment and candidate-evidence helpers.
- Added portability, compiler boundary and launcher failure-path tests; compiler rejects arbitrary template/scope and ignores advisory rule text.

## Verification

| Check | Result |
| --- | --- |
| Python unit suite (`unittest discover -s tests -v`) | 111 passed |
| Synthetic fixture suite | 4 passed |
| Frontend API/grouping tests | 6 passed |
| React production build | Passed |
| Actual Docker Compose CLI v2.39.4: base, fixture and full merged config | Passed |
| Actual launcher `-CheckOnly` from a different working directory | Passed; temporary .env removed |
| PowerShell 7.4.6 launcher scenarios with mocked Docker/HTTP | 7 passed |
| Actual PowerShell updater against an isolated copy of the uploaded project | Passed; configuration preserved, old files backed up |

The Python suite emits a Starlette/httpx deprecation warning in this runtime; it reports no failures or errors. PowerShell source parses successfully. The supplied test harness chooses its installed PowerShell executable on Windows or Linux.

A full Linux container build, live ArmorIQ cloud ALLOW/BLOCK, Windows PowerShell 5.1 runtime, actual Git for Windows execution and visual/video playback still require the operator machine. Passing configuration and unit checks is not evidence those live checks succeeded.

## Apply the exact patch

`docs/patches/final-touches.patch` is a Git patch against the uploaded ZIP's original source. It includes new files, renames/deletions and code changes; it intentionally does not include itself. Extract that one patch into a separate directory, then run from your original source checkout:

```text
git apply --check /path/to/final-touches.patch
git apply /path/to/final-touches.patch
```

For a project with your own uncommitted changes, inspect the diff first. Do not force a failed patch. The supplied full source ZIP already contains all changes, so do not apply the patch again to that updated tree.

The historical updater preserves custom `.env` and Compose files and backs up replaced/relocated files. Its preservation behavior means Compose changes need manual review against this patch on an older installation. The full release ZIP contains the current four Compose files.
