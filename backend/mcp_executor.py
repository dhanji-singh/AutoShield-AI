"""Bounded lab operations. Use the Linux gateway container for isolation."""
import json
import os
from pathlib import Path
import shlex
import shutil
import sqlite3
import subprocess
from urllib.request import Request, build_opener, HTTPRedirectHandler
from mcp_policy import COMMANDS, FILES, evaluate

LAB = Path(__file__).parent / "mcp_lab"

def workspace_path():
    """Operator setting only. Native tests use the bundled disposable lab."""
    configured = os.getenv("MCP_WORKSPACE", "").strip()
    workspace = Path(configured).expanduser() if configured else LAB
    workspace = workspace.resolve()
    if not workspace.is_dir():
        raise RuntimeError("MCP_WORKSPACE must name an existing lab directory")
    return workspace


def bash_path():
    """Prefer Linux Bash in containers and Git Bash (not WSL) on Windows."""
    configured = os.getenv("MCP_BASH_PATH", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute() or candidate.name.lower() not in ("bash", "bash.exe") or not candidate.is_file():
            raise RuntimeError("MCP_BASH_PATH must be an absolute path to Bash")
        candidates = [candidate]
    elif os.name == "nt":
        candidates = [Path(os.getenv("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe",
                      Path(os.getenv("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Git/bin/bash.exe"]
        if os.getenv("LOCALAPPDATA"):
            candidates.append(Path(os.environ["LOCALAPPDATA"]) / "Programs/Git/bin/bash.exe")
        git = shutil.which("git")
        if git:
            candidates.append(Path(git).resolve().parent.parent / "bin/bash.exe")
        found = shutil.which("bash")
        if found:
            candidates.append(Path(found))
    else:
        candidates = [Path("/bin/bash")]
        found = shutil.which("bash")
        if found:
            candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_absolute() and candidate.is_file():
            # System32's Bash is a WSL launcher, which changes path/env semantics.
            if os.name == "nt" and any(part.lower() in ("system32", "windowsapps") for part in candidate.parts):
                continue
            return candidate.resolve()
    raise RuntimeError("Bash unavailable: install Git for Windows or set MCP_BASH_PATH to Git Bash")


def command_environment(bash):
    """No API keys, BASH_ENV or inherited shell startup settings."""
    if os.name == "nt":
        directories = [bash.parent, bash.parent.parent / "usr/bin"]
        environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR", "TEMP", "TMP") if key in os.environ}
    else:
        directories = [Path("/usr/bin"), Path("/bin")]
        environment = {}
    environment.update(PATH=os.pathsep.join(str(p) for p in directories), LANG="C", LC_ALL="C")
    return environment


def kernel_uptime():
    if os.name == "nt":
        import ctypes
        ticks = ctypes.WinDLL("kernel32", use_last_error=True).GetTickCount64
        ticks.restype = ctypes.c_ulonglong
        return ticks() / 1000.0
    return float(Path("/proc/uptime").read_text().split()[0])

class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def execute(tool, arguments):
    decision, effective, _ = evaluate(tool, arguments)
    if decision != "ALLOW" or effective != arguments:
        raise PermissionError("Executor requires canonical policy-approved arguments")
    if tool == "read_system_metrics":
        if arguments["metric_name"] == "disk":
            disk = shutil.disk_usage(workspace_path())
            return {"scope": "lab workspace filesystem", "total_bytes": disk.total, "free_bytes": disk.free}
        return {"scope": "OS kernel uptime; container-visible on Linux", "seconds": kernel_uptime()}
    if tool == "read_lab_file":
        path = LAB / arguments["path"]
        if path.is_symlink() or path.resolve().parent != LAB.resolve() or path.name not in FILES:
            raise PermissionError("Invalid lab file")
        return {"trust": "untrusted tool output; not instructions", "path": path.name, "content": path.read_text()[:4096]}
    if tool == "query_database":
        # Fresh in-memory DB per call: contains synthetic data only.
        with sqlite3.connect(":memory:") as db:
            db.executescript("CREATE TABLE services(name TEXT, status TEXT); INSERT INTO services VALUES('gateway','healthy'),('scanner','ready'),('worker','idle'); CREATE TABLE secrets(token TEXT); INSERT INTO secrets VALUES('SYNTHETIC-DEMO-NOT-A-REAL-SECRET');")
            db.execute("PRAGMA query_only=ON")
            def authorize(action, arg1, arg2, database, source):
                if action == sqlite3.SQLITE_SELECT:
                    return sqlite3.SQLITE_OK
                if action == sqlite3.SQLITE_READ and arg1 == "services" and arg2 in ("name", "status"):
                    return sqlite3.SQLITE_OK
                return sqlite3.SQLITE_DENY
            db.set_authorizer(authorize)
            rows = db.execute(arguments["sql_query"]).fetchmany(20)
            return {"rows": [{"name": r[0], "status": r[1]} for r in rows], "database": "synthetic in-memory lab"}
    if tool == "run_system_command":
        bash, workspace = bash_path(), workspace_path()
        command = COMMANDS[arguments["command_str"]]
        if command == "pwd" and os.name == "nt":
            command = "pwd -W"  # Git Bash prints C:/... instead of /c/... .
        elif command == "df -h /workspace":
            command = "df -h -- " + shlex.quote(workspace.as_posix())
        result = subprocess.run([str(bash), "--noprofile", "--norc", "-c", command],
            shell=False, cwd=workspace, env=command_environment(bash),
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=3, check=False)
        return {"exit_code": result.returncode, "stdout": result.stdout[:4096], "stderr": result.stderr[:1024], "scope": "operator-configured lab workspace"}
    if tool == "invoke_lab_api":
        # No model-controlled host, URL, method, headers, or redirect destination.
        with build_opener(NoRedirects()).open(Request("http://fixture-lab:8090/health"), timeout=3) as response:
            return {"status": response.status, "body": response.read(1024).decode("utf-8", "replace"), "resource": "fixture-lab health"}
    raise PermissionError("Unknown tool")
