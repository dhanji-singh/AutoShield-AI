import os
import importlib.util
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel, Field
from scan_settings import default_max_pages, default_verify_ssl

import scan_store as store
from scan_ai import AIUnavailable, REVIEW_VERSION, configuration, review_fingerprint, review_scan
from scan_engine import Scope, assess
from scan_mcp_client import MCPScanTransport, GatewayBlocked
from scan_report import render_html, render_comparison_html
from scan_compare import compare_scans

router = APIRouter(prefix="/scans", tags=["Web assessment"])
executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="autoshield-scan")
scan_lock = threading.Lock()
ai_lock = threading.Lock()
shutdown_event = threading.Event()


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    mode: Literal["passive", "active"] = "passive"
    max_pages: int | None = Field(default_factory=default_max_pages, ge=0, strict=True)
    verify_ssl: bool = Field(default_factory=default_verify_ssl, strict=True)
    max_seconds: int = Field(default=900, ge=1, le=86400)
    max_requests: int = Field(default=1000, ge=1, le=10000)
    max_depth: int = Field(default=2, ge=0, le=4)
    delay_seconds: float = Field(default=0.5, ge=0.25, le=5)
    ai_review: bool = False
    authorization_confirmed: bool = Field(default=False, strict=True)


def lab_origins():
    return tuple(x.strip() for x in os.getenv("AUTOSHIELD_LAB_ORIGINS", "http://proxy").split(",") if x.strip())


def initialize():
    shutdown_event.clear()
    store.initialize()


def shutdown():
    shutdown_event.set()


def load(scan_id):
    if not 1 <= scan_id < 9223372036854775807:
        raise HTTPException(422, "Invalid scan ID")
    try:
        return store.get(scan_id)
    except LookupError:
        raise HTTPException(404, "Scan not found") from None


def run_review(scan_id):
    if not ai_lock.acquire(blocking=False):
        raise HTTPException(409, "An AI review is already running")
    try:
        scan = load(scan_id)
        if scan["status"] in ("running", "queued"):
            raise HTTPException(409, "Wait for the scan to finish")
        try:
            provider, _, model = configuration()
            cached = scan.get("ai_review") or {}
            if (cached.get("status") == "completed" and
                    cached.get("provider", "gemini") == provider and cached.get("model") == model and
                    cached.get("review_version") == REVIEW_VERSION and
                    cached.get("input_sha256") == review_fingerprint(scan)):
                return cached
            review = review_scan(scan)
        except AIUnavailable as exc:
            review = {"status": "unavailable", "message": str(exc), "advisory_only": True}
        store.save_ai(scan_id, review)
        return review
    finally:
        ai_lock.release()


def worker(scan_id, target, options):
    try:
        initial = store.get(scan_id)["report"]
        initial["status"] = "running"
        store.save(scan_id, initial)
        cancelled = lambda: shutdown_event.is_set() or store.cancelled(scan_id)
        with MCPScanTransport(target, options, lab_origins(), cancelled) as transport:
            report = assess(target, options, cancelled=cancelled,
                progress=lambda r: store.save(scan_id, r), lab_origins=lab_origins(),
                transport_factory=lambda *args: transport)
        store.save(scan_id, report, final=True)
        if options["ai_review"] and report["status"] in ("completed", "partial") and not shutdown_event.is_set():
            try:
                run_review(scan_id)
            except Exception:
                store.save_ai(scan_id, {"status": "unavailable", "message": "AI review could not complete. Retry from the dashboard.", "advisory_only": True})
    except GatewayBlocked as exc:
        report = store.get(scan_id)['report']
        report.update(status='failed', stop_reason=str(exc), gateway=exc.policy)
        report.setdefault('errors', []).append({'error': str(exc), 'gateway': exc.policy})
        store.save(scan_id, report, final=True)
    except Exception as exc:
        # Keep saved evidence and avoid exposing raw network/provider exceptions.
        current = store.get(scan_id)
        report = current["report"]
        report.update(status="failed", stop_reason="Worker error: " + type(exc).__name__)
        store.save(scan_id, report, final=True)
    finally:
        scan_lock.release()


@router.post("", status_code=202)
def start_scan(request: ScanRequest):
    if not request.authorization_confirmed:
        raise HTTPException(422, "Confirm authorization for this target before starting a session")
    try:
        scope = Scope(request.target, lab_origins())
        if not request.verify_ssl and not scope.lab:
            raise ValueError("TLS verification must remain enabled for public targets")
        scope.check(scope.target)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if not scan_lock.acquire(blocking=False):
        raise HTTPException(409, "One scan is already running; stop it or wait for completion")
    try:
        options = request.model_dump(exclude={"target"})
        scan_id = store.create(scope.target, options)
        executor.submit(worker, scan_id, scope.target, options)
    except Exception:
        scan_lock.release()
        raise
    return {"id": scan_id, "status": "queued"}


@router.get("")
def list_scans(limit: int = Query(default=50, ge=1, le=100)):
    return {"scans": store.history(limit)}


@router.get("/readiness")
def scanner_readiness():
    """Local prerequisites only; never sends a target request or cloud check."""
    mcp_installed = importlib.util.find_spec("mcp") is not None
    armor_installed = importlib.util.find_spec("armoriq_sdk") is not None
    key_present = bool(os.getenv("ARMORIQ_API_KEY", "").strip())
    latest = None
    for row in store.history(10):
        report = store.get(row["id"])["report"] or {}
        for run in reversed(report.get("check_runs", [])):
            policy = run.get("gateway") or {}
            if policy.get("attribution") == "ArmorIQ":
                latest = {"scan_id": row["id"], "action": policy.get("action"),
                          "reason": policy.get("reason"), "at": run.get("finished_at") or run.get("started_at")}
                break
        if latest:
            break
    try:
        provider, _, model = configuration()
        ai = {"configured": True, "provider": provider, "model": model}
    except AIUnavailable:
        ai = {"configured": False}
    return {"backend": "reachable", "scanner_armoriq_mode": "required",
            "mcp_dependencies_installed": mcp_installed,
            "armoriq_sdk_installed": armor_installed, "armoriq_key_present": key_present,
            "prerequisites_ready": mcp_installed and armor_installed and key_present,
            "mcp_connection": "verified only when a scan opens its MCP session",
            "latest_recorded_armoriq_decision": latest, "ai_review": ai,
            "note": "Configuration is not cloud authorization. Each request still requires a fresh policy decision. No request was sent by this readiness check."}


@router.get("/{scan_id}")
def get_scan(scan_id: int):
    return load(scan_id)


@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: int):
    load(scan_id)
    store.cancel(scan_id)
    return {"id": scan_id, "status": load(scan_id)["status"], "cancel_requested": load(scan_id)["cancel_requested"]}


@router.post("/{scan_id}/ai-review")
def ai_review(scan_id: int):
    return run_review(scan_id)


@router.get("/{scan_id}/report")
def download_report(scan_id: int):
    return JSONResponse(load(scan_id), headers={"Content-Disposition": f'attachment; filename="autoshield-scan-{scan_id}.json"'})


@router.get("/{scan_id}/report.html")
def download_html_report(scan_id: int):
    return HTMLResponse(render_html(load(scan_id)), headers={
        "Content-Disposition": f'attachment; filename="autoshield-scan-{scan_id}.html"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })


@router.get("/{scan_id}/compare/{baseline_id}")
def compare_report(scan_id: int, baseline_id: int):
    current, baseline = load(scan_id), load(baseline_id)
    try:
        return compare_scans(baseline, current)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None


@router.get("/{scan_id}/compare/{baseline_id}/report.html")
def download_comparison_html(scan_id: int, baseline_id: int):
    comparison = compare_report(scan_id, baseline_id)
    return HTMLResponse(render_comparison_html(comparison), headers={
        "Content-Disposition": f'attachment; filename="autoshield-compare-{baseline_id}-to-{scan_id}.html"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    })
