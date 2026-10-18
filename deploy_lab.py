import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


ROOT = Path(__file__).resolve().parent
DEPLOYMENT = ROOT / "deployment"
ACTIVE = DEPLOYMENT / "active.conf"
STATE = DEPLOYMENT / "state.json"
LOCK = DEPLOYMENT / "controller.lock"

API = "http://127.0.0.1:8010"
PROTECTED = "http://127.0.0.1:8083"

CANDIDATE_RULE_PATH = (
    "/etc/modsecurity.d/owasp-crs/rules/"
    "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
)

BASELINE_CONTENT = b"# AutoShield initial state: baseline CRS only.\n"


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = build_opener(ProxyHandler({}), NoRedirects())


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(content):
    return hashlib.sha256(content).hexdigest()


def api_get(path):
    with OPENER.open(API + path, timeout=10) as response:
        return json.load(response)


def docker(*args):
    result = subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )

    if result.returncode:
        raise RuntimeError(result.stdout + "\n" + result.stderr)

    return result.stdout, result.stderr


def container_id(service):
    output, _ = docker("compose", "ps", "-q", service)
    value = output.strip()

    if not value:
        raise RuntimeError(f"{service} is not running")

    return value


def atomic_write(path, content):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")

    try:
        with temporary.open("wb") as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temporary, path)

    finally:
        temporary.unlink(missing_ok=True)


def save_state(state):
    atomic_write(
        STATE,
        json.dumps(state, indent=2).encode("utf-8"),
    )


def http_status(query):
    request = Request(
        PROTECTED + "/rest/products/search?" + urlencode(query),
        headers={
            "User-Agent": "AutoShield-Lab-Deployment/0.1",
            "Connection": "close",
        },
    )

    try:
        with OPENER.open(request, timeout=5) as response:
            return response.status

    except HTTPError as exc:
        code = exc.code
        exc.close()
        return code


def verify_runtime(cid, expected_ids):
    # Verify normal traffic through fresh connections.
    for query in ("apple", "banana"):
        if http_status({"q": query}) != 200:
            raise RuntimeError(f"Normal request failed: {query}")

    # Correlate a new blocking probe with its exact audit transaction.
    started = now()
    probe_id = uuid.uuid4().hex

    code = http_status({
        "q": "' OR 1=1--",
        "_autoshield_deploy_probe": probe_id,
    })

    if code != 403:
        raise RuntimeError(f"Blocking probe returned HTTP {code}")

    expected = {str(value) for value in expected_ids}

    for _ in range(5):
        stdout, stderr = docker("logs", "--since", started, cid)

        for line in (stdout + "\n" + stderr).splitlines():
            try:
                audit = json.loads(line)
            except ValueError:
                continue

            if not isinstance(audit, dict):
                continue

            transaction = audit.get("transaction", {})
            uri = transaction.get("request", {}).get("uri", "")
            parameters = parse_qs(urlsplit(uri).query)

            if parameters.get("_autoshield_deploy_probe") != [probe_id]:
                continue

            messages = transaction.get("messages", [])
            ids = {
                str(item.get("details", {}).get("ruleId"))
                for item in messages
            }

            has_autoshield_message = any(
                str(item.get("message", "")).startswith(
                    "AutoShield candidate "
                )
                for item in messages
            )

            blocked = (
                transaction.get("is_interrupted") is True
                and transaction.get("response", {}).get("http_code") == 403
            )

            # Baseline rollback must not retain an AutoShield match
            # on this probe.
            correct_rule = (
                bool(ids & expected)
                if expected
                else not has_autoshield_message
            )

            if blocked and correct_rule:
                return {
                    "probe_id": probe_id,
                    "transaction_id": transaction.get("unique_id"),
                    "matched_rule_ids": sorted(ids),
                    "verified_at": now(),
                }

        time.sleep(0.5)

    raise RuntimeError("Expected runtime rule attribution was not observed")


def reload_and_verify(cid, expected_ids):
    docker("exec", cid, "nginx", "-t")
    docker("exec", cid, "nginx", "-s", "reload")

    # Reload acknowledgment is not proof that new workers are ready.
    last_error = None

    for _ in range(4):
        try:
            return verify_runtime(cid, expected_ids)
        except Exception as exc:
            last_error = exc
            time.sleep(1)

    raise RuntimeError(f"Post-reload verification failed: {last_error}")


def rollback(state):
    state["status"] = "rolling_back"
    save_state(state)

    backup = DEPLOYMENT / state["backup_file"]
    previous = backup.read_bytes()

    if digest(previous) != state["previous_sha256"]:
        raise RuntimeError("Backup hash mismatch; rollback stopped")

    cid = container_id("enforcement-waf")
    atomic_write(ACTIVE, previous)

    state["rollback_evidence"] = reload_and_verify(cid, [])
    state["status"] = "rolled_back"
    state["rolled_back_at"] = now()
    save_state(state)

    print("Rollback verified: baseline CRS restored.")


def promote(run_id):
    if STATE.exists():
        current_state = json.loads(STATE.read_text(encoding="utf-8"))

        if current_state.get("status") != "rolled_back":
            raise RuntimeError(
                "A deployment is active or incomplete. "
                "Run rollback before another promotion."
            )

    # This first controller supports baseline -> proposal -> baseline.
    previous = ACTIVE.read_bytes()

    if previous != BASELINE_CONTENT:
        raise RuntimeError(
            "Expected the initial baseline-only active.conf. "
            "Do not overwrite it manually; inspect deployment state."
        )

    history = api_get("/validations?limit=100")["validation_runs"]
    run = next((item for item in history if item["id"] == run_id), None)

    if run is None:
        raise RuntimeError("Validation run not found in the latest 100 runs")

    report = run["report"]
    cases = report.get("cases", [])
    counts = report.get("counts", {})

    if (
        len(cases) != 8
        or run["status"] != "review_required"
        or counts.get("pass", 0) < 7
        or any(
            case.get("verdict") not in ("pass", "known_application_issue")
            for case in cases
        )
        or any(
            case.get("verdict") == "known_application_issue"
            and case.get("case") != "known_apostrophe_issue"
            for case in cases
        )
    ):
        raise RuntimeError("Validation run is not eligible for this lab demo")

    proposal_id = run["proposal_id"]
    compiled = api_get(f"/proposals/{proposal_id}/compiled")
    content = compiled["content"].encode("utf-8")

    if digest(content) != run["compiled_sha256"]:
        raise RuntimeError("Compiled rule differs from the validation run")

    # This probe suite currently supports the numeric-tautology template.
    proposal = api_get("/proposals?limit=100")["proposals"]
    selected = next(
        (item for item in proposal if item["id"] == proposal_id),
        None,
    )

    if (
        selected is None
        or selected["policy"]["template_ids"]
        != ["search_numeric_tautology_v1"]
    ):
        raise RuntimeError("This lab controller supports numeric SQLi only")

    evidence = api_get(f"/validations/{run_id}/evidence")["evidence"]

    if not any(
        item["report"].get("candidate_match_verified") is True
        and item["report"].get("expected_compiled_sha256")
        == run["compiled_sha256"]
        for item in evidence
    ):
        raise RuntimeError("Matching attached probe evidence is missing")

    candidate = container_id("candidate-waf")
    enforcement = container_id("enforcement-waf")

    candidate_info = json.loads(docker("inspect", candidate)[0])[0]
    enforcement_info = json.loads(docker("inspect", enforcement)[0])[0]

    if candidate_info["Image"] != enforcement_info["Image"]:
        raise RuntimeError("Candidate and enforcement image IDs differ")

    candidate_hash = docker(
        "exec", candidate, "sha256sum", CANDIDATE_RULE_PATH
    )[0].split()[0]

    if candidate_hash != run["compiled_sha256"]:
        raise RuntimeError("Current candidate rule file differs from validation")

    # Confirm the current baseline works before changing its rule file.
    docker("exec", enforcement, "nginx", "-t")
    verify_runtime(enforcement, [])

    deployment_id = uuid.uuid4().hex
    backup_name = f"backup-{deployment_id}.conf"

    with (DEPLOYMENT / backup_name).open("xb") as file:
        file.write(previous)
        file.flush()
        os.fsync(file.fileno())

    state = {
        "deployment_id": deployment_id,
        "mode": "local_lab_demo",
        "status": "prepared",
        "validation_run_id": run_id,
        "proposal_id": proposal_id,
        "previous_sha256": digest(previous),
        "candidate_sha256": digest(content),
        "backup_file": backup_name,
        "created_at": now(),
        "production_ready": False,
    }

    save_state(state)

    try:
        atomic_write(ACTIVE, content)

        state["promotion_evidence"] = reload_and_verify(
            enforcement,
            compiled["rule_ids"],
        )

        state["status"] = "active"
        state["activated_at"] = now()
        save_state(state)

        print("Lab promotion verified on port 8083.")
        print(json.dumps(state, indent=2))

    except Exception as exc:
        state["promotion_error"] = str(exc)
        save_state(state)
        print(f"Promotion failed: {exc}\nRestoring baseline...")
        rollback(state)
        raise RuntimeError("Promotion failed; baseline rollback was verified")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["promote", "rollback"])
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--lab-demo", action="store_true")
    args = parser.parse_args()

    if not args.lab_demo:
        parser.error("Use --lab-demo: this controller is for the local lab")

    if args.action == "promote" and args.run_id is None:
        parser.error("Promotion requires --run-id")

    DEPLOYMENT.mkdir(exist_ok=True)

    try:
        lock_fd = os.open(
            LOCK,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
        )
    except FileExistsError:
        raise RuntimeError(
            "Controller lock exists. Check whether another deployment "
            "is running before investigating recovery."
        )

    os.close(lock_fd)

    try:
        if args.action == "promote":
            promote(args.run_id)
        else:
            if not STATE.exists():
                raise RuntimeError("No deployment state exists")

            state = json.loads(STATE.read_text(encoding="utf-8"))
            rollback(state)

    finally:
        LOCK.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Controller error: {exc}", file=sys.stderr)
        sys.exit(1)