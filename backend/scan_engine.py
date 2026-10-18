"""Bounded, same-origin HTTP assessment. No shell or model-generated execution."""
from scan_settings import default_max_pages, default_verify_ssl, page_limit
from scan_identity import finding_fingerprint
from scan_checks import RESPONSE_CHECKS, COVERAGE, check_injection
import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

MAX_BODY = 262144
SENSITIVE = re.compile(r"password|passwd|secret|token|api.?key|authorization|session|cookie|code", re.I)
UNSAFE_PATH = re.compile(r"(?:^|[/_.-])(logout|delete|remove|destroy|unsubscribe|signout|purchase|checkout)(?:$|[/_.-])", re.I)
LIMITATIONS = [
    "HTTP(S) crawl: JavaScript is not executed; SPA routes and hidden APIs may be missed.",
    "No authenticated sessions, role-based access-control tests, POST submissions, file uploads, or destructive tests.",
    "Checks cover selected OWASP 2021 response heuristics and optional query probes, not a full Top 10 audit.",
    "A reflected marker does not prove XSS; a database error does not prove exploitable SQL injection.",
    "No findings does not mean the target is secure. Out-of-scope redirects are not followed.",
]


class ScopeError(ValueError):
    pass


class StopScan(Exception):
    pass


def canonical_url(value):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 33 for c in value) or "\\" in value:
        raise ScopeError("Invalid URL")
    if value.startswith('//'):
        value = 'https:' + value
    elif '://' not in value:
        if re.match(r'^(?:file|ftp|javascript|data|mailto):', value, re.I):
            raise ScopeError('Unsupported URL scheme')
        value = 'https://' + value
    p = urlsplit(value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
        raise ScopeError("Use an HTTP(S) URL without embedded credentials")
    try:
        host = p.hostname.encode("idna").decode("ascii").lower()
        port = p.port or (443 if p.scheme == "https" else 80)
    except (ValueError, UnicodeError):
        raise ScopeError("Invalid host or port") from None
    if not 1 <= port <= 65535:
        raise ScopeError("Invalid port")
    display = f"[{host}]" if ":" in host else host
    default = 443 if p.scheme == "https" else 80
    netloc = display if port == default else f"{display}:{port}"
    return urlunsplit((p.scheme, netloc, p.path or "/", p.query, ""))


def origin(value):
    p = urlsplit(canonical_url(value))
    return f"{p.scheme}://{p.netloc}"


def redact_url(value):
    p = urlsplit(value)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode([
        (k, "[REDACTED]" if SENSITIVE.search(k) else v)
        for k, v in parse_qsl(p.query, keep_blank_values=True)
    ]), ""))


class Scope:
    def __init__(self, target, lab_origins=()):
        self.target = canonical_url(target)
        self.origin = origin(self.target)
        self.lab = self.origin in {origin(x) for x in lab_origins}
        if any(SENSITIVE.search(k) for k, _ in parse_qsl(urlsplit(self.target).query)):
            raise ScopeError("Remove credentials or secret query parameters from the target URL")

    def check(self, value):
        value = canonical_url(value)
        if origin(value) != self.origin:
            raise ScopeError("URL is outside the selected origin")
        path = urlsplit(value).path
        if UNSAFE_PATH.search(path):
            raise ScopeError("State-changing-looking URL excluded")
        if any(SENSITIVE.search(k) for k, _ in parse_qsl(urlsplit(value).query)):
            raise ScopeError("Sensitive query parameter excluded")
        return value

    def resolve(self, value):
        p = urlsplit(self.check(value))
        port = p.port or (443 if p.scheme == "https" else 80)
        answers = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(item[4][0] for item in answers))
        if not addresses:
            raise ScopeError("Target resolved to no addresses")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not self.lab and (not ip.is_global or ip.is_multicast):
                raise ScopeError("Private/reserved addresses require an operator-configured lab origin")
        return addresses[0], port


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout, verify_ssl=True):
        context = ssl.create_default_context()
        if not verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=context)
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class Transport:
    def __init__(self, scope, request_budget, delay, cancelled, max_seconds=180):
        self.scope, self.budget, self.delay = scope, request_budget, delay
        self.cancelled = cancelled
        self.verify_ssl = True
        self.count = 0
        self.last = 0
        self.deadline = time.monotonic() + max_seconds

    def check_stop(self):
        if self.cancelled():
            raise StopScan("cancelled")
        if time.monotonic() >= self.deadline:
            raise StopScan("time limit reached")

    def fetch(self, url):
        self.check_stop()
        if self.count >= self.budget:
            raise StopScan("request budget reached")
        url = self.scope.check(url)
        while time.monotonic() - self.last < self.delay:
            self.check_stop()
            time.sleep(0.05)
        address, port = self.scope.resolve(url)
        self.check_stop()
        p = urlsplit(url)
        conn = (PinnedHTTPS(p.hostname, port, address, 5, self.verify_ssl) if p.scheme == "https"
                else http.client.HTTPConnection(address, port, timeout=5))
        self.count += 1
        started = time.monotonic()
        try:
            conn.request("GET", urlunsplit(("", "", p.path or "/", p.query, "")), headers={
                "Host": p.netloc, "User-Agent": "AutoShield-Assessment/0.4",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            response = conn.getresponse()
            headers = response.getheaders()
            chunks, size = [], 0
            while size <= MAX_BODY:
                self.check_stop()
                chunk = response.read1(min(8192, MAX_BODY + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            # No cookie values or full response bodies are persisted.
            body = raw[:MAX_BODY].decode("utf-8", errors="replace")
            return {"url": url, "status": response.status, "headers": headers,
                    "body": body, "truncated": len(raw) > MAX_BODY,
                    "body_sha256": hashlib.sha256(raw[:MAX_BODY]).hexdigest(),
                    "elapsed_ms": round((time.monotonic() - started) * 1000)}
        finally:
            conn.close()
            self.last = time.monotonic()


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.assets, self.forms = [], [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag in ("script", "img", "iframe", "link"):
            value = attrs.get("src") or attrs.get("href")
            if value:
                self.assets.append(value)
        if tag == "form":
            self.forms.append({"method": attrs.get("method", "get").upper(), "action": attrs.get("action", "")})


def header_map(response):
    return {k.lower(): v for k, v in response["headers"]}


def evidence(response, **extra):
    return {"url": redact_url(response["url"]), "method": "GET", "status": response["status"],
            "body_sha256": response["body_sha256"], "body_truncated": response["truncated"],
            "elapsed_ms": response["elapsed_ms"], **extra}


def assess(target, options, cancelled=lambda: False, progress=lambda report: None, lab_origins=(), transport_factory=Transport):
    options = dict(options)
    max_pages = page_limit(options['max_pages'] if 'max_pages' in options else default_max_pages())
    verify_ssl = options['verify_ssl'] if 'verify_ssl' in options else default_verify_ssl()
    if type(verify_ssl) is not bool:
        raise ValueError('verify_ssl must be boolean')
    scope = Scope(target, lab_origins)
    if not verify_ssl and not scope.lab:
        raise ScopeError('Disabling TLS verification requires a configured lab origin')
    transport = transport_factory(scope, options["max_requests"], options["delay_seconds"], cancelled)
    transport.verify_ssl = verify_ssl
    transport.deadline = time.monotonic() + options.get('max_seconds', 900)
    report = {"target": redact_url(scope.target), "origin": scope.origin, "status": "running",
              "pages": [], "findings": [], "errors": [], "requests_sent": 0,
              "coverage": {"mode": options["mode"], "pages_checked": 0, "query_parameters_probed": 0, "max_pages": max_pages, "verify_ssl": verify_ssl, "owasp_2021": dict(COVERAGE)},
              "limitations": LIMITATIONS[:], "stop_reason": None,
              "timeline": [], "check_runs": [], "current_activity": "Starting assessment"}
    if not verify_ssl:
        report['limitations'].append('TLS certificate verification disabled explicitly for this lab; server identity was not authenticated.')
    if options['mode'] == 'passive':
        report['coverage']['owasp_2021']['A03:2021'] = 'Not run: passive mode; no active injection probes.'
    report['coverage']['request_transport'] = 'MCP stdio + required ArmorIQ' if hasattr(transport, 'set_context') else 'Direct transport (library/test use)'
    seen_findings = set()

    def emit(stage, message, **details):
        report["requests_sent"] = transport.count
        report["current_activity"] = message
        report["timeline"].append({"id": len(report["timeline"]) + 1,
            "at": datetime.now(timezone.utc).isoformat(), "stage": stage,
            "message": message, **details})
        progress(report)

    def failure(exc):
        if isinstance(exc, socket.gaierror):
            return "DNS lookup failed. For the Docker lab, start the proxy and juice-shop services."
        if isinstance(exc, ConnectionRefusedError):
            return "Connection refused. Check that the target service is running and listening."
        if isinstance(exc, (TimeoutError, socket.timeout)):
            return "Target timed out. Check target health and network connectivity."
        if isinstance(exc, ssl.SSLCertVerificationError):
            return 'TLS certificate verification failed. Install a trusted lab CA or explicitly set verify_ssl=false for a configured lab.'
        if isinstance(exc, ssl.SSLError):
            return "TLS connection failed. Check the target certificate and HTTPS configuration."
        if isinstance(exc, ScopeError):
            return "Request excluded by scope policy. Check the configured target origin."
        return "Request failed (" + type(exc).__name__ + "). Check target health and connectivity."

    def fetch_logged(url, check, parameter=None, baseline=None):
        run = {"id": len(report["check_runs"]) + 1, "check": check,
               "url": redact_url(url), "parameter": parameter, "status": "running",
               "started_at": datetime.now(timezone.utc).isoformat(), "finding_ids": []}
        if baseline is not None:
            run["baseline"] = evidence(baseline)
        report["check_runs"].append(run)
        emit("request", "Running " + check, check_run_id=run["id"], url=run["url"])
        try:
            if hasattr(transport, 'set_context'):
                transport.set_context(check)
            response = transport.fetch(url)
            if getattr(transport, 'last_policy', None):
                run['gateway'] = transport.last_policy
                emit('gateway', 'ArmorIQ allowed request', check_run_id=run['id'], gateway=transport.last_policy)
        except StopScan as exc:
            run.update(status="stopped", reason=str(exc), finished_at=datetime.now(timezone.utc).isoformat())
            emit("stopped", str(exc), check_run_id=run["id"])
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if hasattr(exc, 'policy'):
                run.update(status='blocked', gateway=exc.policy, reason=str(exc), finished_at=datetime.now(timezone.utc).isoformat())
                report['errors'].append({'url': redact_url(url), 'error': str(exc), 'gateway': exc.policy})
                emit('gateway', 'Request blocked: ' + str(exc), check_run_id=run['id'], gateway=exc.policy)
                raise StopScan('Gateway blocked: ' + str(exc)) from None
            reason = str(exc) if hasattr(transport, 'last_policy') and isinstance(exc, ScopeError) else failure(exc)
            run.update(status="error", reason=reason, finished_at=datetime.now(timezone.utc).isoformat())
            report["errors"].append({"url": redact_url(url), "error": reason, "check_run_id": run["id"]})
            emit("error", reason, check_run_id=run["id"])
            return None, run
        run.update(status="response_received", response=evidence(response))
        emit("response", "Response received: HTTP " + str(response["status"]), check_run_id=run["id"])
        return response, run

    def finish_run(run, first_finding):
        run.update(status="completed", finished_at=datetime.now(timezone.utc).isoformat(),
                   finding_ids=[f["id"] for f in report["findings"][first_finding:]])
        run["outcome"] = "observations_recorded" if run["finding_ids"] else "no_observation"
        emit("check", "Completed " + run["check"], check_run_id=run["id"], outcome=run["outcome"])

    emit("session", "Assessment started")
    if options["mode"] == "passive":
        emit("skipped", "Active query probes were not run: passive mode selected")

    def add(check, title, severity, verdict, why, response, remediation, **details):
        finding = {"id": len(report["findings"]) + 1, "check": check,
            "title": title, "severity": severity, "verdict": verdict, "description": why,
            "evidence": evidence(response, **details), "remediation": remediation}
        key = finding_fingerprint(finding)
        if key in seen_findings:
            return
        seen_findings.add(key)
        finding['fingerprint'] = key
        report['findings'].append(finding)

    queue, visited, probe_keys = deque([(scope.target, 0)]), set(), set()
    scheduled = {scope.target}
    try:
        while queue and (not max_pages or len(report["pages"]) < max_pages):
            if cancelled():
                raise StopScan("cancelled")
            url, depth = queue.popleft()
            try:
                url = scope.check(url)
            except ValueError:
                continue
            if url in visited:
                continue
            visited.add(url)
            response, page_run = fetch_logged(url, "page_fetch")
            if response is None:
                continue
            finish_run(page_run, len(report["findings"]))
            headers = header_map(response)
            page = evidence(response, content_type=headers.get("content-type", ""), forms=[])
            report["pages"].append(page)
            report["coverage"]["pages_checked"] += 1
            if 300 <= response["status"] < 400 and headers.get("location"):
                try:
                    dest = scope.check(urljoin(url, headers["location"]))
                    if dest not in scheduled:
                        scheduled.add(dest)
                        queue.append((dest, depth))
                except ValueError:
                    page["redirect_skipped"] = "Redirect left scope or was excluded"
                    emit("skipped", page["redirect_skipped"], url=redact_url(url))
                continue
            first_finding = len(report["findings"])
            config_run = {"id": len(report["check_runs"]) + 1, "check": "response_configuration",
                "url": redact_url(url), "status": "running", "response": evidence(response),
                "started_at": datetime.now(timezone.utc).isoformat(), "finding_ids": []}
            report["check_runs"].append(config_run)
            emit("check", "Checking response configuration", check_run_id=config_run["id"])
            for check_function in RESPONSE_CHECKS:
                check_function(response, headers, add)
            html = "text/html" in headers.get("content-type", "").lower()
            if html and 200 <= response["status"] < 300:
                parser = PageParser()
                parser.feed(response["body"])
                page["forms"] = [{"method": f["method"], "action": redact_url(urljoin(url, f["action"]))} for f in parser.forms[:20]]
                if depth < options["max_depth"]:
                    for link in parser.links:
                        if len(queue) >= options["max_requests"] * 10:
                            break
                        try:
                            candidate = scope.check(urljoin(url, link))
                            if candidate not in scheduled and not re.search(r"\.(?:pdf|zip|png|jpg|jpeg|gif|mp4|exe|woff2?)$", urlsplit(candidate).path, re.I):
                                scheduled.add(candidate)
                                queue.append((candidate, depth + 1))
                        except ValueError:
                            pass
                mixed = [a for a in parser.assets if urljoin(url, a).startswith("http://")]
                if urlsplit(url).scheme == "https" and mixed:
                    add("mixed_content", "HTTP resources referenced by HTTPS page", "low", "confirmed", "The HTML references unencrypted resource URLs; browser loading behavior was not tested.", response, "Use HTTPS resource URLs.", resource_count=len(mixed))
            for key, value in response["headers"]:
                if key.lower() == "set-cookie":
                    flags = {part.strip().split("=", 1)[0].lower() for part in value.split(";")[1:]}
                    missing = [f for f in ("secure", "httponly", "samesite") if f not in flags]
                    if missing:
                        add("cookie_flags", "Cookie attributes need review", "low", "suspected", "A Set-Cookie header lacks recommended attributes. Cookie purpose and JavaScript requirements need review.", response, "Set Secure, HttpOnly and SameSite as appropriate for each cookie.", missing_attributes=missing)
            finish_run(config_run, first_finding)
            if options["mode"] == "active" and 200 <= response["status"] < 300:
                pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
                for index, (parameter, value) in enumerate(pairs[:5]):
                    key = (urlsplit(url).path, parameter)
                    if key in probe_keys or SENSITIVE.search(parameter) or len(value) > 200:
                        continue
                    probe_keys.add(key)
                    report["coverage"]["query_parameters_probed"] += 1
                    marker = "autoshield_" + uuid.uuid4().hex[:16]
                    for kind, replacement in [("reflection", marker), ("sql_error", value + "'")]:
                        changed = pairs[:]
                        changed[index] = (parameter, replacement)
                        p = urlsplit(url)
                        probe_url = urlunsplit((p.scheme, p.netloc, p.path, urlencode(changed), ""))
                        probe, probe_run = fetch_logged(probe_url, kind, parameter, response)
                        if probe is None:
                            continue
                        first_finding = len(report["findings"])
                        check_injection(response, evidence(response), probe, kind, marker, parameter, add)
                        finish_run(probe_run, first_finding)
            report["requests_sent"] = transport.count
            progress(report)
        report["status"] = "completed" if report["pages"] else "failed"
        if queue:
            report["stop_reason"] = "page limit reached"
    except StopScan as exc:
        report["stop_reason"] = str(exc)
        report["status"] = "cancelled" if str(exc) == "cancelled" else ("failed" if not report["pages"] and str(exc).startswith("Gateway blocked:") else "partial")
    report["requests_sent"] = transport.count
    if report["errors"] and report["status"] == "completed":
        report["status"] = "partial"
    if report["status"] == "failed" and not report["stop_reason"]:
        report["stop_reason"] = report["errors"][0]["error"] if report["errors"] else "No pages could be assessed."
    emit("session", "Assessment " + report["status"], reason=report["stop_reason"])
    return report
