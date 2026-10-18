"""Modular OWASP 2021 heuristics; no credential guesses or extra requests."""

import re
from urllib.parse import urlsplit, parse_qsl, unquote

SQL_ERROR = re.compile(
    r"SQLITE_ERROR|SQL syntax.*?MySQL|PostgreSQL.*?ERROR|unclosed quotation mark|ORA-\d{5}|sqlite3\.OperationalError",
    re.I,
)
COVERAGE = {
    "A01:2021": "Listing/file/traversal heuristics; role and ownership tests not performed.",
    "A02:2021": "HTTP, mixed content and secret-material patterns; no cryptographic implementation audit.",
    "A03:2021": "Optional differential query probes; no exploit confirmation.",
    "A05:2021": "Response headers and error leakage.",
    "A07:2021": "Basic auth and discovered login paths; no credential guessing or session audit.",
    "A09:2021": "Public log heuristic only; logging, alerting and retention require manual review.",
}


def observe(
    add,
    r,
    check,
    title,
    why,
    fix,
    category,
    severity="low",
    verdict="suspected",
    **details
):
    add(check, title, severity, verdict, why, r, fix, owasp=category, **details)


def check_access_control(r, h, add):
    if 200 <= r["status"] < 300 and re.search(r"<title>\s*Index of /", r["body"], re.I):
        observe(
            add,
            r,
            "directory_listing",
            "Directory listing needs access review",
            "A directory-index title was returned. Intended access policy is unknown.",
            "Disable unintended listings and verify authorization.",
            "A01:2021",
        )
    if re.search(r"^root:[^\n:]*:0:0:", r["body"], re.M):
        observe(
            add,
            r,
            "system_file_exposure",
            "Possible system account file exposure",
            "Response resembles a Unix account file; traversal bypass is not established.",
            "Remove exposed files and verify path and authorization checks.",
            "A01:2021",
            "medium",
        )
    for parameter, value in parse_qsl(urlsplit(r["url"]).query):
        if "../" in unquote(value) or "..\\" in unquote(value):
            observe(
                add,
                r,
                "traversal_input",
                "Traversal-like input needs verification",
                "A crawled URL contains a traversal-like value. No bypass was demonstrated.",
                "Constrain file access to an allowlisted root.",
                "A01:2021",
                verdict="inconclusive",
                parameter=parameter,
            )


def check_crypto(r, h, add):
    if urlsplit(r["url"]).scheme == "http":
        observe(
            add,
            r,
            "http_transport",
            "Page served over HTTP",
            "This response used an unencrypted HTTP connection.",
            "Serve HTTPS and redirect HTTP to HTTPS.",
            "A02:2021",
            "medium",
            "confirmed",
        )
    patterns = {
        "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "credential_assignment": r"""["'](?:api_key|access_token|password)["']\s*:\s*["'][^"'\s]{12,}["']""",
    }
    for name, pattern in patterns.items():
        if re.search(pattern, r["body"], re.I):
            observe(
                add,
                r,
                "sensitive_response_" + name,
                "Possible sensitive material in response",
                "A secret-material pattern was observed. Values are not retained; validity requires review.",
                "Remove unintended secret material and rotate confirmed exposed credentials.",
                "A02:2021",
                "medium",
                signature_type=name,
            )


def check_misconfiguration(r, h, add):
    if (
        "text/html" not in h.get("content-type", "").lower()
        or not 200 <= r["status"] < 300
    ):
        return
    required = [
        (
            "content-security-policy",
            "Content Security Policy header absent",
            "Define a tested Content-Security-Policy.",
        ),
        (
            "x-content-type-options",
            "MIME-sniffing protection header absent",
            "Return X-Content-Type-Options: nosniff.",
        ),
        (
            "x-frame-options",
            "X-Frame-Options header absent",
            "Use CSP frame-ancestors or X-Frame-Options.",
        ),
    ]
    if urlsplit(r["url"]).scheme == "https":
        required.append(
            (
                "strict-transport-security",
                "HSTS header absent",
                "Assess HSTS after confirming HTTPS works.",
            )
        )
    for name, title, fix in required:
        if name not in h:
            if name == "x-frame-options" and re.search(
                r"(?:^|;)\s*frame-ancestors\s+",
                h.get("content-security-policy", ""),
                re.I,
            ):
                continue
            observe(
                add,
                r,
                "hsts" if name == "strict-transport-security" else name,
                title,
                "Header absent on this response; a configuration observation, not proof of exploitation.",
                fix,
                "A05:2021",
                verdict="confirmed",
            )


def check_authentication(r, h, add):
    if any(
        k.lower() == "www-authenticate" and re.search(r"\bbasic\b", v, re.I)
        for k, v in r["headers"]
    ):
        observe(
            add,
            r,
            "basic_auth",
            "HTTP Basic authentication challenge observed",
            "Basic authentication was advertised. No credentials were submitted.",
            "Require HTTPS and review credential policy.",
            "A07:2021",
            verdict="confirmed",
        )
    if (
        re.search(
            r"/(?:admin|login|wp-login\.php|phpmyadmin)(?:/|$)",
            urlsplit(r["url"]).path,
            re.I,
        )
        and 200 <= r["status"] < 300
    ):
        observe(
            add,
            r,
            "authentication_surface",
            "Authentication or administration path discovered",
            "A common login/admin path returned success. Default credentials and bypass are not established.",
            "Review access restrictions, MFA and default-account removal.",
            "A07:2021",
            "info",
            "inconclusive",
        )


def check_error_logging(r, h, add):
    if re.search(
        r"Traceback \(most recent call last\):|Fatal error:.*? on line \d+|Exception in thread|\bat [\w.$]+\([^\n]+\.java:\d+\)",
        r["body"],
    ):
        observe(
            add,
            r,
            "stack_trace",
            "Detailed error or stack trace exposed",
            "A stack-trace pattern was found; raw trace content is not retained.",
            "Return generic errors; keep details in access-controlled logs.",
            "A05:2021",
        )
    if urlsplit(r["url"]).path.lower().endswith(".log") and re.search(
        r"(?m)^.*\b(?:ERROR|WARN|INFO)\b.+", r["body"]
    ):
        observe(
            add,
            r,
            "public_log",
            "Possible public log content",
            "Log-like content observed. Logging effectiveness requires manual review.",
            "Restrict log access and verify event capture, redaction and alerting.",
            "A09:2021",
        )


RESPONSE_CHECKS = (
    check_access_control,
    check_crypto,
    check_misconfiguration,
    check_authentication,
    check_error_logging,
)


def check_injection(baseline, baseline_evidence, probe, kind, marker, parameter, add):
    details = {
        "parameter": parameter,
        "baseline": baseline_evidence,
        "probe_kind": kind,
        "owasp": "A03:2021",
    }
    if kind == "reflection" and marker in probe["body"]:
        add(
            "reflection",
            "Query input reflected in response",
            "info",
            "inconclusive",
            "A harmless marker appeared in the response. This is not confirmed XSS.",
            probe,
            "Apply context-appropriate output encoding.",
            marker=marker,
            **details
        )
    if kind == "sql_error":
        match = SQL_ERROR.search(probe["body"])
        if match and not SQL_ERROR.search(baseline["body"]):
            add(
                "sql_error",
                "Database error appeared after query mutation",
                "medium",
                "suspected",
                "A quote introduced a database-error signature absent from baseline. Exploitability is unverified.",
                probe,
                "Use parameterized queries.",
                signature=match.group(0)[:100],
                **details
            )
