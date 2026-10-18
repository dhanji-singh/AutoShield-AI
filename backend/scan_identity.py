"""Stable observation identity; raw probe markers are never part of identity."""

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def normalized_url(value):
    p = urlsplit(value)
    host = (p.hostname or "").encode("idna").decode("ascii").lower()
    if ":" in host:
        host = "[" + host + "]"
    if p.port and p.port != (443 if p.scheme.lower() == "https" else 80):
        host += ":" + str(p.port)

    def escape(match):
        char = chr(int(match[1], 16))
        return (
            char
            if char.isascii() and (char.isalnum() or char in "-._~")
            else "%" + match[1].upper()
        )

    path = re.sub(r"%([0-9a-fA-F]{2})", escape, p.path or "/")
    pairs = sorted(parse_qsl(p.query, keep_blank_values=True), key=lambda pair: pair[0])
    return urlunsplit((p.scheme.lower(), host, path, urlencode(pairs), ""))


def finding_fingerprint(finding):
    ev = finding.get("evidence") or {}
    baseline = ev.get("baseline") or {}
    identity = [
        finding.get("check") or finding.get("vuln_type") or finding.get("title"),
        normalized_url(baseline.get("url") or ev.get("url") or finding.get("url", "")),
        ev.get("parameter", finding.get("parameter")),
        ev.get("method", finding.get("http_method", "GET")).upper(),
    ]
    return hashlib.sha256(
        json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()


def deduplicate_findings(findings):
    seen, result = set(), []
    for finding in findings:
        ev = finding.get("evidence") or {}
        if not (
            ev.get("url") or (ev.get("baseline") or {}).get("url") or finding.get("url")
        ):
            # Preserve incomplete legacy records rather than collapse unrelated evidence.
            result.append(dict(finding))
            continue
        key = finding_fingerprint(finding)
        if key not in seen:
            seen.add(key)
            result.append({**finding, "fingerprint": key})
    return result
