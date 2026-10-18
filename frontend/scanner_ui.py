import json
from urllib.parse import urlsplit, parse_qsl
import requests
import streamlit as st


def api(base, method, path, raw=False, **kwargs):
    with requests.request(method, base + path, timeout=(5, 45), allow_redirects=False, **kwargs) as response:
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", "Request failed")
            except ValueError:
                detail = "Request failed"
            raise ValueError(f"HTTP {response.status_code}: {detail}")
        return response.text if raw else response.json()


def scanner_page(base):
    st.subheader("Start a testing session")
    st.caption("Public HTTP/HTTPS assessment · MCP + ArmorIQ enforcement")
    with st.form("new_scan"):
        target = st.text_input("Target URL", value="http://proxy/rest/products/search?q=apple",
                               help="Use an authorized public HTTP/HTTPS target, or a configured private lab origin. Every request requires ArmorIQ approval.")
        mode = st.selectbox("Scan mode", ["passive", "active"], format_func=lambda m: {
            "passive": "Crawl + response configuration checks",
            "active": "Crawl + query reflection and database-error probes",
        }[m])
        left, right = st.columns(2)
        max_pages = left.number_input("Maximum pages (0 = unlimited)", min_value=0, value=200)
        max_requests = right.number_input("Maximum HTTP requests", 1, 10000, 1000)
        depth = left.number_input("Link depth", 0, 4, 2)
        delay = right.number_input("Pause between requests (seconds)", 0.25, 5.0, 0.5, 0.25)
        verify_ssl = st.checkbox("Verify TLS certificates", value=True)
        max_seconds = st.number_input("Maximum scan seconds", 1, 86400, 900)
        ai = st.checkbox("Automatically review results with AI", value=False)
        st.caption("AI receives finding summaries and coverage only, excluding raw bodies, cookies and URL queries. Requires your configured AI provider key and model.")
        st.caption("Use targets within your testing scope. Same-origin redirects only. No form submissions, login attempts or JavaScript execution.")
        authorized = st.checkbox("I am authorized to test this target within the selected limits.", value=False)
        submitted = st.form_submit_button("Start authorized testing", type="primary")
    if submitted:
        try:
            result = api(base, "POST", "/scans", json={"target": target.strip(), "mode": mode,
                "max_pages": max_pages, "max_requests": max_requests, "max_depth": depth,
                "delay_seconds": delay, "verify_ssl": verify_ssl, "max_seconds": max_seconds, "ai_review": ai, "authorization_confirmed": authorized})
            st.session_state["scan_selected"] = result["id"]
            st.success(f"Scan #{result['id']} queued")
        except (requests.RequestException, ValueError) as exc:
            st.error(str(exc))
    scan_history(base)


@st.fragment(run_every=3)
def scan_history(base):
    try:
        rows = api(base, "GET", "/scans")["scans"]
        if not rows:
            st.info("Start a scan to collect evidence.")
            return
        st.dataframe(rows, hide_index=True, width="stretch")
        ids = [row["id"] for row in rows]
        if st.session_state.get("scan_selected") not in ids:
            st.session_state["scan_selected"] = ids[0]
        selected = st.selectbox("Inspect scan", ids, key="scan_selected", format_func=lambda n: f"Scan #{n}")
        scan = api(base, "GET", f"/scans/{selected}")
    except (requests.RequestException, ValueError) as exc:
        st.error(f"Could not load scans: {exc}")
        return
    report = scan["report"]
    cols = st.columns(4)
    cols[0].metric("Status", scan["status"])
    cols[1].metric("Requests sent", report.get("requests_sent", 0))
    cols[2].metric("Pages checked", len(report.get("pages", [])))
    cols[3].metric("Observations", len(report.get("findings", [])))
    if scan["status"] in ("running", "queued"):
        if st.button("Stop scan", key=f"cancel_{selected}", disabled=scan["cancel_requested"]):
            try:
                api(base, "POST", f"/scans/{selected}/cancel")
                st.info("Cancellation requested. The current network operation may take a few seconds to finish.")
            except (requests.RequestException, ValueError) as exc:
                st.error(str(exc))
    if report.get("stop_reason"):
        st.warning(report["stop_reason"])
    recon_tab, findings_tab, probes_tab, session_tab, reports_tab = st.tabs([
        "Reconnaissance", "Vulnerabilities", "Payloads & Probes", "Testing Session", "Reports"])
    with recon_tab:
        st.subheader("Discovered attack surface")
        st.caption("Observed HTTP pages and HTML forms only. JavaScript execution, port scanning and technology fingerprinting are not included.")
        pages = report.get("pages", [])
        if pages:
            st.dataframe([{"URL": page.get("url"), "Status": page.get("status"),
                "Content type": page.get("content_type", "unknown"),
                "Query parameters": ", ".join(dict.fromkeys(k for k, _ in parse_qsl(urlsplit(page.get("url", "")).query, keep_blank_values=True))),
                "Forms": len(page.get("forms", []))} for page in pages], hide_index=True, width="stretch")
            with st.expander("Saved page and form evidence"):
                st.json(pages)
        else:
            st.info("No pages recorded yet.")
    with findings_tab:
        st.caption("Confirmed means the stated observation was measured; it does not imply confirmed exploitability.")
        findings = report.get("findings", [])
        if findings:
            st.dataframe([{k: f[k] for k in ("id", "title", "severity", "verdict")} for f in findings], hide_index=True, width="stretch")
            for finding in findings:
                with st.expander(f"#{finding['id']} · {finding['title']}"):
                    st.text(finding["description"])
                    st.write("Evidence")
                    st.json(finding["evidence"])
                    st.write("Remediation")
                    st.text(finding["remediation"])
        elif scan["status"] not in ("queued", "running"):
            st.info("No observations were produced by these checks. This is not a security clearance.")
        if scan["status"] not in ("running", "queued"):
            st.subheader("AI review")
            st.caption("Advisory summary of saved findings. Model output cannot start tests or change finding verdicts.")
            if st.button("Generate / retrieve AI review", key=f"review_{selected}"):
                try:
                    with st.spinner("Reviewing findings..."):
                        scan["ai_review"] = api(base, "POST", f"/scans/{selected}/ai-review")
                except (requests.RequestException, ValueError) as exc:
                    st.error(str(exc))
            review = scan.get("ai_review")
            if review:
                if review.get("status") == "completed":
                    st.text(review["text"])
                    st.caption(f"Provider: {review.get('provider', 'gemini')} · Model: {review['model']} · {review['created_at']} · Advisory only")
                else:
                    st.info(review.get("message", "AI review unavailable"))

    with probes_tab:
        st.subheader("Supported probes")
        st.dataframe([
            {"Probe": "Query reflection", "Input": "Unique harmless marker", "Interpretation": "Reflection is not proof of XSS"},
            {"Probe": "Database error", "Input": "One quote appended to an existing value", "Interpretation": "Differential error signature; SQL injection remains suspected"},
        ], hide_index=True, width="stretch")
        st.caption("Active mode selects both probes. Passive mode sends neither. Eligibility rules and scan limits can prevent execution.")
        if report.get("coverage", {}).get("mode") == "passive":
            st.info("This session is passive: active query probes were not run.")
        st.subheader("Recorded probe findings")
        probes = [f for f in report.get("findings", []) if f.get("check") in ("reflection", "sql_error")]
        for finding in probes:
            with st.expander(f"#{finding['id']} · {finding['title']}"):
                st.json(finding.get("evidence", {}))
        if not probes:
            st.info("No probe findings are recorded. This does not establish that every probe ran or passed.")
        st.caption("Evidence includes saved request URLs, status codes and response hashes where available. Raw response bodies and a complete per-probe execution log are not retained.")
    with session_tab:
        st.subheader("Session scope and activity")
        st.text("Target: " + scan["target"])
        st.text("Origin: " + str(report.get("origin", "not recorded")))
        st.text("Started: " + str(scan.get("created_at", "")))
        st.text("Finished: " + str(scan.get("finished_at") or "Not finished"))
        if scan.get("options", {}).get("authorization_confirmed"):
            st.caption("Operator acknowledged authorization for this lab session. This is not DNS ownership verification.")
        else:
            st.caption("Legacy scan: no authorization acknowledgment was stored.")
        st.json(scan.get("options", {}))
        st.caption("Same-origin scope, bounded GET requests and the Stop scan control above govern this session. Counters refresh every 3 seconds; they are saved progress, not a complete request trace.")
        with st.expander("Coverage, errors and limitations", expanded=bool(report.get("errors"))):
            st.json(report.get("coverage", {}))
            for text in report.get("limitations", []):
                st.text(text)
            st.json(report.get("errors", []))
    with reports_tab:
        st.download_button("Download evidence report (JSON)", json.dumps(scan, indent=2),
                           file_name=f"autoshield-scan-{selected}.json", mime="application/json", key=f"download_{selected}")
        if st.button("Prepare HTML / PDF report", key=f"prepare_html_{selected}"):
            try:
                html = api(base, "GET", f"/scans/{selected}/report.html", raw=True)
                st.session_state[f"html_report_{selected}"] = html
            except (requests.RequestException, ValueError) as exc:
                st.error(str(exc))
        html = st.session_state.get(f"html_report_{selected}")
        if html:
            st.download_button("Download report (HTML)", html,
                file_name=f"autoshield-scan-{selected}.html", mime="text/html", key=f"html_download_{selected}")
            st.caption("Open the downloaded file in your browser → Ctrl+P → Save as PDF. Click Prepare again after changing the scan or AI review to refresh this snapshot.")

        st.subheader("Compare saved scans")
        st.caption("The inspected scan is Current. Choose another scan as Baseline. Comparison uses saved evidence and makes no new requests.")
        candidates = [row for row in rows if row["id"] != selected and row["status"] not in ("queued", "running")]
        if scan["status"] in ("queued", "running"):
            st.info("Wait for the current scan to finish before comparing.")
        elif not candidates:
            st.info("Two finished scans are needed for comparison.")
        else:
            baseline_id = st.selectbox("Baseline scan", [row["id"] for row in candidates],
                format_func=lambda n: f"Scan #{n}", key=f"baseline_{selected}")
            cache_key = f"comparison_{selected}_{baseline_id}"
            if st.button("Compare scans", key=f"compare_{selected}"):
                try:
                    st.session_state[cache_key] = api(base, "GET", f"/scans/{selected}/compare/{baseline_id}")
                except (requests.RequestException, ValueError) as exc:
                    st.session_state.pop(cache_key, None)
                    st.error(str(exc))
            comparison = st.session_state.get(cache_key)
            if comparison:
                st.write(f"Baseline #{baseline_id} → Current #{selected}")
                for warning in comparison["warnings"]:
                    st.warning(warning)
                st.info("No longer observed does not mean fixed. New means absent from this baseline. Counts represent matched observation groups.")
                labels = [("new", "New"), ("repeated", "Repeated"), ("no_longer_observed", "No longer observed")]
                for column, (key, label) in zip(st.columns(3), labels):
                    column.metric(label, comparison["counts"][key])
                for key, label in labels:
                    with st.expander(label, expanded=bool(comparison[key])):
                        for item in comparison[key]:
                            old, new = item["baseline_findings"], item["current_findings"]
                            title = (new or old)[0].get("title", item["identity"]["check"])
                            st.text(title)
                            st.text(item["identity"]["url"])
                            st.write({"Baseline IDs": [f["id"] for f in old], "Current IDs": [f["id"] for f in new],
                                "Baseline severity/verdict": [f'{f["severity"]} / {f["verdict"]}' for f in old],
                                "Current severity/verdict": [f'{f["severity"]} / {f["verdict"]}' for f in new]})
                            if item.get("severity_or_verdict_changed"):
                                st.warning("Recorded severity or verdict changed; inspect both evidence records.")
                            st.json(item)
                        if not comparison[key]:
                            st.caption("No matching observations in this category.")
                with st.expander("Comparison limits"):
                    for limitation in comparison["limitations"]:
                        st.text(limitation)
                st.download_button("Download comparison (JSON)", json.dumps(comparison, indent=2),
                    file_name=f"autoshield-compare-{baseline_id}-to-{selected}.json", mime="application/json",
                    key=f"comparison_download_{selected}_{baseline_id}")

                html_key = f"comparison_html_{selected}_{baseline_id}"
                if st.button("Prepare comparison HTML / PDF", key=f"prepare_{html_key}"):
                    try:
                        st.session_state[html_key] = api(base, "GET",
                            f"/scans/{selected}/compare/{baseline_id}/report.html", raw=True)
                    except (requests.RequestException, ValueError) as exc:
                        st.session_state.pop(html_key, None)
                        st.error(str(exc))
                if st.session_state.get(html_key):
                    st.download_button("Download comparison (HTML)", st.session_state[html_key],
                        file_name=f"autoshield-compare-{baseline_id}-to-{selected}.html", mime="text/html",
                        key=f"download_{html_key}")
                    st.caption("Open HTML in a browser → Ctrl+P → Save as PDF. Select A4 and disable headers and footers. Re-prepare to refresh this saved snapshot.")
