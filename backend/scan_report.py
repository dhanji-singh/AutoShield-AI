"""Offline, escaped HTML export of saved scan evidence. No network or AI calls."""
from scan_identity import deduplicate_findings
import json
from html import escape


def esc(value):
    return escape(str(value), quote=True)


def pre(value):
    return '<pre>' + esc(json.dumps(value, indent=2, ensure_ascii=False)) + '</pre>'


def render_html(scan):
    report = scan.get('report') or {}
    coverage = report.get('coverage') or {}
    findings = deduplicate_findings(report.get('findings') or [])
    review = scan.get('ai_review') or {}
    cards = []
    for finding in findings:
        cards.append(f'''<article class="finding">
<h3>#{esc(finding.get('id', '?'))} · {esc(finding.get('title', 'Observation'))}</h3>
<p class="badge">Severity: {esc(finding.get('severity', 'unknown'))} · Verdict: {esc(finding.get('verdict', 'unknown'))}</p>
<p>{esc(finding.get('description', ''))}</p>
<h4>Recorded remediation</h4><p>{esc(finding.get('remediation', ''))}</p>
<h4>Evidence</h4>{pre(finding.get('evidence', {}))}</article>''')
    limits = ''.join('<li>' + esc(item) + '</li>' for item in report.get('limitations', []))
    if review.get('status') == 'completed':
        ai = (f'<p class="muted">Provider: {esc(review.get("provider", "unknown"))} · '
              f'Model: {esc(review.get("model", "unknown"))} · {esc(review.get("created_at", ""))}</p>'
              '<p>AI explanations are advisory and unverified. Structure validation does not prove factual accuracy.</p>'
              '<pre class="prose">' + esc(review.get('text', '')) + '</pre>')
    else:
        ai = '<p>' + esc(review.get('message') or 'No completed AI review is saved for this scan.') + '</p>'
    status = scan.get('status', 'unknown')
    note = ('This is a snapshot of an unfinished scan.' if status in ('queued', 'running') else
            'This report describes only the checks and evidence recorded below.')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AutoShield · Scan {esc(scan.get('id', '?'))}</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#edf1f7;color:#18263c;font:15px/1.65 system-ui,Arial,sans-serif}}
main{{max-width:1040px;margin:32px auto;background:white;padding:48px;border-radius:16px}}
header{{border-bottom:4px solid #2563eb;padding-bottom:24px}}.brand{{color:#1d4ed8;font-weight:800;letter-spacing:2px;font-size:13px}}
h1{{font-size:36px;line-height:1.15;margin:12px 0}}h2{{font-size:23px;margin-top:36px}}h3{{font-size:19px;margin-top:0}}h4{{margin-bottom:6px}}
p{{overflow-wrap:anywhere}}.muted,footer{{color:#52647a;font-size:13px}}.target{{font-family:monospace;font-size:14px}}
.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}}.metric{{background:#eff5ff;padding:16px;border-radius:8px}}
.metric strong{{display:block;font-size:25px}}.metric span{{font-size:12px;color:#52647a}}.notice{{border-left:4px solid #2563eb;background:#eff5ff;padding:12px 18px}}
.finding{{border:1px solid #d8e1ec;border-radius:10px;padding:24px;margin:18px 0}}.badge{{display:inline-block;background:#fff3dc;padding:4px 10px;border-radius:5px;font-size:13px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#f4f6fa;padding:16px;font:12px/1.6 monospace}}
.prose{{font:14px/1.7 system-ui,Arial,sans-serif}}li{{margin:8px 0}}footer{{margin-top:36px;border-top:1px solid #d8e1ec;padding-top:16px}}
@media(max-width:650px){{main{{padding:22px;margin:0;border-radius:0}}.metrics{{grid-template-columns:repeat(2,1fr)}}h1{{font-size:28px}}}}
@page{{size:A4;margin:16mm}}@media print{{body{{background:white;font-size:11px}}main{{padding:0;margin:0;max-width:none}}h1{{font-size:28px}}h2{{font-size:18px}}h3{{font-size:15px}}h2,h3,h4{{break-after:avoid}}pre{{font-size:9px}}.metric{{break-inside:avoid}}.screen-only{{display:none}}.finding{{padding:14px}}}}
</style></head><body><main>
<header><div class="brand">AUTOSHIELD AI / WEB ASSESSMENT</div><h1>Security assessment report</h1>
<p class="target">{esc(scan.get('target', report.get('target', 'Unknown target')))}</p>
<p class="muted">Scan #{esc(scan.get('id', '?'))} · Status: {esc(status)} · Mode: {esc(coverage.get('mode', 'unknown'))}</p>
<p class="muted">Started: {esc(scan.get('created_at', 'Not recorded'))}<br>Finished: {esc(scan.get('finished_at') or 'Not recorded')}</p></header>
<p class="screen-only muted">Save as PDF: press Ctrl+P (Windows/Linux) or Cmd+P (Mac), then choose Save as PDF. Timestamps include their recorded timezone.</p>
<div class="metrics"><div class="metric"><strong>{esc(report.get('requests_sent', 0))}</strong><span>HTTP requests</span></div>
<div class="metric"><strong>{esc(coverage.get('pages_checked', len(report.get('pages', []))))}</strong><span>Pages checked</span></div>
<div class="metric"><strong>{esc(coverage.get('query_parameters_probed', 0))}</strong><span>Parameters probed</span></div>
<div class="metric"><strong>{len(findings)}</strong><span>Recorded observations</span></div></div>
<div class="notice">{esc(note)} Confirmed means the stated observation was measured; it does not establish exploitability. No findings does not establish security.</div>
<h2>01 / Recorded findings</h2>{''.join(cards) or '<p>No observations were recorded by these checks.</p>'}
<h2>02 / Coverage and limitations</h2>{pre(coverage)}<ul>{limits}</ul>
<h4>Stop reason</h4><p>{esc(report.get('stop_reason') or 'None recorded')}</p>
<h4>Recorded errors</h4>{pre(report.get('errors', []))}
<h2>03 / AI advisory review</h2>{ai}
<h2>04 / Scan settings and discovered pages</h2>{pre(scan.get('options', {}))}{pre(report.get('pages', []))}
<footer>AutoShield AI · Saved evidence export · No new requests or AI calls are made when generating this report.</footer>
</main></body></html>'''


def render_comparison_html(comparison):
    """Offline comparison export; every dynamic value is escaped."""
    baseline, current = comparison['baseline'], comparison['current']
    sections = []
    for key, label in [('new', 'New observations'), ('repeated', 'Repeated observations'),
                       ('no_longer_observed', 'No longer observed')]:
        items = []
        for item in comparison[key]:
            old, new = item['baseline_findings'], item['current_findings']
            title = (new or old)[0].get('title', item['identity']['check'])
            rows = []
            for side, findings in [('Baseline', old), ('Current', new)]:
                if not findings:
                    rows.append(f'<p><strong>{side}:</strong> No matching recorded observation.</p>')
                for finding in findings:
                    rows.append(f'''<h4>{side} finding #{esc(finding.get('id', '?'))}</h4>
<p>Severity: {esc(finding.get('severity', 'unknown'))} · Verdict: {esc(finding.get('verdict', 'unknown'))}</p>
<p>{esc(finding.get('description', ''))}</p>
<p><strong>Recorded remediation:</strong> {esc(finding.get('remediation', ''))}</p>
{pre(finding.get('evidence', {}))}''')
            changed = ('<p class="notice">Recorded severity or verdict changed. Inspect both evidence records.</p>'
                       if item.get('severity_or_verdict_changed') else '')
            items.append(f'<article><h3>{esc(title)}</h3><p>{esc(item["identity"]["url"])}</p>{changed}{"".join(rows)}</article>')
        sections.append(f'<section><h2>{label} ({len(comparison[key])})</h2>{"".join(items) or "<p>None recorded in this category.</p>"}</section>')
    warnings = ''.join('<li>' + esc(x) + '</li>' for x in comparison['warnings'])
    limits = ''.join('<li>' + esc(x) + '</li>' for x in comparison['limitations'])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AutoShield comparison {esc(baseline['id'])} to {esc(current['id'])}</title>
<style>
*{{box-sizing:border-box}}body{{font:15px/1.6 system-ui,Arial,sans-serif;color:#18263c;background:#edf1f7;margin:0}}
main{{max-width:1000px;background:white;margin:32px auto;padding:42px;border-radius:14px}}header{{border-bottom:4px solid #2563eb;padding-bottom:20px}}
h1{{font-size:32px;line-height:1.2}}h2{{margin-top:32px}}h3,h4{{break-after:avoid}}.brand{{color:#1d4ed8;letter-spacing:2px;font-weight:bold}}
article{{border:1px solid #d8e1ec;border-radius:8px;padding:20px;margin:16px 0}}.notice{{border-left:4px solid #d99517;background:#fff7e8;padding:12px 16px}}
p,li{{overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:#f4f6fa;padding:14px;font:12px/1.5 monospace}}
.metrics{{display:flex;gap:16px;margin:22px 0}}.metric{{flex:1;background:#eff5ff;padding:15px}}.metric strong{{display:block;font-size:26px}}
footer,.hint{{color:#52647a;font-size:12px}}footer{{margin-top:30px;border-top:1px solid #d8e1ec;padding-top:16px}}
@media(max-width:600px){{main{{margin:0;padding:20px}}.metrics{{flex-direction:column}}}}
@page{{size:A4;margin:16mm}}@media print{{body{{background:white;font-size:11px}}main{{margin:0;padding:0}}h1{{font-size:26px}}h2{{font-size:18px;break-after:avoid}}pre{{font-size:9px}}.screen-only{{display:none}}}}
</style></head><body><main><header><p class="brand">AUTOSHIELD AI / SCAN COMPARISON</p>
<h1>Evidence comparison report</h1><p>Baseline #{esc(baseline['id'])} → Current #{esc(current['id'])}</p>
<p>{esc(current.get('target', ''))}</p></header>
<p class="hint screen-only">Print: Ctrl+P → Save as PDF → A4. Disable browser headers and footers.</p>
<div class="metrics"><div class="metric"><strong>{esc(comparison['counts']['new'])}</strong>New</div>
<div class="metric"><strong>{esc(comparison['counts']['repeated'])}</strong>Repeated</div>
<div class="metric"><strong>{esc(comparison['counts']['no_longer_observed'])}</strong>No longer observed</div></div>
<p class="notice">No longer observed does not mean fixed. New means absent from the selected baseline, not newly introduced. Counts represent observation groups.</p>
<h2>Coverage warnings</h2>{'<ul>' + warnings + '</ul>' if warnings else '<p>No differences flagged by these comparison checks. This does not prove equivalent test coverage.</p>'}
<h2>Scan context</h2><h3>Baseline</h3>{pre(baseline)}<h3>Current</h3>{pre(current)}
{''.join(sections)}<h2>Interpretation limits</h2><ul>{limits}</ul>
<footer>AutoShield AI · Saved evidence comparison · No target requests or AI calls were made for this export.</footer>
</main></body></html>'''
