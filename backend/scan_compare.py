"""Compare saved observations without making requests or inferring remediation."""
from scan_identity import finding_fingerprint
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit


def canonical_url(url):
    p = urlsplit(url)
    if p.scheme.lower() not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Comparison requires valid saved HTTP(S) URLs')
    host = p.hostname.lower()
    if ':' in host:
        host = '[' + host + ']'
    port = p.port
    if port and port != (443 if p.scheme.lower() == 'https' else 80):
        host += ':' + str(port)
    return urlunsplit((p.scheme.lower(), host, p.path or '/', p.query, ''))


def origin(scan):
    url = canonical_url(scan.get('report', {}).get('origin') or scan['target'])
    p = urlsplit(url)
    return p.scheme, p.netloc


def group_findings(scan):
    groups = {}
    for finding in scan.get('report', {}).get('findings', []):
        evidence = finding.get('evidence') or {}
        # Match probes by their original URL, never their random marker/mutated URL.
        url = (evidence.get('baseline') or {}).get('url') or evidence.get('url')
        if not url or not finding.get('check'):
            raise ValueError('A finding lacks a check or evidence URL; comparison cannot match it reliably')
        identity = {'check': finding['check'], 'url': canonical_url(url),
                    'method': evidence.get('method', 'GET').upper(),
                    'parameter': evidence.get('parameter'), 'probe_kind': evidence.get('probe_kind')}
        key = finding_fingerprint(finding)
        group = groups.setdefault(key, {'fingerprint': key,
                                       'identity': identity, 'findings': []})
        group['findings'].append(finding)
    return groups


def facts(scan):
    report = scan.get('report') or {}
    return {'id': scan['id'], 'target': scan.get('target'), 'status': scan.get('status'),
            'created_at': scan.get('created_at'), 'coverage': report.get('coverage', {}),
            'requests_sent': report.get('requests_sent', 0),
            'stop_reason': report.get('stop_reason'), 'errors_count': len(report.get('errors', []))}


def compare_scans(baseline, current):
    if baseline['id'] == current['id']:
        raise ValueError('Select two different scans')
    if any(s.get('status') in ('queued', 'running') for s in (baseline, current)):
        raise ValueError('Wait for both scans to finish before comparing')
    if origin(baseline) != origin(current):
        raise ValueError('Select scans of the same origin (scheme, host and port)')
    before, after = group_findings(baseline), group_findings(current)
    warnings = []
    if canonical_url(baseline['target']) != canonical_url(current['target']):
        warnings.append('Starting URLs differ. Findings may differ because discovery started at different pages or query values.')
    relevant = ('mode', 'max_pages', 'max_requests', 'max_depth', 'delay_seconds')
    changed = [key for key in relevant if baseline.get('options', {}).get(key) != current.get('options', {}).get(key)]
    if changed:
        warnings.append('Scan settings differ: ' + ', '.join(changed) + '. This is not an equivalent retest.')
    for label, scan in (('Baseline', baseline), ('Current', current)):
        report = scan.get('report') or {}
        if scan.get('status') != 'completed' or report.get('errors') or report.get('stop_reason'):
            warnings.append(label + ' has incomplete coverage, recorded errors, or a stop reason. Inspect its evidence.')
    bp = {p.get('url') for p in baseline.get('report', {}).get('pages', [])}
    cp = {p.get('url') for p in current.get('report', {}).get('pages', [])}
    if bp != cp:
        warnings.append('The recorded page sets differ. Absence may reflect a page that was not revisited.')
    if baseline.get('report', {}).get('coverage') != current.get('report', {}).get('coverage'):
        warnings.append('Recorded coverage differs; page and parameter counts do not establish identical tests.')
    result = {'comparison_version': 'observations-v1', 'baseline': facts(baseline), 'current': facts(current),
              'warnings': warnings,
              'limitations': [
                  'New means absent from the selected baseline, not newly introduced or newly exploitable.',
                  'No longer observed does not mean fixed. Per-check negative results are not recorded, so an equivalent successful retest cannot be proven.',
                  'Matching uses check, original evidence URL (including saved query values), method, parameter and probe kind. Finding IDs are local to each scan.',
                  'Saved URL redaction can hide differences. Matching is based only on retained evidence; duplicate identities are grouped without discarding findings.',
                  'Comparison makes no target requests or AI calls and does not change severity or verdict.'
              ], 'new': [], 'repeated': [], 'no_longer_observed': []}
    for key in sorted(before.keys() | after.keys()):
        b, a = before.get(key), after.get(key)
        group = a or b
        item = {'fingerprint': group['fingerprint'], 'identity': group['identity'],
                'baseline_findings': b['findings'] if b else [], 'current_findings': a['findings'] if a else []}
        if a and b:
            item['severity_or_verdict_changed'] = (
                sorted((f.get('severity', ''), f.get('verdict', '')) for f in b['findings']) !=
                sorted((f.get('severity', ''), f.get('verdict', '')) for f in a['findings']))
            result['repeated'].append(item)
        else:
            result['new' if a else 'no_longer_observed'].append(item)
    result['counts'] = {key: len(result[key]) for key in ('new', 'repeated', 'no_longer_observed')}
    return result
