import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from scan_compare import compare_scans
import scan_api
from fastapi import FastAPI
from fastapi.testclient import TestClient

URL = 'http://proxy/search?q=apple'

def finding(check='sql_error', fid=1, marker='one'):
    return {'id': fid, 'check': check, 'title': check, 'severity': 'medium', 'verdict': 'suspected',
            'evidence': {'url': 'http://proxy/search?q=' + marker, 'method': 'GET', 'parameter': 'q',
                         'probe_kind': check, 'baseline': {'url': URL}}}

def scan(sid, findings, mode='active'):
    return {'id': sid, 'target': URL, 'status': 'completed', 'options': {'mode': mode},
            'report': {'origin': 'http://proxy', 'coverage': {'mode': mode},
                       'pages': [{'url': URL}], 'findings': findings, 'errors': []}}

class ComparisonTests(unittest.TestCase):
    def test_match_ignores_id_marker_hash_and_detects_verdict_change(self):
        a, b = scan(1, [finding('reflection', 3, 'randomA')]), scan(2, [finding('reflection', 7, 'randomB')])
        b['report']['findings'][0]['verdict'] = 'inconclusive'
        original = copy.deepcopy((a, b))
        result = compare_scans(a, b)
        self.assertEqual(result['counts'], {'new': 0, 'repeated': 1, 'no_longer_observed': 0})
        self.assertTrue(result['repeated'][0]['severity_or_verdict_changed'])
        self.assertEqual((a, b), original)

    def test_new_missing_and_passive_coverage_never_claim_fixed(self):
        result = compare_scans(scan(1, [finding()]), scan(2, [finding('http_transport')], 'passive'))
        self.assertEqual(result['counts'], {'new': 1, 'repeated': 0, 'no_longer_observed': 1})
        self.assertTrue(any('settings differ' in x for x in result['warnings']))
        self.assertTrue(any('does not mean fixed' in x for x in result['limitations']))

    def test_different_query_values_paths_and_parameters_do_not_merge(self):
        for field in ('url', 'parameter'):
            a, b = scan(1, [finding()]), scan(2, [finding()])
            if field == 'url':
                b['report']['findings'][0]['evidence']['baseline']['url'] = 'http://proxy/search?q=other'
            else:
                b['report']['findings'][0]['evidence']['parameter'] = 'other'
            self.assertEqual(compare_scans(a,b)['counts']['repeated'], 0)

    def test_invalid_pairs_and_missing_identity(self):
        a = scan(1, [finding()])
        for change in ('same', 'running', 'origin', 'missing'):
            b = scan(2, [finding()])
            if change == 'same': b['id'] = 1
            if change == 'running': b['status'] = 'running'
            if change == 'origin': b['report']['origin'] = 'https://proxy'
            if change == 'missing': b['report']['findings'][0]['evidence'] = {}
            with self.subTest(change=change), self.assertRaises(ValueError): compare_scans(a,b)

    def test_duplicate_groups_preserve_evidence_and_partial_warns(self):
        a, b = scan(1, [finding(), finding(fid=2)]), scan(2, [])
        b['status'] = 'partial'; b['report']['pages'] = []
        result = compare_scans(a,b)
        self.assertEqual(len(result['no_longer_observed'][0]['baseline_findings']), 2)
        self.assertTrue(any('incomplete' in x for x in result['warnings']))
        self.assertTrue(any('page sets differ' in x for x in result['warnings']))

    def test_default_port_and_hostname_normalization(self):
        a,b=scan(1,[finding()]),scan(2,[finding()])
        b['report']['origin']='http://PROXY:80'
        b['report']['findings'][0]['evidence']['baseline']['url']='http://PROXY:80/search?q=apple'
        self.assertEqual(compare_scans(a,b)['counts']['repeated'],1)

    def test_api_direction_and_error(self):
        app=FastAPI(); app.include_router(scan_api.router)
        saved={1:scan(1,[finding()]),2:scan(2,[])}
        with patch.object(scan_api,'load',side_effect=lambda sid:saved[sid]):
            client=TestClient(app)
            result=client.get('/scans/2/compare/1')
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.json()['counts']['no_longer_observed'],1)
            self.assertEqual(client.get('/scans/1/compare/1').status_code,422)

if __name__=='__main__': unittest.main()
