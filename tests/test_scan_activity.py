"""Deterministic lifecycle tests: no network or model calls."""
import copy
import socket
import os
import tempfile
from unittest.mock import patch
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from scan_engine import assess, StopScan

OPTIONS = dict(mode='active', max_pages=1, max_requests=10, max_depth=0, delay_seconds=0)

class FakeTransport:
    def __init__(self, scope, budget, delay, cancelled):
        self.count, self.budget = 0, budget
    def fetch(self, url):
        if self.count >= self.budget:
            raise StopScan('request budget reached')
        self.count += 1
        value = parse_qs(urlsplit(url).query).get('q', [''])[0]
        body = 'SQLITE_ERROR' if "'" in value else value
        return dict(url=url, status=200, headers=[('Content-Type','application/json')],
                    body=body, body_sha256='fixture', truncated=False, elapsed_ms=1)

class ActivityTests(unittest.TestCase):
    def scan(self, transport=FakeTransport, **options):
        self.snapshots=[]
        return assess('http://proxy/?q=apple', {**OPTIONS, **options},
            lab_origins=('http://proxy',), transport_factory=transport,
            progress=lambda r:self.snapshots.append(copy.deepcopy(r)))
    def test_live_lifecycle_and_finding_links(self):
        report=self.scan()
        self.assertTrue(any(r['check_runs'] and r['check_runs'][-1]['status']=='running' for r in self.snapshots))
        self.assertEqual(report['requests_sent'],3)
        probes=[r for r in report['check_runs'] if r['check'] in ('reflection','sql_error')]
        self.assertEqual(len(probes),2)
        self.assertTrue(all(r['status']=='completed' and r['baseline'] and r['finding_ids'] for r in probes))
        ids={f['id'] for f in report['findings']}
        self.assertTrue(all(set(r['finding_ids'])<=ids for r in probes))
        self.assertEqual(report['timeline'][-1]['message'],'Assessment completed')
    def test_dns_failure_is_persisted_before_finish(self):
        class Broken(FakeTransport):
            def fetch(self,url): raise socket.gaierror('private diagnostic')
        report=self.scan(Broken)
        self.assertEqual(report['status'],'failed')
        self.assertIn('DNS lookup failed',report['stop_reason'])
        self.assertNotIn('private diagnostic',str(report))
        self.assertTrue(any(r['errors'] and r['status']=='running' for r in self.snapshots))
    def test_budget_does_not_mark_unperformed_probe_completed(self):
        report=self.scan(max_requests=1)
        self.assertEqual(report['status'],'partial')
        probe=report['check_runs'][-1]
        self.assertEqual(probe['status'],'stopped')
        self.assertNotIn('response',probe)
        self.assertEqual(probe['finding_ids'],[])
    def test_passive_has_no_probe_runs(self):
        report=self.scan(mode='passive')
        self.assertFalse(any(r['check'] in ('reflection','sql_error') for r in report['check_runs']))
        self.assertTrue(any(e['stage']=='skipped' for e in report['timeline']))
    def test_no_signal_is_not_a_pass(self):
        class Quiet(FakeTransport):
            def fetch(self,url):
                r=super().fetch(url);r['body']='constant';return r
        report=self.scan(Quiet)
        probes=report['check_runs'][-2:]
        self.assertTrue(all(r['outcome']=='no_observation' for r in probes))

class RecoveryTests(unittest.TestCase):
    def test_restart_preserves_evidence_and_closes_pending_operation(self):
        import scan_store as store
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"AUTOSHIELD_DB_PATH":folder+"/test.db"}):
            store.initialize()
            ident=store.create("http://proxy/", OPTIONS)
            report={"status":"running","findings":[{"id":1}],"check_runs":[{"id":1,"status":"running"}],
                    "timeline":[{"id":1,"message":"Running page_fetch"}]}
            store.save(ident,report)
            store.initialize()
            saved=store.get(ident)
            self.assertEqual(saved["status"],"interrupted")
            self.assertEqual(saved["report"]["status"],"interrupted")
            self.assertEqual(saved["report"]["check_runs"][0]["status"],"stopped")
            self.assertEqual(saved["report"]["findings"],[{"id":1}])

if __name__=='__main__': unittest.main()
