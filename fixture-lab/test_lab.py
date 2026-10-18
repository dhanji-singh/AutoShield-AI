import hashlib
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit
from app import route
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from scan_engine import assess, StopScan

class FixtureTransport:
    def __init__(self,scope,budget,delay,cancelled):
        self.scope,self.budget,self.count=scope,budget,0
    def fetch(self,url):
        self.scope.check(url)
        if self.count>=self.budget: raise StopScan('request budget reached')
        self.count+=1
        p=urlsplit(url)
        status,headers,body=route(p.path+'?'+p.query)
        return dict(url=url,status=status,headers=headers,body=body.decode(),body_sha256=hashlib.sha256(body).hexdigest(),truncated=False,elapsed_ms=0)

class LabTests(unittest.TestCase):
    def scan(self,path='/',mode='active'):
        return assess('http://fixture-lab:8090'+path,dict(mode=mode,max_pages=10,max_requests=40,max_depth=2,delay_seconds=0),lab_origins=('http://fixture-lab:8090',),transport_factory=FixtureTransport)
    def test_active_crawl_and_expected_verdicts(self):
        r=self.scan()
        self.assertEqual(r['status'],'completed')
        self.assertEqual(len(r['pages']),6)
        self.assertEqual(r['requests_sent'],12)
        findings=r['findings']
        self.assertEqual([f['verdict'] for f in findings if f['check']=='sql_error'],['suspected'])
        self.assertEqual([f['verdict'] for f in findings if f['check']=='reflection'],['inconclusive'])
        self.assertTrue(any(f['check']=='cookie_flags' for f in findings))
        self.assertTrue(any(p.get('redirect_skipped') for p in r['pages']))
    def test_control_has_only_http_observation(self):
        r=self.scan('/secure?q=apple')
        # Control links to home, so isolate observations by URL path.
        found=[f['check'] for f in r['findings'] if urlsplit(f['evidence']['url']).path=='/secure']
        self.assertTrue(found)
        self.assertEqual(set(found),{'http_transport'})
    def test_passive_never_reports_active_signals(self):
        r=self.scan(mode='passive')
        self.assertEqual(r['requests_sent'],6)
        self.assertFalse(any(f['check'] in ('reflection','sql_error') for f in r['findings']))
    def test_reflection_is_html_escaped(self):
        _,_,body=route('/reflect?q=%3Cscript%3Ealert(1)%3C/script%3E')
        self.assertNotIn(b'<script>',body)
        self.assertIn(b'&lt;script&gt;',body)

if __name__=='__main__': unittest.main()
