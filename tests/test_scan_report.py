import copy
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
from fastapi import FastAPI
from fastapi.testclient import TestClient
import scan_api
from scan_report import render_html

class Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

class ReportTests(unittest.TestCase):
    def test_untrusted_values_are_text_and_input_is_unchanged(self):
        attack = '<script>alert(1)</script><img src=x onerror=alert(1)>'
        scan = {'id': 11, 'target': attack, 'status': 'completed',
                'report': {'findings': [{'id': 2, 'title': attack, 'severity': 'medium',
                'verdict': 'suspected', 'evidence': {'url': attack}}], 'limitations': [attack]},
                'ai_review': {'status': 'completed', 'text': attack}}
        original = copy.deepcopy(scan)
        result = render_html(scan)
        parser = Tags(); parser.feed(result)
        self.assertFalse(any(tag in ('script', 'img', 'iframe', 'a') for tag, _ in parser.tags))
        self.assertNotIn(attack, result)
        self.assertIn('&lt;script&gt;', result)
        self.assertIn('Verdict: suspected', result)
        self.assertEqual(scan, original)
        self.assertIn("default-src 'none'", result)

    def test_empty_partial_and_legacy_reviews(self):
        self.assertIn('No observations were recorded', render_html({'report': {}}))
        self.assertIn('unfinished scan', render_html({'status': 'running'}))
        self.assertIn('Older review', render_html({'ai_review': {'status': 'completed', 'text': 'Older review'}}))
        self.assertIn('Provider unavailable', render_html({'ai_review': {'message': 'Provider unavailable'}}))

    def test_endpoint_exports_saved_scan_without_ai(self):
        app = FastAPI(); app.include_router(scan_api.router)
        with patch.object(scan_api, 'load', return_value={'id': 11, 'report': {}}), patch.object(scan_api, 'review_scan') as ai:
            response = TestClient(app).get('/scans/11/report.html')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers['content-type'].startswith('text/html'))
        self.assertIn('autoshield-scan-11.html', response.headers['content-disposition'])
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        ai.assert_not_called()

class ComparisonExportTests(unittest.TestCase):
    def test_untrusted_comparison_is_escaped(self):
        from scan_report import render_comparison_html
        from scan_compare import compare_scans
        attack = '<script>alert(1)</script>'
        def saved(sid):
            return {'id': sid, 'target': 'http://proxy/', 'status': 'completed',
                'report': {'findings': [{'id': 1, 'check': 'http_transport', 'title': attack,
                    'description': attack, 'evidence': {'url': 'http://proxy/', 'extra': attack}}]}}
        result = render_comparison_html(compare_scans(saved(1), saved(2)))
        self.assertNotIn(attack, result)
        self.assertIn('&lt;script&gt;', result)
        self.assertIn('No longer observed does not mean fixed', result)
        self.assertIn('Baseline finding #1', result)
        self.assertIn('Current finding #1', result)

    def test_comparison_export_endpoint(self):
        app = FastAPI(); app.include_router(scan_api.router)
        def saved(sid):
            return {'id': sid, 'target': 'http://proxy/', 'status': 'completed', 'report': {}}
        with patch.object(scan_api, 'load', side_effect=saved), patch.object(scan_api, 'review_scan') as ai:
            client = TestClient(app)
            response = client.get('/scans/2/compare/1/report.html')
            self.assertEqual(response.status_code, 200)
            self.assertIn('autoshield-compare-1-to-2.html', response.headers['content-disposition'])
            self.assertEqual(client.get('/scans/1/compare/1/report.html').status_code, 422)
            ai.assert_not_called()

if __name__ == '__main__':
    unittest.main()
