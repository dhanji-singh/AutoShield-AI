import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import scan_ai
import scan_api

SCAN = {'status': 'completed', 'report': {'findings': [], 'pages': ['PRIVATE'], 'coverage': {}, 'limitations': []}}
ENV = {'AI_PROVIDER': 'groq', 'GROQ_API_KEY': 'test-secret', 'GROQ_MODEL': 'openai/gpt-oss-20b'}

class AITests(unittest.TestCase):
    def response(self, body):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = json.dumps(body).encode()
        return opener

    def test_groq_request_minimized_and_key_redacted(self):
        opener = self.response({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'findings': []})}}]})
        with patch.dict(os.environ, ENV), patch.object(scan_ai, 'build_opener', return_value=opener):
            result = scan_ai.review_scan(SCAN)
        req = opener.open.call_args.args[0]
        self.assertEqual(req.full_url, 'https://api.groq.com/openai/v1/chat/completions')
        self.assertEqual(req.get_header('Authorization'), 'Bearer test-secret')
        self.assertNotIn('PRIVATE', req.data.decode())
        self.assertNotIn('tools', json.loads(req.data))
        self.assertIn('No findings to explain', result['text'])
        self.assertEqual(req.get_header('User-agent'), 'AutoShield-AI/0.4')
        self.assertEqual(result['provider'], 'groq')

    def test_rejects_incomplete_and_tool_responses(self):
        for choice in [
            {'finish_reason': 'length', 'message': {'content': 'partial'}},
            {'finish_reason': 'stop', 'message': {'content': 'x', 'tool_calls': [{'id': 'x'}]}},
            {'finish_reason': 'stop', 'message': {'content': None}},
        ]:
            with self.subTest(choice=choice), patch.dict(os.environ, ENV), patch.object(scan_ai, 'build_opener', return_value=self.response({'choices': [choice]})):
                with self.assertRaises(scan_ai.AIUnavailable): scan_ai.review_scan(SCAN)

    def test_503_does_not_expose_provider_body(self):
        opener = MagicMock()
        opener.open.side_effect = HTTPError('https://api.groq.com', 503, 'test-secret', {}, io.BytesIO(b'test-secret'))
        with patch.dict(os.environ, ENV), patch.object(scan_ai, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(scan_ai.AIUnavailable, 'groq returned HTTP 503') as caught:
                scan_ai.review_scan(SCAN)
        self.assertNotIn('test-secret', str(caught.exception))

    def test_gemini_retained(self):
        opener = self.response({'candidates': [{'finishReason': 'STOP', 'content': {'parts': [{'text': json.dumps({'findings': []})}]}}]})
        with patch.dict(os.environ, {'AI_PROVIDER': 'gemini', 'GEMINI_API_KEY': 'test', 'GEMINI_MODEL': 'test-model'}), patch.object(scan_ai, 'build_opener', return_value=opener):
            self.assertEqual(scan_ai.review_scan(SCAN)['provider'], 'gemini')

    def test_provider_switch_refreshes_cache(self):
        saved = {**SCAN, 'ai_review': {'status': 'completed', 'provider': 'gemini', 'model': 'old'}}
        new = {'status': 'completed', 'provider': 'groq', 'model': ENV['GROQ_MODEL'], 'review_version': scan_ai.REVIEW_VERSION, 'input_sha256': scan_ai.review_fingerprint(SCAN)}
        with patch.dict(os.environ, ENV), patch.object(scan_api, 'load', return_value=saved), patch.object(scan_api, 'review_scan', return_value=new) as review, patch.object(scan_api.store, 'save_ai') as save:
            self.assertEqual(scan_api.run_review(1), new)
            review.assert_called_once()
            save.assert_called_once_with(1, new)
            saved['ai_review'] = new
            scan_api.run_review(1)
            self.assertEqual(review.call_count, 1)



FINDING = dict(id=1, check='sql_error', title='Database error', severity='medium',
               verdict='suspected', description='Database signature after quote, not proof of exploitation.',
               remediation='Use parameterized queries.', evidence={'body': 'PRIVATE-EVIDENCE'})
ROW = dict(id=1, explanation='Observed error is not proof of exploitation.', remediation='Review parameter binding.')

class StructuredTests(unittest.TestCase):
    def test_reject_invalid_shapes_and_ids(self):
        invalid = [
            {}, {'findings': []}, {'findings': [ROW], 'severity': 'high'},
            {'findings': [{**ROW, 'id': 9}]}, {'findings': [{**ROW, 'id': True}]},
            {'findings': [{**ROW, 'severity': 'high'}]},
            {'findings': [{**ROW, 'verdict': 'confirmed'}]},
            {'findings': [{**ROW, 'explanation': ''}]},
            {'findings': [{**ROW, 'explanation': 'x' * 601}]},
            {'findings': [{**ROW, 'explanation': ['wrong type']}]},
            {'findings': [{**ROW, 'explanation': 'new\nline'}]},
            {'findings': [{**ROW, 'explanation': '```code```'}]},
        ]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(scan_ai.AIUnavailable):
                scan_ai.validate_review(json.dumps(item), [FINDING])

    def test_reject_duplicate_rows_and_json_keys(self):
        with self.assertRaises(scan_ai.AIUnavailable):
            scan_ai.validate_review(json.dumps({'findings': [ROW, ROW]}), [FINDING, {**FINDING, 'id': 2}])
        with self.assertRaises(scan_ai.AIUnavailable):
            scan_ai.validate_review('{"findings":[],"findings":[]}', [])
        with self.assertRaises(scan_ai.AIUnavailable):
            scan_ai.validate_review('```json\n{"findings":[]}\n```', [])

    def test_order_and_source_facts_preserved(self):
        context = scan_ai.review_input({'status': 'completed', 'report': {
            'origin': 'http://proxy', 'findings': [FINDING, {**FINDING, 'id': 2}],
            'coverage': {'mode': 'passive', 'pages_checked': 1, 'query_parameters_probed': 0},
            'requests_sent': 1, 'limitations': ['No authenticated checks.']}})
        original = json.dumps(context, sort_keys=True)
        rows = scan_ai.validate_review(json.dumps({'findings': [{**ROW, 'id': 2}, ROW]}), context['findings'])
        text = scan_ai.render_review(context, rows)
        self.assertEqual([r['id'] for r in rows], [1, 2])
        self.assertEqual(text.count('Recorded severity: medium | Recorded verdict: suspected'), 2)
        self.assertIn('Active query probes were not run.', text)
        self.assertIn('Lab HTTP is a configuration observation.', text)
        self.assertEqual(json.dumps(context, sort_keys=True), original)
        self.assertNotIn('PRIVATE-EVIDENCE', json.dumps(context))

    def test_review_limits_and_context_invalidation(self):
        scan = {'status': 'completed', 'report': {'origin': 'http://proxy', 'findings': [{**FINDING, 'id': n} for n in range(1, 13)]}}
        with patch.dict(os.environ, {'AUTOSHIELD_LAB_ORIGINS': 'http://proxy'}):
            context = scan_ai.review_input(scan)
            before = scan_ai.review_fingerprint(scan)
        self.assertEqual(context['total_findings'], 12)
        self.assertEqual(len(context['findings']), 10)
        with patch.dict(os.environ, {'AUTOSHIELD_LAB_ORIGINS': ''}):
            self.assertNotEqual(before, scan_ai.review_fingerprint(scan))

    def test_key_redaction_and_mocked_review_end_to_end(self):
        scan = {'status': 'completed', 'report': {'origin': 'http://proxy', 'findings': [FINDING],
                'coverage': {'mode': 'active', 'pages_checked': 1, 'query_parameters_probed': 1}, 'requests_sent': 3}}
        body = {'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps({'findings': [{**ROW, 'explanation': 'test-secret'}]})}}]}
        opener = AITests().response(body)
        with patch.dict(os.environ, ENV), patch.object(scan_ai, 'build_opener', return_value=opener):
            result = scan_ai.review_scan(scan)
        self.assertNotIn('test-secret', json.dumps(result))
        self.assertIn('[REDACTED]', result['text'])
        self.assertEqual(result['structured']['scan_facts']['findings'][0]['verdict'], 'suspected')

    def test_old_review_regenerated_and_invalid_result_not_completed(self):
        saved = {**SCAN, 'ai_review': {'status': 'completed', 'provider': 'groq', 'model': ENV['GROQ_MODEL']}}
        with patch.dict(os.environ, ENV), patch.object(scan_api, 'load', return_value=saved), patch.object(scan_api, 'review_scan', side_effect=scan_ai.AIUnavailable('Invalid JSON')) as review, patch.object(scan_api.store, 'save_ai') as save:
            result = scan_api.run_review(1)
            self.assertEqual(result['status'], 'unavailable')
            review.assert_called_once()
            save.assert_called_once_with(1, result)

if __name__ == '__main__': unittest.main()
