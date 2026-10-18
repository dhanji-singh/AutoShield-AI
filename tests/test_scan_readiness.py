import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import scan_api


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        app.include_router(scan_api.router)
        self.client = TestClient(app)

    def test_missing_key_and_dependencies_are_not_ready_and_never_scan(self):
        with patch.dict('os.environ', {'ARMORIQ_API_KEY': ''}), patch.object(scan_api.store, 'history', return_value=[]), patch.object(scan_api.importlib.util, 'find_spec', return_value=None), patch.object(scan_api.executor, 'submit') as submit:
            response = self.client.get('/scans/readiness')
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data['prerequisites_ready'])
            self.assertFalse(data['armoriq_key_present'])
            self.assertIsNone(data['latest_recorded_armoriq_decision'])
            submit.assert_not_called()

    def test_ready_is_configuration_only_and_secret_never_returned(self):
        with patch.dict('os.environ', {'ARMORIQ_API_KEY': 'secret-test-value'}), patch.object(scan_api.store, 'history', return_value=[{'id': 3}]), patch.object(scan_api.store, 'get', return_value={'report': {'check_runs': [{'gateway': {'attribution': 'ArmorIQ', 'action': 'BLOCK', 'reason': 'policy_denied'}}]}}), patch.object(scan_api.importlib.util, 'find_spec', return_value=object()):
            response = self.client.get('/scans/readiness')
            data = response.json()
            self.assertTrue(data['prerequisites_ready'])
            self.assertEqual(data['scanner_armoriq_mode'], 'required')
            self.assertEqual(data['latest_recorded_armoriq_decision']['action'], 'BLOCK')
            self.assertNotIn('secret-test-value', response.text)
            self.assertIn('not cloud authorization', data['note'])
