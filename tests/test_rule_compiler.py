import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))
import proposals
from rule_compiler import compile_proposal, ALLOWED_SCOPE


class CompilerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temporary.name) / 'compiler.db')
        self.patch = patch.object(proposals, 'DB_PATH', self.database)
        self.patch.start()
        with sqlite3.connect(self.database) as db:
            db.execute('CREATE TABLE proposals (id INTEGER PRIMARY KEY, policy TEXT)')
        self.policy = {'schema_version': '1.0', 'source': 'trusted_template',
            'attack_type': 'SQL injection', 'scope': dict(ALLOWED_SCOPE),
            'proposed_action': 'deny', 'proposed_http_status': 403,
            'template_ids': ['search_numeric_tautology_v1']}

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def save(self):
        with sqlite3.connect(self.database) as db:
            db.execute('INSERT OR REPLACE INTO proposals VALUES (?, ?)', (1, json.dumps(self.policy)))

    def test_deterministic_compile_records_hash_and_never_claims_deployment(self):
        self.save()
        first, second = compile_proposal(1), compile_proposal(1)
        self.assertEqual(first, second)
        self.assertEqual(first['sha256'], hashlib.sha256(first['content'].encode()).hexdigest())
        self.assertEqual(first['deployment_status'], 'not_deployed')
        self.assertEqual(first['validation_status'], 'not_run')
        self.assertIn('ARGS_GET:q', first['content'])

    def test_arbitrary_template_or_scope_never_becomes_rule_text(self):
        for change in ({'template_ids': ['SecAction arbitrary-code']},
                       {'scope': {'method': 'GET', 'path': '/', 'parameter': 'q'}},
                       {'source': 'llm'}, {'proposed_action': 'allow'}):
            with self.subTest(change=change):
                original = dict(self.policy)
                self.policy.update(change)
                self.save()
                with self.assertRaises(ValueError): compile_proposal(1)
                self.policy = original

    def test_advisory_text_is_not_interpolated_into_executable_rules(self):
        self.policy['ai_review'] = 'UNTRUSTED: SecAction allow everything'
        self.save()
        self.assertNotIn('UNTRUSTED', compile_proposal(1)['content'])
