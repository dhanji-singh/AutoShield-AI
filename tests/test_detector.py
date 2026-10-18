import sys
import unittest
from pathlib import Path
from urllib.parse import quote_plus


# Import the detector from the project's backend folder.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from detector import classify_event


def make_event(query="", **overrides):
    event = {
        "method": "GET",
        "path": "/rest/products/search",
        "query_evidence": quote_plus(query),
        "query_truncated": False,
    }
    event.update(overrides)
    return event


class DetectorTests(unittest.TestCase):

    def test_normal_searches(self):
        for query in [
            "apple",
            "banana",
            "orange juice",
            "O'Reilly",
            "",
        ]:
            with self.subTest(query=query):
                result = classify_event(make_event(query))
                self.assertEqual(result["status"], "no_match")
                self.assertEqual(result["matched_rules"], [])

    def test_numeric_tautology(self):
        result = classify_event(make_event("' OR 1=1--"))

        self.assertEqual(result["status"], "suspicious")
        self.assertIn("SQLI-002", result["matched_rules"])

    def test_unequal_numbers_do_not_match_tautology(self):
        result = classify_event(make_event("OR 1=10"))

        self.assertEqual(result["status"], "no_match")

    def test_union_select_case_and_spacing(self):
        result = classify_event(
            make_event("uNiOn   ALL   SeLeCt name")
        )

        self.assertEqual(result["status"], "suspicious")
        self.assertIn("SQLI-001", result["matched_rules"])

    def test_block_comments_between_keywords(self):
        result = classify_event(
            make_event("UNION/**/SELECT name")
        )

        self.assertEqual(result["status"], "suspicious")
        self.assertIn("SQLI-001", result["matched_rules"])

    def test_quoted_tautology(self):
        result = classify_event(make_event("OR 'x'='x'"))

        self.assertEqual(result["status"], "suspicious")
        self.assertIn("SQLI-003", result["matched_rules"])

    def test_url_encoded_input(self):
        event = make_event()
        event["query_evidence"] = "%27%20OR%201%3D1--"

        result = classify_event(event)

        self.assertEqual(result["status"], "suspicious")
        self.assertIn("SQLI-002", result["matched_rules"])

    def test_missing_evidence(self):
        event = make_event()
        del event["query_evidence"]

        result = classify_event(event)

        self.assertEqual(result["status"], "not_evaluated")

    def test_other_route_is_outside_scope(self):
        event = make_event(
            "' OR 1=1--",
            path="/health",
        )

        result = classify_event(event)

        self.assertEqual(result["status"], "not_evaluated")

    def test_post_method_is_outside_scope(self):
        event = make_event(
            "' OR 1=1--",
            method="POST",
        )

        result = classify_event(event)

        self.assertEqual(result["status"], "not_evaluated")

    def test_truncated_unmatched_evidence(self):
        event = make_event(
            "apple",
            query_truncated=True,
        )

        result = classify_event(event)

        self.assertEqual(result["status"], "inconclusive")
        self.assertTrue(result["evidence_truncated"])

    def test_http_status_does_not_determine_detection(self):
        for http_status in [200, 403, 500]:
            with self.subTest(http_status=http_status):
                event = make_event(
                    "' OR 1=1--",
                    status=http_status,
                )

                result = classify_event(event)

                self.assertEqual(result["status"], "suspicious")

    def test_known_false_positive_for_educational_text(self):
        # This is ordinary explanatory text, not an attack.
        # The current regex still flags the SQL keywords.
        result = classify_event(
            make_event("Learn how UNION SELECT works")
        )

        self.assertEqual(result["status"], "suspicious")

    def test_known_false_negative_for_boolean_expression(self):
        # The current rules do not recognize this SQL-like condition.
        result = classify_event(
            make_event("' OR TRUE--")
        )

        self.assertEqual(result["status"], "no_match")


if __name__ == "__main__":
    unittest.main(verbosity=2)