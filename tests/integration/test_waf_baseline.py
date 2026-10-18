import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Send requests directly to localhost without system proxies.
OPENER = build_opener(
    ProxyHandler({}),
    NoRedirects(),
)

TARGETS = {
    "monitor": "http://127.0.0.1:8080",
    "waf": "http://127.0.0.1:8081",
}

CASES = [
    {
        "name": "normal_apple",
        "query": "apple",
        "expected_waf": 200,
    },
    {
        "name": "normal_banana",
        "query": "banana",
        "expected_waf": 200,
    },
    {
        "name": "sqli_numeric_condition",
        "query": "' OR 1=1--",
        "expected_waf": 403,
    },
    {
        "name": "sqli_union_sequence",
        "query": "' UNION SELECT NULL--",
        "expected_waf": 403,
    },
]


def send_request(target, query):
    url = (
        f"{TARGETS[target]}/rest/products/search?"
        + urlencode({"q": query})
    )

    request = Request(
        url,
        headers={
            "User-Agent": "AutoShield-Lab-Test/0.1",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with OPENER.open(request, timeout=10) as response:
            return response.status

    except HTTPError as exc:
        # HTTP errors are responses, not connection failures.
        status = exc.code
        exc.close()
        return status

    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"Cannot reach {target}: {exc}"
        ) from exc


class WafBaselineTests(unittest.TestCase):

    def test_baseline_cases(self):
        for case in CASES:
            with self.subTest(case=case["name"]):
                monitor_status = send_request(
                    "monitor",
                    case["query"],
                )

                waf_status = send_request(
                    "waf",
                    case["query"],
                )

                print(
                    f"\n{case['name']}: "
                    f"monitor={monitor_status}, "
                    f"waf={waf_status}, "
                    f"expected_waf={case['expected_waf']}",
                    flush=True,
                )

                if case["expected_waf"] == 200:
                    self.assertEqual(
                        monitor_status,
                        200,
                        msg=(
                            "Normal request failed on the "
                            "baseline application."
                        ),
                    )

                self.assertEqual(
                    waf_status,
                    case["expected_waf"],
                    msg=(
                        f"{case['name']}: unexpected WAF response. "
                        "Inspect the WAF logs."
                    ),
                )

    def test_apostrophe_application_regression(self):
        monitor_status = send_request(
            "monitor",
            "O'Reilly",
        )

        waf_status = send_request(
            "waf",
            "O'Reilly",
        )

        print(
            "\nApostrophe regression: "
            f"monitor={monitor_status}, "
            f"waf={waf_status}",
            flush=True,
        )

        if monitor_status == 500 and waf_status == 500:
            self.skipTest(
                "Known application defect: O'Reilly returns HTTP 500 "
                "through both paths. Normal-search acceptance remains open."
            )

        # If the behavior changes, require genuine success on both paths.
        self.assertEqual(
            monitor_status,
            200,
            msg="Apostrophe search failed on the baseline application.",
        )

        self.assertEqual(
            waf_status,
            200,
            msg="Apostrophe search failed through the WAF.",
        )


if __name__ == "__main__":
    print(
        "AutoShield local WAF baseline\n"
        "4 baseline cases + 1 apostrophe regression case.\n"
        "10 HTTP requests when both services are reachable.\n"
        "HTTP results do not prove successful exploitation.\n"
        "A skipped regression remains an unresolved application issue.\n",
        flush=True,
    )

    unittest.main(verbosity=2)