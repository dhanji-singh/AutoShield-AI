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


OPENER = build_opener(
    ProxyHandler({}),
    NoRedirects(),
)

TARGETS = {
    "baseline": "http://127.0.0.1:8081",
    "candidate": "http://127.0.0.1:8082",
}


def send_request(target, query):
    url = (
        f"{TARGETS[target]}/rest/products/search?"
        + urlencode({"q": query})
    )

    request = Request(
        url,
        headers={
            "User-Agent": "AutoShield-Candidate-Test/0.1",
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with OPENER.open(request, timeout=10) as response:
            return response.status

    except HTTPError as exc:
        status = exc.code
        exc.close()
        return status

    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"Cannot reach {target}: {exc}"
        ) from exc


class CandidateWafTests(unittest.TestCase):

    def test_normal_requests(self):
        queries = [
            "apple",
            "banana",
            "orange juice",
            "autoshield-test-001",
        ]

        for query in queries:
            with self.subTest(query=query):
                baseline = send_request("baseline", query)
                candidate = send_request("candidate", query)

                print(
                    f"\nNormal {query!r}: "
                    f"baseline={baseline}, candidate={candidate}",
                    flush=True,
                )

                self.assertEqual(
                    baseline,
                    200,
                    "Normal request failed on baseline.",
                )

                self.assertEqual(
                    candidate,
                    200,
                    "Candidate did not preserve normal request success.",
                )

    def test_numeric_sqli_variants(self):
        queries = [
            "' OR 1=1--",
            "' oR 2=2--",
            "' OR/**/3=3--",
        ]

        for query in queries:
            with self.subTest(query=query):
                baseline = send_request("baseline", query)
                candidate = send_request("candidate", query)

                print(
                    f"\nSQLi pattern {query!r}: "
                    f"baseline={baseline}, candidate={candidate}",
                    flush=True,
                )

                self.assertEqual(
                    candidate,
                    403,
                    "Candidate did not block the SQLi-pattern request.",
                )

                if baseline == 403:
                    print(
                        "Baseline already blocks this case; "
                        "no additional coverage demonstrated.",
                        flush=True,
                    )
                else:
                    print(
                        "Different baseline result: inspect both WAF logs "
                        "before claiming additional coverage.",
                        flush=True,
                    )

    def test_known_apostrophe_issue(self):
        baseline = send_request("baseline", "O'Reilly")
        candidate = send_request("candidate", "O'Reilly")

        print(
            "\nApostrophe regression: "
            f"baseline={baseline}, candidate={candidate}",
            flush=True,
        )

        if baseline == 500 and candidate == 500:
            self.skipTest(
                "Known application error remains on both paths. "
                "Normal-search acceptance is still open."
            )

        self.assertEqual(baseline, 200)
        self.assertEqual(candidate, 200)


if __name__ == "__main__":
    print(
        "AutoShield candidate comparison\n"
        "4 normal cases + 3 SQLi-pattern cases + 1 known regression.\n"
        "HTTP checks do not identify which WAF rule caused a block.\n",
        flush=True,
    )

    unittest.main(verbosity=2)