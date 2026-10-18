import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from fastapi import FastAPI
from fastapi.testclient import TestClient
import scan_api


class AuthorizationTests(unittest.TestCase):
    def test_missing_false_or_string_acknowledgment_cannot_start_worker(self):
        app = FastAPI()
        app.include_router(scan_api.router)
        client = TestClient(app)
        with patch.object(scan_api.executor, "submit") as submit:
            for payload in (
                {"target": "http://proxy/"},
                {"target": "http://proxy/", "authorization_confirmed": False},
                {"target": "http://proxy/", "authorization_confirmed": "true"},
            ):
                self.assertEqual(client.post("/scans", json=payload).status_code, 422)
            submit.assert_not_called()

    def test_public_origin_accepted_with_acknowledgment(self):
        app = FastAPI()
        app.include_router(scan_api.router)
        with patch.object(
            scan_api, "lab_origins", return_value=("http://proxy",)
        ), patch.object(scan_api.executor, "submit") as submit, patch.object(
            scan_api.store, "create", return_value=123
        ):
            try:
                response = TestClient(app).post(
                    "/scans",
                    json={
                        "target": "https://example.com/",
                        "authorization_confirmed": True,
                    },
                )
                self.assertEqual(response.status_code, 202)
                submit.assert_called_once()
            finally:
                if scan_api.scan_lock.locked():
                    scan_api.scan_lock.release()

    def test_public_target_cannot_disable_tls_verification(self):
        app = FastAPI()
        app.include_router(scan_api.router)
        with patch.object(scan_api.executor, "submit") as submit:
            response = TestClient(app).post(
                "/scans",
                json={
                    "target": "https://example.com/",
                    "authorization_confirmed": True,
                    "verify_ssl": False,
                },
            )
            self.assertEqual(response.status_code, 422)
            submit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
