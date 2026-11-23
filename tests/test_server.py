#!/usr/bin/env python3
"""Integration tests for SecureFileGuard server hardening and security safeguards.
Stdlib only (unittest, http.client, urllib.request, etc.).
"""
import http.client
import json
import os
import subprocess
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(BASE, "server"))

import app


class TestServerSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure fixtures and binaries are ready
        subprocess.run(["bash", os.path.join(BASE, "tools", "make_fixtures.sh"), app.FIX],
                       check=True, stdout=subprocess.DEVNULL)
        app.JAIL = os.path.realpath(os.path.join(app.FIX, "secure_files"))
        app.RATE_LIMITER.enabled = False  # Avoid rate limiting during test assertions

        # Bind to port 0 for random free port
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.H)
        cls.host, cls.port = cls.server.server_address
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _post(self, path, body, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        h = {
            "Host": f"{self.host}:{self.port}",
            "Content-Type": "application/json"
        }
        if headers:
            h.update(headers)
        if isinstance(body, dict):
            body_bytes = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = body
        conn.request("POST", path, body=body_bytes, headers=h)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, res.getheaders(), data

    def _get(self, path, headers=None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        h = {
            "Host": f"{self.host}:{self.port}"
        }
        if headers:
            h.update(headers)
        conn.request("GET", path, headers=h)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, res.getheaders(), data

    def test_outside_jail_no_leak(self):
        """A1: For target outside jail, resolved path and file kind MUST be null."""
        status, _, data = self._post("/api/check", {"path": "/etc/shadow"})
        self.assertEqual(status, 200)
        j = json.loads(data.decode("utf-8"))
        self.assertEqual(j.get("expected"), "DENY")
        self.assertIsNone(j.get("resolved"), f"Expected null resolved, got: {j.get('resolved')}")
        self.assertIsNone(j.get("kind"), f"Expected null kind, got: {j.get('kind')}")
        self.assertEqual(j.get("reason"), "resolves OUTSIDE the jail")

    def test_inside_jail_shows_resolved_and_kind(self):
        """Inside-jail results may still show resolved path and kind."""
        status, _, data = self._post("/api/check", {"path": "notes.txt"})
        self.assertEqual(status, 200)
        j = json.loads(data.decode("utf-8"))
        self.assertEqual(j.get("expected"), "ALLOW")
        self.assertIsNotNone(j.get("resolved"))
        self.assertEqual(j.get("kind"), "regular file")

    def test_bad_host_header_rejected(self):
        """A2: Host header check: request with Host: evil.com must return 403."""
        status, _, data = self._post("/api/check", {"path": "notes.txt"}, headers={"Host": "evil.com"})
        self.assertEqual(status, 403)
        j = json.loads(data.decode("utf-8"))
        self.assertIn("error", j)

    def test_get_host_validation(self):
        """2.1: GET request with bad Host header must return 403; valid Host returns 200."""
        status, _, data = self._get("/", headers={"Host": "evil.com"})
        self.assertEqual(status, 403)
        j = json.loads(data.decode("utf-8"))
        self.assertIn("error", j)

        status, headers, data = self._get("/")
        self.assertEqual(status, 200)

    def test_allowed_host_wildcard_and_domain(self):
        """Verify explicit and wildcard allowed hosts work with port or without."""
        app.ALLOWED_HOSTS.add("*.onrender.com")
        app.ALLOWED_HOSTS.add("custom.example.org")
        try:
            # Subdomain of *.onrender.com should succeed
            status, _, _ = self._get("/", headers={"Host": "my-demo.onrender.com"})
            self.assertEqual(status, 200)

            # Subdomain of *.onrender.com with port
            status, _, _ = self._get("/", headers={"Host": "my-demo.onrender.com:443"})
            self.assertEqual(status, 200)

            # custom.example.org should succeed
            status, _, _ = self._get("/", headers={"Host": "custom.example.org"})
            self.assertEqual(status, 200)

            # Different domain should still fail with 403
            status, _, _ = self._get("/", headers={"Host": "attacker.com"})
            self.assertEqual(status, 403)
        finally:
            app.ALLOWED_HOSTS.discard("*.onrender.com")
            app.ALLOWED_HOSTS.discard("custom.example.org")

    def test_security_headers_present(self):
        """2.3: Security response headers: X-Frame-Options, Referrer-Policy, Cross-Origin-Resource-Policy."""
        status, headers, _ = self._get("/")
        self.assertEqual(status, 200)
        h_dict = {k.lower(): v for k, v in headers}
        self.assertEqual(h_dict.get("x-frame-options"), "DENY")
        self.assertEqual(h_dict.get("referrer-policy"), "no-referrer")
        self.assertEqual(h_dict.get("cross-origin-resource-policy"), "same-origin")

    def test_rate_limiting_triggers_429(self):
        """2.2/4.1: When rate limiting is enabled, exceeding limit returns 429."""
        try:
            app.RATE_LIMITER.enabled = True
            app.RATE_LIMITER.requests.clear()
            # Send 60 allowed requests
            for _ in range(60):
                status, _, _ = self._get("/api/info")
                self.assertEqual(status, 200)
            # 61st request must trigger 429
            status, _, data = self._get("/api/info")
            self.assertEqual(status, 429)
            j = json.loads(data.decode("utf-8"))
            self.assertIn("error", j)
        finally:
            app.RATE_LIMITER.enabled = False
            app.RATE_LIMITER.requests.clear()

    def test_race_api_response_shape(self):
        """4.1: Verify /api/race response format for multi-run demo."""
        status, _, data = self._post("/api/race", {"iterations": 1000, "runs": 2})
        self.assertEqual(status, 200)
        j = json.loads(data.decode("utf-8"))
        self.assertEqual(j.get("iterations"), 1000)
        self.assertEqual(j.get("runs"), 2)
        self.assertIn("rows", j)
        self.assertTrue(len(j["rows"]) >= 3)
        for row in j["rows"]:
            self.assertIn("variant", row)
            self.assertIn("attempts", row)
            self.assertIn("allowed", row)
            self.assertIn("opened", row)
            self.assertIn("escapes_min", row)
            self.assertIn("escapes_max", row)
            self.assertIn("escapes_total", row)
            self.assertIn("runs", row)
            self.assertEqual(len(row["runs"]), 2)

    def test_results_api_parsing_and_metrics(self):
        """4.1: /api/results correctly parses results.csv with new metrics."""
        # Ensure results.csv is generated
        subprocess.run([os.path.join(BASE, "build", "run_tests"), app.FIX, app.RESULTS_CSV],
                       check=True, stdout=subprocess.DEVNULL)
        status, _, data = self._get("/api/results")
        self.assertEqual(status, 200)
        j = json.loads(data.decode("utf-8"))
        self.assertIn("tests", j)
        self.assertIn("variants", j)
        self.assertIn("tests_detail", j)
        for v in j["variants"]:
            self.assertIn("containment_safe_rate", v)
            self.assertIn("containment_safe_count", v)
            self.assertIn("type_policy_rate", v)
            self.assertIn("type_policy_count", v)
            self.assertIn("missing_policy_rate", v)
            self.assertIn("missing_policy_count", v)
            self.assertIn("allow_rate", v)
            self.assertIn("allow_count", v)
            self.assertIn("containment_failures", v)

    def test_server_never_returns_file_contents(self):
        """4.1: The testbench must NEVER leak file contents in any JSON response."""
        # notes.txt content: "public notes", outside_secret.txt content: "OUTSIDE_SECRET", private.txt content: "sibling private"
        forbidden_contents = ["public notes", "OUTSIDE_SECRET", "sibling private"]
        test_paths = ["notes.txt", "../outside_secret.txt", "reports/marks.txt", "../secure_files_backup/private.txt"]
        for p in test_paths:
            status, _, data = self._post("/api/check", {"path": p})
            self.assertEqual(status, 200)
            text = data.decode("utf-8", "replace")
            for forbidden in forbidden_contents:
                self.assertNotIn(forbidden, text, f"Server leaked file content '{forbidden}' for path '{p}'")

    def test_forbidden_origin_rejected(self):
        """A2: Origin header check: cross-site origin must return 403."""
        status, _, data = self._post("/api/check", {"path": "notes.txt"},
                                     headers={"Origin": "http://evil.com"})
        self.assertEqual(status, 403)
        j = json.loads(data.decode("utf-8"))
        self.assertIn("error", j)

    def test_missing_json_content_type_rejected(self):
        """A2: POST without Content-Type: application/json must return 403."""
        status, _, data = self._post("/api/check", '{"path": "notes.txt"}',
                                     headers={"Content-Type": "text/plain"})
        self.assertEqual(status, 403)
        j = json.loads(data.decode("utf-8"))
        self.assertIn("error", j)

    def test_oversized_body_rejected(self):
        """A4/A5: Request body exceeding 20 KB must return 413."""
        oversized = {"path": "a" * 25000}
        status, _, data = self._post("/api/check", oversized)
        self.assertEqual(status, 413)
        j = json.loads(data.decode("utf-8"))
        self.assertIn("error", j)


if __name__ == "__main__":
    unittest.main()
