import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
import app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.port=cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def request(self,path,method="GET",body=None,headers=None,retries=2):
        # Windows can abort a connection that the server closes right after a
        # 4xx response (WinError 10053). Retry once so those races do not make
        # an otherwise deterministic test flaky.
        last=None
        for attempt in range(retries):
            conn=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
            try:
                conn.request(method,path,body=body,headers=headers or {})
                r=conn.getresponse(); return (r.status,r.read(),dict(r.getheaders()))
            except (ConnectionAbortedError,ConnectionResetError) as exc:
                last=exc
            finally:
                conn.close()
        raise last

    def headers(self):
        return {"Origin":f"http://127.0.0.1:{self.port}","Content-Type":"application/json","X-CSRF-Token":app.CSRF_TOKEN}
    def test_ui(self): self.assertEqual(self.request("/")[0],200)
    def test_content_security_policy(self): self.assertIn("frame-ancestors 'none'",self.request("/")[2]["Content-Security-Policy"])
    def test_bad_host(self): self.assertEqual(self.request("/",headers={"Host":"evil.example"})[0],403)
    def test_unknown_path(self): self.assertEqual(self.request("/missing")[0],404)
    def test_no_csrf(self): self.assertEqual(self.request("/api/source","POST","{}")[0],403)
    def test_bad_origin(self):
        h=self.headers();h["Origin"]="http://evil.example"
        self.assertEqual(self.request("/api/source","POST","{}",h)[0],403)
    def test_source_api(self):
        r=self.request("/api/source","POST",json.dumps({"source":"node.innerHTML = input;"}),self.headers())
        self.assertEqual(r[0],200)
        findings=json.loads(r[1])["findings"]
        self.assertTrue(findings)
        self.assertTrue(all(f["status"]=="needs_review" for f in findings))

    def test_non_object_json(self): self.assertEqual(self.request("/api/source","POST","[]",self.headers())[0],400)
    def test_public_target_rejected(self):
        self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://example.com"}),self.headers())[0],400)
    def test_active_must_be_boolean(self):
        self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://localhost:3000","active":"yes"}),self.headers())[0],400)
    def test_openapi_fuzz_must_be_boolean(self):
        self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://localhost:3000","openapi_fuzz":"not_bool"}),self.headers())[0],400)
    def test_ai_hybrid_must_be_boolean(self):
        self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://localhost:3000","ai_hybrid":"not_bool"}),self.headers())[0],400)
    def test_scan_hybrid_telemetry_included(self):
        from unittest.mock import patch
        mock_report = {
            "schema_version": "1.1",
            "mode": "hybrid_dast_sast",
            "target": "http://localhost:3000",
            "findings": [
                {
                    "rule": "xss_injection",
                    "title": "DOM XSS in Client Script",
                    "severity": "medium",
                    "confidence": "medium",
                    "evidence": "document.write(location.search)",
                    "remediation": "Use safe DOM sinks",
                    "cwe": "CWE-79"
                }
            ],
            "client_source_sample": "document.write(location.search);"
        }
        with patch("app.scan", return_value=mock_report):
            status, body, _ = self.request("/api/scan", "POST", json.dumps({"target": "http://localhost:3000", "ai_hybrid": True}), self.headers())
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertIn("ai_telemetry", data)
            self.assertIn("confidence", data["ai_telemetry"])
            self.assertIn("risk_level", data["ai_telemetry"])
            self.assertIn("active_features", data["ai_telemetry"])
            self.assertTrue(len(data["findings"]) > 0)
            self.assertIn("ai_confidence", data["findings"][0])
            self.assertTrue(data["findings"][0]["ai_rescored"])
            self.assertIn("ai_gauge", data)
            self.assertIsInstance(data["ai_gauge"], dict)
            self.assertIn("risk_percent", data["ai_gauge"])
            self.assertIn("findings", data["ai_gauge"])
            self.assertIn("total", data["ai_gauge"])

    def test_scan_hybrid_disabled_gauge_omitted(self):
        from unittest.mock import patch
        mock_report = {
            "schema_version": "1.1",
            "mode": "dast_only",
            "target": "http://localhost:3000",
            "findings": []
        }
        with patch("app.scan", return_value=mock_report):
            status, body, _ = self.request("/api/scan", "POST", json.dumps({"target": "http://localhost:3000", "ai_hybrid": False}), self.headers())
            self.assertEqual(status, 200)
            data = json.loads(body)
            self.assertNotIn("ai_gauge", data)

    def test_report_downloads_include_ai_gauge(self):
        from unittest.mock import patch
        mock_report = {
            "schema_version": "1.1",
            "mode": "hybrid_dast_sast",
            "target": "http://localhost:3000",
            "findings": [],
            "records": [{"path": "/"}],
            "errors": [],
            "client_source_sample": "var x = 1;"
        }
        with patch("app.scan", return_value=mock_report):
            self.request("/api/scan", "POST", json.dumps({"target": "http://localhost:3000", "ai_hybrid": True}), self.headers())
            # Test JSON report
            status, body, _ = self.request("/api/report")
            self.assertEqual(status, 200)
            json_data = json.loads(body)
            self.assertIn("ai_gauge", json_data)
            # Test HTML report
            status, html_body, _ = self.request("/api/report.html")
            self.assertEqual(status, 200)
            self.assertIn("AI Risk Gauge", html_body.decode("utf-8"))

    def test_concurrent_scan_rejected(self):
        app.SCAN_LOCK.acquire()
        try: self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://localhost:3000"}),self.headers())[0],409)
        finally: app.SCAN_LOCK.release()
    def test_wrong_content_type(self):
        h=self.headers();h["Content-Type"]="text/plain"
        self.assertEqual(self.request("/api/source","POST","{}",h)[0],415)
    def test_ai_telemetry_get(self):
        status, body, _ = self.request("/api/ai")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("model_mode", data)
        self.assertIn("features", data)
        self.assertTrue(len(data["features"]) >= 30)
    def test_ai_predict_post(self):
        status, body, _ = self.request("/api/ai/predict", "POST", json.dumps({"source": "db.query('SELECT * FROM users WHERE id=' + req.body.id);"}), self.headers())
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertIn("prediction", data)
        self.assertIn("active_features", data)
        self.assertIn("confidence", data)


if __name__ == "__main__": unittest.main()
