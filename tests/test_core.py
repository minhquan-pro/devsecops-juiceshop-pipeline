import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from juicesec.core import target_address, analyze_response, analyze_source, html_report, collect, scan
from tests.fixture_server import Fixture


def record(path="/", body="", headers=None, status=200):
    return {"path":path,"body":body,"headers":headers or {"content-type":"text/html"},"status":status}


class TargetTests(unittest.TestCase):
    def test_loopback(self):
        self.assertEqual(target_address("http://127.0.0.1:3000"),("127.0.0.1",3000))
    def test_localhost_pinned(self):
        self.assertEqual(target_address("http://localhost:3000"),("127.0.0.1",3000))
    def test_ipv6(self):
        self.assertEqual(target_address("http://[::1]:3000"),("::1",3000))
    def test_forbidden_targets(self):
        for url in ["https://127.0.0.1", "http://example.com", "http://10.0.0.1", "file:///etc/passwd", "http://127.0.0.1.evil", "http://127.0.0.1@evil", "http://user@127.0.0.1", "http://127.0.0.1/a", "http://127.0.0.1?x=1", "http://127.0.0.1#x", "http://127.0.0.1:99999", " http://localhost", "http://localhost:0"]:
            with self.subTest(url=url), self.assertRaises(ValueError): target_address(url)


class RuleTests(unittest.TestCase):
    def test_headers_missing(self): self.assertEqual(len(analyze_response(record())),3)
    def test_headers_present(self):
        self.assertFalse(analyze_response(record(headers={"content-type":"text/html","content-security-policy":"default-src 'self'; frame-ancestors 'none'","x-content-type-options":"nosniff"})))
    def test_json_does_not_need_html_headers(self):
        self.assertFalse(analyze_response(record(headers={"content-type":"application/json"})))
    def test_redirect_has_no_header_findings(self): self.assertFalse(analyze_response(record(status=302)))
    def test_spa_200_not_swagger(self): self.assertFalse(analyze_response(record("/api-docs/","<html>SPA shell</html>")))
    def test_swagger_marker(self): self.assertEqual(analyze_response(record("/api-docs/",'<div id="swagger-ui"></div>'))[0]["rule_id"],"INFO-API")
    def test_prometheus(self):
        self.assertEqual(analyze_response(record("/metrics","# TYPE demo_total counter\ndemo_total 1",{"content-type":"text/plain"}))[0]["rule_id"],"INFO-METRICS")
    def test_spa_200_not_metrics(self): self.assertFalse(analyze_response(record("/metrics","<html>SPA shell</html>")))
    def test_error_not_confirmed_sqli(self):
        item=analyze_response(record("/search","SQLITE_ERROR",status=500))[0]
        self.assertEqual(item["cwe"],"CWE-209"); self.assertEqual(item["status"],"needs_review")
    def test_directory_not_traversal(self):
        self.assertEqual(analyze_response(record("/ftp/","Index of /ftp"))[0]["cwe"],"CWE-548")
    def test_sast_unsafe(self): self.assertTrue(analyze_source("node.innerHTML = user;"))
    def test_sast_text_sink(self): self.assertFalse(analyze_source("node.textContent = user;"))
    def test_sast_line_number(self): self.assertEqual(analyze_source("// header\neval(x)")[0]["evidence"]["line"],2)
    def test_sast_limit(self):
        with self.assertRaises(ValueError): analyze_source("a"*200001)
    def test_sast_unicode_bytes(self):
        with self.assertRaises(ValueError): analyze_source("ữ"*100000)
    def test_sast_output_cap(self): self.assertEqual(len(analyze_source("eval(x)\n"*300)),200)
    def test_report_escaping(self):
        report=html_report({"target":"<img src=x onerror=alert(1)>","findings":[]})
        self.assertNotIn("<img",report); self.assertIn("&lt;img",report)
    def test_known_regex_false_positive(self):
        self.assertTrue(analyze_source("// example only: node.innerHTML = user;"))
    def test_known_regex_false_negative(self):
        self.assertFalse(analyze_source("const sink = 'inner' + 'HTML'; node[sink] = input;"))


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(("127.0.0.1",0),Fixture)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True);cls.thread.start()
        cls.url=f"http://127.0.0.1:{cls.server.server_port}"
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()
    def test_cookie_redacted(self): self.assertEqual(collect(self.url,"/")["headers"]["set-cookie"],"[REDACTED]")
    def test_unknown_path_denied(self):
        with self.assertRaises(ValueError): collect(self.url,"/private")
    def test_baseline_request_count(self): self.assertEqual(len(scan(self.url)["records"]),5)
    def test_active_request_count(self): self.assertEqual(len(scan(self.url,True)["records"]),6)
    def test_body_not_persisted(self):
        data=scan(self.url); self.assertTrue(all("body" not in r for r in data["records"])); self.assertNotIn("do_not_export",json.dumps(data))


if __name__ == "__main__": unittest.main()
