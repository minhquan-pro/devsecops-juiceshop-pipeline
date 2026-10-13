import json
import threading
import subprocess
import sys
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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
    def test_regex_false_positive_now_suppressed(self):
        # Comment-only lines are inert; the AST engine plus the comment filter
        # suppress the old line-regex false positive.
        self.assertFalse(analyze_source("// example only: node.innerHTML = user;"))
    def test_known_regex_false_negative(self):
        self.assertFalse(analyze_source("const sink = 'inner' + 'HTML'; node[sink] = input;"))
    def test_static_string_sink_not_flagged(self):
        # A fixed HTML literal is not attacker-controlled.
        self.assertFalse(analyze_source('node.innerHTML = "<strong>Fixed label</strong>";'))
    def test_flow_engine_catches_intermediate_variable(self):
        # Source assigned to a variable, then used as a sink on a later line.
        findings=analyze_source("const file = req.query.file;\nfs.readFile(file, handler);")
        self.assertTrue(any(f["rule_id"]=="SAST-AST-PATH" for f in findings))
    def test_flow_engine_catches_multiline_sql(self):
        findings=analyze_source('const q = "SELECT id FROM Users WHERE email=";\nconst final = q + input;\ndb.query(final);')
        self.assertTrue(any(f["rule_id"]=="SAST-AST-SQL" for f in findings))
    def test_flow_engine_catches_alias(self):
        findings=analyze_source("loader = pickle.loads; obj = loader(request.body)")
        self.assertTrue(any(f["rule_id"]=="SAST-AST-DESER" for f in findings))
    def test_python_ast_engine_taint(self):
        findings=analyze_source("path = request.args['f']\nopen(path)", "sample.py")
        self.assertTrue(any(f["rule_id"]=="SAST-AST-PATH" for f in findings))
    def test_benign_jwt_preview_not_flagged(self):
        self.assertFalse(analyze_source("const preview = jwt.decode(token); showDebugOnly(preview);"))
    def test_jwt_decode_for_authorization_flagged(self):
        self.assertTrue(analyze_source("const user = jwt.decode(token); allow(user.role);"))



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



class LabScriptTests(unittest.TestCase):
    """Checks for the real-exploit and redaction helpers in labs/."""

    def test_redaction_masks_jwt(self):
        from labs.redact_evidence import redact_text
        token=("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        self.assertEqual(redact_text(f"Bearer {token}"), "Bearer <jwt-redacted>")

    def test_redaction_masks_sensitive_keys(self):
        from labs.redact_evidence import redact_value
        masked=redact_value({"token":"abc","email":"a@b.c","nested":{"password":"p"}})
        self.assertEqual(masked["token"],"<redacted>")
        self.assertEqual(masked["nested"]["password"],"<redacted>")
        self.assertEqual(masked["email"],"a@b.c")

    def test_jwt_claims_decoded(self):
        from labs.juice_shop_exploits import _claims
        token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.x"
        self.assertEqual(_claims(token).get("sub"),"1234567890")

    def test_exploit_script_refuses_non_loopback(self):
        root=Path(__file__).resolve().parents[1]
        proc=subprocess.run([sys.executable,str(root/"labs"/"juice_shop_exploits.py"),
                             "--target","http://192.0.2.10:3000"],
                            capture_output=True,text=True)
        self.assertNotEqual(proc.returncode,0)
        self.assertIn("non-loopback",proc.stderr)

    def test_token_preview_truncated(self):
        from labs.juice_shop_exploits import _redact
        self.assertTrue(_redact("x"*500).endswith("REDACTED"))
        self.assertEqual(len(_redact("x"*500)),len("x"*12)+len("…REDACTED"))


if __name__ == "__main__": unittest.main()

