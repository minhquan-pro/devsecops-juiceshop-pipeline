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
    def request(self,path,method="GET",body=None,headers=None):
        conn=http.client.HTTPConnection("127.0.0.1",self.port,timeout=3)
        conn.request(method,path,body=body,headers=headers or {})
        r=conn.getresponse(); result=(r.status,r.read(),dict(r.getheaders()));conn.close();return result
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
        self.assertEqual(r[0],200);self.assertEqual(len(json.loads(r[1])["findings"]),1)
    def test_non_object_json(self): self.assertEqual(self.request("/api/source","POST","[]",self.headers())[0],400)
    def test_public_target_rejected(self):
        self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://example.com"}),self.headers())[0],400)
    def test_active_must_be_boolean(self):
        self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://localhost:3000","active":"yes"}),self.headers())[0],400)
    def test_concurrent_scan_rejected(self):
        app.SCAN_LOCK.acquire()
        try: self.assertEqual(self.request("/api/scan","POST",json.dumps({"target":"http://localhost:3000"}),self.headers())[0],409)
        finally: app.SCAN_LOCK.release()
    def test_wrong_content_type(self):
        h=self.headers();h["Content-Type"]="text/plain"
        self.assertEqual(self.request("/api/source","POST","{}",h)[0],415)


if __name__ == "__main__": unittest.main()
