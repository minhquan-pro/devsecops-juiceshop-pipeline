"""Synthetic HTTP fixture. THIS IS NOT OWASP JUICE SHOP."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        status, mime, body = 200, "text/html", "<html><body>Fixture SPA</body></html>"
        if self.path == "/metrics":
            mime, body = "text/plain", "# HELP demo_total Synthetic count\n# TYPE demo_total counter\ndemo_total 1\n"
        elif self.path == "/ftp/":
            body = '<html><title>Index of /ftp</title><a href="sample.md">sample</a></html>'
        elif self.path.endswith("%27"):
            status, mime, body = 500, "application/json", '{"error":"SQLITE_ERROR synthetic fixture"}'
        elif self.path.startswith("/rest/"):
            mime, body = "application/json", '{"data":[]}'
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Set-Cookie", "synthetic_session=do_not_export")
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == "__main__":
    print("Synthetic fixture at http://127.0.0.1:3001; not Juice Shop", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 3001), Fixture).serve_forever()
