from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

HOST = "127.0.0.1"
PORT = 3000
BACKEND_BASE = "http://127.0.0.1:8000"
PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"


class FrontendProxyHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(PUBLIC_DIR), **kwargs)

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._proxy_request("GET")
            return

        if self.path == "/":
            self.path = "/index.html"

        super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._proxy_request("POST")
            return
        self.send_error(405, "Method Not Allowed")

    def _proxy_request(self, method: str):
        target_path = self.path.removeprefix("/api")
        target_url = f"{BACKEND_BASE}{target_path}"

        body = None
        content_length = self.headers.get("Content-Length")
        if content_length:
            body = self.rfile.read(int(content_length))

        headers = {
            k: v
            for k, v in self.headers.items()
            if k.lower() not in {"host", "connection", "content-length"}
        }

        try:
            req = Request(target_url, data=body, headers=headers, method=method)
            with urlopen(req, timeout=30) as resp:
                payload = resp.read()
                self.send_response(resp.status)
                for key, value in resp.headers.items():
                    if key.lower() in {"transfer-encoding", "connection"}:
                        continue
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(payload)
        except HTTPError as err:
            payload = err.read()
            self.send_response(err.code)
            self.send_header("Content-Type", err.headers.get("Content-Type", "application/json"))
            self.end_headers()
            self.wfile.write(payload)
        except URLError:
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"detail":"Backend unavailable"}')


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), FrontendProxyHandler)
    print(f"Frontend available at http://{HOST}:{PORT}")
    print(f"Proxying /api/* to {BACKEND_BASE}")
    server.serve_forever()
