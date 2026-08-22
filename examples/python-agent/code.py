"""Agent IA code minimal — sandbox d'évaluation.

Partage le runtime python3 avec chat.py via le registry CAS.
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8766"))


class CodeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return

        if self.path.startswith("/code?expr="):
            expr = self.path[11:]
            try:
                result = eval(expr, {"__builtins__": {}}, {})
                body = f"code: {result}".encode()
                self.send_response(200)
            except Exception as e:
                body = f"error: {e}".encode()
                self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, *_):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), CodeHandler)
    print(f"Code agent listening on http://127.0.0.1:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
