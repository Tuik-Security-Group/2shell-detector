#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
# Copyright (c) 2026 Tuik Security Group
"""Local response simulator for twoshell.py. It runs no vulnerable software."""

import argparse
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/chain-1", "/chain-2", "/chain-3"):
            target = {"/chain-1": "/chain-2", "/chain-2": "/chain-3",
                      "/chain-3": "/rsc"}[self.path]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/entry")
            self.end_headers()
            return
        if self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "https://example.invalid/elsewhere")
            self.end_headers()
            return
        if self.path not in ("/vulnerable", "/patched", "/unknown", "/generic-error", "/broad-error", "/generic-broad-error", "/entry", "/rsc", "/waf", "/gzip-vulnerable", "/preexisting-broad"):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if self.path == "/preexisting-broad":
            body = b'Error: {"digest":"already-in-baseline"}'
        elif self.path == "/entry":
            body = b'<html><a href="/rsc">app</a><a href="https://example.invalid/outside">outside</a></html>'
        elif self.path == "/rsc":
            body = b"<html><script>self.__next_f=[]</script>RSC fixture only</html>"
        elif self.path in ("/vulnerable", "/gzip-vulnerable"):
            self.send_header("X-Powered-By", "PHP/8.4.26, Next.js")
            body = b"<html><script>self.__next_f=[]</script>fixture only</html>"
        elif self.path == "/patched":
            self.send_header("X-Powered-By", "PHP/8.4.27, Next.js")
            body = b"<html><script>self.__next_f=[]</script>fixture only</html>"
        else:
            body = b"<html>opaque fixture</html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path == "/waf":
            self.send_error(403, "Synthetic WAF block")
            return
        if self.path not in ("/vulnerable", "/patched", "/generic-error", "/broad-error", "/generic-broad-error", "/rsc", "/gzip-vulnerable", "/preexisting-broad"):
            self.send_error(405, "No probe fixture at this path")
            return
        size = int(self.headers.get("Content-Length", "0"))
        if size > 4096 or size <= 0:
            self.send_error(400)
            return
        body = self.rfile.read(size)
        if self.headers.get("Next-Action"):
            if (not self.headers.get("Next-Router-State-Tree") or
                    b' name="1"' not in body or b' name="0"' not in body or
                    (b'["$1:a:a"]' not in body and b'["$1:a"]' not in body)):
                self.send_error(400)
                return
            if self.path == "/generic-broad-error" or (
                    self.path in ("/broad-error", "/preexisting-broad") and b'["$1:a:a"]' in body):
                status, content_type = 500, "text/x-component"
                response = b'Error: {"digest":"fixture-only"}\n'
            elif self.path == "/generic-error" or (
                    self.path in ("/vulnerable", "/rsc", "/gzip-vulnerable") and b'["$1:a:a"]' in body):
                status, content_type = 500, "text/x-component"
                response = b'0:{"a":"fixture"}\n1:E{"digest":"fixture-only"}\n'
            else:
                status, content_type = 404, "text/plain; charset=utf-8"
                response = b"Server action not found.\n"
        else:
            if (self.headers.get("Cookie") != "PHPSESSID=_" or
                    b' name="PHP_SESSION_UPLOAD_PROGRESS"' not in body):
                self.send_error(400)
                return
            status, content_type = 200, "text/plain; charset=utf-8"
            if self.path in ("/vulnerable", "/gzip-vulnerable"):
                response = (b"Warning: Session ID is too long or contains illegal characters\n"
                            b"Warning: Failed to read session data\n"
                            b"Warning: Failed to write session data (files)\n")
            else:
                response = b"Probe received; patched fixture emits no PHP warning sequence.\n"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if self.path == "/gzip-vulnerable":
            response = gzip.compress(response)
            self.send_header("Content-Encoding", "gzip")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, fmt, *args):
        print("fixture:", fmt % args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), FixtureHandler)
    print(f"Fixture listening on http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
