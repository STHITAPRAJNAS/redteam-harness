"""Zero-dependency fallback web server (used when FastAPI isn't installed).

Mirrors the FastAPI routes (minus the auto /docs) using http.server, including
the /mcp tool endpoint, so `rtharness serve` works in any environment.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse, parse_qs

from . import __version__
from . import _service_common as sc


class Handler(BaseHTTPRequestHandler):
    server_version = "rtharness/" + __version__

    def log_message(self, *a):
        pass

    def _json(self, code: int, obj: Any):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code: int, text: str, ctype="text/html; charset=utf-8"):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def do_GET(self):
        route = urlparse(self.path)
        path = route.path.rstrip("/") or "/"
        if path == "/":
            self._text(200, sc.DASHBOARD_HTML)
        elif path == "/health":
            self._json(200, {"status": "ok", "version": __version__, "jobs": len(sc.JOBS)})
        elif path == "/probes":
            self._json(200, sc.probe_inventory())
        elif path == "/presets":
            from . import presets as _p
            self._json(200, {"presets": [{"name": n, "description": _p.describe(n)}
                                          for n in _p.names()]})
        elif path.startswith("/scan/"):
            parts = path.split("/")
            job = sc.JOBS.get(parts[2]) if len(parts) > 2 else None
            if job is None:
                self._json(404, {"error": "no such scan"})
                return
            if len(parts) >= 4 and parts[3] == "report":
                if job.result is None:
                    self._json(409, {"error": "scan not finished", "status": job.status})
                    return
                fmt = (parse_qs(route.query).get("format", ["json"])[0]).lower()
                content, ctype = sc.render_report(job, fmt)
                if fmt == "json":
                    self._text(200, content, ctype)
                else:
                    self._text(200, content, ctype)
            else:
                self._json(200, job.summary())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        try:
            body = self._body()
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        if path == "/scan":
            if "target" not in body:
                self._json(400, {"error": "body must include a 'target' object"})
                return
            try:
                job = sc.start_scan(body)
            except Exception as exc:  # noqa: BLE001
                self._json(400, {"error": "%s: %s" % (type(exc).__name__, exc)})
                return
            self._json(202, {"id": job.id, "status": job.status})
        elif path == "/mcp":
            resp = sc.mcp_dispatch(body)
            self._json(200, resp if resp is not None else {})
        else:
            self._json(404, {"error": "not found"})


def serve_stdlib(host: str = "127.0.0.1", port: int = 8900):
    httpd = ThreadingHTTPServer((host, port), Handler)
    print("rtharness (stdlib) on http://%s:%d  — dashboard /, MCP /mcp" % (host, port))
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: non-local bind with NO auth; do not expose publicly.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
