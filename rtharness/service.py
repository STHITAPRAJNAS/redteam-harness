"""Local web service for rtharness — REST API + a minimal dashboard.

Built on the standard library (zero extra dependencies), matching the harness's
air-gap-friendly philosophy. It is a **local operator tool**: it binds to
127.0.0.1 by default and has no authentication, so do not expose it publicly —
it launches scans against arbitrary targets on request.

Endpoints
---------
- ``GET  /``                      minimal HTML dashboard
- ``GET  /health``                liveness
- ``GET  /probes``                probe + corpus-pack inventory
- ``POST /scan``                  start a scan (JSON body = a RunConfig dict); returns {id}
- ``GET  /scan/<id>``             status + summary + progress log
- ``GET  /scan/<id>/report?format=json|md|html``   the report

Scans run in background threads; results live in memory for the process
lifetime.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse, parse_qs

from . import __version__, api
from .config import RunConfig
from .core import registry
from .core.tier import Tier
from .corpus import builtin_packs
from .report import to_json, to_markdown, to_html


class _Job:
    def __init__(self, cfg: RunConfig):
        self.id = uuid.uuid4().hex[:12]
        self.cfg = cfg
        self.status = "queued"          # queued | running | done | error
        self.error: Optional[str] = None
        self.result = None
        self.log: list = []
        self.created = time.time()

    def on_event(self, ev: str, data: dict):
        # Keep a compact progress trail for the dashboard to poll.
        if ev in ("run_start", "probe_done", "run_done"):
            self.log.append({"ev": ev, **data})

    def summary(self) -> Dict[str, Any]:
        d = {"id": self.id, "status": self.status, "error": self.error,
             "target": self.cfg.target.get("name") or self.cfg.target.get("type"),
             "tier": int(self.cfg.tier), "created": self.created,
             "log": self.log[-60:]}
        if self.result is not None:
            r = self.result
            d.update({"risk_score": r.risk_score(),
                      "highest_severity": r.highest_severity().label,
                      "vulnerable_findings": len(r.vulnerable_findings),
                      "total_findings": len(r.findings),
                      "total_attempts": r.total_attempts,
                      "duration_s": r.duration_s,
                      "severity_counts": r.severity_counts()})
        return d


_JOBS: Dict[str, _Job] = {}


def _start_scan(body: dict) -> _Job:
    cfg = RunConfig.from_dict(body)
    job = _Job(cfg)
    _JOBS[job.id] = job

    def _work():
        job.status = "running"
        try:
            job.result = api.execute_scan(cfg, on_event=job.on_event)
            job.status = "done"
        except Exception as exc:  # noqa: BLE001
            job.error = "%s: %s" % (type(exc).__name__, exc)
            job.status = "error"

    threading.Thread(target=_work, daemon=True).start()
    return job


def _probe_inventory() -> dict:
    probes = registry.select(Tier.ADAPTIVE)
    return {
        "probes": [{"id": p.id, "title": p.title, "severity": p.severity.label,
                    "min_tier": int(p.min_tier), "owasp": p.owasp,
                    "atlas": p.atlas, "tags": p.tags} for p in probes],
        "corpus_packs": [{"name": "corpus.%s" % pk.name, "payloads": len(pk.payloads),
                          "severity": pk.severity.label, "description": pk.description}
                         for pk in builtin_packs()],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "rtharness/" + __version__

    def log_message(self, *a):  # quieter console
        pass

    # --- helpers -----------------------------------------------------------
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
        if not n:
            return {}
        return json.loads(self.rfile.read(n) or b"{}")

    # --- routes ------------------------------------------------------------
    def do_GET(self):
        route = urlparse(self.path)
        path = route.path.rstrip("/") or "/"
        if path == "/":
            self._text(200, _DASHBOARD)
        elif path == "/health":
            self._json(200, {"status": "ok", "version": __version__,
                             "jobs": len(_JOBS)})
        elif path == "/probes":
            self._json(200, _probe_inventory())
        elif path.startswith("/scan/"):
            parts = path.split("/")
            job = _JOBS.get(parts[2]) if len(parts) > 2 else None
            if job is None:
                self._json(404, {"error": "no such scan"})
                return
            if len(parts) >= 4 and parts[3] == "report":
                if job.result is None:
                    self._json(409, {"error": "scan not finished", "status": job.status})
                    return
                fmt = (parse_qs(route.query).get("format", ["json"])[0]).lower()
                if fmt == "md":
                    self._text(200, to_markdown(job.result), "text/markdown; charset=utf-8")
                elif fmt == "html":
                    self._text(200, to_html(job.result))
                else:
                    self._json(200, json.loads(to_json(job.result)))
            else:
                self._json(200, job.summary())
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/scan":
            try:
                body = self._body()
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON body"})
                return
            if "target" not in body:
                self._json(400, {"error": "body must include a 'target' object"})
                return
            try:
                job = _start_scan(body)
            except Exception as exc:  # noqa: BLE001
                self._json(400, {"error": "%s: %s" % (type(exc).__name__, exc)})
                return
            self._json(202, {"id": job.id, "status": job.status})
        else:
            self._json(404, {"error": "not found"})


def serve(host: str = "127.0.0.1", port: int = 8900):
    httpd = ThreadingHTTPServer((host, port), Handler)
    public = host not in ("127.0.0.1", "localhost", "::1")
    print("rtharness web service on http://%s:%d  (dashboard at /)" % (host, port))
    if public:
        print("WARNING: bound to a non-local address with NO authentication. "
              "It launches scans on request — do not expose this publicly.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()


_DASHBOARD = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width, initial-scale=1">
<title>rtharness</title><style>
:root{color-scheme:light dark}
body{font-family:ui-sans-serif,system-ui,sans-serif;max-width:860px;margin:0 auto;padding:24px;line-height:1.5}
h1{font-size:1.4rem;margin-bottom:0}.muted{color:#888;font-size:.9rem}
fieldset{border:1px solid #8884;border-radius:10px;margin:16px 0;padding:14px}
label{display:block;font-size:.85rem;margin:8px 0 2px}
input,select{width:100%;padding:7px;border-radius:7px;border:1px solid #8886;background:transparent;color:inherit}
.row{display:flex;gap:12px}.row>div{flex:1}
button{margin-top:12px;padding:9px 16px;border-radius:8px;border:0;background:#2563eb;color:#fff;font-weight:600;cursor:pointer}
pre{background:#8881;padding:12px;border-radius:8px;overflow:auto;font-size:.82rem;max-height:320px}
a.btn{display:inline-block;margin-right:10px;margin-top:8px}
</style></head><body>
<h1>rtharness</h1>
<div class=muted>Local red-team console for agent apps (chat / A2A / MCP). Authorised testing only.</div>
<fieldset><legend>New scan</legend>
<div class=row>
<div><label>Target type</label><select id=type>
<option value=a2a>a2a</option><option value=mcp>mcp</option>
<option value=http>http (chat)</option><option value=openai>openai-compatible</option>
<option value=adk>adk</option><option value=langserve>langserve</option>
<option value=anthropic>anthropic</option></select></div>
<div><label>Tier</label><select id=tier>
<option>1</option><option selected>2</option><option>3</option><option>4</option></select></div>
<div><label>Effort</label><input id=effort value=1.0></div>
</div>
<label>Target URL / base_url</label><input id=url placeholder="http://localhost:9999">
<div class=row>
<div><label>Model (openai/anthropic)</label><input id=model placeholder="optional"></div>
<div><label>App name (adk)</label><input id=app placeholder="optional"></div>
</div>
<label><input type=checkbox id=mcponly style=width:auto> MCP checks only (include=mcp)</label>
<button onclick=start()>Start scan</button>
</fieldset>
<div id=out></div>
<script>
function val(id){return document.getElementById(id).value.trim()}
async function start(){
 const t=val('type'); const target={type:t, name:t+'-target'};
 const u=val('url'); if(u){ if(t==='http'){target.url=u;target.response_path='reply'} else if(t==='mcp'||t==='langserve'){target.url=u} else {target.base_url=u} }
 if(val('model'))target.model=val('model'); if(val('app'))target.app_name=val('app');
 const body={target, tier:parseInt(val('tier')), profile:{effort:parseFloat(val('effort'))}, formats:['json']};
 if(document.getElementById('mcponly').checked)body.include=['mcp'];
 const r=await fetch('/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const j=await r.json(); if(j.error){document.getElementById('out').innerHTML='<pre>'+j.error+'</pre>';return}
 poll(j.id);
}
async function poll(id){
 const r=await fetch('/scan/'+id); const j=await r.json();
 let h='<h3>Scan '+id+' — '+j.status+'</h3>';
 if(j.risk_score!==undefined){h+='<p><b>Risk '+j.risk_score+'/100</b> · highest '+j.highest_severity+' · '+j.vulnerable_findings+'/'+j.total_findings+' findings · '+j.total_attempts+' attempts</p>';}
 if(j.error)h+='<pre>'+j.error+'</pre>';
 h+='<pre>'+(j.log||[]).map(e=>JSON.stringify(e)).join('\\n')+'</pre>';
 if(j.status==='done')h+='<a class=btn href="/scan/'+id+'/report?format=html" target=_blank>Open HTML report</a><a class=btn href="/scan/'+id+'/report?format=json" target=_blank>JSON</a>';
 document.getElementById('out').innerHTML=h;
 if(j.status==='queued'||j.status==='running')setTimeout(()=>poll(id),1200);
}
</script></body></html>"""
