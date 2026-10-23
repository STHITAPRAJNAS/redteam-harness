"""Shared pieces for the web service: job store, inventory, dashboard, and the
MCP-tool bridge. Used by both the FastAPI server and the stdlib fallback so the
two stay in lockstep.
"""
from __future__ import annotations

import threading
import time
import uuid
from typing import Any, Dict, Optional

from . import api
from .config import RunConfig
from .core import registry
from .core.tier import Tier
from .corpus import builtin_packs
from .report import to_json, to_markdown, to_html, to_sarif, to_junit


class Job:
    def __init__(self, cfg: RunConfig):
        self.id = uuid.uuid4().hex[:12]
        self.cfg = cfg
        self.status = "queued"      # queued | running | done | error
        self.error: Optional[str] = None
        self.result = None
        self.log: list = []
        self.created = time.time()

    def on_event(self, ev: str, data: dict):
        if ev in ("run_start", "probe_done", "run_done"):
            self.log.append({"ev": ev, **data})

    def summary(self) -> Dict[str, Any]:
        d = {"id": self.id, "status": self.status, "error": self.error,
             "target": self.cfg.target.get("name") or self.cfg.target.get("type"),
             "tier": int(self.cfg.tier), "created": self.created,
             "modes": api.capabilities(self.cfg), "log": self.log[-60:]}
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


JOBS: Dict[str, Job] = {}


def start_scan(body: dict) -> Job:
    cfg = RunConfig.from_dict(body)
    job = Job(cfg)
    JOBS[job.id] = job

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


def run_scan_blocking(body: dict, timeout: float = 600.0) -> Job:
    """Start a scan and wait for it (used by the synchronous MCP tool)."""
    job = start_scan(body)
    deadline = time.time() + timeout
    while job.status in ("queued", "running") and time.time() < deadline:
        time.sleep(0.2)
    return job


def render_report(job: Job, fmt: str) -> tuple:
    """Return (content, content_type) for a finished job's report."""
    if fmt == "md":
        return to_markdown(job.result), "text/markdown; charset=utf-8"
    if fmt == "html":
        return to_html(job.result), "text/html; charset=utf-8"
    if fmt == "sarif":
        return to_sarif(job.result), "application/json"
    if fmt == "junit":
        return to_junit(job.result), "application/xml; charset=utf-8"
    return to_json(job.result), "application/json"


def probe_inventory() -> dict:
    probes = registry.select(Tier.ADAPTIVE)
    return {
        "probes": [{"id": p.id, "title": p.title, "severity": p.severity.label,
                    "min_tier": int(p.min_tier), "owasp": p.owasp,
                    "atlas": p.atlas, "tags": p.tags} for p in probes],
        "corpus_packs": [{"name": "corpus.%s" % pk.name, "payloads": len(pk.payloads),
                          "severity": pk.severity.label, "description": pk.description}
                         for pk in builtin_packs()],
    }


# --- MCP tool bridge: expose rtharness itself as MCP tools -----------------
MCP_TOOLS = [
    {"name": "scan_agent",
     "description": ("Red-team an agent application over its chat / A2A / MCP "
                     "surface and return a risk summary. For authorised testing."),
     "inputSchema": {
         "type": "object",
         "properties": {
             "target": {"type": "object",
                        "description": "target config, e.g. {\"type\":\"a2a\",\"base_url\":\"...\"}"},
             "tier": {"type": "integer", "minimum": 1, "maximum": 4, "default": 2},
             "include": {"type": "array", "items": {"type": "string"},
                         "description": "optional probe id/prefix filter, e.g. [\"mcp\"]"},
             "effort": {"type": "number", "default": 1.0},
         },
         "required": ["target"]}},
    {"name": "list_probes",
     "description": "List available probes and corpus packs.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def mcp_call_tool(name: str, arguments: dict) -> dict:
    """Execute an exposed MCP tool; returns an MCP tools/call result dict."""
    if name == "list_probes":
        return _mcp_text(_json(probe_inventory()))
    if name == "scan_agent":
        body = {"target": arguments.get("target", {}),
                "tier": arguments.get("tier", 2),
                "profile": {"effort": arguments.get("effort", 1.0)}}
        if arguments.get("include"):
            body["include"] = arguments["include"]
        job = run_scan_blocking(body)
        if job.status == "error":
            return {"isError": True, "content": [{"type": "text", "text": job.error}]}
        summary = job.summary()
        summary["findings"] = [
            {"probe": f.probe_id, "severity": f.severity.label,
             "vulnerable": f.vulnerable, "owasp": f.owasp}
            for f in job.result.findings if f.vulnerable]
        return _mcp_text(_json(summary))
    return {"isError": True, "content": [{"type": "text", "text": "unknown tool %r" % name}]}


def _mcp_text(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _json(obj) -> str:
    import json
    return json.dumps(obj, default=str, indent=2)


def mcp_dispatch(req: dict) -> Optional[dict]:
    """Handle one MCP JSON-RPC request. Returns a response dict, or None for a
    notification (no reply expected)."""
    method = req.get("method")
    rpc_id = req.get("id")
    params = req.get("params") or {}
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "rtharness", "version": _version()}}
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        result = {"tools": MCP_TOOLS}
    elif method == "tools/call":
        result = mcp_call_tool(params.get("name"), params.get("arguments") or {})
    else:
        return {"jsonrpc": "2.0", "id": rpc_id,
                "error": {"code": -32601, "message": "method not found: %s" % method}}
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _version() -> str:
    from . import __version__
    return __version__


DASHBOARD_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
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
code{background:#8882;padding:1px 5px;border-radius:4px}
</style></head><body>
<h1>rtharness</h1>
<div class=muted>Local red-team console for agent apps (chat / A2A / MCP). Authorised testing only.
API docs at <code>/docs</code> · MCP endpoint at <code>/mcp</code>.</div>
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
 const j=await r.json(); if(j.error||j.detail){document.getElementById('out').innerHTML='<pre>'+(j.error||JSON.stringify(j.detail))+'</pre>';return}
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
