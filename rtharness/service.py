"""rtharness web service.

Primary implementation is **FastAPI** (OpenAPI docs at ``/docs``, request
validation, and an MCP endpoint that exposes rtharness itself as a tool so any
agent framework — ADK, LangGraph, Claude, … — can call it). If FastAPI/uvicorn
are not installed it transparently falls back to a zero-dependency stdlib
server, so ``rtharness serve`` always works.

Install the server extra for the FastAPI experience::

    pip install 'rtharness[server]'

It is a **local operator tool**: binds to 127.0.0.1, no authentication, and it
launches scans against targets on request — do not expose it publicly.
"""
# NOTE: do NOT add `from __future__ import annotations` here — FastAPI needs the
# real type objects (locally-defined Pydantic models, Request) to classify
# params; stringised annotations would be misread as query parameters.
from typing import Any, Dict, List, Optional

from . import _service_common as sc


def _build_fastapi_app():
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel, Field

    app = FastAPI(
        title="rtharness",
        version=sc._version(),
        description="Local red-team service for agent apps (chat / A2A / MCP). "
                    "Authorised testing only.")

    class ScanRequest(BaseModel):
        target: Dict[str, Any] = Field(..., description="target config, e.g. "
                                       "{'type':'a2a','base_url':'http://localhost:9999'}")
        preset: Optional[str] = Field(None, description="named profile, e.g. "
                                      "'owasp-llm', 'mcp', 'deep' (see GET /presets)")
        tier: Optional[int] = None
        include: Optional[List[str]] = None
        exclude: Optional[List[str]] = None
        tags: Optional[List[str]] = None
        profile: Dict[str, Any] = Field(default_factory=dict)
        rate_limit_s: float = 0.0

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard():
        return sc.DASHBOARD_HTML

    @app.get("/health")
    def health():
        return {"status": "ok", "version": sc._version(), "jobs": len(sc.JOBS)}

    @app.get("/probes")
    def probes():
        return sc.probe_inventory()

    @app.get("/presets")
    def presets_list():
        from . import presets as _p
        return {"presets": [{"name": n, "description": _p.describe(n)} for n in _p.names()]}

    @app.post("/scan", status_code=202)
    def scan(req: ScanRequest):
        try:
            job = sc.start_scan(req.model_dump(exclude_none=True))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, "%s: %s" % (type(exc).__name__, exc))
        return {"id": job.id, "status": job.status}

    @app.get("/scan/{job_id}")
    def scan_status(job_id: str):
        job = sc.JOBS.get(job_id)
        if job is None:
            raise HTTPException(404, "no such scan")
        return job.summary()

    @app.get("/scan/{job_id}/report")
    def scan_report(job_id: str, format: str = "json"):
        job = sc.JOBS.get(job_id)
        if job is None:
            raise HTTPException(404, "no such scan")
        if job.result is None:
            raise HTTPException(409, "scan not finished (status=%s)" % job.status)
        content, ctype = sc.render_report(job, format.lower())
        if format.lower() == "json":
            return JSONResponse(content=__import__("json").loads(content))
        return Response(content=content, media_type=ctype)

    # MCP endpoint: rtharness exposed as an agent-callable tool server.
    @app.post("/mcp", include_in_schema=False)
    async def mcp(request: Request):
        body = await request.json()
        resp = sc.mcp_dispatch(body)
        return JSONResponse(content=resp if resp is not None else {})

    return app


def serve(host: str = "127.0.0.1", port: int = 8900):
    public = host not in ("127.0.0.1", "localhost", "::1")
    try:
        import uvicorn  # noqa: F401
        app = _build_fastapi_app()
        print("rtharness (FastAPI) on http://%s:%d  — dashboard /, docs /docs, MCP /mcp"
              % (host, port))
        if public:
            print("WARNING: non-local bind with NO auth; it launches scans on "
                  "request — do not expose publicly.")
        import uvicorn
        uvicorn.run(app, host=host, port=port, log_level="warning")
    except ImportError:
        print("FastAPI/uvicorn not installed; using the stdlib server "
              "(pip install 'rtharness[server]' for /docs + /mcp).")
        from ._service_stdlib import serve_stdlib
        serve_stdlib(host=host, port=port)
