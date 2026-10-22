"""Model Context Protocol (MCP) target — streamable-HTTP transport.

MCP servers expose *tools* to agents. Their attack surface is (a) tool
descriptions/schemas that a host LLM reads during tool selection ("tool
poisoning" / rug-pull), and (b) the tools themselves (what they do with
arguments, what they leak). This adapter speaks the MCP JSON-RPC handshake over
HTTP:

    initialize -> notifications/initialized -> tools/list -> tools/call

It handles both ``application/json`` and ``text/event-stream`` (SSE) responses
and echoes the ``Mcp-Session-Id`` header. ``generate()`` maps a chat turn onto a
``tools/call`` of a chosen tool (configurable; else the first tool, with the
prompt placed in its first string parameter), so the normal probe set can drive
an MCP server too. The discovered tools are exposed via :attr:`tools` for the
MCP-specific probe.
"""
from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

import requests

from ..core.target import Response, Target, Turn
from . import _http


def _parse_sse(text: str) -> List[dict]:
    msgs = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data = "".join(line[5:].lstrip() for line in block.splitlines()
                       if line.startswith("data:"))
        if data:
            try:
                msgs.append(json.loads(data))
            except json.JSONDecodeError:
                pass
    return msgs


class MCPTarget(Target):
    def __init__(
        self,
        url: str,
        name: Optional[str] = None,
        tool: Optional[str] = None,
        arg: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_env: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        protocol_version: str = "2025-06-18",
        timeout: float = 60.0,
        verify_tls: bool = True,
        auto_init: bool = True,
    ):
        self.url = url
        self.name = name or ("mcp:" + url)
        self.tool_name = tool
        self.arg_name = arg
        self.protocol_version = protocol_version
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream"}
        self.headers.update(headers or {})
        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers["Authorization"] = "Bearer " + key
        self.session_id: Optional[str] = None
        self.tools: List[Dict[str, Any]] = []
        self.resources: List[Dict[str, Any]] = []
        self.prompts: List[Dict[str, Any]] = []
        self._initialised = False
        if auto_init:
            try:
                self.initialize()
                self.list_tools()
                self.list_resources()
                self.list_prompts()
            except Exception:  # noqa: BLE001 - surfaced later per-call
                pass

    # --- transport ---------------------------------------------------------
    def _rpc(self, method: str, params: Optional[dict] = None, notify: bool = False):
        body = {"jsonrpc": "2.0", "method": method}
        if not notify:
            body["id"] = uuid.uuid4().hex
        if params is not None:
            body["params"] = params
        hdrs = dict(self.headers)
        if self.session_id:
            hdrs["Mcp-Session-Id"] = self.session_id
        resp = requests.post(self.url, json=body, headers=hdrs,
                             timeout=self.timeout, verify=self.verify_tls)
        sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if sid:
            self.session_id = sid
        if notify:
            return None
        if resp.status_code >= 400:
            raise _http.HTTPError("MCP %s -> HTTP %d: %s" % (method, resp.status_code, resp.text[:300]))
        ctype = resp.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            msgs = _parse_sse(resp.text)
            for m in msgs:
                if "result" in m or "error" in m:
                    return m
            return msgs[-1] if msgs else {}
        return resp.json()

    # --- handshake ---------------------------------------------------------
    def initialize(self) -> dict:
        data = self._rpc("initialize", {
            "protocolVersion": self.protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "rtharness", "version": "0.2"},
        })
        self._rpc("notifications/initialized", {}, notify=True)
        self._initialised = True
        return data

    def list_tools(self) -> List[Dict[str, Any]]:
        if not self._initialised:
            self.initialize()
        data = self._rpc("tools/list", {})
        self.tools = ((data or {}).get("result") or {}).get("tools", []) or []
        return self.tools

    def list_resources(self) -> List[Dict[str, Any]]:
        if not self._initialised:
            self.initialize()
        try:
            data = self._rpc("resources/list", {})
            self.resources = ((data or {}).get("result") or {}).get("resources", []) or []
        except Exception:  # noqa: BLE001 - server may not support resources
            self.resources = []
        return self.resources

    def list_prompts(self) -> List[Dict[str, Any]]:
        if not self._initialised:
            self.initialize()
        try:
            data = self._rpc("prompts/list", {})
            self.prompts = ((data or {}).get("result") or {}).get("prompts", []) or []
        except Exception:  # noqa: BLE001 - server may not support prompts
            self.prompts = []
        return self.prompts

    def read_resource(self, uri: str) -> str:
        data = self._rpc("resources/read", {"uri": uri})
        contents = ((data or {}).get("result") or {}).get("contents", []) or []
        return "\n".join(c.get("text", "") for c in contents if isinstance(c, dict))

    def get_prompt(self, name: str, arguments: Optional[dict] = None) -> str:
        data = self._rpc("prompts/get", {"name": name, "arguments": arguments or {}})
        msgs = ((data or {}).get("result") or {}).get("messages", []) or []
        out = []
        for m in msgs:
            content = m.get("content") if isinstance(m, dict) else None
            if isinstance(content, dict):
                out.append(content.get("text", ""))
            elif isinstance(content, list):
                out += [c.get("text", "") for c in content if isinstance(c, dict)]
        return "\n".join(out)

    def call_tool(self, name: str, arguments: dict) -> Response:
        def _call():
            if not self._initialised:
                self.initialize()
            data = self._rpc("tools/call", {"name": name, "arguments": arguments})
            if data.get("error"):
                raise _http.HTTPError("MCP tool error: %s" % data["error"])
            result = data.get("result") or {}
            parts = []
            for c in result.get("content", []) or []:
                if isinstance(c, dict) and isinstance(c.get("text"), str):
                    parts.append(c["text"])
            return "\n".join(parts), data, []
        return self._timed(_call)

    # --- chat mapping ------------------------------------------------------
    def _pick_tool(self) -> Optional[Dict[str, Any]]:
        if not self.tools:
            try:
                self.list_tools()
            except Exception:  # noqa: BLE001
                return None
        if self.tool_name:
            for t in self.tools:
                if t.get("name") == self.tool_name:
                    return t
        return self.tools[0] if self.tools else None

    def _arg_for(self, tool: Dict[str, Any]) -> str:
        if self.arg_name:
            return self.arg_name
        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        props = schema.get("properties") or {}
        for key, spec in props.items():
            if (spec or {}).get("type", "string") == "string":
                return key
        return next(iter(props), "input")

    def generate(self, messages: List[Turn]) -> Response:
        latest = next((t.content for t in reversed(messages) if t.role == "user"), "")
        tool = self._pick_tool()
        if tool is None:
            return Response(text="", error="no MCP tools available to call")
        return self.call_tool(tool.get("name"), {self._arg_for(tool): latest})
