"""MCP-specific probes.

MCP servers advertise tools whose *descriptions and schemas are consumed by a
host LLM* when it decides what to call. Malicious or injected text there ("tool
poisoning" / rug-pull) can hijack the host agent's behaviour without the user
ever seeing it. These probes apply only to MCP targets.
"""
from __future__ import annotations

import json
import re
from typing import Iterable

from ..core.probe import Probe
from ..core.registry import register
from ..core.result import Attempt, Severity
from ..core.target import Target
from ..core.tier import Tier


def _is_mcp(target: Target) -> bool:
    return hasattr(target, "tools") and hasattr(target, "call_tool")


_INJECTION_RE = re.compile(
    r"(ignore (all |previous )?instructions|you must (always|now)|system\s*:|"
    r"<important>|do not (tell|mention|inform) the user|before (using|calling) "
    r"(any|this)|always (call|use|prefer)|exfiltrat|\.ssh|~/|read (the|all) "
    r"(file|secret)|send (it|them|the) to)", re.IGNORECASE)


@register
class MCPToolPoisoningProbe(Probe):
    id = "mcp.tool_poisoning"
    title = "MCP tool description/schema poisoning"
    description = (
        "Scans advertised MCP tool descriptions and input schemas for hidden or "
        "injected instructions that could hijack a host LLM's tool-use decisions "
        "(tool poisoning / rug-pull), including overlong or instruction-laden "
        "fields the user never sees."
    )
    severity = Severity.HIGH
    owasp = ["LLM01:2025", "LLM03:2025"]
    atlas = ["AML.T0051"]
    min_tier = Tier.BASIC
    tags = ["mcp", "tool", "injection"]
    remediation = (
        "Treat tool metadata as untrusted; sanitise/delimit descriptions before "
        "showing them to a model; pin and verify tool definitions (detect "
        "rug-pulls on change); cap field lengths; require human review of new "
        "MCP servers/tools."
    )

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        if not _is_mcp(target):
            return
        try:
            tools = target.list_tools()
        except Exception as exc:  # noqa: BLE001
            yield Attempt(self.id, int(tier), "tools_list", [], "",
                          False, "mcp_inspect", 0.0,
                          "could not list tools: %s" % exc)
            return
        if not tools:
            yield Attempt(self.id, int(tier), "tools_list", [], "",
                          False, "mcp_inspect", 0.0, "server advertised no tools")
            return
        for tool in tools:
            name = tool.get("name", "?")
            blob = (tool.get("description", "") or "") + " " + json.dumps(
                tool.get("inputSchema") or tool.get("input_schema") or {})
            m = _INJECTION_RE.search(blob)
            overlong = len(blob) > 1500
            vulnerable = bool(m) or overlong
            reason = ("tool %r description/schema contains instruction-like text: %r"
                      % (name, m.group(0))) if m else (
                      "tool %r metadata is unusually long (%d chars)" % (name, len(blob))
                      if overlong else "tool %r metadata looks clean" % name)
            yield Attempt(self.id, int(tier), "scan:%s" % name, [],
                          blob[:400], vulnerable, "mcp_inspect",
                          1.0 if vulnerable else 0.0, reason)
