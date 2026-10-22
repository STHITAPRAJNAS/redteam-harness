"""MCP-specific probes — the dynamic, black-box complement to static MCP
scanners (Snyk/Invariant mcp-scan, SplxAI Agentic Radar).

MCP exposes three kinds of LLM-read metadata — **tools**, **resources**, and
**prompts** — and all three are prompt-injection channels ("tool poisoning" /
rug-pull). Static scanners catch declared-metadata issues but, by their own
docs, cannot catch data-borne injection in what a tool/resource *returns*; this
probe set covers the declared surface and the returned-content surface.

Mapped to the OWASP MCP Top 10 (beta, 2026): tool poisoning = MCP03.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Iterable, List

from ..core.probe import Probe
from ..core.registry import register
from ..core.result import Attempt, Severity
from ..core.target import Target
from ..core.tier import Tier


def _is_mcp(target: Target) -> bool:
    return hasattr(target, "tools") and hasattr(target, "call_tool")


_INJECTION_RE = re.compile(
    r"(ignore (all |previous )?instructions|you must (always|now)|system\s*:|"
    r"<important>|do not (tell|mention|inform|reveal)|before (using|calling|answering)|"
    r"always (call|use|prefer|select)|exfiltrat|\.ssh|~/\.|read (the|all) "
    r"(file|secret|config)|send (it|them|the \w+) to|curl |http://|https://)",
    re.IGNORECASE)


def _mk(pid, tier, tech, text, vuln, reason, score=1.0):
    return Attempt(pid, int(tier), tech, [], text, vuln, "mcp_inspect",
                   score if vuln else 0.0, reason)


def _entries(target):
    """Yield (surface, name, text_blob) across tools/resources/prompts."""
    for t in getattr(target, "tools", []) or []:
        blob = (t.get("description", "") or "") + " " + json.dumps(
            t.get("inputSchema") or t.get("input_schema") or {})
        yield "tool", t.get("name", "?"), blob
    for r in getattr(target, "resources", []) or []:
        blob = " ".join(str(r.get(k, "")) for k in ("name", "description", "uri", "mimeType"))
        yield "resource", r.get("name") or r.get("uri", "?"), blob
    for p in getattr(target, "prompts", []) or []:
        blob = (p.get("description", "") or "") + " " + json.dumps(p.get("arguments") or [])
        yield "prompt", p.get("name", "?"), blob


@register
class MCPMetadataPoisoningProbe(Probe):
    id = "mcp.metadata_poisoning"
    title = "MCP tool/resource/prompt metadata poisoning"
    description = (
        "Scans every advertised MCP tool, resource and prompt for hidden or "
        "injected instructions a host LLM would read during selection "
        "(tool poisoning / rug-pull channel). OWASP MCP03."
    )
    severity = Severity.HIGH
    owasp = ["LLM01:2025", "LLM03:2025", "MCP03:2025"]
    atlas = ["AML.T0051"]
    min_tier = Tier.BASIC
    tags = ["mcp", "tool", "resource", "prompt", "injection"]
    remediation = (
        "Treat all MCP metadata (tool/resource/prompt descriptions and schemas) "
        "as untrusted; sanitise/delimit before showing to a model; pin and "
        "verify definitions to detect rug-pulls; cap field lengths; require "
        "human review before enabling a new MCP server."
    )

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        if not _is_mcp(target):
            return
        for fn in ("list_tools", "list_resources", "list_prompts"):
            try:
                getattr(target, fn)()
            except Exception:  # noqa: BLE001
                pass
        seen = False
        for surface, name, blob in _entries(target):
            seen = True
            m = _INJECTION_RE.search(blob)
            overlong = len(blob) > 1500
            vuln = bool(m) or overlong
            reason = ("%s %r metadata contains instruction-like text: %r"
                      % (surface, name, m.group(0))) if m else (
                      "%s %r metadata unusually long (%d chars)" % (surface, name, len(blob))
                      if overlong else "%s %r metadata looks clean" % (surface, name))
            yield _mk(self.id, tier, "scan:%s:%s" % (surface, name), blob[:400], vuln, reason)
        if not seen:
            yield _mk(self.id, tier, "scan", "", False, "server advertised no tools/resources/prompts")


@register
class MCPReturnedContentInjectionProbe(Probe):
    id = "mcp.returned_injection"
    title = "MCP resource / tool returns attacker-style injected content"
    description = (
        "Reads MCP resources (and the output of read-only tools) and flags "
        "data-borne injected instructions in what comes back — the data-flow "
        "attack static scanners explicitly miss."
    )
    severity = Severity.HIGH
    owasp = ["LLM01:2025", "MCP03:2025"]
    atlas = ["AML.T0051", "AML.T0051.001"]
    min_tier = Tier.INTERMEDIATE
    tags = ["mcp", "resource", "indirect", "injection"]
    remediation = (
        "Never treat MCP-returned content as instructions; spotlight/delimit it; "
        "strip embedded directives before it reaches the model's instruction "
        "channel."
    )

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        if not _is_mcp(target):
            return
        resources = getattr(target, "resources", []) or []
        if not resources:
            try:
                resources = target.list_resources()
            except Exception:  # noqa: BLE001
                resources = []
        if not resources:
            return
        for r in resources[:20]:
            uri = r.get("uri") or r.get("name")
            if not uri:
                continue
            try:
                body = target.read_resource(uri)
            except Exception as exc:  # noqa: BLE001
                yield _mk(self.id, tier, "read:%s" % uri, "", False,
                          "could not read resource %s: %s" % (uri, exc))
                continue
            m = _INJECTION_RE.search(body or "")
            vuln = bool(m)
            reason = ("resource %s returned injected instruction: %r" % (uri, m.group(0))
                      if m else "resource %s content looks clean" % uri)
            yield _mk(self.id, tier, "read:%s" % uri, (body or "")[:400], vuln, reason)


@register
class MCPRugPullProbe(Probe):
    id = "mcp.rug_pull"
    title = "MCP definition drift / rug-pull (description pinning)"
    description = (
        "Pins a hash of every tool/resource/prompt definition on first run and "
        "flags any later change — the mechanism behind rug-pull attacks where a "
        "trusted server silently swaps in a malicious definition."
    )
    severity = Severity.HIGH
    owasp = ["LLM03:2025", "MCP03:2025"]
    atlas = ["AML.T0010"]
    min_tier = Tier.BASIC
    tags = ["mcp", "rug-pull", "integrity"]
    remediation = (
        "Pin tool/resource/prompt definitions and verify them on every "
        "connection; alert on any change; allow-list servers."
    )

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        if not _is_mcp(target):
            return
        baseline_path = self.profile.get("mcp_baseline")
        if not baseline_path:
            # No baseline configured: record current hashes for the report only.
            n = sum(1 for _ in _entries(target))
            yield _mk(self.id, tier, "pin", "", False,
                      "no mcp_baseline set; recorded %d definitions (set "
                      "profile.mcp_baseline to enable drift detection)" % n)
            return
        current = {f"{s}:{n}": hashlib.sha256(b.encode()).hexdigest()
                   for s, n, b in _entries(target)}
        if not os.path.exists(baseline_path):
            with open(baseline_path, "w", encoding="utf-8") as fh:
                json.dump(current, fh, indent=2)
            yield _mk(self.id, tier, "baseline", "", False,
                      "baseline written to %s (%d defs); re-run to detect drift"
                      % (baseline_path, len(current)))
            return
        with open(baseline_path, "r", encoding="utf-8") as fh:
            baseline = json.load(fh)
        changed = [k for k, v in current.items() if baseline.get(k) not in (None, v)]
        added = [k for k in current if k not in baseline]
        removed = [k for k in baseline if k not in current]
        vuln = bool(changed)
        reason = ("definitions changed since baseline: %s" % ", ".join(changed)
                  if changed else
                  "no drift (added=%d removed=%d)" % (len(added), len(removed)))
        yield _mk(self.id, tier, "drift", json.dumps({"changed": changed,
                  "added": added, "removed": removed}), vuln, reason)


@register
class MCPUnauthProbe(Probe):
    id = "mcp.unauth_access"
    title = "MCP server lists/calls without authentication"
    description = (
        "Repeats tools/list with the Authorization header stripped; if the "
        "server still enumerates its tools, the MCP endpoint is exposed to "
        "anonymous reconnaissance and use."
    )
    severity = Severity.HIGH
    owasp = ["LLM06:2025", "MCP03:2025"]
    atlas = ["AML.T0049"]
    min_tier = Tier.INTERMEDIATE
    tags = ["mcp", "auth", "access-control"]
    remediation = (
        "Require authentication on the MCP endpoint; reject unauthenticated "
        "initialize/list/call; scope tokens to least privilege."
    )

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        if not _is_mcp(target) or "Authorization" not in getattr(target, "headers", {}):
            # Only meaningful when auth was configured in the first place.
            if _is_mcp(target) and not getattr(target, "headers", {}).get("Authorization"):
                yield _mk(self.id, tier, "unauth", "", False,
                          "no auth configured for this target; cannot assess unauth bypass")
            return
        saved = dict(target.headers)
        try:
            target.headers = {k: v for k, v in saved.items() if k != "Authorization"}
            target._initialised = False
            target.session_id = None
            tools = target.list_tools()
            vuln = bool(tools)
            reason = ("tools/list succeeded without auth (%d tools exposed)" % len(tools)
                      if vuln else "unauthenticated tools/list returned nothing")
            yield _mk(self.id, tier, "unauth_list", str([t.get("name") for t in tools])[:300],
                      vuln, reason)
        except Exception as exc:  # noqa: BLE001 - rejection is the good outcome
            yield _mk(self.id, tier, "unauth_list", "", False,
                      "unauthenticated access rejected: %s" % exc)
        finally:
            target.headers = saved
            target._initialised = False
            target.session_id = None
