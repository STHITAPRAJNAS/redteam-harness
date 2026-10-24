"""Optional integrations with external scanners (garak, mcp-scan).

When the external tool is installed and the target is applicable, rtharness can
run it as a subprocess and merge its findings into the same RunResult/report
(tagged ``source=<tool>``), so one report spans native + third-party coverage.

By design these are **opt-in** (``run --with garak`` / ``--with mcp-scan``):
nothing is auto-run. If a tool isn't installed, the integration is a clean
no-op that records a note. CLI invocation/output schemas vary by tool version,
so the command and the parsed keys are best-effort and overridable via the run
profile (``integrations.<tool>.cmd``).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

from .core.result import Attempt, Finding, Severity

_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
        "informational": Severity.INFO}


def _sev(name, default=Severity.MEDIUM) -> Severity:
    return _SEV.get(str(name or "").strip().lower(), default)


class ExternalTool:
    name = "external"
    binary = ""

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def applicable(self, target_cfg: dict) -> bool:
        return True

    def run(self, target_cfg: dict, profile: dict, timeout: float = 600.0):
        raise NotImplementedError


# --- garak (NVIDIA) --------------------------------------------------------
class GarakTool(ExternalTool):
    """Runs NVIDIA garak against an HTTP/OpenAI-compatible target and parses its
    report.jsonl (eval entries where passed < total => a failing probe)."""
    name = "garak"
    binary = "garak"

    def applicable(self, target_cfg: dict) -> bool:
        return (target_cfg.get("type") or "").lower() in ("openai", "openai_compat", "http", "http_chat")

    def _endpoint(self, target_cfg: dict) -> Optional[str]:
        return target_cfg.get("base_url") or target_cfg.get("url")

    def run(self, target_cfg, profile, timeout=600.0) -> Tuple[List[Finding], str]:
        endpoint = self._endpoint(target_cfg)
        if not endpoint:
            return [], "garak: target has no base_url/url to point at"
        outdir = tempfile.mkdtemp(prefix="garak-")
        prefix = os.path.join(outdir, "run")
        icfg = (profile.get("integrations") or {}).get("garak") or {}
        model_type = icfg.get("model_type", "openai")
        model_name = icfg.get("model_name") or target_cfg.get("model", "model")
        # Command is overridable; default is a conservative openai-generator run.
        cmd = icfg.get("cmd") or [
            "garak", "--model_type", model_type, "--model_name", model_name,
            "--report_prefix", prefix]
        if icfg.get("probes"):
            cmd += ["--probes", icfg["probes"]]
        env = dict(os.environ)
        if model_type == "openai" and endpoint:
            env.setdefault("OPENAI_BASE_URL", endpoint)
        try:
            subprocess.run(cmd, timeout=timeout, capture_output=True, env=env, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return [], "garak: failed to run (%s)" % exc
        report = prefix + ".report.jsonl"
        if not os.path.exists(report):
            # some versions append a suffix; find any jsonl in outdir
            cand = [f for f in os.listdir(outdir) if f.endswith(".jsonl")]
            report = os.path.join(outdir, cand[0]) if cand else report
        return self._parse(report), "garak: parsed %s" % report

    def _parse(self, report: str) -> List[Finding]:
        findings: List[Finding] = []
        if not os.path.exists(report):
            return findings
        with open(report, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("entry_type") != "eval":
                    continue
                total = e.get("total") or 0
                passed = e.get("passed")
                if passed is None or total <= 0 or passed >= total:
                    continue
                probe = e.get("probe") or e.get("probe_classname") or "garak.probe"
                rate = 1.0 - (passed / total)
                findings.append(self._finding(probe, e.get("detector", ""), passed, total, rate))
        return findings

    def _finding(self, probe, detector, passed, total, rate) -> Finding:
        sev = Severity.HIGH if rate >= 0.5 else Severity.MEDIUM
        att = Attempt(probe_id="garak:" + probe, tier=0, technique="garak:" + (detector or "eval"),
                      sent=[], response_text="", vulnerable=True, detector="garak",
                      score=round(rate, 3),
                      rationale="garak probe failed %d/%d" % (total - passed, total))
        return Finding(probe_id="garak:" + probe, title="garak: " + probe, severity=sev,
                       owasp=["LLM01:2025"], atlas=[], nist=["AML.evasion"],
                       description="Imported from NVIDIA garak (failing probe).",
                       remediation="See garak probe documentation for %s." % probe,
                       attempts=[att], source="garak")


# --- mcp-scan / Snyk agent scan -------------------------------------------
class McpScanTool(ExternalTool):
    """Runs an MCP static scanner (Invariant mcp-scan / Snyk agent scan) against
    an MCP target and parses its JSON issue list."""
    name = "mcp-scan"
    binary = "mcp-scan"

    def applicable(self, target_cfg: dict) -> bool:
        return (target_cfg.get("type") or "").lower() == "mcp"

    def run(self, target_cfg, profile, timeout=600.0) -> Tuple[List[Finding], str]:
        url = target_cfg.get("url")
        if not url:
            return [], "mcp-scan: target has no url"
        icfg = (profile.get("integrations") or {}).get("mcp-scan") or {}
        cmd = icfg.get("cmd") or ["mcp-scan", "scan", url, "--json"]
        try:
            proc = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return [], "mcp-scan: failed to run (%s)" % exc
        return self._parse(proc.stdout), "mcp-scan: exit %d" % proc.returncode

    def _parse(self, stdout: str) -> List[Finding]:
        try:
            data = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            return []
        issues = None
        if isinstance(data, list):
            issues = data
        elif isinstance(data, dict):
            for k in ("issues", "findings", "results", "vulnerabilities"):
                if isinstance(data.get(k), list):
                    issues = data[k]
                    break
        findings: List[Finding] = []
        for i, it in enumerate(issues or []):
            if not isinstance(it, dict):
                continue
            title = it.get("title") or it.get("name") or it.get("rule") or ("issue-%d" % i)
            desc = it.get("description") or it.get("message") or ""
            att = Attempt(probe_id="mcp-scan:" + title, tier=0, technique="mcp-scan",
                          sent=[], response_text=str(desc)[:400], vulnerable=True,
                          detector="mcp-scan", score=1.0, rationale=str(desc)[:200])
            findings.append(Finding(
                probe_id="mcp-scan:" + title, title="mcp-scan: " + title,
                severity=_sev(it.get("severity")), owasp=["LLM03:2025", "MCP03:2025"],
                atlas=["AML.T0010"], nist=["AML.poisoning.data"],
                description="Imported from mcp-scan.", attempts=[att], source="mcp-scan"))
        return findings


_TOOLS = {"garak": GarakTool, "mcp-scan": McpScanTool}


def run_external(names: List[str], target_cfg: dict, profile: dict,
                 timeout: float = 600.0) -> Tuple[List[Finding], List[str]]:
    findings: List[Finding] = []
    notes: List[str] = []
    for name in names:
        cls = _TOOLS.get(name)
        if cls is None:
            notes.append("%s: unknown tool (known: %s)" % (name, ", ".join(_TOOLS)))
            continue
        tool = cls()
        if not tool.available():
            notes.append("%s: not installed (skipped)" % name)
            continue
        if not tool.applicable(target_cfg):
            notes.append("%s: not applicable to target type %r (skipped)"
                         % (name, target_cfg.get("type")))
            continue
        try:
            got, note = tool.run(target_cfg, profile, timeout)
        except Exception as exc:  # noqa: BLE001
            notes.append("%s: error (%s)" % (name, exc))
            continue
        findings += got
        notes.append("%s: %d finding(s) — %s" % (name, len(got), note))
    return findings, notes
