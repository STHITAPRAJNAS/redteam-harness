"""Compliance coverage — map the probe library (and a run's results) onto the
security frameworks, for an auditable covered / partial / gap view.

Two modes:
- *capability* coverage: what the harness can test, from probe metadata.
- *run* coverage: given a report JSON, which framework IDs were exercised and
  which actually fired.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from .core import registry
from .core.tier import Tier
from . import probes as _probes  # noqa: F401 (register probes)
from .probes.corpus_probe import build_corpus_probes

# --- canonical framework catalogues ---------------------------------------
OWASP_LLM_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data & Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector & Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

OWASP_MCP_2025 = {"MCP03:2025": "Tool Poisoning"}

NIST_AML = {
    "AML.evasion": "Evasion",
    "AML.poisoning.data": "Data Poisoning (runtime)",
    "AML.privacy.extraction": "Privacy — Model Extraction",
    "AML.privacy.data-reconstruction": "Privacy — Data Reconstruction",
    "AML.abuse": "Abuse / Misinformation",
}

# IDs that are intentionally only partially covered by a black-box runtime scan.
PARTIAL = {
    "LLM03:2025": "runtime trust (agent card / MCP rug-pull) only; "
                  "model/dependency supply chain needs an SCA tool",
    "LLM04:2025": "runtime/retrieval poisoning only; training-time dataset "
                  "poisoning & model backdoors are out of black-box scope",
}


def _all_probes(tier: Tier = Tier.ADAPTIVE):
    probes = registry.select(tier)
    probes += build_corpus_probes({"corpus_builtin": True}, tier)
    return probes


def _index(field: str, tier: Tier = Tier.ADAPTIVE) -> Dict[str, List[str]]:
    """framework-id -> [probe ids] from probe metadata (owasp/atlas/nist)."""
    idx: Dict[str, List[str]] = {}
    for p in _all_probes(tier):
        for fid in getattr(p, field, []) or []:
            idx.setdefault(fid, []).append(p.id)
    return idx


def capability_matrix() -> Dict[str, Dict]:
    """Per-framework status from what the probe library can test."""
    owasp = _index("owasp")
    nist = _index("nist")
    out = {"owasp_llm": [], "owasp_mcp": [], "nist_aml": []}
    for fid, name in OWASP_LLM_2025.items():
        probes = sorted(set(owasp.get(fid, [])))
        status = "gap" if not probes else ("partial" if fid in PARTIAL else "covered")
        out["owasp_llm"].append({"id": fid, "name": name, "status": status,
                                 "probes": probes, "note": PARTIAL.get(fid, "")})
    for fid, name in OWASP_MCP_2025.items():
        probes = sorted(set(owasp.get(fid, [])))
        out["owasp_mcp"].append({"id": fid, "name": name,
                                 "status": "covered" if probes else "gap",
                                 "probes": probes, "note": ""})
    for fid, name in NIST_AML.items():
        probes = sorted(set(nist.get(fid, [])))
        partial = fid.startswith("AML.privacy") or fid == "AML.poisoning.data"
        status = "gap" if not probes else ("partial" if partial else "covered")
        note = ("runtime slice only" if partial and probes else "")
        out["nist_aml"].append({"id": fid, "name": name, "status": status,
                                "probes": probes, "note": note})
    return out


def run_matrix(report_path: str) -> Dict[str, Dict]:
    """Per-framework exercised/fired status from a report JSON."""
    with open(report_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    findings = data.get("result", data).get("findings", [])
    exercised: Dict[str, bool] = {}   # fid -> any attempt run
    fired: Dict[str, bool] = {}       # fid -> any confirmed finding
    for f in findings:
        vuln = f.get("vulnerable")
        for key in ("owasp", "nist"):
            for fid in f.get(key, []) or []:
                exercised[fid] = True
                fired[fid] = fired.get(fid, False) or bool(vuln)
    out = {"target": data.get("result", data).get("target"), "frameworks": []}
    for catalogue in (OWASP_LLM_2025, OWASP_MCP_2025, NIST_AML):
        for fid, name in catalogue.items():
            if fid not in exercised:
                continue
            out["frameworks"].append({
                "id": fid, "name": name,
                "exercised": True, "fired": fired.get(fid, False)})
    return out


# --- rendering -------------------------------------------------------------
_MARK = {"covered": "✅", "partial": "◑", "gap": "⬚"}


def render_capability(fmt: str = "text") -> str:
    m = capability_matrix()
    if fmt == "json":
        return json.dumps(m, indent=2)
    lines = []
    md = fmt == "md"
    def row(a, b, c, d):
        return "| %s | %s | %s | %s |" % (a, b, c, d) if md else \
               "  %-13s %-2s %-34s %s" % (a, b, c, d)
    for title, key in (("OWASP LLM Top 10 (2025)", "owasp_llm"),
                       ("OWASP MCP", "owasp_mcp"), ("NIST AML", "nist_aml")):
        lines.append(("## " if md else "== ") + title + ("" if md else " =="))
        if md:
            lines.append("| ID | | Risk | Probes |")
            lines.append("|---|---|---|---|")
        for e in m[key]:
            probes = ", ".join(e["probes"]) or (e["note"] or "—")
            lines.append(row(e["id"], _MARK[e["status"]], e["name"], probes))
        lines.append("")
    legend = "Legend: ✅ covered · ◑ partial (runtime slice) · ⬚ gap/out-of-scope"
    lines.append(legend)
    return "\n".join(lines)


def render_run(report_path: str, fmt: str = "text") -> str:
    m = run_matrix(report_path)
    if fmt == "json":
        return json.dumps(m, indent=2)
    lines = ["Run coverage for target: %s" % m["target"]]
    for e in sorted(m["frameworks"], key=lambda x: x["id"]):
        mark = "FIRED" if e["fired"] else "tested"
        lines.append("  [%s] %-12s %s" % (mark, e["id"], e["name"]))
    lines.append("\n%d framework IDs exercised, %d fired."
                 % (len(m["frameworks"]), sum(1 for e in m["frameworks"] if e["fired"])))
    return "\n".join(lines)
