"""SARIF 2.1.0 report — for GitHub code scanning and other SARIF consumers.

Each probe becomes a SARIF *rule*; each confirmed-vulnerable finding becomes a
*result* with a severity level and a logical location naming the target and the
technique that fired. This lets agent-security findings land in the same place
as SAST results.
"""
from __future__ import annotations

import json

from ..core.result import RunResult, Severity
from ..version import __version__

_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "none",
}


def to_sarif(result: RunResult) -> str:
    rules, rule_index = [], {}
    for f in result.findings:
        if f.probe_id in rule_index:
            continue
        rule_index[f.probe_id] = len(rules)
        rules.append({
            "id": f.probe_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description or f.title},
            "helpUri": "https://github.com/sthitaprajnas/redteam-harness",
            "properties": {"owasp": f.owasp, "atlas": f.atlas,
                           "security-severity": _sev_score(f.severity)},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
        })

    results = []
    for f in result.vulnerable_findings:
        fired = next((a for a in f.attempts if a.vulnerable), None)
        tech = fired.technique if fired else "unknown"
        results.append({
            "ruleId": f.probe_id,
            "ruleIndex": rule_index[f.probe_id],
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": "%s — fired via %s (%d/%d attempts). %s"
                        % (f.title, tech, f.n_vulnerable, f.n_attempts,
                           (fired.rationale if fired else ""))},
            "locations": [{"logicalLocations": [
                {"name": result.target_name, "kind": "resource",
                 "fullyQualifiedName": "%s::%s" % (result.target_name, f.probe_id)}]}],
            "properties": {"owasp": f.owasp, "atlas": f.atlas,
                           "severity": f.severity.label, "technique": tech},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "rtharness",
                "version": __version__,
                "informationUri": "https://github.com/sthitaprajnas/redteam-harness",
                "rules": rules,
            }},
            "results": results,
            "properties": {"target": result.target_name, "tier": result.tier,
                           "risk_score": result.risk_score()},
        }],
    }
    return json.dumps(sarif, indent=2)


def _sev_score(sev: Severity) -> str:
    # GitHub code-scanning numeric severity (0-10).
    return {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0", Severity.INFO: "0.0"}.get(sev, "5.0")


def write_sarif(result: RunResult, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_sarif(result))
    return path
