"""Runner — orchestrates probes against a target and assembles a RunResult."""
from __future__ import annotations

import sys
import time
from typing import Callable, List, Optional

from .probe import Probe
from .result import Finding, RunResult
from .target import Target
from .tier import Tier


class Runner:
    def __init__(
        self,
        target: Target,
        tier: Tier = Tier.BASIC,
        on_event: Optional[Callable[[str, dict], None]] = None,
        rate_limit_s: float = 0.0,
        stop_on_error: bool = False,
    ):
        self.target = target
        self.tier = Tier.parse(tier)
        self.on_event = on_event or (lambda ev, data: None)
        self.rate_limit_s = rate_limit_s
        self.stop_on_error = stop_on_error

    def run(self, probes: List[Probe]) -> RunResult:
        result = RunResult(target_name=getattr(self.target, "name", "target"),
                           tier=int(self.tier))
        self.on_event("run_start", {"n_probes": len(probes), "tier": int(self.tier)})
        for probe in probes:
            self.on_event("probe_start", {"probe": probe.id, "title": probe.title})
            attempts = []
            try:
                for attempt in probe.run(self.target, self.tier):
                    attempts.append(attempt)
                    self.on_event("attempt", {
                        "probe": probe.id,
                        "technique": attempt.technique,
                        "vulnerable": attempt.vulnerable,
                        "error": attempt.error,
                    })
                    if self.rate_limit_s:
                        time.sleep(self.rate_limit_s)
            except Exception as exc:  # noqa: BLE001
                self.on_event("probe_error", {"probe": probe.id, "error": str(exc)})
                if self.stop_on_error:
                    raise
            finding: Finding = probe.to_finding(attempts)
            result.findings.append(finding)
            self.on_event("probe_done", {
                "probe": probe.id,
                "vulnerable": finding.vulnerable,
                "n_vulnerable": finding.n_vulnerable,
                "n_attempts": finding.n_attempts,
                "severity": finding.severity.label,
            })
        result.finished_at = time.time()
        self.on_event("run_done", {
            "risk_score": result.risk_score(),
            "vulnerable_findings": len(result.vulnerable_findings),
        })
        return result


def console_reporter(verbose: bool = True) -> Callable[[str, dict], None]:
    """A simple on_event callback that prints progress to stderr."""
    def cb(ev: str, data: dict):
        if ev == "run_start":
            print("[*] Starting run: %d probes at tier %d"
                  % (data["n_probes"], data["tier"]), file=sys.stderr)
        elif ev == "probe_start" and verbose:
            print("  -> %s" % data["title"], file=sys.stderr)
        elif ev == "probe_done":
            mark = "VULN" if data["vulnerable"] else " ok "
            print("    [%s] %s  (%d/%d attempts fired, sev=%s)"
                  % (mark, data["probe"], data["n_vulnerable"],
                     data["n_attempts"], data["severity"]), file=sys.stderr)
        elif ev == "probe_error":
            print("    [ERR] %s: %s" % (data["probe"], data["error"]), file=sys.stderr)
        elif ev == "run_done":
            print("[*] Done. Risk score %d/100, %d vulnerable finding(s)."
                  % (data["risk_score"], data["vulnerable_findings"]), file=sys.stderr)
    return cb
