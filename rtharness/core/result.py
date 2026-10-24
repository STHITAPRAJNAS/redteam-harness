"""Result data model: attempts, findings, run results, severity scoring."""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def parse(cls, value) -> "Severity":
        if isinstance(value, Severity):
            return value
        return cls[str(value).strip().upper()]


@dataclass
class Attempt:
    """A single probe attempt: what we sent, what came back, and the verdict."""
    probe_id: str
    tier: int
    technique: str                      # e.g. "direct", "crescendo", "base64"
    # Conversation we sent (list of {"role", "content"}). For single-turn this
    # is one user turn.
    sent: List[Dict[str, str]]
    response_text: str
    vulnerable: bool                    # did a detector fire?
    detector: str                       # which detector decided
    score: float                        # 0..1 confidence from the detector
    rationale: str = ""                 # human-readable why
    latency_ms: float = 0.0
    error: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A vulnerability class result for one probe against one target."""
    probe_id: str
    title: str
    severity: Severity
    owasp: List[str] = field(default_factory=list)     # e.g. ["LLM01:2025"]
    atlas: List[str] = field(default_factory=list)      # e.g. ["AML.T0051"]
    nist: List[str] = field(default_factory=list)       # NIST AML, e.g. ["AML.evasion"]
    description: str = ""
    remediation: str = ""
    attempts: List[Attempt] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return any(a.vulnerable for a in self.attempts)

    @property
    def n_vulnerable(self) -> int:
        return sum(1 for a in self.attempts if a.vulnerable)

    @property
    def n_attempts(self) -> int:
        return len(self.attempts)

    @property
    def effective_severity(self) -> Severity:
        """INFO if nothing fired; otherwise the probe's declared severity."""
        return self.severity if self.vulnerable else Severity.INFO

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "probe_id": self.probe_id,
            "title": self.title,
            "severity": self.severity.label,
            "effective_severity": self.effective_severity.label,
            "vulnerable": self.vulnerable,
            "n_vulnerable": self.n_vulnerable,
            "n_attempts": self.n_attempts,
            "owasp": self.owasp,
            "atlas": self.atlas,
            "nist": self.nist,
            "description": self.description,
            "remediation": self.remediation,
            "attempts": [a.to_dict() for a in self.attempts],
        }
        return d


@dataclass
class RunResult:
    target_name: str
    tier: int
    findings: List[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    # --- aggregate helpers -------------------------------------------------
    @property
    def vulnerable_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.vulnerable]

    @property
    def duration_s(self) -> float:
        end = self.finished_at or time.time()
        return round(end - self.started_at, 3)

    @property
    def total_attempts(self) -> int:
        return sum(f.n_attempts for f in self.findings)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.label: 0 for s in Severity if s is not Severity.INFO}
        for f in self.vulnerable_findings:
            counts[f.severity.label] += 1
        return counts

    def highest_severity(self) -> Severity:
        sevs = [f.severity for f in self.vulnerable_findings]
        return max(sevs) if sevs else Severity.INFO

    def risk_score(self) -> int:
        """0-100 roll-up weighted by severity of confirmed findings."""
        weights = {
            Severity.LOW: 3,
            Severity.MEDIUM: 8,
            Severity.HIGH: 18,
            Severity.CRITICAL: 32,
        }
        raw = sum(weights.get(f.severity, 0) for f in self.vulnerable_findings)
        return min(100, raw)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target_name,
            "tier": self.tier,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration_s,
            "risk_score": self.risk_score(),
            "highest_severity": self.highest_severity().label,
            "severity_counts": self.severity_counts(),
            "total_findings": len(self.findings),
            "vulnerable_findings": len(self.vulnerable_findings),
            "total_attempts": self.total_attempts,
            "meta": self.meta,
            "findings": [f.to_dict() for f in self.findings],
        }
