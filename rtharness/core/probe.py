"""Probe abstraction — a single vulnerability test.

A probe yields one or more :class:`Attempt`\\ s against a target. Probes declare
their metadata (OWASP/ATLAS mapping, severity, minimum tier) and implement
:meth:`run`, which is handed the target and the active :class:`Tier`.

Most probes build their attempts from an *objective* plus an *attack strategy*
(see :mod:`rtharness.core.attack`), so a new probe is usually a small amount of
glue + a payload/objective list.
"""
from __future__ import annotations

import abc
from typing import Iterable, List

from .result import Attempt, Finding, Severity
from .target import Target
from .tier import Tier


class Probe(abc.ABC):
    #: Stable identifier, e.g. "prompt_injection.direct".
    id: str = "probe"
    #: One-line human title.
    title: str = ""
    #: Longer description of what weakness this probe looks for.
    description: str = ""
    #: Severity if the probe fires.
    severity: Severity = Severity.MEDIUM
    #: OWASP LLM / Agentic Top 10 identifiers.
    owasp: List[str] = []
    #: MITRE ATLAS technique IDs.
    atlas: List[str] = []
    #: Lowest tier at which this probe runs.
    min_tier: Tier = Tier.BASIC
    #: Remediation guidance surfaced in the report.
    remediation: str = ""
    #: Free-form tags for filtering (e.g. "a2a", "injection", "exfil").
    tags: List[str] = []

    def __init__(self):
        #: Operator-supplied knobs (planted canaries, gated tool names, exfil
        #: beacon host, custom objectives, attacker model, ...). Populated by
        #: :meth:`configure` before :meth:`run`.
        self.profile: dict = {}

    def configure(self, profile: dict) -> "Probe":
        self.profile = dict(profile or {})
        return self

    def applies(self, tier: Tier) -> bool:
        return tier >= self.min_tier

    @abc.abstractmethod
    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        """Execute the probe, yielding attempts."""
        raise NotImplementedError

    def to_finding(self, attempts: List[Attempt]) -> Finding:
        return Finding(
            probe_id=self.id,
            title=self.title,
            severity=self.severity,
            owasp=list(self.owasp),
            atlas=list(self.atlas),
            description=self.description,
            remediation=self.remediation,
            attempts=list(attempts),
        )
