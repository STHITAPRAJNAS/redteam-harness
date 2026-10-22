"""rtharness — a red-team harness for LLM agents.

Finds vulnerabilities in agents exposed over a chat interface or the
Agent-to-Agent (A2A) protocol. Attacks are organised into escalating
sophistication tiers and mapped to the OWASP Top 10 for LLM Applications
(2025), the OWASP Agentic Top 10, and MITRE ATLAS.

Intended for authorised testing of agents you own or are permitted to assess.
See the README "Responsible use" section.
"""

from .version import __version__
from .core.result import Severity, Attempt, Finding, RunResult
from .core.target import Target, Session, Response, Turn
from .core.probe import Probe
from .core.detector import Detector, DetectionResult
from .core.tier import Tier
from .core.runner import Runner
from .core import registry

__all__ = [
    "__version__",
    "Severity",
    "Attempt",
    "Finding",
    "RunResult",
    "Target",
    "Session",
    "Response",
    "Turn",
    "Probe",
    "Detector",
    "DetectionResult",
    "Tier",
    "Runner",
    "registry",
]
