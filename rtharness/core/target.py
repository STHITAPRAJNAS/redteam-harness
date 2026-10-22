"""Target abstraction — the system under test.

A ``Target`` is any agent we can hold a conversation with. The harness never
assumes a particular framework; it only assumes a chat-style request/response
(and, for A2A, a task-style one). Adapters in ``rtharness.targets`` map our
neutral conversation model onto a concrete wire protocol.

Multi-turn contract
--------------------
``generate(messages)`` receives the FULL conversation so far (a list of
``Turn``) and returns a single ``Response`` — the agent's next reply. Stateless
HTTP chat APIs map the whole list into their request. Session-based protocols
(ADK, A2A) create a fresh server-side session per conversation and replay the
turns in order, returning the final reply. This keeps attack strategies
protocol-agnostic: they just append turns and re-``generate``.
"""
from __future__ import annotations

import abc
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Turn:
    role: str      # "user" | "assistant" | "system"
    content: str

    def to_dict(self) -> Dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass
class Response:
    text: str
    raw: Any = None
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    latency_ms: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


class Session:
    """Holds the running conversation for one attack attempt."""

    def __init__(self, target: "Target"):
        self.target = target
        self.turns: List[Turn] = []
        self.responses: List[Response] = []

    def send(self, content: str, role: str = "user") -> Response:
        self.turns.append(Turn(role, content))
        resp = self.target.generate(list(self.turns))
        self.turns.append(Turn("assistant", resp.text))
        self.responses.append(resp)
        return resp

    def transcript(self) -> List[Dict[str, str]]:
        return [t.to_dict() for t in self.turns]


class Target(abc.ABC):
    """Base class for all target adapters.

    Subclasses implement :meth:`generate`. Everything else (sessions,
    timing, error capture) is provided here.
    """

    #: Human-readable name used in reports.
    name: str = "target"

    def new_session(self) -> Session:
        return Session(self)

    @abc.abstractmethod
    def generate(self, messages: List[Turn]) -> Response:
        """Given the full conversation, return the agent's next reply."""
        raise NotImplementedError

    # Convenience for single-turn probes.
    def ask(self, prompt: str) -> Response:
        return self.generate([Turn("user", prompt)])

    def health_check(self) -> Response:
        """Light liveness probe. Adapters may override for protocol specifics."""
        return self.ask("Hello, are you there?")

    @staticmethod
    def _timed(fn):
        start = time.time()
        try:
            text, raw, tool_calls = fn()
            return Response(
                text=text or "",
                raw=raw,
                tool_calls=tool_calls or [],
                latency_ms=round((time.time() - start) * 1000, 2),
            )
        except Exception as exc:  # noqa: BLE001 - surface any adapter error
            return Response(
                text="",
                raw=None,
                error="%s: %s" % (type(exc).__name__, exc),
                latency_ms=round((time.time() - start) * 1000, 2),
            )
