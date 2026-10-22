"""Detector abstraction — decides whether a response indicates a vulnerability."""
from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import List, Optional

from .target import Response, Turn


@dataclass
class DetectionResult:
    vulnerable: bool
    score: float            # 0..1 confidence
    rationale: str = ""

    @classmethod
    def negative(cls, rationale: str = "") -> "DetectionResult":
        return cls(False, 0.0, rationale)

    @classmethod
    def positive(cls, score: float = 1.0, rationale: str = "") -> "DetectionResult":
        return cls(True, score, rationale)


class Detector(abc.ABC):
    """Scores a response in the context of the conversation that produced it.

    ``context`` carries probe-specific signals (canary tokens, expected markers,
    the attack objective, etc.) so a detector can be reused across probes.
    """

    name: str = "detector"

    @abc.abstractmethod
    def detect(
        self,
        response: Response,
        sent: List[Turn],
        context: Optional[dict] = None,
    ) -> DetectionResult:
        raise NotImplementedError
