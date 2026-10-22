"""Combine detectors with AND / OR semantics."""
from __future__ import annotations

from typing import List, Optional

from ..core.detector import Detector, DetectionResult
from ..core.target import Response, Turn


class CompositeDetector(Detector):
    name = "composite"

    def __init__(self, detectors: List[Detector], mode: str = "or", name: Optional[str] = None):
        if mode not in ("and", "or"):
            raise ValueError("mode must be 'and' or 'or'")
        self.detectors = detectors
        self.mode = mode
        if name:
            self.name = name
        else:
            self.name = "composite(%s:%s)" % (mode, "+".join(d.name for d in detectors))

    def detect(self, response: Response, sent: List[Turn], context: Optional[dict] = None):
        results = [d.detect(response, sent, context) for d in self.detectors]
        fired = [r for r in results if r.vulnerable]
        if self.mode == "or":
            if fired:
                best = max(fired, key=lambda r: r.score)
                return DetectionResult.positive(best.score, best.rationale)
            return DetectionResult.negative("; ".join(r.rationale for r in results))
        # AND
        if all(r.vulnerable for r in results) and results:
            score = min(r.score for r in results)
            return DetectionResult.positive(
                score, " AND ".join(r.rationale for r in results))
        missing = [r.rationale for r in results if not r.vulnerable]
        return DetectionResult.negative("AND not satisfied: %s" % "; ".join(missing))
