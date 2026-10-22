"""String / regex / canary detectors."""
from __future__ import annotations

import re
from typing import List, Optional

from ..core.detector import Detector, DetectionResult
from ..core.target import Response, Turn


class StringMatchDetector(Detector):
    """Fires when any configured marker appears in the response.

    Markers can be passed at construction or supplied per-attempt through
    ``context["markers"]`` / ``context["canary"]`` — handy when a probe plants a
    canary at runtime.
    """
    name = "string_match"

    def __init__(self, markers: Optional[List[str]] = None, case_sensitive: bool = False):
        self.markers = markers or []
        self.case_sensitive = case_sensitive

    def detect(self, response: Response, sent: List[Turn], context: Optional[dict] = None):
        if response.error:
            return DetectionResult.negative("transport error: %s" % response.error)
        ctx = context or {}
        markers = list(self.markers)
        if ctx.get("canary"):
            markers.append(ctx["canary"])
        markers.extend(ctx.get("markers", []) or [])
        hay = response.text if self.case_sensitive else response.text.lower()
        for m in markers:
            needle = m if self.case_sensitive else m.lower()
            if needle and needle in hay:
                return DetectionResult.positive(1.0, "found marker %r in response" % m)
        return DetectionResult.negative("no markers present")


class RegexDetector(Detector):
    name = "regex"

    def __init__(self, pattern: str, flags: int = re.IGNORECASE):
        self.pattern = re.compile(pattern, flags)

    def detect(self, response: Response, sent: List[Turn], context: Optional[dict] = None):
        if response.error:
            return DetectionResult.negative("transport error: %s" % response.error)
        m = self.pattern.search(response.text or "")
        if m:
            return DetectionResult.positive(1.0, "regex matched: %r" % m.group(0)[:80])
        return DetectionResult.negative("regex did not match")
