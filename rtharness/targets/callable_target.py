"""In-process target wrapping a Python callable.

Useful for CI, unit tests, and for assessing an agent you can import directly
(no network). The callable receives the conversation as a list of
``{"role", "content"}`` dicts and must return either a string, or a dict with
``{"text": ..., "tool_calls": [...]}``.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List

from ..core.target import Response, Target, Turn


class CallableTarget(Target):
    def __init__(self, fn: Callable[[List[Dict[str, str]]], Any], name: str = "callable"):
        self.fn = fn
        self.name = name

    def generate(self, messages: List[Turn]) -> Response:
        payload = [t.to_dict() for t in messages]

        def _call():
            out = self.fn(payload)
            if isinstance(out, dict):
                return out.get("text", ""), out, out.get("tool_calls", [])
            return str(out), {"text": str(out)}, []

        return self._timed(_call)
