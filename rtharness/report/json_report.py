"""JSON report — the machine-readable artifact for CI gating and diffing."""
from __future__ import annotations

import json

from ..core.result import RunResult
from ..version import __version__


def to_json(result: RunResult, indent: int = 2) -> str:
    payload = {
        "schema": "rtharness.report/1",
        "tool_version": __version__,
        "result": result.to_dict(),
    }
    return json.dumps(payload, indent=indent, default=str)


def write_json(result: RunResult, path: str, indent: int = 2) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_json(result, indent))
    return path
