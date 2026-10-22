"""Optional-dependency helpers so the harness degrades gracefully.

The harness must run in locked-down assessment environments where installing
packages may be impossible. Only ``requests`` is a hard dependency; anything
else is probed for here and substituted with a stdlib fallback when absent.
"""
from __future__ import annotations

import json
from typing import Any


def load_yaml_or_json(path: str) -> Any:
    """Load a config file. Uses PyYAML if available, else falls back to JSON.

    A ``.json`` file always parses with the stdlib. A ``.yaml``/``.yml`` file
    needs PyYAML; if it is missing we raise a clear, actionable error.
    """
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    lowered = path.lower()
    if lowered.endswith(".json"):
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError:
        # Last-ditch: many simple YAML files are also valid JSON.
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Reading %r needs PyYAML (pip install 'rtharness[yaml]') "
                "or a .json config file." % path
            ) from exc
    return yaml.safe_load(text)


def has_requests() -> bool:
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False
