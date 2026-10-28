"""Config loading and run-profile assembly.

A config file (YAML or JSON) describes the target, the tier, probe selection,
and the operator *profile* (planted canaries, gated tool names, exfil host,
custom objectives). Example in ``examples/config.example.yaml``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ._optional import load_yaml_or_json
from .core.tier import Tier


@dataclass
class RunConfig:
    target: Dict[str, Any]
    tier: Tier = Tier.BASIC
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    profile: Dict[str, Any] = field(default_factory=dict)
    rate_limit_s: float = 0.0
    fail_on: Optional[str] = None            # min severity that exits non-zero
    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["json", "md"])

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunConfig":
        if "target" not in data:
            raise ValueError("config must contain a 'target' section")
        if data.get("preset"):
            from . import presets
            base = presets.get(data["preset"])
            # Preset fills gaps; explicitly-set keys in `data` win.
            merged = dict(base)
            for k, v in data.items():
                if k == "preset":
                    continue
                if v not in (None, [], {}):
                    merged[k] = v
            data = merged
        return cls(
            target=data["target"],
            tier=Tier.parse(data.get("tier", 1)),
            include=list(data.get("include", []) or []),
            exclude=list(data.get("exclude", []) or []),
            tags=list(data.get("tags", []) or []),
            profile=dict(data.get("profile", {}) or {}),
            rate_limit_s=float(data.get("rate_limit_s", 0.0) or 0.0),
            fail_on=data.get("fail_on"),
            output_dir=data.get("output_dir", "reports"),
            formats=list(data.get("formats", ["json", "md"]) or ["json", "md"]),
        )

    @classmethod
    def load(cls, path: str) -> "RunConfig":
        return cls.from_dict(load_yaml_or_json(path))
