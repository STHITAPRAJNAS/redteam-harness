"""Attack sophistication tiers.

Users choose how hard the harness pushes. Tiers are cumulative: a run at
tier N includes every probe/attack variant at tiers <= N.
"""
from __future__ import annotations

from enum import IntEnum


class Tier(IntEnum):
    #: Single-shot, well-known payloads. Fast smoke test, low false positives.
    BASIC = 1
    #: Obfuscation + simple roleplay/context-switching. Still single-turn mostly.
    INTERMEDIATE = 2
    #: Multi-turn (crescendo), indirect/second-order injection, tool abuse.
    ADVANCED = 3
    #: Adaptive attacks that use an attacker LLM to rewrite/escalate on refusal.
    ADAPTIVE = 4

    @classmethod
    def parse(cls, value) -> "Tier":
        if isinstance(value, Tier):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        aliases = {
            "1": cls.BASIC, "BASIC": cls.BASIC, "SMOKE": cls.BASIC,
            "2": cls.INTERMEDIATE, "INTERMEDIATE": cls.INTERMEDIATE, "MED": cls.INTERMEDIATE,
            "3": cls.ADVANCED, "ADVANCED": cls.ADVANCED, "ADV": cls.ADVANCED,
            "4": cls.ADAPTIVE, "ADAPTIVE": cls.ADAPTIVE, "MAX": cls.ADAPTIVE,
        }
        if key not in aliases:
            raise ValueError(
                "Unknown tier %r. Use 1..4 or basic/intermediate/advanced/adaptive." % value
            )
        return aliases[key]

    @property
    def label(self) -> str:
        return self.name.capitalize()
