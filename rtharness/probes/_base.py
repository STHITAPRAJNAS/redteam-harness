"""Shared base for objective-driven probes.

An ``ObjectiveProbe`` declares a list of :class:`Objective`\\ s and runs each one
through every attack strategy enabled at the active tier. This is where "levels
of attack based on sophistication" comes from: the same objective is attempted
directly at tier 1 and escalated (encoding, roleplay, crescendo, adaptive) at
higher tiers.
"""
from __future__ import annotations

import secrets as _secrets
from typing import Iterable, List

from ..core.attack import Objective, strategies_for_tier
from ..core.probe import Probe
from ..core.result import Attempt
from ..core.target import Target
from ..core.tier import Tier


def new_canary(prefix: str = "RT") -> str:
    """A unique, benign token used to prove information flow (never a secret)."""
    return "%s_CANARY_%s" % (prefix, _secrets.token_hex(4))


class ObjectiveProbe(Probe):
    def objectives(self, target: Target, tier: Tier) -> List[Objective]:
        raise NotImplementedError

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        attacker = self.profile.get("attacker_target")
        strategies = strategies_for_tier(tier, attacker=attacker)
        for obj in self.objectives(target, tier):
            for strat in strategies:
                if tier < strat.min_tier:
                    continue
                yield strat.execute(target, obj, self.id, tier)
