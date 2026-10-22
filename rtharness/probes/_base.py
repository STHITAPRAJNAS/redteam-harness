"""Shared base for objective-driven probes.

An ``ObjectiveProbe`` declares a list of :class:`Objective`\\ s and hands each one
to the :class:`AttackEngine`, which attacks it as hard as the active tier and
``effort`` allow. This is where "levels of attack based on sophistication" comes
from: the same objective is tried direct at tier 1 and escalated through the
whole transform/multi-turn/adaptive-mutation arsenal at higher tiers.
"""
from __future__ import annotations

import secrets as _secrets
from typing import Iterable, List

from ..core.attack import Objective
from ..core.engine import AttackEngine
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
        effort = float(self.profile.get("effort", 1.0) or 1.0)
        attacker = self.profile.get("attacker_target")
        stop_on_first = bool(self.profile.get("stop_on_first", True))
        engine = AttackEngine(attacker=attacker,
                              seed=int(self.profile.get("seed", 1337)))
        for obj in self.objectives(target, tier):
            for att in engine.run_objective(target, obj, tier, effort=effort,
                                             stop_on_first=stop_on_first):
                att.probe_id = self.id
                yield att
