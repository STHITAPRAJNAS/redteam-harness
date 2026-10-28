"""Probe that runs an attack *corpus* (a :class:`Pack`) against the target.

Unlike the registered built-in probes, corpus probes are built dynamically from
packs (built-in benign packs + anything the operator points ``--corpus`` at), so
they are constructed by :func:`build_corpus_probes` and appended to the run.

By default each payload is sent directly (it is already a crafted attack),
keeping cost linear in corpus size. With ``profile['corpus_expand']=True`` each
payload is additionally run through the full :class:`AttackEngine` (transforms,
multi-turn, mutation), multiplying coverage at higher cost.
"""
from __future__ import annotations

from typing import Iterable, List, Optional

from ..core.attack import Objective
from ..core.engine import AttackEngine
from ..core.probe import Probe
from ..core.result import Attempt
from ..core.target import Target
from ..core.tier import Tier
from ..corpus import Pack, builtin_packs, load_pack


class CorpusProbe(Probe):
    def __init__(self, pack: Pack):
        super().__init__()
        self.pack = pack
        self.id = "corpus.%s" % pack.name
        self.title = "Corpus: %s" % (pack.description or pack.name)
        self.description = ("Runs the '%s' attack corpus (%d payloads)."
                            % (pack.name, len(pack.payloads)))
        self.severity = pack.severity
        self.owasp = pack.owasp
        self.atlas = pack.atlas
        self.min_tier = pack.min_tier
        self.tags = pack.tags
        self.remediation = ("Review each confirmed payload; corpus findings share "
                            "remediations with the matching built-in probe category.")

    def run(self, target: Target, tier: Tier) -> Iterable[Attempt]:
        expand = bool(self.profile.get("corpus_expand", False))
        effort = float(self.profile.get("effort", 1.0) or 1.0)
        stop_on_first = bool(self.profile.get("stop_on_first", True))
        engine = AttackEngine(attacker=self.profile.get("attacker_target"),
                              seed=int(self.profile.get("seed", 1337))) if expand else None

        for i, payload in enumerate(self.pack.payloads):
            prompt, det, ctx, label = payload.materialize(self.profile)
            if engine is not None:
                obj = Objective("%s-%d" % (self.pack.name, i), prompt, det, ctx, label)
                for att in engine.run_objective(target, obj, tier, effort=effort,
                                                 stop_on_first=stop_on_first):
                    att.probe_id = self.id
                    att.extra.setdefault("payload", label)
                    yield att
            else:
                s = target.new_session()
                resp = s.send(prompt)
                d = det.detect(resp, s.turns, ctx)
                yield Attempt(self.id, int(tier), "corpus:%s" % payload.technique,
                              s.transcript(), resp.text, d.vulnerable, det.name,
                              d.score, d.rationale, resp.latency_ms, resp.error,
                              extra={"payload": label})


def build_corpus_probes(
    profile: dict,
    tier: Tier,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
) -> List[CorpusProbe]:
    """Assemble corpus probes: built-in benign packs (unless disabled) plus any
    operator-supplied corpus paths. Honours the same filters as registry.select."""
    packs: List[Pack] = []
    if profile.get("corpus_builtin", True):
        packs += builtin_packs()
    for path in profile.get("corpus", []) or []:
        packs.append(load_pack(path))

    probes: List[CorpusProbe] = []
    for pack in packs:
        probe = CorpusProbe(pack).configure(profile)
        if not probe.applies(tier):
            continue
        if include and not _match(probe.id, include):
            continue
        if exclude and _match(probe.id, exclude):
            continue
        if tags and not (set(tags) & set(probe.tags or [])):
            continue
        probes.append(probe)
    return probes


def _match(pid: str, patterns: List[str]) -> bool:
    return any(pid == p or pid.startswith(p + ".") or p == "corpus" for p in patterns)
