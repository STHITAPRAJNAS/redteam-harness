"""Programmatic scan API — the single entry point shared by the CLI and the
web service.

``execute_scan(cfg)`` turns a :class:`RunConfig` into a :class:`RunResult`:
build the target, wire optional attacker/judge models, select probes + corpus
packs, and run them. Keeping this in one place means the CLI and ``rtharness
serve`` behave identically.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from .config import RunConfig
from .core import registry
from .core.probe import Probe
from .core.result import RunResult
from .core.runner import Runner
from .targets import from_config
from . import probes as _probes  # noqa: F401  (registers built-in probes)


def attach_helpers(cfg: RunConfig) -> None:
    """Build the optional attacker (tier-4 rewrites) and judge (semantic
    detection) models from the profile, if configured. Both need an LLM key;
    without them the harness still runs fully on its deterministic engine."""
    att = cfg.profile.get("attacker")
    if isinstance(att, dict) and "attacker_target" not in cfg.profile:
        cfg.profile["attacker_target"] = from_config(att)
    judge = cfg.profile.get("judge")
    if isinstance(judge, dict) and "judge_target" not in cfg.profile:
        cfg.profile["judge_target"] = from_config(judge)


def select_probes(cfg: RunConfig) -> List[Probe]:
    selected = registry.select(
        cfg.tier, include=cfg.include or None, exclude=cfg.exclude or None,
        tags=cfg.tags or None, profile=cfg.profile)
    # Corpus packs (built-in + any --corpus paths) are added here too.
    from .probes.corpus_probe import build_corpus_probes
    selected += build_corpus_probes(
        cfg.profile, cfg.tier, include=cfg.include or None,
        exclude=cfg.exclude or None, tags=cfg.tags or None)
    selected.sort(key=lambda p: p.id)
    return selected


def capabilities(cfg: RunConfig) -> dict:
    """Which LLM-powered enhancements this config will use. Everything else runs
    on the deterministic engine regardless."""
    p = cfg.profile or {}
    has_attacker = bool(p.get("attacker") or p.get("attacker_target"))
    has_judge = bool(p.get("judge") or p.get("judge_target"))
    agentic = p.get("agentic")
    agentic = has_attacker if agentic is None else bool(agentic)
    return {"attacker": has_attacker, "judge": has_judge,
            "agentic": agentic and has_attacker,
            "deterministic_engine": True}


def capability_line(cfg: RunConfig) -> str:
    c = capabilities(cfg)
    def onoff(k, label):
        return "%s: %s" % (label, "on" if c[k] else "off")
    tail = "" if c["judge"] else "  (no judge -> mechanical detection only)"
    return "modes -> deterministic engine: on, %s, %s, %s%s" % (
        onoff("attacker", "adaptive attacker"), onoff("agentic", "agentic planner"),
        onoff("judge", "LLM judge"), tail)


def execute_scan(cfg: RunConfig,
                 on_event: Optional[Callable[[str, dict], None]] = None) -> RunResult:
    target = from_config(cfg.target)
    attach_helpers(cfg)
    selected = select_probes(cfg)
    if not selected:
        raise ValueError("No probes selected (check tier/include/exclude/tags).")
    runner = Runner(target, tier=cfg.tier, rate_limit_s=cfg.rate_limit_s,
                    on_event=on_event or (lambda ev, data: None))
    return runner.run(selected)
