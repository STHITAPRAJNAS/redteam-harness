"""Registry for probes so the CLI and runner can discover them by id/tag.

Probe classes register themselves via the :func:`register` decorator. Importing
:mod:`rtharness.probes` populates the registry (see its ``__init__``).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Type

from .probe import Probe
from .tier import Tier

_PROBES: Dict[str, Type[Probe]] = {}


def register(cls: Type[Probe]) -> Type[Probe]:
    if not getattr(cls, "id", None):
        raise ValueError("Probe %r must define a non-empty id" % cls)
    if cls.id in _PROBES and _PROBES[cls.id] is not cls:
        raise ValueError("Duplicate probe id: %s" % cls.id)
    _PROBES[cls.id] = cls
    return cls


def all_probe_classes() -> List[Type[Probe]]:
    return list(_PROBES.values())


def get(probe_id: str) -> Type[Probe]:
    return _PROBES[probe_id]


def select(
    tier: Tier,
    include: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    profile: Optional[dict] = None,
) -> List[Probe]:
    """Return instantiated probes matching the filters, within ``tier``.

    ``include``/``exclude`` match probe ids by exact id or dotted prefix
    (``prompt_injection`` matches ``prompt_injection.direct``). ``tags`` keeps
    only probes carrying at least one of the listed tags.
    """
    chosen: List[Probe] = []
    for cls in _PROBES.values():
        probe = cls()
        probe.configure(profile or {})
        if not probe.applies(tier):
            continue
        if include and not _matches_any(probe.id, include):
            continue
        if exclude and _matches_any(probe.id, exclude):
            continue
        if tags and not (set(tags) & set(probe.tags or [])):
            continue
        chosen.append(probe)
    chosen.sort(key=lambda p: p.id)
    return chosen


def _matches_any(probe_id: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if probe_id == pat or probe_id.startswith(pat + "."):
            return True
    return False
