"""Named scan presets / compliance profiles.

A preset is a one-word shorthand that sets sensible defaults for a run — tier
plus probe selection — so operators (and CI) don't hand-assemble filters.
Explicit CLI flags / config keys always override a preset.

Think of these like promptfoo's red-team presets or DeepTeam's framework maps:
pick `owasp-llm` or `mcp` and you get the right bundle.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# Each preset maps to RunConfig fields. Anything omitted keeps its default.
PRESETS: Dict[str, dict] = {
    # Depth presets
    "quick":    {"tier": 1, "desc": "Fast smoke test — single-shot, low false positives."},
    "standard": {"tier": 2, "desc": "Obfuscation + indirect injection; good default."},
    "deep":     {"tier": 4, "desc": "Full arsenal incl. multi-turn + adaptive/agentic."},

    # Compliance / framework profiles (select by mapped tags).
    "owasp-llm": {"tier": 3,
                  "tags": ["injection", "disclosure", "exfil", "agency", "jailbreak",
                           "output", "pii", "dos"],
                  "desc": "OWASP Top 10 for LLM Applications (2025) coverage."},
    "owasp-agentic": {"tier": 3,
                      "include": ["agency", "memory", "a2a", "mcp",
                                  "prompt_injection.indirect"],
                      "desc": "OWASP Agentic risks: tool misuse, memory, delegation."},
    "mitre-atlas": {"tier": 3, "desc": "Everything, mapped to MITRE ATLAS techniques."},

    # Surface presets
    "mcp":  {"tier": 3, "include": ["mcp"], "desc": "MCP server checks only."},
    "a2a":  {"tier": 3, "include": ["a2a"], "desc": "A2A protocol checks only."},
    "chat": {"tier": 3, "exclude": ["a2a", "mcp"], "desc": "Chat-surface checks only."},

    # Theme presets
    "injection": {"tier": 3, "tags": ["injection"], "desc": "All prompt-injection probes."},
    "exfil":     {"tier": 3, "tags": ["exfil", "disclosure"], "desc": "Data-exfiltration & disclosure."},
    "jailbreak": {"tier": 3, "tags": ["jailbreak"], "desc": "Guardrail-bypass probes + corpora."},
}


def names() -> List[str]:
    return list(PRESETS.keys())


def get(name: str) -> dict:
    key = name.strip().lower()
    if key not in PRESETS:
        raise KeyError("Unknown preset %r. Available: %s" % (name, ", ".join(names())))
    return {k: v for k, v in PRESETS[key].items() if k != "desc"}


def describe(name: str) -> str:
    return PRESETS.get(name.strip().lower(), {}).get("desc", "")


def apply_to(config_dict: dict, name: str) -> dict:
    """Merge a preset into a config dict (preset fills gaps; explicit keys win)."""
    preset = get(name)
    merged = dict(preset)
    merged.update({k: v for k, v in config_dict.items() if v not in (None, [], {})})
    # tier: explicit config value wins only if it was actually set.
    if "tier" in config_dict and config_dict["tier"] is not None:
        merged["tier"] = config_dict["tier"]
    return merged
