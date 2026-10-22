"""Detectors — turn a model response into a vulnerable/not verdict.

- :class:`RefusalDetector`     — did the agent refuse? (used to invert: a
  *non*-refusal to a disallowed objective is the signal)
- :class:`StringMatchDetector` — canary token / marker / regex present
- :class:`SystemPromptLeakDetector` — planted system-prompt secret exposed
- :class:`SecretLeakDetector`  — PII / API-key-shaped strings in output
- :class:`ToolAbuseDetector`   — the agent invoked a gated/unexpected tool
- :class:`JudgeDetector`       — optional LLM-as-judge (pluggable model)
- :class:`CompositeDetector`   — OR/AND combination of the above
"""
from .refusal import RefusalDetector, NonRefusalDetector
from .stringmatch import StringMatchDetector, RegexDetector
from .secrets import SystemPromptLeakDetector, SecretLeakDetector
from .toolabuse import ToolAbuseDetector
from .judge import JudgeDetector
from .composite import CompositeDetector

__all__ = [
    "RefusalDetector",
    "NonRefusalDetector",
    "StringMatchDetector",
    "RegexDetector",
    "SystemPromptLeakDetector",
    "SecretLeakDetector",
    "ToolAbuseDetector",
    "JudgeDetector",
    "CompositeDetector",
]
