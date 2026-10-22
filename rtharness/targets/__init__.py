"""Target adapters mapping the neutral conversation model onto wire protocols.

- :class:`CallableTarget`   — in-process Python callable (tests, CI, custom glue)
- :class:`HTTPChatTarget`   — generic JSON chat endpoint (configurable mapping)
- :class:`OpenAIChatTarget` — OpenAI-compatible /v1/chat/completions
- :class:`A2ATarget`        — Agent-to-Agent JSON-RPC (message/send)
- :class:`ADKTarget`        — Google ADK dev server (/run, sessions)
"""
from .callable_target import CallableTarget
from .http_chat import HTTPChatTarget
from .openai_compat import OpenAIChatTarget
from .a2a import A2ATarget
from .adk import ADKTarget

__all__ = [
    "CallableTarget",
    "HTTPChatTarget",
    "OpenAIChatTarget",
    "A2ATarget",
    "ADKTarget",
    "from_config",
]


def from_config(cfg: dict):
    """Build a target from a config dict with a ``type`` field.

    Example::

        {"type": "openai", "name": "my-agent",
         "base_url": "http://localhost:8080/v1",
         "model": "gpt-4o-mini", "api_key_env": "OPENAI_API_KEY"}
    """
    kind = (cfg.get("type") or "").lower()
    args = {k: v for k, v in cfg.items() if k != "type"}
    builders = {
        "callable": CallableTarget,
        "http": HTTPChatTarget,
        "http_chat": HTTPChatTarget,
        "openai": OpenAIChatTarget,
        "openai_compat": OpenAIChatTarget,
        "a2a": A2ATarget,
        "adk": ADKTarget,
    }
    if kind not in builders:
        raise ValueError(
            "Unknown target type %r. Known: %s" % (kind, ", ".join(sorted(builders)))
        )
    return builders[kind](**args)
