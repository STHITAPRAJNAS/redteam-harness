"""Deliberately-vulnerable + secure mock agents for demos and the test suite.

The implementation lives in the installed package (``rtharness._mocks``) so that
``rtharness selftest`` / ``rtharness demo`` work even when rtharness is
pip-installed (the console script doesn't put this ``examples/`` dir on the
import path). This module just re-exports it, and the HTTP/A2A/MCP mock server
(``examples/mock_server.py``) imports ``vulnerable_agent`` from here.
"""
from rtharness._mocks import (  # noqa: F401
    SYS_CANARY,
    MOCK_SYSTEM_PROMPT,
    DEFAULT_PROFILE,
    vulnerable_agent,
    secure_agent,
    build_callable_target,
    build_secure_target,
)

__all__ = [
    "SYS_CANARY", "MOCK_SYSTEM_PROMPT", "DEFAULT_PROFILE",
    "vulnerable_agent", "secure_agent",
    "build_callable_target", "build_secure_target",
]
