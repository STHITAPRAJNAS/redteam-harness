"""Probe library. Importing this module registers all built-in probes.

Probes are grouped by weakness and mapped to the OWASP Top 10 for LLM
Applications (2025), the OWASP Agentic Top 10 (2025), and MITRE ATLAS.
"""
# Import side-effect: each module registers its probes with the registry.
from . import prompt_injection      # noqa: F401
from . import system_prompt_leak    # noqa: F401
from . import jailbreak             # noqa: F401
from . import data_exfiltration     # noqa: F401
from . import excessive_agency      # noqa: F401
from . import a2a_specific          # noqa: F401
from . import mcp_specific          # noqa: F401
from . import more                  # noqa: F401
from . import coverage              # noqa: F401
