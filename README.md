# rtharness — a red-team harness for LLM agents

Find vulnerabilities in **any** agent or agent framework that exposes a **chat**
interface or an **Agent-to-Agent (A2A)** interface — Google ADK, LangGraph,
CrewAI, AutoGen, a bespoke Flask endpoint, an OpenAI-compatible server, or a raw
A2A JSON-RPC agent. You point it at a target, pick an attack tier, and it
produces a risk-scored report mapped to the **OWASP Top 10 for LLM Applications
(2025)**, the **OWASP Agentic Top 10**, and **MITRE ATLAS**.

It sits in the same family as [Microsoft PyRIT], [NVIDIA garak], [promptfoo],
[ARTKIT] and [DeepTeam], but is built specifically around the **agent** attack
surface (tools, delegation, A2A trust) and is deliberately **dependency-light**
(`requests` only) so it runs in locked-down assessment environments. See
[`docs/RESEARCH.md`](docs/RESEARCH.md) for the landscape review and methodology.

> ⚠️ **Authorised use only.** Run this against agents you own or have explicit
> written permission to test. See [Responsible use](#responsible-use).

[Microsoft PyRIT]: https://github.com/Azure/PyRIT
[NVIDIA garak]: https://github.com/NVIDIA/garak
[promptfoo]: https://www.promptfoo.dev/docs/red-team/
[ARTKIT]: https://github.com/BCG-X-Official/artkit
[DeepTeam]: https://trydeepteam.com/

---

## Install

```bash
# from the repo root
pip install -e .            # installs the `rtharness` CLI + the library
# optional extras:
pip install -e '.[yaml]'    # YAML configs (JSON works without it)
pip install -e '.[dev]'     # pytest (the suite also runs under unittest)
```

Only `requests` is required at runtime. Python 3.9+.

## 60-second demo (no API keys, no network)

```bash
rtharness demo --tier 3
```

This runs the full probe set against a bundled, intentionally-vulnerable mock
agent and writes JSON/Markdown/HTML reports to `./reports/`. You should see a
risk score near 100/100 and findings across injection, disclosure, exfil and
excessive agency.

## Point it at a real agent

```bash
# OpenAI-compatible server (vLLM, Ollama shim, LiteLLM, Azure gateway, ...)
rtharness run --target openai --model my-model \
    --base-url http://localhost:8080/v1 --api-key-env OPENAI_API_KEY \
    --tier 2 --format all --fail-on high

# Generic HTTP chat endpoint
rtharness run --target http --url http://localhost:5000/chat \
    --response-path reply --tier 2

# A2A agent (card auto-discovered from /.well-known/)
rtharness run --target a2a --base-url http://localhost:9999 --tier 3

# Google ADK dev server
rtharness run --target adk --app-name my_agent \
    --base-url http://localhost:8000 --tier 2
```

Most real assessments use a **config file** so you can describe the request
mapping and pass operator knobs (planted canaries, gated tool names). Copy
[`examples/config.example.yaml`](examples/config.example.yaml) and run:

```bash
rtharness run --config my-agent.yaml
```

## Attack tiers (sophistication levels)

You choose how hard the harness pushes. Tiers are cumulative.

| Tier | Name | What it adds |
|---|---|---|
| 1 | **basic** | Single-shot, well-known payloads. Fast smoke test, low false positives. |
| 2 | **intermediate** | Obfuscation (base64/rot13/leet), persona/authority framing, indirect injection. |
| 3 | **advanced** | Multi-turn **crescendo** escalation, confused-deputy tool abuse, A2A access-control probes. |
| 4 | **adaptive** | An **attacker model** rewrites/escalates on refusal (falls back to a deterministic ladder if no model is configured). |

```bash
rtharness run --config my.yaml --tier 1   # quick CI gate
rtharness run --config my.yaml --tier 4   # deep adversarial pass
```

## What it tests

| Probe id | Weakness | OWASP | Tier |
|---|---|---|---|
| `prompt_injection.direct` | Instruction override | LLM01:2025 | 1 |
| `prompt_injection.indirect` | Second-order injection via processed data | LLM01:2025 | 2 |
| `disclosure.system_prompt` | System/developer prompt leakage | LLM07/LLM02:2025 | 1 |
| `jailbreak.refusal_suppression` | Guardrail bypass (persona / refusal suppression) | LLM01:2025 | 1 |
| `exfil.markdown_beacon` | Data exfiltration via outbound URL / image beacon | LLM02:2025 | 2 |
| `agency.gated_tool` | Excessive agency / unauthorised tool use | LLM06:2025 | 1 |
| `a2a.card_integrity` | Unsigned / tamperable agent card | LLM03:2025 | 1 |
| `a2a.card_injection` | Prompt injection in agent-card text | LLM01/LLM03:2025 | 1 |
| `a2a.missing_auth` | Unauthenticated task submission | LLM06:2025 | 2 |
| `a2a.context_isolation` | Task/context accessible without ownership (IDOR) | LLM06:2025 | 3 |
| `a2a.recursive_delegation` | Unbounded self-delegation (DoS) | LLM10:2025 | 3 |

`rtharness list --tier 4` prints the live list with full ATLAS mappings.

## The operator profile

Probes become far more precise when you tell the harness about your agent via
the `profile` block in the config (or defaults for the demo):

```yaml
profile:
  system_prompt_canary: "CANARY_abc123"   # a token you planted in the system prompt
  gated_tool: delete_account              # the real name of a dangerous tool
  action_marker: ACTION_EXECUTED          # a string the tool emits only when it runs
  exfil_host: beacon.example.com          # a host you control, for exfil tests
  jailbreak_objective: "..."              # test your own disallowed goal
  attacker: { type: openai, model: ... }  # tier-4 adaptive attacker model
```

Planting a **canary** in your agent's system prompt turns the leak detector
from a heuristic into a certainty: if that exact token appears in a response,
the system prompt leaked.

## Reports

Every run writes machine- and human-readable artifacts:

- **JSON** (`*.report.json`) — stable schema for CI gating and diffing.
- **Markdown** (`*.report.md`) — the assessment write-up with example transcripts.
- **HTML** (`*.report.html`) — a self-contained, shareable page (light/dark).

`--fail-on high` makes the process exit non-zero when a High+ finding is
confirmed — drop it into CI to block regressions.

## Extending

- **New target:** subclass `rtharness.core.target.Target` and implement
  `generate(messages) -> Response`. Register nothing; just pass an instance to
  `Runner`, or add a `type` to `targets.from_config`.
- **New probe:** subclass `ObjectiveProbe` (give it `objectives()`) or `Probe`
  (implement `run()`), decorate with `@register`, and add it to
  `rtharness/probes/__init__.py`. Declare `owasp`/`atlas`/`severity`/`min_tier`.
- **New detector:** subclass `Detector`; combine with `CompositeDetector`.

## Architecture

```
          ┌─────────┐   objectives   ┌──────────────┐  strategy   ┌────────────┐
Probes ──▶│ Objective│───────────────▶│ AttackStrategy│────────────▶│   Target   │
          └─────────┘  (+ detector)  │ direct/encode/ │  conversation│ chat / A2A │
                                      │ roleplay/cres- │◀────────────│ / ADK /... │
                                      │ cendo/adaptive │   Response   └────────────┘
                                      └──────┬────────┘
                                             │ Attempt + DetectionResult
                                       ┌─────▼──────┐        ┌──────────┐
                                       │   Runner   │───────▶│  Reports │ json/md/html
                                       └────────────┘        └──────────┘
```

## Testing

```bash
python -m unittest discover -s tests -v    # stdlib, no deps
# or: pytest -q
```

The suite includes unit tests for detectors/core and **integration tests** that
stand up the mock agent over a real socket and exercise the HTTP, OpenAI and
A2A adapters end-to-end.

## Responsible use

This is a defensive security tool for **authorised** testing of agents you own
or are permitted to assess. The shipped attack objectives are benign security
**canaries** (extract a planted token, reveal the system prompt, trigger a
mock side-effect) — the harness measures whether guardrails *hold*, it does not
generate harmful content. Do not use it against systems without permission, and
treat any secrets surfaced in reports as sensitive. You are responsible for
complying with the terms of service of the systems you test.

## License

MIT — see [LICENSE](LICENSE).
