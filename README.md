# rtharness — a red-team harness for LLM agents

Red-team the **agent application** — not the underlying model. rtharness drives
an agent app built with **any** framework (Google ADK, LangGraph, CrewAI,
AutoGen, LlamaIndex, a bespoke service…) through the surfaces it actually
exposes — a **chat** interface, an **Agent-to-Agent (A2A)** interface, or an
**MCP** server — and attacks it as a black box. You point it at a target, pick
an attack tier, and it produces a risk-scored report mapped to the **OWASP Top
10 for LLM Applications (2025)**, the **OWASP Agentic Top 10**, the **OWASP MCP
Top 10**, and **MITRE ATLAS**.

> It tests the *app's* guardrails, tools, memory, delegation and protocol
> handling — the things the application is responsible for — not a raw LLM's
> safety. (Raw OpenAI/Anthropic adapters exist only as a convenient *chat
> surface* for an app that speaks those APIs.)

### Positioning

rtharness is the **dynamic, black-box** layer of an agent-security program. It
complements — doesn't replace — the two other families, and is designed to be
combined with them:

| Layer | Examples | What it sees | rtharness relation |
|---|---|---|---|
| **Static** workflow/config scan | SplxAI **Agentic Radar**, Snyk/Invariant **mcp-scan** | source, declared tool/MCP metadata | run it first; rtharness then attacks the running app live |
| **Benchmark** suites | **AgentDojo**, InjecAgent, Agent Security Bench | fixed task+injection datasets | rtharness borrows their *attack structure* and ingests their corpora |
| **Dynamic black-box** (this) | rtharness | the live A2A/chat/MCP surface | catches **data-borne** injection & runtime behaviour static scans miss |

Deliberately a **raw-protocol client** (hand-rolled JSON-RPC/SSE, not the
framework SDKs): a conformance-normalising SDK hides the very bugs a security
test is looking for.

At its core is an **adaptive attack engine**: every probe states a benign
*objective*, and the engine attacks it with a large library of transforms
(encodings, canary-safe obfuscations, jailbreak framings), multi-turn
strategies (crescendo, echo-chamber), and — at the top tier — a **mutation /
beam search** that composes attacks and escalates on refusal (optionally with
an attacker LLM in the loop). Attack intensity scales with a tier **and** a free
`--effort` multiplier, so against a hardened target a single run can fire
**hundreds to thousands** of distinct attempts across ~30 techniques.

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

To confirm the harness works end-to-end (it should break the vulnerable mock
and leave a secure mock standing), run:

```bash
rtharness selftest        # exits 0 on PASS, 1 on FAIL — drop it in CI
```

## Two ways to run it

**CLI** (local, scriptable, CI) and a **local web service** (REST API + a small
dashboard) share the exact same scan engine.

```bash
pip install 'rtharness[server]'      # FastAPI + uvicorn (optional)
rtharness serve                      # http://127.0.0.1:8900  (dashboard /, API docs /docs)
rtharness serve --host 0.0.0.0 --port 8900   # (prints a warning: no auth, local-only tool)
```

The service runs on **FastAPI** when `rtharness[server]` is installed (giving
OpenAPI docs at `/docs` and the `/mcp` tool endpoint below); if it isn't, it
transparently falls back to a **zero-dependency stdlib server** so `serve`
always works.

REST API (all JSON):

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/scan` | start a scan; body is a config object (`{"target": {...}, "tier": 3, ...}`); returns `{id}` |
| `GET` | `/scan/<id>` | status, risk score, severity counts, live progress log |
| `GET` | `/scan/<id>/report?format=json\|md\|html` | the finished report |
| `GET` | `/probes` | probe + corpus-pack inventory |
| `GET` | `/health` | liveness |

```bash
curl -s -X POST localhost:8900/scan -H 'content-type: application/json' \
  -d '{"target":{"type":"a2a","base_url":"http://localhost:9999"},"tier":3}'
# -> {"id":"ab12cd34ef56","status":"queued"}
curl -s localhost:8900/scan/ab12cd34ef56            # poll
curl -s "localhost:8900/scan/ab12cd34ef56/report?format=html" -o report.html
```

The service is a **local operator tool**: it binds to `127.0.0.1`, has no auth,
and launches scans against targets you specify — don't expose it publicly.

### Let other agents call rtharness (MCP tool server)

rtharness also exposes **itself** as an MCP server at `POST /mcp`, offering two
tools — `scan_agent` and `list_probes`. Any agent framework that speaks MCP
(Google ADK, LangGraph, Claude, …) can therefore invoke the harness as a tool
with **no bespoke integration**:

```jsonc
// POST /mcp  — JSON-RPC 2.0
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"scan_agent",
           "arguments":{"target":{"type":"a2a","base_url":"http://localhost:9999"},"tier":2}}}
```

Example: give a Google **ADK** agent the ability to red-team other agents by
pointing ADK's MCP toolset at this endpoint —

```python
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import MCPToolset, StreamableHTTPConnectionParams

redteam = MCPToolset(connection_params=StreamableHTTPConnectionParams(
    url="http://localhost:8900/mcp"))
agent = LlmAgent(model="gemini-2.0-flash", name="security_reviewer",
                 tools=[redteam])  # can now call scan_agent / list_probes
```

> **Design note — why rtharness is *not* itself an ADK agent.** The harness is a
> framework-neutral *tester*; making the product an ADK (or any single
> framework's) agent would couple it to one ecosystem and bury the deterministic
> scan engine under an unnecessary LLM layer. Exposing it as an **MCP tool**
> (and a REST API, and an A2A-callable surface) keeps it callable from *every*
> framework — and lets rtharness red-team its own MCP server, dogfooding the MCP
> probes.

## Do I need an LLM API key?

**No — the harness runs fully without one.** The attack engine (transforms,
obfuscation, multi-turn, mutation), the corpora, and the canary/refusal/secret/
tool detectors are all deterministic. Tiers 1–3 and all protocol/MCP/A2A probes
work key-free. To turn the optional LLM features on, see
**[docs/RUNNING_LIVE_LLM.md](docs/RUNNING_LIVE_LLM.md)** (cloud, self-hosted, or
air-gapped).

A key makes it **smarter**, in three optional places:

- **Agentic attacker (tier 4)** — an LLM *attack brain* reasons over the live
  transcript, picks techniques from the static library, crafts tailored
  multi-turn attacks, and adapts on each failure (a PAIR/TAP-style automated
  red-teamer, scoped to the benign canary objective). This is the "use the
  static arsenal **and** the model's reasoning" mode. Without a key, tier 4
  falls back to a deterministic mutation/beam search.
- **LLM-as-judge** — semantic success detection for the fuzzy cases lexical
  detectors can't catch.

Both reuse the static engine: the agentic planner's "tools" are the same
transforms/corpora, and the judge grades alongside the mechanical detectors.
The run prints which modes are active, e.g.
`modes -> deterministic engine: on, adaptive attacker: on, agentic planner: on, LLM judge: on`.

Wire them in the `profile` (keys read from env vars, never inlined):

```yaml
profile:
  attacker: { type: openai, model: gpt-4o-mini, api_key_env: OPENAI_API_KEY }
  judge:    { type: anthropic, model: claude-haiku-4-5, api_key_env: ANTHROPIC_API_KEY }
```

> The key is for the **attacker/judge** models that help *generate and grade*
> attacks — never for the agent under test (that's your target). The harness
> itself does not require any key to operate.

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

# MCP server (tests tool descriptions for poisoning + drives its tools)
rtharness run --target mcp --url http://localhost:3000/mcp --tier 3

# LangServe (LangChain/LangGraph) runnable, or Anthropic Messages API
rtharness run --target langserve --url http://localhost:8001/my-chain --tier 2
rtharness run --target anthropic --model claude-haiku-4-5 --api-key-env ANTHROPIC_API_KEY --tier 2
```

### Targeting frameworks

rtharness attacks over an **interface**, so it works with any framework that
exposes one:

| Framework | How to target it |
|---|---|
| LangGraph / LangChain | `--target langserve --url .../invoke`, or `--target openai` if OpenAI-compatible |
| Google ADK | `--target adk --app-name <app>` |
| CrewAI / AutoGen / LlamaIndex | serve behind FastAPI and use `--target http` (set `--response-path`) or `--target openai` |
| OpenAI Agents SDK / Assistants | `--target openai` against the compatible endpoint |
| Anthropic API agents | `--target anthropic --model ...` |
| MCP servers (tools) | `--target mcp --url .../mcp` |
| Anything A2A | `--target a2a --base-url ...` |

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
| 4 | **adaptive** | With an attacker model: an **agentic LLM planner** reasons over the transcript and crafts tailored multi-turn attacks from the static library. Without one: a deterministic mutation/beam search. |

```bash
rtharness run --config my.yaml --tier 1              # quick CI gate (~1 attempt/objective)
rtharness run --config my.yaml --tier 4              # deep adversarial pass
rtharness run --config my.yaml --tier 4 --effort 3   # grind: ~3x the attempts
rtharness run --config my.yaml --tier 3 --exhaustive # don't stop at first hit; try the whole budget
```

**Effort** (`--effort`, default 1.0) is an intensity multiplier on top of the
tier — `0.3` for a fast skim, `3`+ to hammer a hardened target. By default the
engine stops attacking an objective once it finds one working break (enough to
confirm the vuln); `--exhaustive` makes it spend the full budget to enumerate
*every* way in.

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
| `a2a.push_notification_hijack` | Attacker-controlled task webhook (exfil/SSRF) | LLM02/LLM06:2025 | 3 |
| `mcp.metadata_poisoning` | Injected tool/resource/prompt metadata | LLM01/MCP03 | 1 |
| `mcp.returned_injection` | Data-borne injection in MCP resource/tool output | LLM01/MCP03 | 2 |
| `mcp.rug_pull` | MCP definition drift vs pinned baseline | LLM03/MCP03 | 1 |
| `mcp.unauth_access` | Unauthenticated MCP list/call | LLM06/MCP03 | 2 |
| `disclosure.pii` | PII / training-data extraction | LLM02:2025 | 2 |
| `output.insecure_handling` | Insecure output handling (XSS/SQLi echo) | LLM05:2025 | 2 |
| `recon.model_enumeration` | Model / tool fingerprinting | LLM07:2025 | 1 |
| `dos.resource_exhaustion` | Unbounded output / denial-of-wallet | LLM10:2025 | 2 |
| `memory.poisoning` | Persistent conversational memory injection | LLM01:2025 | 3 |
| `agency.goal_hijacking` | Mid-task goal redirection / task deviation | LLM01:2025 | 2 |
| `corpus.jb_scaffolds` | Built-in jailbreak-scaffold pack (15) | LLM01:2025 | 2 |
| `corpus.indirect_tool` | AgentDojo/InjecAgent-structured injection | LLM01/LLM06:2025 | 2 |
| `corpus.advanced_jailbreaks` | Recent named techniques (policy-puppetry, skeleton-key, …) | LLM01:2025 | 2 |

Each probe's *objective* is then exploded by the engine into many attempts
(direct → encodings → obfuscations → framings → multi-turn → mutations), so the
table lists weakness classes, not attempt counts. `rtharness list --tier 4`
prints the live list with full ATLAS mappings.

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
  effort: 1.0                             # intensity multiplier (0.3 .. 3+)
  attacker: { type: openai, model: ... }  # tier-4 adaptive attacker model
  judge:    { type: openai, model: ... }  # LLM-as-judge for semantic detection
  corpus: [ ./garak/garak/data, ./my_payloads.jsonl ]   # external attack corpora
```

### External attack corpora

Point `--corpus` (repeatable) at any attack set you're licensed to use and the
harness runs it alongside the engine:

```bash
# a local garak data dir (Apache-2.0), a promptfoo export, or your own JSONL
rtharness run --config my.yaml --corpus ./garak/garak/data --corpus ./payloads.jsonl
rtharness run --config my.yaml --corpus-expand   # also mutate each payload through the engine
rtharness run --config my.yaml --no-builtin-corpus   # skip the built-in packs
```

Supported formats: `.jsonl`/`.json`/`.yaml` (objects with `template`/`prompt`,
optional `expect: canary|tool|regex|refusal_bypass`), a `.txt` file, or a
**directory** of `.txt` payload lists (garak's shape). Imported prompts are
judged by refusal-bypass (and the judge model, if configured), the standard ASR
proxy. We don't bundle third-party datasets — you supply what you're licensed
for. Two benign packs ship built in (`corpus.jb_scaffolds`, `corpus.indirect_tool`).

Planting a **canary** in your agent's system prompt turns the leak detector
from a heuristic into a certainty: if that exact token appears in a response,
the system prompt leaked.

## Presets / compliance profiles

Named bundles pick the right probes + tier for a goal (`rtharness presets` lists
them): `quick`, `standard`, `deep`, `owasp-llm`, `owasp-agentic`, `mitre-atlas`,
`mcp`, `a2a`, `chat`, `injection`, `exfil`, `jailbreak`.

```bash
rtharness run --target a2a --base-url http://host --preset owasp-llm
rtharness run --target mcp --url http://host/mcp --preset mcp
```
Explicit flags/config override a preset; the web API takes `"preset": "..."` and
`GET /presets` lists them.

## Reports

Every run writes machine- and human-readable artifacts (`--format`, repeatable,
or `all`):

- **JSON** (`*.report.json`) — stable schema for CI gating and diffing.
- **Markdown** (`*.report.md`) — the assessment write-up with example transcripts.
- **HTML** (`*.report.html`) — a self-contained, shareable page (light/dark).
- **SARIF** (`*.sarif`) — for **GitHub code scanning** / SARIF consumers.
- **JUnit** (`*.junit.xml`) — for CI test dashboards.

`--fail-on high` exits non-zero when a High+ finding is confirmed. For
regression gating across runs:

```bash
rtharness diff baseline.report.json current.report.json   # exit 2 on new findings
```

See **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** (layers + usage matrix) and
**[docs/DISTRIBUTION.md](docs/DISTRIBUTION.md)** (pip/pipx/Docker/CI, secrets).

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
          ┌──────────┐  objectives   ┌───────────────┐  attempts    ┌────────────┐
Probes ──▶│ Objective │──────────────▶│  AttackEngine  │─────────────▶│   Target   │
          │ + Detector│               │ transforms ×30 │  conversation│ chat / A2A │
          └──────────┘               │ multi-turn      │◀─────────────│ / ADK /... │
                                      │ mutation/beam   │   Response   └────────────┘
                                      │ (+attacker LLM) │
                                      └──────┬─────────┘
                                             │ Attempt + DetectionResult (scored)
                                       ┌─────▼──────┐        ┌──────────┐
                                       │   Runner   │───────▶│  Reports │ json/md/html
                                       └────────────┘        └──────────┘
```

The engine (`rtharness/core/engine.py`) draws from the transform library
(`core/transforms.py`): encodings (base64/base32/hex/rot13/reverse/atbash/
morse/binary/url), canary-safe obfuscations (homoglyph/zero-width/spacing/
scramble/**Unicode-tag smuggling**), and jailbreak framings — refusal-
suppression, persona, hypothetical, past-tense, payload-splitting, many-shot,
competing-objectives, translation, code-completion, JSON/markdown, plus recent
named techniques: **Policy Puppetry** (HiddenLayer), **Skeleton Key** (MS),
**Bad Likert Judge** (Unit 42) and distraction/overflow. Multi-turn adds
crescendo, echo-chamber, obedience-ramp and **Deceptive Delight** (Unit 42). It
composes and mutates these under a tier×effort budget, scoring each attempt with
layered detectors.

## Verifying it works

```bash
rtharness selftest           # breaks the vulnerable mock, resists the secure mock
python -m examples.mock_server --port 8009   # run the mock over HTTP/A2A/ADK to test adapters
```

`selftest` runs the whole probe set against two bundled mock agents — one
intentionally vulnerable, one that refuses — and asserts the harness fires on
the former and produces **zero** false positives on the latter, even after the
adaptive engine exhausts hundreds of attempts. It exits non-zero on failure, so
it doubles as a CI health check.

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
