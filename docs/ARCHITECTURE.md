# rtharness architecture

rtharness red-teams **agent applications** (ADK, LangGraph, any framework) as a
black box, through the surfaces they expose — **chat, A2A, MCP**. It is
layered so the core runs with zero LLM and the LLM is a bolt-on enhancement.

## Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│  FRONT-ENDS (pick any; all drive one engine)                               │
│   • Library    from rtharness.api import execute_scan                      │
│   • CLI        rtharness run / selftest / list / presets / diff / serve    │
│   • Web API    FastAPI: POST /scan, GET /scan/<id>[/report], /probes, ...  │
│   • MCP tool   POST /mcp  (scan_agent, list_probes) — callable by agents   │
├──────────────────────────────────────────────────────────────────────────┤
│  OPTIONAL LLM LAYER (only if an API key is configured)                     │
│   • Agentic planner   reasons over the transcript, crafts tailored attacks │
│   • Adaptive attacker rewrites/escalates on refusal                        │
│   • LLM judge         semantic success detection                           │
├──────────────────────────────────────────────────────────────────────────┤
│  DETERMINISTIC CORE (always on, no key)                                    │
│   • Attack engine     transforms + multi-turn + mutation/beam search       │
│   • Transform library ~31 encodings / obfuscations / jailbreak framings    │
│   • Corpus packs      built-in benign + imported (garak/promptfoo/AgentDojo)│
│   • Probes            21+ weakness classes, OWASP/ATLAS/MCP-Top10 mapped    │
│   • Detectors         refusal, canary, secret, tool-abuse, composite, judge │
│   • Runner + reports  JSON / Markdown / HTML / SARIF / JUnit + risk score  │
├──────────────────────────────────────────────────────────────────────────┤
│  TARGET ADAPTERS (the system under test — reached over the wire)           │
│   chat(http/openai/langserve/anthropic) · a2a · adk · mcp · callable       │
└──────────────────────────────────────────────────────────────────────────┘
```

**Key property:** nothing below the LLM layer imports an LLM SDK or a target
framework SDK. The only hard dependency is `requests`. Target frameworks are
reached over HTTP/JSON-RPC, so their versions/bugs are never rtharness's
concern.

## Data flow of one scan

```
RunConfig ──▶ api.execute_scan ──▶ select probes (+ presets, + corpus)
                                      │
                 each probe ─▶ Objective(+detector) ─▶ AttackEngine
                                      │  direct → transforms → multi-turn
                                      │  → mutation  (or → agentic planner if LLM)
                                      ▼
                 Target (chat/A2A/MCP) ⇄ Response ─▶ Detector ─▶ Attempt
                                      ▼
                 Runner aggregates ─▶ RunResult ─▶ reports (json/md/html/sarif/junit)
```

## Usage matrix

| Front-end | Keyless (default) | With LLM key |
|---|---|---|
| Library | deterministic scan, in-process | + agentic/judge |
| CLI | `rtharness run --preset owasp-llm` | `--effort`, attacker/judge via config |
| Web API | `POST /scan` against any target | same, modes reported per job |
| MCP tool | other agents call `scan_agent` | same |

Every target surface (chat, A2A, MCP, ADK, callable) works from every
front-end, keyless or keyed. The active modes are printed by the CLI banner and
returned in each service job's `modes` field.

## Module map

| Path | Responsibility |
|---|---|
| `core/target.py` | neutral conversation model + `Target`/`Session`/`Response` |
| `targets/*` | wire adapters (http, openai, a2a, adk, mcp, langserve, anthropic, callable) |
| `core/transforms.py` | encodings / obfuscations / jailbreak framings |
| `core/engine.py` | tier×effort budget, transform sweep, multi-turn, mutation |
| `core/agentic.py` | LLM attack-planner loop (optional) |
| `detectors/*` | success detection (lexical + optional judge) |
| `probes/*`, `corpus.py` | weakness tests + attack corpora |
| `core/runner.py` | orchestration → `RunResult` |
| `report/*` | json / markdown / html / sarif / junit |
| `api.py` | `execute_scan` + capability reporting (shared by CLI + service) |
| `presets.py` | named compliance/surface profiles |
| `service.py`, `_service_*` | FastAPI (+ stdlib fallback) REST + dashboard + `/mcp` |
| `cli.py` | `run / selftest / list / presets / diff / serve` |
