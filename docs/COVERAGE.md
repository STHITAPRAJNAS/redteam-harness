# Coverage: OWASP LLM Top 10, OWASP Agentic, MITRE ATLAS, NIST AML

What rtharness tests, mapped to the frameworks — and, honestly, what is **out of
black-box scope** (and therefore a job for complementary static / pipeline
tools, not a runtime agent scanner).

Legend: ✅ covered · ◑ partial (runtime-observable slice) · ⬚ out of black-box scope

## OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Status | Probes |
|----|------|--------|--------|
| LLM01 | Prompt Injection | ✅ | `prompt_injection.direct`/`.indirect`, `jailbreak.refusal_suppression`, `agency.goal_hijacking`, `a2a.card_injection`, `mcp.metadata_poisoning`/`.returned_injection`, corpus packs |
| LLM02 | Sensitive Information Disclosure | ✅ | `disclosure.pii`, `disclosure.system_prompt`, `exfil.markdown_beacon`, `disclosure.training_data`, `a2a.push_notification_hijack` |
| LLM03 | Supply Chain | ◑ | `a2a.card_integrity`, `mcp.rug_pull` (agent/tool trust + drift). ⬚ model/dependency SCA & weight provenance need a software-supply-chain scanner |
| LLM04 | Data & Model Poisoning | ◑ | `memory.poisoning`, `rag.context_poisoning` (runtime/retrieval). ⬚ training-time dataset poisoning & model backdoors need training-pipeline access |
| LLM05 | Improper Output Handling | ✅ | `output.insecure_handling` (XSS / SQLi echo) |
| LLM06 | Excessive Agency | ✅ | `agency.gated_tool`, `a2a.missing_auth`, `a2a.context_isolation`, `mcp.unauth_access` |
| LLM07 | System Prompt Leakage | ✅ | `disclosure.system_prompt`, `recon.model_enumeration` |
| LLM08 | Vector & Embedding Weaknesses | ✅ | `rag.context_poisoning` (poisoned-retrieval). ◑ embedding inversion / cross-tenant retrieval leakage need direct vector-store access |
| LLM09 | Misinformation | ✅ | `misinformation.fabrication` (judge-backed) |
| LLM10 | Unbounded Consumption | ✅ | `dos.resource_exhaustion`, `a2a.recursive_delegation`, `disclosure.training_data` (divergence) |

**All 10 categories are exercised.** LLM03/LLM04 are covered for the parts
observable at runtime; the rest is explicitly supply-chain/training-pipeline
work (run a SCA / data-governance tool alongside).

## OWASP Agentic Top 10 (2025)

| Risk | Status | Probes |
|------|--------|--------|
| Tool misuse | ✅ | `agency.gated_tool`, corpus `indirect_tool` |
| Goal / intent manipulation | ✅ | `agency.goal_hijacking` |
| Memory poisoning | ✅ | `memory.poisoning` |
| Privilege / identity / auth | ✅ | `a2a.missing_auth`, `a2a.context_isolation`, `mcp.unauth_access` |
| Cascading / multi-agent | ✅ | `a2a.recursive_delegation`, `a2a.card_injection`, `mcp.*` |
| Resource exhaustion | ✅ | `dos.resource_exhaustion` |
| Untrusted inputs / RAG | ✅ | `prompt_injection.indirect`, `rag.context_poisoning`, `mcp.returned_injection` |

## NIST AML taxonomy (NIST AI 100-2)

| Class | Status | Probes |
|-------|--------|--------|
| Evasion | ✅ | all injection/jailbreak probes + transforms + corpora |
| Poisoning | ◑ | `memory.poisoning`, `rag.context_poisoning` (runtime). ⬚ training-time out of scope |
| Privacy — model extraction | ◑ | `recon.model_enumeration` |
| Privacy — data reconstruction / membership | ◑ | `disclosure.training_data`, `disclosure.pii` |
| Abuse | ✅ | `misinformation.fabrication`, guardrail-bypass probes |

> NIST AI RMF / GenAI profile (AI 600-1) is governance/process, not a scan
> target; rtharness reports feed its *measure/manage* functions. Run with
> `--preset nist`.

## Tools: what we reuse vs. reimplement

- **Corpora** (garak, promptfoo, JailbreakBench, AgentDojo/InjecAgent) — ingested
  via `--corpus` (you bring what you're licensed for).
- **Static scanners** (Snyk/Invariant `mcp-scan`, SplxAI Agentic Radar) — their
  checks are **reimplemented dynamically** against the live surface; we don't
  wrap them as subprocesses (black-box, dependency-light by design). Run them
  alongside for the static/source view.
- **Orchestration shape** (PyRIT) — mirrored in the attack engine
  (transforms=converters, detectors=scorers, agentic planner=orchestrator).

## Known out-of-scope (by design)

A black-box runtime harness cannot see these; pair rtharness with the noted
tooling:
- Training-data / fine-tune dataset poisoning, model backdoors → data governance
  + training-pipeline controls.
- Model/dependency supply chain, weight provenance → SCA / artifact signing.
- Embedding inversion / membership inference at the store → vector-store audit.
- Model governance, documentation, bias/fairness measurement → NIST AI RMF
  process, not a scanner.
