# Agent Red-Teaming: Landscape Review, Threat Model, and the rtharness Approach

_Last updated: 2026-10-22. This document grounds `rtharness` in current research
and tooling, explains the threat model it targets, and justifies the design._

---

## 1. Why agents need a dedicated harness

Most LLM-security tooling matured around the **single-turn chatbot**: send a
prompt, score a response. Agents break those assumptions in three ways that
materially change the attack surface:

1. **Tools / actions.** An agent can *do* things (call APIs, delete records,
   send mail). The worst outcome is no longer "says something bad" but
   "performs an unauthorised, irreversible action" — OWASP's *Excessive Agency*
   (LLM06) and the Agentic Top 10's *Tool Misuse* / *Privilege Compromise*.
2. **Untrusted data in the loop.** Agents read tool output, documents, web
   pages and other agents' messages. That makes **indirect (second-order)
   prompt injection** the realistic attack: the adversary is not the user.
3. **Multi-agent / A2A topologies.** With the Agent-to-Agent protocol, agents
   discover and delegate to each other via **agent cards**, creating trust,
   identity and authorisation problems that simply don't exist for a lone chatbot.

A harness that is "good at finding vulnerabilities in any agent" therefore has
to speak both the **chat** and the **A2A** interface, test **tool/agency**
abuse, exercise **multi-turn** attacks, and inspect **protocol-level** trust.
That is the scope `rtharness` is built for.

## 2. Threat frameworks we map to

We map every probe to recognised taxonomies so findings are actionable and
auditable.

### OWASP Top 10 for LLM Applications (2025)
The 2025 list is the industry baseline; relevant entries for agents include
**LLM01 Prompt Injection**, **LLM02 Sensitive Information Disclosure**,
**LLM06 Excessive Agency**, **LLM07 System Prompt Leakage**, and
**LLM03 Supply Chain** (which we invoke for untrusted agent-card content).
([OWASP LLM Top 10 2025 PDF][owasp-pdf], [overview][superwise])

### OWASP Agentic Top 10 (2025)
A separate agentic threat list covers **goal hijacking, tool misuse, memory
poisoning, and delegation/authorisation failures** — the agent-specific risks
beyond the base LLM list. ([promptfoo's agentic mapping][pf-agentic],
[EthicalHat overview][ethicalhat])

### MITRE ATLAS
ATLAS (the "ATT&CK for AI") provides adversary **tactics and techniques**; as of
the Nov-2025 update it spans 16 tactics / 84 techniques. We tag probes with
technique IDs (e.g. `AML.T0051` prompt injection, `AML.T0054` jailbreak,
`AML.T0056/T0057` system-prompt extraction) so a run plugs into ATT&CK-style
planning. ([MITRE ATLAS overview][atlas], [ATLAS vs OWASP][redfox])

> Technique IDs here are best-effort mappings for planning; confirm against
> `atlas.mitre.org` for your report's authoritative citations.

## 3. Tooling landscape (and where rtharness fits)

The user's brief referenced PyRIT, "OpenRT", ARTKIT and Promptfoo. Here is how
the current open-source building blocks compare, and why we still build a thin
agent-focused harness on top of these ideas rather than forking one.

| Tool | Core architecture | Strength | Gap for *agent* testing |
|---|---|---|---|
| **[PyRIT]** (Microsoft) | Orchestrators + converters + scorers | High-realism, programmable **multi-turn** campaigns; enterprise/Azure hooks | Model-centric; A2A / agent-card / tool-abuse not first-class |
| **[garak]** (NVIDIA) | Probe + detector + generator plugins | Huge **breadth** of single-turn vuln probes; fast bulk scans | Primarily single-turn, model-focused; no A2A |
| **[promptfoo]** | Assertion matrix + attack-generation plugins | Large jailbreak corpus, **OWASP/ATLAS presets**, great DevOps/CI ergonomics | JS/config-centric; agent protocol surface limited |
| **[ARTKIT]** (BCG) | Scriptable Python pipeline APIs | Extremely **extensible/scriptable**; good for custom harnesses | You build the attack logic yourself |
| **[DeepTeam]** | Vuln + attack modules, framework mappings | Maps results to **OWASP/NIST/ATLAS**; many attack types | General LLM focus; A2A-specific probes absent |

**Design stance.** `rtharness` borrows the proven decomposition that these tools
share — **probe → attack/converter → detector/scorer → report** — and adds the
pieces that are thin or missing for agents specifically:

- **A2A as a first-class target** (card discovery, JSON-RPC `message/send`,
  `tasks/get`) plus **protocol-level probes** (unsigned cards, card injection,
  missing auth, context-ownership/IDOR, recursive-delegation DoS).
- **Tool/agency abuse** as a core category (structured tool-call inspection +
  side-effect receipts), including the **confused-deputy** (indirect) variant.
- **Explicit sophistication tiers** so one tool serves both a 10-second CI gate
  and a deep adversarial pass.
- **Near-zero dependencies** (`requests` only) so it drops into air-gapped or
  locked-down assessment environments where `pip install` of a large tree is a
  non-starter.

`rtharness` is complementary, not a replacement: use garak/promptfoo for sheer
breadth of model-level jailbreaks, PyRIT for bespoke enterprise campaigns, and
`rtharness` for agent/A2A-shaped coverage and quick, portable regression gates.

[PyRIT]: https://github.com/Azure/PyRIT
[garak]: https://github.com/NVIDIA/garak
[promptfoo]: https://www.promptfoo.dev/docs/red-team/
[ARTKIT]: https://github.com/BCG-X-Official/artkit
[DeepTeam]: https://trydeepteam.com/

## 4. Attack techniques implemented

### Direct & indirect prompt injection (LLM01)
Direct injection tests instruction-override ("ignore previous instructions…");
indirect injection plants the hostile instruction **inside data the agent
processes** (a support ticket, an HTML comment), modelling the realistic case
where attacker ≠ user. The success signal is a benign **canary echo**, proving
loss of instruction integrity without producing harmful content.

### Crescendo (multi-turn)
Crescendo (Russinovich, Salem, Eldan, Microsoft 2024) opens with benign,
on-topic turns and **escalates gradually**, exploiting the model's tendency to
stay consistent with recent (especially its own) output. A 2025 ICML analysis
showed each turn keeps outputs in a "benign" representation region, which is why
single-turn/per-message defences miss it — the recommended defence is
**conversation-level** monitoring. We implement the ramp + one backtrack on
refusal. ([USENIX ;login: writeup][crescendo-login], [arXiv paper][crescendo-arxiv])

### Obfuscation & persona (tier 2)
Base64/ROT13/leet wrappers dodge keyword filters; persona/authority framings
("diagnostic mode", "ConfigInspector") test whether refusals are only skin-deep.

### Adaptive (tier 4)
An optional **attacker model** reads the agent's refusal and rewrites the next
message toward the (benign) objective — the automated-red-teamer pattern
(cf. PAIR/TAP-style loops). Without a model configured it degrades to a
deterministic rephrase ladder so tier-4 still runs offline.

### Data exfiltration via outbound URL
The "zero-click" agent-exfil pattern: coax the agent into embedding confidential
context into a **markdown image / link** to an attacker host, which a rendering
client auto-fetches. We plant a benign secret and detect the beacon host **and**
the secret appearing together (an exfil URL was constructed); nothing is sent.

### Excessive agency / tool misuse (LLM06)
Direct ("use your `delete_account` tool now") and **confused-deputy** (the gated
action is requested *inside* processed data). Detection uses both the structured
`tool_calls` the agent emits and a textual **side-effect receipt** marker.

## 5. A2A-specific research grounding

A2A puts several critical controls at SHOULD/MAY level, which concentrates risk
in a few places our probes target:

- **Agent-card trust.** Clients decide which remote agent to trust — and how to
  authenticate — from the card. A tampered/spoofed card (DNS/CDN compromise,
  look-alike "card shadowing" domain) subverts the whole interaction; skills are
  self-asserted strings with no built-in verification. Trustwave reported a 2025
  attack where an **inflated card description manipulates an LLM host agent's
  selection logic** — i.e. prompt injection through card text. Mitigation:
  **sign cards and verify on retrieval**, re-verify before high-value
  delegation, use a trusted-issuer registry.
  → probes `a2a.card_integrity`, `a2a.card_injection`.
  ([Palo Alto A2A risks][pan-a2a], [SecureW2][securew2], [survey][a2a-survey])
- **Optional authentication / weak identity at discovery.** The "A2ABreak"
  analysis finds identity verification at discovery is optional and that
  conversation contexts **lack ownership binding or access control**.
  → probes `a2a.missing_auth` (unauthenticated `message/send`),
  `a2a.context_isolation` (`tasks/get` on a foreign id — an IDOR test).
  ([A2ABreak][a2abreak], ["Securing Agentic AI" / A2A threat model][sec-agentic])
- **Delegation hazards.** Recursive delegation can deadlock/loop (recursive
  DoS); **authorisation creep** occurs when an orchestrator forwards full-scope
  credentials to less-privileged sub-agents.
  → probe `a2a.recursive_delegation`; remediation guidance on **downscoping**
  delegated credentials and enforcing depth/fan-out limits.
  ([agentic AI security survey][agentic-survey], [Google secure-A2A paper][google-a2a])

## 6. The tiered methodology

| Tier | Intent | Techniques | Typical use |
|---|---|---|---|
| 1 Basic | Smoke test, low FP | direct single-shot | CI gate on every PR |
| 2 Intermediate | Filter-evasion | +base64/rot13/leet, persona, indirect injection | nightly / pre-release |
| 3 Advanced | Realistic adversary | +crescendo multi-turn, confused-deputy, A2A access-control | release / pen-test |
| 4 Adaptive | Worst-case | +attacker-model rewrite-on-refusal | deep assessment |

Tiers are **cumulative** and selected per run (`--tier`), so sophistication
scales with need. Findings carry a per-attempt **technique** label and a
detector **rationale**, and the run rolls up to a 0–100 **risk score** weighted
by confirmed-finding severity.

## 7. Detection philosophy & false positives

Detectors are intentionally **layered and mostly lexical/structural** (refusal,
canary/marker, secret-shape, tool-call), because these are cheap, deterministic,
model-agnostic and auditable. Two guardrails against false positives:

- **Canaries over heuristics.** A planted system-prompt canary makes leakage a
  certainty rather than a guess; an injection canary proves instruction override.
- **Composite AND.** The exfil finding requires both the beacon host and the
  secret in the same response, not either alone.

An optional **LLM-as-judge** detector (`JudgeDetector`) is available for
semantic cases, wired to any chat model — but the harness never *requires* a
second model, so it works with zero extra setup.

## 8. Limitations & honest caveats

- Findings are **signals, not proofs** — confirm manually before acting.
- Lexical detectors can miss paraphrased leakage; enable the judge for depth.
- A2A/ADK wire formats **drift between versions**; adapters send tolerant
  payloads (both snake/camel casing; new and old well-known card paths) but you
  should confirm against your deployed server version.
- Several cited A2A sources are preprints/vendor blogs; the Trustwave card-
  injection result is reported second-hand. Treat the mechanisms as well-
  established and specific numbers as provisional.

## References

- OWASP Top 10 for LLM Applications 2025 — [PDF][owasp-pdf] · [overview][superwise]
- OWASP Agentic / agentic attack surface — [promptfoo][pf-agentic] · [EthicalHat][ethicalhat]
- MITRE ATLAS — [overview][atlas] · [ATLAS vs OWASP][redfox]
- Crescendo multi-turn jailbreak — [USENIX ;login:][crescendo-login] · [arXiv][crescendo-arxiv]
- A2A security — [A2ABreak][a2abreak] · [Palo Alto][pan-a2a] · [SecureW2][securew2] · [Google secure-A2A][google-a2a] · [interoperability survey][a2a-survey]
- Agentic AI security survey — [arXiv][agentic-survey] · ["Securing Agentic AI"][sec-agentic]
- Tooling — [PyRIT] · [garak] · [promptfoo] · [ARTKIT] · [DeepTeam] · [AI red-team tools compared][vdf]

[owasp-pdf]: https://owasp.github.io/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf
[superwise]: https://superwise.ai/learn/owasp-top-10-for-llm-applications/
[pf-agentic]: https://www.promptfoo.dev/docs/red-team/owasp-agentic-ai/
[ethicalhat]: https://www.ethicalhat.com/owasp-for-llms-and-agents-understanding-the-new-ai-attack-surface/
[atlas]: https://www.vectra.ai/topics/mitre-atlas
[redfox]: https://www.redfoxsec.com/blog/mitre-atlas-vs-owasp-llm-top-10-which-framework-should-you-use-in-2026
[crescendo-login]: https://www.usenix.org/publications/loginonline/crescendo-quiet-crescendo-arms-race-llm-jailbreaking
[crescendo-arxiv]: https://arxiv.org/abs/2404.01833
[a2abreak]: https://arxiv.org/html/2609.10871v1
[pan-a2a]: https://live.paloaltonetworks.com/t5/community-blogs/safeguarding-ai-agents-an-in-depth-look-at-a2a-protocol-risks/ba-p/1235996
[securew2]: https://securew2.com/blog/a2a-protocol-security
[google-a2a]: https://arxiv.org/html/2504.16902v1
[a2a-survey]: https://arxiv.org/pdf/2505.02279
[agentic-survey]: https://arxiv.org/pdf/2510.23883
[sec-agentic]: https://arxiv.org/pdf/2608.01558
[vdf]: https://vdf.ai/blog/ai-red-teaming-tools/
