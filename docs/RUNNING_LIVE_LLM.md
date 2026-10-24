# Running a live LLM scan

How to run rtharness against a real agent with the LLM-powered features (the
**agentic attacker** and **LLM judge**) switched on. Everything here needs
network egress to your target and to whatever model you choose — run it in an
environment that allows that (a locked-down CI/sandbox may block provider hosts;
`rtharness run` prints which hosts it couldn't reach).

> The deterministic engine (tiers 1–3 + all protocol/MCP/A2A probes) needs **no
> LLM at all**. The steps below only add the optional LLM layer.

## 1. Choose where the attack-brain/judge model runs

Pick one. rtharness never needs a key for the **target** beyond the target's own
auth — the key below is only for the attacker/judge models.

### Option A — cloud provider (OpenAI, Anthropic, …)
```bash
export OPENAI_API_KEY=sk-...        # or ANTHROPIC_API_KEY=...
```
In a managed cloud environment, add it as an **environment variable / secret**
in the environment settings (never paste keys into a prompt), then start a fresh
session so it's loaded.

### Option B — self-hosted / air-gapped (no cloud key)
Run an OpenAI-compatible model locally and point rtharness at it:
```bash
# Ollama example
ollama serve &
ollama pull llama3.1:8b
# (vLLM / LM Studio / TGI expose the same /v1 API — just change base_url)
```
Use `examples/config.local-llm.yaml` (base_url `http://localhost:11434/v1`).

### Option C — enterprise gateway
Point `base_url` at your Azure/Bedrock/Vertex OpenAI-compatible gateway and set
its `api_key_env`.

## 2. Configure the run

Copy a config and set the `attacker` / `judge` blocks (keys come from env vars,
never inline):

```yaml
# my-scan.yaml
target: { type: a2a, base_url: https://my-agent.internal }   # or openai/http/adk/mcp/...
preset: deep                                                  # tier 4 => agentic + judge
profile:
  attacker: { type: openai, model: gpt-4o-mini, api_key_env: OPENAI_API_KEY }
  judge:    { type: openai, model: gpt-4o-mini, api_key_env: OPENAI_API_KEY }
  # For self-hosted, add base_url: http://localhost:11434/v1 and model: llama3.1:8b
fail_on: high
formats: [json, md, html, sarif]
```

## 3. Run it

```bash
rtharness run --config my-scan.yaml
```
The banner confirms what's active, e.g.
`modes -> deterministic engine: on, adaptive attacker: on, agentic planner: on, LLM judge: on`.
Reports land in `./reports/` (JSON/MD/HTML/SARIF). `--fail-on high` sets the
exit code for CI; `rtharness diff old.json new.json` gates regressions.

## 4. Try it end-to-end against the bundled LLM agent

A ready demo target (a deliberately-weak Claude-backed "ShopBot"):
```bash
export ANTHROPIC_API_KEY=...        # ShopBot + attacker/judge both use this
bash examples/run_llm_scan.sh       # launches ShopBot, runs examples/config.llm.yaml
```

## 5. Validate the LLM pipeline with no model/key (CI)

To exercise the agentic + judge loop over real HTTP without spending tokens:
```bash
python -m examples.local_openai_stub --port 8300 &     # keyless OpenAI-compatible stub
python -m examples.mock_server --port 8090 &           # a target
rtharness run --target a2a --base-url http://127.0.0.1:8090 --preset deep \
  --format json --out reports \
  # point attacker/judge at the stub via a config's base_url http://127.0.0.1:8300/v1
```

## Operational notes

- **Authorisation:** only scan agents you own or are explicitly permitted to
  test. Reports can contain data the target leaks — treat them as sensitive.
- **Cost/rate limits:** tier 4 + `--effort` multiplies attacker/judge calls. The
  client retries 429/5xx with backoff; use `--rate-limit` and a smaller
  `--effort` against metered endpoints. `RTHARNESS_HTTP_TIMEOUT` /
  `RTHARNESS_HTTP_RETRIES` tune the client.
- **Secrets:** keys are read from env only, forwarded solely to their own API,
  and redacted from any error text. Never commit them; use `.env`/secret stores.
- **Egress:** the run needs to reach the target host and the model host. In a
  restricted sandbox, prefer Option B (self-hosted) on the same network.
