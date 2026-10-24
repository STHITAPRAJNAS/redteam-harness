#!/usr/bin/env bash
# Launch the LLM-backed test agent and scan it with rtharness.
# Requires ANTHROPIC_API_KEY in the environment (agent + attacker/judge use it).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY is not set. Add it in the environment's settings"
  echo "(Network secrets / environment variable), start a new session, and re-run."
  exit 1
fi

PORT="${PORT:-8200}"
export RT_AGENT_CANARY="${RT_AGENT_CANARY:-ACME_CFG_7Q2X9}"

echo "[*] starting ShopBot test agent on :$PORT"
python -m examples.llm_test_agent --port "$PORT" &
AGENT=$!
trap 'kill $AGENT 2>/dev/null || true' EXIT
sleep 2

echo "[*] agent health: $(curl -sS http://127.0.0.1:$PORT/ || true)"
echo "[*] running harness (preset deep, agentic + judge via Anthropic)"
rtharness run --config examples/config.llm.yaml
