"""Convenience adapters for common agent frameworks.

Most frameworks expose either an OpenAI-compatible endpoint (use
``OpenAIChatTarget``) or a plain HTTP endpoint (use ``HTTPChatTarget``). These
two adapters cover the cases with their own wire shape:

* :class:`LangServeTarget` — LangChain/LangGraph ``LangServe`` runnables
  (``POST {base}/invoke`` with ``{"input": ...}`` → ``{"output": ...}``).
* :class:`AnthropicTarget` — the Anthropic Messages API (``/v1/messages``),
  surfacing ``tool_use`` blocks as tool calls.

For CrewAI / AutoGen / LlamaIndex / OpenAI Agents SDK, serve the agent behind an
HTTP or OpenAI-compatible endpoint and point ``HTTPChatTarget`` /
``OpenAIChatTarget`` at it (see the README "Targeting frameworks" recipes).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.target import Response, Target, Turn
from . import _http


class LangServeTarget(Target):
    def __init__(
        self,
        url: str,
        name: str = "langserve",
        input_key: str = "input",
        output_path: str = "output",
        as_messages: bool = False,
        headers: Optional[Dict[str, str]] = None,
        api_key: Optional[str] = None,
        api_key_env: Optional[str] = None,
        timeout: float = 90.0,
        verify_tls: bool = True,
    ):
        # Accept either the runnable base or its full /invoke URL.
        self.url = url if url.rstrip("/").endswith("invoke") else url.rstrip("/") + "/invoke"
        self.name = name
        self.input_key = input_key
        self.output_path = output_path
        self.as_messages = as_messages
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers["Authorization"] = "Bearer " + key

    def generate(self, messages: List[Turn]) -> Response:
        if self.as_messages:
            value: Any = [t.to_dict() for t in messages]
        else:
            value = next((t.content for t in reversed(messages) if t.role == "user"), "")
        body = {"input": {self.input_key: value}} if self.input_key != "input" or self.as_messages \
            else {"input": value}

        def _call():
            data = _http.post_json(self.url, body, self.headers, self.timeout, self.verify_tls)
            out = _http.json_get(data, self.output_path, default=data.get("output", ""))
            if isinstance(out, dict):
                out = out.get("content") or out.get("output") or out.get("text") or str(out)
            return (out if isinstance(out, str) else str(out)), data, []
        return self._timed(_call)


class AnthropicTarget(Target):
    def __init__(
        self,
        model: str,
        name: Optional[str] = None,
        base_url: str = "https://api.anthropic.com",
        api_key: Optional[str] = None,
        api_key_env: str = "ANTHROPIC_API_KEY",
        system_prompt: Optional[str] = None,
        max_tokens: int = 1024,
        anthropic_version: str = "2023-06-01",
        extra_body: Optional[Dict[str, Any]] = None,
        timeout: float = 90.0,
        verify_tls: bool = True,
    ):
        self.model = model
        self.name = name or ("anthropic:" + model)
        self.base_url = base_url.rstrip("/")
        self.system_prompt = system_prompt
        self.max_tokens = max_tokens
        self.extra_body = extra_body or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"Content-Type": "application/json",
                        "anthropic-version": anthropic_version}
        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers["x-api-key"] = key

    def generate(self, messages: List[Turn]) -> Response:
        msgs = [t.to_dict() for t in messages if t.role in ("user", "assistant")]
        body: Dict[str, Any] = {"model": self.model, "max_tokens": self.max_tokens,
                                "messages": msgs}
        if self.system_prompt:
            body["system"] = self.system_prompt
        body.update(self.extra_body)
        url = self.base_url + "/v1/messages"

        def _call():
            data = _http.post_json(url, body, self.headers, self.timeout, self.verify_tls)
            texts, tool_calls = [], []
            for block in data.get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    texts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    tool_calls.append({"name": block.get("name"),
                                       "arguments": block.get("input", {})})
            return "\n".join(texts), data, tool_calls
        return self._timed(_call)
