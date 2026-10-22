"""OpenAI-compatible chat target (/v1/chat/completions).

Works against OpenAI, Azure OpenAI-style gateways, vLLM, Ollama's OpenAI shim,
LiteLLM proxy, and most "OpenAI-compatible" agent servers. Sends the full
conversation as ``messages`` and reads ``choices[0].message.content``. Any
``tool_calls`` on the message are surfaced for the agency detectors.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.target import Response, Target, Turn
from . import _http


class OpenAIChatTarget(Target):
    def __init__(
        self,
        model: str,
        name: Optional[str] = None,
        base_url: str = "https://api.openai.com/v1",
        api_key: Optional[str] = None,
        api_key_env: str = "OPENAI_API_KEY",
        system_prompt: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: Optional[int] = None,
        extra_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 90.0,
        verify_tls: bool = True,
    ):
        self.model = model
        self.name = name or ("openai:" + model)
        self.base_url = base_url.rstrip("/")
        self.system_prompt = system_prompt
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.extra_body = extra_body or {}
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers["Authorization"] = "Bearer " + key

    def generate(self, messages: List[Turn]) -> Response:
        msgs: List[Dict[str, str]] = []
        if self.system_prompt and not any(t.role == "system" for t in messages):
            msgs.append({"role": "system", "content": self.system_prompt})
        msgs.extend(t.to_dict() for t in messages)

        body: Dict[str, Any] = {
            "model": self.model,
            "messages": msgs,
            "temperature": self.temperature,
        }
        if self.max_tokens:
            body["max_tokens"] = self.max_tokens
        body.update(self.extra_body)
        url = self.base_url + "/chat/completions"

        def _call():
            data = _http.post_json(url, body, self.headers, self.timeout, self.verify_tls)
            text = _http.json_get(data, "choices.0.message.content", default="") or ""
            tool_calls = _http.json_get(data, "choices.0.message.tool_calls", default=[]) or []
            return text, data, tool_calls

        return self._timed(_call)
