"""Generic HTTP chat target.

Point it at any JSON chat endpoint by describing how to build the request body
and where the reply text lives. Three ways to supply the conversation:

- ``message_var`` (default ``"prompt"``): the latest user message is
  substituted for ``{{prompt}}`` in ``body_template``.
- ``history_var``: the full conversation (flattened text) is substituted for
  ``{{history}}``.
- a custom ``body_template`` referencing either placeholder.

The reply text is read from ``response_path`` (dotted path, list indices ok).
Optional ``tool_calls_path`` extracts structured tool invocations for the
excessive-agency detectors.

Example (a Flask agent that takes ``{"message": "..."}`` and returns
``{"reply": "..."}``)::

    HTTPChatTarget(
        url="http://localhost:5000/chat",
        body_template={"message": "{{prompt}}"},
        response_path="reply",
    )
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..core.target import Response, Target, Turn
from . import _http


class HTTPChatTarget(Target):
    def __init__(
        self,
        url: str,
        name: str = "http-chat",
        body_template: Optional[Dict[str, Any]] = None,
        response_path: str = "reply",
        tool_calls_path: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        api_key: Optional[str] = None,
        api_key_env: Optional[str] = None,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer ",
        message_var: str = "prompt",
        history_var: str = "history",
        method: str = "POST",
        timeout: float = 60.0,
        verify_tls: bool = True,
    ):
        self.url = url
        self.name = name
        self.body_template = body_template or {"message": "{{prompt}}"}
        self.response_path = response_path
        self.tool_calls_path = tool_calls_path
        self.headers = dict(headers or {})
        self.message_var = message_var
        self.history_var = history_var
        self.method = method.upper()
        self.timeout = timeout
        self.verify_tls = verify_tls

        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers[auth_header] = auth_prefix + key

    def generate(self, messages: List[Turn]) -> Response:
        payload = [t.to_dict() for t in messages]
        latest = payload[-1]["content"] if payload else ""
        variables = {
            self.message_var: latest,
            self.history_var: _http.messages_to_text(payload),
        }
        body = _http.render_template(self.body_template, variables)

        def _call():
            data = _http.post_json(self.url, body, self.headers, self.timeout, self.verify_tls)
            text = _http.json_get(data, self.response_path, default="")
            if not isinstance(text, str):
                text = str(text)
            tool_calls = []
            if self.tool_calls_path:
                tc = _http.json_get(data, self.tool_calls_path, default=[])
                if isinstance(tc, list):
                    tool_calls = tc
            return text, data, tool_calls

        return self._timed(_call)
