"""Google ADK (Agent Development Kit) dev-server target.

Talks to the ADK API server (``adk api_server`` / ``adk web``, default
http://localhost:8000). For each conversation the adapter creates a fresh
session, posts turns to ``/run``, and extracts the model's text and any
function calls from the returned event list.

Request casing drifts between ADK versions (snake_case ``app_name`` vs
camelCase ``appName``); both are sent so either server accepts it. Session
creation uses ``/apps/{app}/users/{user}/sessions/{id}`` and tolerates an
"already exists" response.

Function calls in the event stream are surfaced as ``tool_calls`` for the
excessive-agency detectors.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import requests

from ..core.target import Response, Session, Target, Turn
from . import _http


def _extract(events: Any) -> (str, List[Dict[str, Any]]):  # type: ignore[valid-type]
    texts: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    if not isinstance(events, list):
        events = [events]
    for ev in events:
        if not isinstance(ev, dict):
            continue
        content = ev.get("content") or {}
        parts = content.get("parts") if isinstance(content, dict) else None
        for p in parts or []:
            if not isinstance(p, dict):
                continue
            if isinstance(p.get("text"), str):
                texts.append(p["text"])
            fc = p.get("functionCall") or p.get("function_call")
            if isinstance(fc, dict):
                tool_calls.append({
                    "name": fc.get("name"),
                    "arguments": fc.get("args") or fc.get("arguments") or {},
                })
    return "\n".join(t for t in texts if t).strip(), tool_calls


class ADKSession(Session):
    def __init__(self, target: "ADKTarget"):
        super().__init__(target)
        self.user_id = "rt-" + uuid.uuid4().hex[:8]
        self.session_id = "s-" + uuid.uuid4().hex[:12]
        self._created = False

    def send(self, content: str, role: str = "user") -> Response:
        self.turns.append(Turn(role, content))
        resp = self.target.run_turn(self, content)
        self.turns.append(Turn("assistant", resp.text))
        self.responses.append(resp)
        return resp


class ADKTarget(Target):
    def __init__(
        self,
        app_name: str,
        name: Optional[str] = None,
        base_url: str = "http://localhost:8000",
        headers: Optional[Dict[str, str]] = None,
        api_key: Optional[str] = None,
        api_key_env: Optional[str] = None,
        timeout: float = 90.0,
        verify_tls: bool = True,
    ):
        self.app_name = app_name
        self.base_url = base_url.rstrip("/")
        self.name = name or ("adk:" + app_name)
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers["Authorization"] = "Bearer " + key

    def new_session(self) -> ADKSession:
        return ADKSession(self)

    def _ensure_session(self, s: ADKSession) -> None:
        if s._created:
            return
        url = "%s/apps/%s/users/%s/sessions/%s" % (
            self.base_url, self.app_name, s.user_id, s.session_id)
        resp = requests.post(url, json={}, headers=self.headers,
                             timeout=self.timeout, verify=self.verify_tls)
        # 200 created; 400 "already exists" is fine for our purposes.
        if resp.status_code >= 400 and "already exists" not in resp.text.lower():
            raise _http.HTTPError(
                "ADK session create %s -> HTTP %d: %s" % (url, resp.status_code, resp.text[:300]))
        s._created = True

    def run_turn(self, s: ADKSession, content: str) -> Response:
        def _call():
            self._ensure_session(s)
            new_message = {"role": "user", "parts": [{"text": content}]}
            body = {
                # Send both casings for cross-version compatibility.
                "app_name": self.app_name, "appName": self.app_name,
                "user_id": s.user_id, "userId": s.user_id,
                "session_id": s.session_id, "sessionId": s.session_id,
                "new_message": new_message, "newMessage": new_message,
            }
            data = _http.post_json(self.base_url + "/run", body, self.headers,
                                   self.timeout, self.verify_tls)
            events = data if isinstance(data, list) else data.get("events", data)
            text, tool_calls = _extract(events)
            return text, data, tool_calls

        return self._timed(_call)

    def generate(self, messages: List[Turn]) -> Response:
        # Stateless path: replay the whole conversation in a throwaway session.
        s = self.new_session()
        resp = Response(text="", error="no user turns")
        for t in messages:
            if t.role == "user":
                resp = self.run_turn(s, t.content)
        return resp
