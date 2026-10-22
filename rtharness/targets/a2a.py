"""Agent-to-Agent (A2A) protocol target.

Speaks JSON-RPC 2.0 ``message/send`` to an A2A server and extracts the reply
text from the returned Message/Task. Handles version drift:

- Agent card is fetched from ``/.well-known/agent-card.json`` (A2A v1.0) with a
  fallback to ``/.well-known/agent.json`` (pre-1.0). The card is cached and
  exposed via :attr:`agent_card` so the A2A-specific probes can inspect it
  (unsigned cards, injection in description/skills, declared security schemes).
- The JSON-RPC endpoint is taken from the card (``url`` / first interface URL)
  when present, else the base URL.
- Method name defaults to ``message/send`` but a PascalCase ``SendMessage``
  alias can be selected for v1.0 SDK servers.

Multi-turn: A2A groups turns by ``contextId``. We keep the contextId returned
by the first reply and attach it to subsequent sends so the server threads the
conversation.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from ..core.target import Response, Session, Target, Turn
from . import _http


def _extract_text(result: Any) -> str:
    """Pull human-readable text out of an A2A Message or Task result."""
    if result is None:
        return ""
    if isinstance(result, str):
        return result
    texts: List[str] = []

    def _parts(parts):
        for p in parts or []:
            if not isinstance(p, dict):
                continue
            # v1.0: {"kind": "text", "text": "..."}; older: {"type":"text",...}
            if "text" in p and isinstance(p["text"], str):
                texts.append(p["text"])
            elif isinstance(p.get("root"), dict) and "text" in p["root"]:
                texts.append(p["root"]["text"])

    if isinstance(result, dict):
        # Direct message result.
        _parts(result.get("parts"))
        # Task result: status.message.parts + artifacts[].parts
        status = result.get("status") or {}
        if isinstance(status, dict):
            msg = status.get("message") or {}
            _parts(msg.get("parts"))
        for art in result.get("artifacts") or []:
            if isinstance(art, dict):
                _parts(art.get("parts"))
        # History (some servers return the full message list).
        for m in result.get("history") or []:
            if isinstance(m, dict) and m.get("role") in ("agent", "assistant"):
                _parts(m.get("parts"))
    return "\n".join(t for t in texts if t).strip()


class A2ASession(Session):
    """A2A session that threads turns via contextId."""

    def __init__(self, target: "A2ATarget"):
        super().__init__(target)
        self.context_id: Optional[str] = None

    def send(self, content: str, role: str = "user") -> Response:
        self.turns.append(Turn(role, content))
        resp = self.target.generate_in_session(self, content)
        self.turns.append(Turn("assistant", resp.text))
        self.responses.append(resp)
        return resp


class A2ATarget(Target):
    WELL_KNOWN = ["/.well-known/agent-card.json", "/.well-known/agent.json"]

    def __init__(
        self,
        base_url: str,
        name: Optional[str] = None,
        rpc_url: Optional[str] = None,
        method: str = "message/send",
        api_key: Optional[str] = None,
        api_key_env: Optional[str] = None,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer ",
        headers: Optional[Dict[str, str]] = None,
        fetch_card: bool = True,
        timeout: float = 60.0,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.method = method
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.headers = {"Content-Type": "application/json"}
        self.headers.update(headers or {})
        key = _http.resolve_secret(api_key, api_key_env)
        if key:
            self.headers[auth_header] = auth_prefix + key

        self.agent_card: Optional[Dict[str, Any]] = None
        self.card_url: Optional[str] = None
        if fetch_card:
            self._load_card()

        self.rpc_url = rpc_url or self._rpc_from_card() or self.base_url
        self.name = name or (self._card_name() or ("a2a:" + self.base_url))

    # --- card handling -----------------------------------------------------
    def _load_card(self) -> None:
        for path in self.WELL_KNOWN:
            url = self.base_url + path
            try:
                self.agent_card = _http.get_json(url, self.headers, self.timeout, self.verify_tls)
                self.card_url = url
                return
            except Exception:  # noqa: BLE001 - try next path / give up
                continue

    def _rpc_from_card(self) -> Optional[str]:
        card = self.agent_card or {}
        if isinstance(card.get("url"), str):
            return card["url"]
        for iface in card.get("supportedInterfaces") or card.get("interfaces") or []:
            if isinstance(iface, dict) and isinstance(iface.get("url"), str):
                return iface["url"]
        return None

    def _card_name(self) -> Optional[str]:
        card = self.agent_card or {}
        n = card.get("name")
        return ("a2a:" + n) if isinstance(n, str) else None

    # --- conversation ------------------------------------------------------
    def new_session(self) -> A2ASession:
        return A2ASession(self)

    def _build_message(self, text: str, context_id: Optional[str]) -> Dict[str, Any]:
        msg: Dict[str, Any] = {
            "kind": "message",
            "role": "user",
            "messageId": uuid.uuid4().hex,
            "parts": [{"kind": "text", "text": text}],
        }
        if context_id:
            msg["contextId"] = context_id
        return msg

    def _rpc(self, message: Dict[str, Any]) -> Dict[str, Any]:
        return self.raw_rpc(self.method, {"message": message})

    def raw_rpc(self, method: str, params: Dict[str, Any],
                headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Send an arbitrary JSON-RPC call. Used by A2A-specific probes to test
        method-level access control (e.g. ``tasks/get`` on a guessed id)."""
        body = {
            "jsonrpc": "2.0",
            "id": uuid.uuid4().hex,
            "method": method,
            "params": params,
        }
        hdrs = dict(self.headers)
        if headers is not None:
            hdrs = headers  # allow unauthenticated probes to drop the auth header
        return _http.post_json(self.rpc_url, body, hdrs, self.timeout, self.verify_tls)

    def generate(self, messages: List[Turn]) -> Response:
        # Stateless entrypoint: send only the latest user turn (context carried
        # by the session when one is used).
        latest = ""
        for t in reversed(messages):
            if t.role == "user":
                latest = t.content
                break

        def _call():
            data = self._rpc(self._build_message(latest, None))
            result = data.get("result")
            if data.get("error"):
                raise _http.HTTPError("A2A error: %s" % data["error"])
            return _extract_text(result), data, []

        return self._timed(_call)

    def generate_in_session(self, session: A2ASession, text: str) -> Response:
        def _call():
            data = self._rpc(self._build_message(text, session.context_id))
            if data.get("error"):
                raise _http.HTTPError("A2A error: %s" % data["error"])
            result = data.get("result") or {}
            ctx = None
            if isinstance(result, dict):
                ctx = result.get("contextId") or (result.get("status") or {}).get("contextId")
            if ctx:
                session.context_id = ctx
            return _extract_text(result), data, []

        return self._timed(_call)
