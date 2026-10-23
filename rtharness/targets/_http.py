"""Shared HTTP helpers for remote target adapters.

Enterprise-grade client behaviour used by every remote adapter (http/openai/
a2a/adk/mcp/langserve/anthropic):

- a pooled ``requests.Session`` (keep-alive, bounded pool),
- retries with exponential backoff + jitter on transient failures (network
  errors and HTTP 429/500/502/503/504), honouring a ``Retry-After`` header,
- configurable timeout / retry budget (args or env:
  ``RTHARNESS_HTTP_TIMEOUT``, ``RTHARNESS_HTTP_RETRIES``),
- secret redaction on any error text we surface (so keys never leak into
  reports or logs),
- TLS verification on by default; honours ``REQUESTS_CA_BUNDLE`` /
  ``HTTPS_PROXY`` from the environment (enterprise proxies / custom CAs).
"""
from __future__ import annotations

import json
import os
import random
import re
import time
from typing import Any, Dict, List, Optional

import requests

_RETRY_STATUS = {429, 500, 502, 503, 504}
_DEFAULT_TIMEOUT = float(os.environ.get("RTHARNESS_HTTP_TIMEOUT", "60") or 60)
_DEFAULT_RETRIES = int(os.environ.get("RTHARNESS_HTTP_RETRIES", "2") or 2)
_BACKOFF_BASE = 0.5
_BACKOFF_CAP = 20.0

# Pooled session shared across calls (connection reuse).
_SESSION = requests.Session()
_SESSION.mount("https://", requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=32))
_SESSION.mount("http://", requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=32))

# Redact common secret shapes before surfacing any response/error text.
_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_\-]{8,}|xox[baprs]-[A-Za-z0-9\-]{8,}|AIza[0-9A-Za-z\-_]{20,}|"
    r"Bearer\s+[A-Za-z0-9._\-]{8,}|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)")


class HTTPError(RuntimeError):
    pass


class AuthError(HTTPError):
    pass


class RateLimitError(HTTPError):
    pass


def redact(text: str) -> str:
    return _SECRET_RE.sub("<redacted>", text or "")


def resolve_secret(value: Optional[str], env: Optional[str]) -> Optional[str]:
    """Prefer an explicit value, else read from an environment variable."""
    if value:
        return value
    if env:
        return os.environ.get(env)
    return None


def json_get(obj: Any, path: str, default: Any = None) -> Any:
    """Fetch a nested value by dotted path. Supports integer list indices."""
    cur = obj
    for part in path.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return default
        elif isinstance(cur, dict):
            if part not in cur:
                return default
            cur = cur[part]
        else:
            return default
    return cur


def _retry_after(resp: requests.Response) -> Optional[float]:
    val = resp.headers.get("Retry-After")
    if not val:
        return None
    try:
        return max(0.0, float(val))
    except ValueError:
        return None  # http-date form; fall back to backoff


def _sleep_for(attempt: int, resp: Optional[requests.Response]) -> float:
    if resp is not None:
        ra = _retry_after(resp)
        if ra is not None:
            return min(ra, _BACKOFF_CAP)
    return min(_BACKOFF_CAP, _BACKOFF_BASE * (2 ** attempt)) + random.uniform(0, 0.4)


def _request(
    method: str,
    url: str,
    body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    verify: bool = True,
    retries: Optional[int] = None,
) -> requests.Response:
    timeout = _DEFAULT_TIMEOUT if timeout is None else timeout
    retries = _DEFAULT_RETRIES if retries is None else retries
    last_exc: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            resp = _SESSION.request(method, url, json=body, headers=headers or {},
                                    timeout=timeout, verify=verify)
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(_sleep_for(attempt, None))
                continue
            raise HTTPError("%s %s failed after %d attempt(s): %s"
                            % (method, url, attempt + 1, redact(str(exc)))) from exc
        if resp.status_code in _RETRY_STATUS and attempt < retries:
            time.sleep(_sleep_for(attempt, resp))
            continue
        return resp
    # Should not reach here, but satisfy the type checker.
    raise HTTPError("%s %s failed: %s" % (method, url, redact(str(last_exc))))


def _raise_for_status(resp: requests.Response, url: str) -> None:
    if resp.status_code < 400:
        return
    body = redact(resp.text[:500])
    msg = "%s -> HTTP %d: %s" % (url, resp.status_code, body)
    if resp.status_code in (401, 403):
        raise AuthError(msg)
    if resp.status_code == 429:
        raise RateLimitError(msg)
    raise HTTPError(msg)


def post_json(
    url: str,
    body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    verify: bool = True,
    retries: Optional[int] = None,
) -> Dict[str, Any]:
    resp = _request("POST", url, body=body, headers=headers, timeout=timeout,
                    verify=verify, retries=retries)
    _raise_for_status(resp, "POST " + url)
    ctype = resp.headers.get("content-type", "")
    if "application/json" in ctype or resp.text.strip().startswith(("{", "[")):
        try:
            return resp.json()
        except json.JSONDecodeError:
            pass
    return {"_raw_text": resp.text}


def get_json(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: Optional[float] = None,
    verify: bool = True,
    retries: Optional[int] = None,
) -> Dict[str, Any]:
    resp = _request("GET", url, headers=headers, timeout=timeout,
                    verify=verify, retries=retries)
    _raise_for_status(resp, "GET " + url)
    return resp.json()


def render_template(template: Any, variables: Dict[str, str]) -> Any:
    """Recursively substitute ``{{var}}`` placeholders inside a JSON template."""
    if isinstance(template, str):
        out = template
        for key, val in variables.items():
            out = out.replace("{{%s}}" % key, val)
        return out
    if isinstance(template, dict):
        return {k: render_template(v, variables) for k, v in template.items()}
    if isinstance(template, list):
        return [render_template(v, variables) for v in template]
    return template


def messages_to_text(messages: List[Dict[str, str]]) -> str:
    """Flatten a conversation into a single prompt for single-shot endpoints."""
    lines = []
    for m in messages:
        role = m.get("role", "user").upper()
        lines.append("%s: %s" % (role, m.get("content", "")))
    lines.append("ASSISTANT:")
    return "\n".join(lines)
