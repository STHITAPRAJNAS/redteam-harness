"""Shared HTTP helpers for remote target adapters."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import requests


class HTTPError(RuntimeError):
    pass


def resolve_secret(value: Optional[str], env: Optional[str]) -> Optional[str]:
    """Prefer an explicit value, else read from an environment variable."""
    if value:
        return value
    if env:
        return os.environ.get(env)
    return None


def json_get(obj: Any, path: str, default: Any = None) -> Any:
    """Fetch a nested value by dotted path. Supports integer list indices.

    ``json_get(resp, "choices.0.message.content")`` ->
    ``resp["choices"][0]["message"]["content"]``. Returns ``default`` if any
    step is missing.
    """
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


def post_json(
    url: str,
    body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
    verify: bool = True,
) -> Dict[str, Any]:
    resp = requests.post(url, json=body, headers=headers or {}, timeout=timeout, verify=verify)
    if resp.status_code >= 400:
        raise HTTPError("POST %s -> HTTP %d: %s" % (url, resp.status_code, resp.text[:500]))
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
    timeout: float = 30.0,
    verify: bool = True,
) -> Dict[str, Any]:
    resp = requests.get(url, headers=headers or {}, timeout=timeout, verify=verify)
    if resp.status_code >= 400:
        raise HTTPError("GET %s -> HTTP %d: %s" % (url, resp.status_code, resp.text[:500]))
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
