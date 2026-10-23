# Distribution & deployment

rtharness ships in the ways teams actually consume a security tool. Core has a
single dependency (`requests`); the web service adds FastAPI/uvicorn via an
extra.

## Install

```bash
pip install rtharness                 # core: CLI + library (requests only)
pipx install 'rtharness[server]'      # isolated CLI + web service (recommended)
pip install 'rtharness[server,yaml]'  # service + YAML configs
```

`pipx` gives the CLI its own venv — no conflicts with anything else on the host.

## Docker

```bash
docker build -t rtharness .
# web service (REST + /mcp + dashboard), unauthenticated — keep on a trusted net
docker run --rm -p 8900:8900 rtharness
# one-off scan, mounting a config and collecting reports
docker run --rm -v "$PWD/my.yaml:/cfg.yaml" -v "$PWD/reports:/app/reports" \
  rtharness run --config /cfg.yaml
# with optional attacker/judge models (keys via env, never in the image)
docker run --rm -p 8900:8900 --env-file .env rtharness
```

## Secrets & network

- The harness needs **no key to run**. Optional attacker/judge model keys are
  read from env at runtime (referenced by `api_key_env` in config) and sent only
  to that model's API. The target's own credential is likewise env-supplied and
  forwarded only to the target.
- Never bake keys into the image or config; use `--env-file` / your secret store.
- Egress required: the **target endpoint**, and (if used) the **LLM API host**.
- The web service is **unauthenticated by design** (local operator tool). Bind
  to `127.0.0.1`, or put it behind your own auth/proxy if remote.
- Report files can contain secrets *leaked by the target* (that's a finding) —
  treat them as sensitive.

## CI integration

- `rtharness selftest` — health gate (exits non-zero on failure).
- `rtharness run --preset owasp-llm --format sarif --fail-on high` — scan +
  upload the SARIF to GitHub code scanning; fail the build on High+.
- `rtharness diff baseline.report.json current.report.json` — fail on newly
  introduced (regressed) findings.

A ready-made workflow is in `.github/workflows/ci.yml` (selftest matrix +
service/MCP smoke + Docker build).

## Versioning

`rtharness --version` / `GET /health` report the package version
(`rtharness/version.py`, mirrored in `pyproject.toml`).
