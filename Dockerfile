# rtharness — slim, non-root image that serves the web API (REST + /mcp + dashboard).
FROM python:3.12-slim

# No build toolchain needed (pure-Python deps). Keep the image small.
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY rtharness ./rtharness
COPY examples ./examples

# Install with the server extra (FastAPI + uvicorn) so `serve` runs on FastAPI.
RUN pip install ".[server,yaml]"

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 rt && chown -R rt:rt /app
USER rt

EXPOSE 8900

# Bind to 0.0.0.0 inside the container; publish with `-p` and keep it on a
# trusted network — the service is unauthenticated by design.
ENTRYPOINT ["rtharness"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8900"]
