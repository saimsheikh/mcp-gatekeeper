# Node is needed because the demo upstream is the official filesystem server,
# which is launched with npx.
FROM node:22-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first, so source edits do not invalidate the install.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/
RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:$PATH"

EXPOSE 8000 8765

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python3 -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/healthz')"

CMD ["mcp-gatekeeper", "run", \
     "--config", "/app/config/gatekeeper.yaml", \
     "--transport", "http", "--host", "0.0.0.0", "--port", "8000"]
