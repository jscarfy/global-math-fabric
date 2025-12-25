FROM python:3.12-slim
WORKDIR /app

RUN pip install --no-cache-dir uv

COPY server/worker/pyproject.toml server/worker/uv.lock* /app/server/worker/
RUN cd /app/server/worker && uv sync --frozen || (uv sync)

COPY server /app/server
CMD ["bash","-lc","cd /app/server/worker && uv run python -m worker.main"]
