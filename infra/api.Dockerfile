FROM python:3.12-slim
WORKDIR /app

RUN pip install --no-cache-dir uv

COPY server/api/pyproject.toml server/api/uv.lock* /app/server/api/
RUN cd /app/server/api && uv sync --frozen || (uv sync)

COPY server /app/server
EXPOSE 8000
CMD ["bash","-lc","cd /app/server/api && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000"]
