FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY verifier.py /app/verifier.py
CMD ["python", "-u", "/app/verifier.py"]
