FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates git curl python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /repo
CMD ["bash","server/cron/run_daily_settle_loop.sh"]
