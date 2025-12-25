#!/usr/bin/env bash
set -euo pipefail

# 每天 UTC 00:10 跑前一天结算
RUN_HOUR="${RUN_HOUR:-0}"
RUN_MIN="${RUN_MIN:-10}"

cd /repo

while true; do
  now_epoch="$(date -u +%s)"
  today="$(date -u +%F)"

  # next run time: today at RUN_HOUR:RUN_MIN UTC, else tomorrow
  run_today_epoch="$(date -u -d "${today} ${RUN_HOUR}:${RUN_MIN}:00" +%s)"
  if [ "$now_epoch" -ge "$run_today_epoch" ]; then
    next_day="$(date -u -d "${today} +1 day" +%F)"
    next_epoch="$(date -u -d "${next_day} ${RUN_HOUR}:${RUN_MIN}:00" +%s)"
  else
    next_epoch="$run_today_epoch"
  fi

  sleep_sec="$(( next_epoch - now_epoch ))"
  echo "[cron] sleeping ${sleep_sec}s until $(date -u -d "@${next_epoch}" +'%F %T UTC')"
  sleep "$sleep_sec"

  day_to_settle="$(date -u -d "$(date -u +%F) -1 day" +%F)"
  echo "[cron] settling day=${day_to_settle}"

  ./scripts/cron/daily_settle.sh "$day_to_settle" || true

  # 可选：如果提供 GH_TOKEN，就自动 commit+push（HTTPS token）
  if [ -n "${GH_TOKEN:-}" ]; then
    git config user.name "gmf-cron"
    git config user.email "gmf-cron@users.noreply.github.com"

    git add ledger releases || true
    git commit -m "cron: daily settle ${day_to_settle}" || true

    # rewrite origin to token https if needed
    ORIGIN="$(git remote get-url origin)"
    if echo "$ORIGIN" | grep -q '^git@github.com:'; then
      ORIGIN="https://github.com/${ORIGIN#git@github.com:}"
      ORIGIN="${ORIGIN%.git}.git"
    fi
    if echo "$ORIGIN" | grep -q '^https://github.com/'; then
      ORIGIN_AUTH="$(echo "$ORIGIN" | sed "s#^https://#https://x-access-token:${GH_TOKEN}@#")"
      git push "$ORIGIN_AUTH" HEAD:main || true
    else
      git push || true
    fi
  fi
done
