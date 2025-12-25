#!/usr/bin/env bash
set -euo pipefail

# 可用環境變數控制 discover：
#   GMF_DISCOVER=1
#   GMF_DISCOVER_GIT_URL=...
#   GMF_DISCOVER_REV=...
#   GMF_DISCOVER_SUBDIR=...
#   GMF_DISCOVER_NAME=...
#   GMF_DISCOVER_INCLUDE_PREFIX=...
#   GMF_DISCOVER_EXCLUDE_CONTAINS=...
#   GMF_DISCOVER_SHARD_SIZE=20
#   GMF_DISCOVER_MAX_FILES=0
#   GMF_DISCOVER_SHUFFLE=0
#   GMF_DISCOVER_SEED=0

if [[ "${GMF_DISCOVER:-0}" == "1" ]]; then
  : "${GMF_DISCOVER_GIT_URL:?set GMF_DISCOVER_GIT_URL}"
  : "${GMF_DISCOVER_REV:?set GMF_DISCOVER_REV}"
  python3 ./tasks/bin/discover_lean_files.py \
    --git-url "${GMF_DISCOVER_GIT_URL}" \
    --rev "${GMF_DISCOVER_REV}" \
    --subdir "${GMF_DISCOVER_SUBDIR:-}" \
    --name "${GMF_DISCOVER_NAME:-auto}" \
    --include-prefix "${GMF_DISCOVER_INCLUDE_PREFIX:-}" \
    --exclude-contains "${GMF_DISCOVER_EXCLUDE_CONTAINS:-}" \
    --shard-size "${GMF_DISCOVER_SHARD_SIZE:-20}" \
    --max-files "${GMF_DISCOVER_MAX_FILES:-0}" \
    $( [[ "${GMF_DISCOVER_SHUFFLE:-0}" == "1" ]] && echo "--shuffle" ) \
    $( [[ -n "${GMF_DISCOVER_SEED:-}" && "${GMF_DISCOVER_SEED:-0}" != "0" ]] && echo "--seed ${GMF_DISCOVER_SEED}" ) \
    --out "tasks/templates/matrix_rows.json"
fi

./tasks/bin/compile_tasks.py
./tasks/bin/inject_expected_source.py
echo "OK: tasks/pool/tasks.jsonl rebuilt (discover=${GMF_DISCOVER:-0})"
