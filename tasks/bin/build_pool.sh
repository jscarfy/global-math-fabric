#!/usr/bin/env bash
set -euo pipefail
./tasks/bin/compile_tasks.py
./tasks/bin/inject_expected_source.py
echo "OK: tasks/pool/tasks.jsonl rebuilt (matrix expanded + expected pins injected)"
