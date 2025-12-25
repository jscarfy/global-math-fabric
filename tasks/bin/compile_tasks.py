#!/usr/bin/env python3
import json
from pathlib import Path

TEMPLATE = Path("tasks/templates/tasks_template.json")
OUT = Path("tasks/pool/tasks.jsonl")

def main():
    data = json.loads(TEMPLATE.read_text())
    defaults = data.get("defaults", {})
    tasks = data.get("tasks", [])
    if not isinstance(tasks, list) or not tasks:
        raise SystemExit("template.tasks must be a non-empty list")

    lines = []
    seen = set()
    for t in tasks:
        obj = dict(defaults)
        obj.update(t)

        if obj.get("protocol") != "gmf/task/v1":
            raise SystemExit(f"bad protocol in task: {obj.get('task_id')}")
        tid = obj.get("task_id")
        if not tid or tid in seen:
            raise SystemExit(f"missing/duplicate task_id: {tid}")
        seen.add(tid)

        if "kind" not in obj:
            raise SystemExit(f"missing kind for task_id={tid}")

        # minimal validation for lean_check
        if obj["kind"] == "lean_check":
            params = obj.get("params") or {}
            for k in ["git_url","rev","cmd","docker_image"]:
                if k not in params:
                    raise SystemExit(f"lean_check {tid} missing params.{k}")
            if "@sha256:" not in params["docker_image"]:
                raise SystemExit(f"lean_check {tid} docker_image must be digest pinned (@sha256:...)")

        lines.append(json.dumps(obj, separators=(",",":")))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} tasks to {OUT}")

if __name__ == "__main__":
    main()
