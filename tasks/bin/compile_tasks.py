#!/usr/bin/env python3
import json, itertools, re, hashlib
from pathlib import Path

TEMPLATE = Path("tasks/templates/tasks_template.json")
OUT = Path("tasks/pool/tasks.jsonl")

VAR_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")

def jcs_like(obj):
    # simple stable JSON for hashing (close enough for work_unit_id)
    return json.dumps(obj, sort_keys=True, separators=(",",":"))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sanitize_task_id(s: str) -> str:
    # make it filesystem + git-friendly
    s = s.replace(" ", "_")
    s = s.replace("/", "_").replace("\\", "_").replace(".", "_").replace(":", "_")
    s = re.sub(r"[^A-Za-z0-9_\-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:160] if len(s) > 160 else s

def subst_str(s: str, env: dict) -> str:
    def rep(m):
        k = m.group(1)
        if k not in env:
            raise SystemExit(f"missing matrix var: {k}")
        return str(env[k])
    return VAR_RE.sub(rep, s)

def subst_any(x, env: dict):
    if isinstance(x, str):
        return subst_str(x, env)
    if isinstance(x, list):
        return [subst_any(i, env) for i in x]
    if isinstance(x, dict):
        return {k: subst_any(v, env) for k, v in x.items()}
    return x

def compute_work_unit_id(task: dict) -> str:
    # anti-dup key: kind + essential params that define the work
    kind = task.get("kind","")
    params = task.get("params") or {}
    unit = {
        "kind": kind,
        "git_url": params.get("git_url",""),
        "rev": params.get("rev",""),
        "subdir": params.get("subdir",""),
        "cmd": params.get("cmd",[]),
        "target_file": params.get("target_file",""),
        "docker_image": params.get("docker_image",""),
        "artifacts_root": params.get("artifacts_root","")
    }
    return sha256_hex(jcs_like(unit).encode("utf-8"))

def main():
    data = json.loads(TEMPLATE.read_text())
    version = data.get("version", 1)
    defaults = data.get("defaults", {})
    tasks_tpl = data.get("tasks", [])
    matrix = data.get("matrix", {}) if version >= 2 else {}

    if not isinstance(tasks_tpl, list) or not tasks_tpl:
        raise SystemExit("template.tasks must be a non-empty list")

    # Build env combinations
    if version >= 2 and matrix:
        keys = list(matrix.keys())
        vals = []
        for k in keys:
            v = matrix[k]
            if not isinstance(v, list) or not v:
                raise SystemExit(f"matrix.{k} must be non-empty list")
            vals.append(v)
        combos = [dict(zip(keys, prod)) for prod in itertools.product(*vals)]
    else:
        combos = [dict()]

    lines = []
    seen_task_id = set()
    seen_unit = set()

    for env in combos:
        for t in tasks_tpl:
            task = subst_any(t, env)

            obj = dict(defaults)
            obj.update(task)

            if obj.get("protocol") != "gmf/task/v1":
                raise SystemExit(f"bad protocol in task: {obj.get('task_id')}")

            tid_raw = obj.get("task_id","")
            if not tid_raw:
                raise SystemExit("missing task_id")
            tid = sanitize_task_id(tid_raw)
            obj["task_id"] = tid

            kind = obj.get("kind","")
            if not kind:
                raise SystemExit(f"missing kind for task_id={tid}")

            params = obj.get("params") or {}
            if kind == "lean_check":
                for k in ["git_url","rev","cmd","docker_image"]:
                    if k not in params:
                        raise SystemExit(f"lean_check {tid} missing params.{k}")
                if "@sha256:" not in params["docker_image"]:
                    raise SystemExit(f"lean_check {tid} docker_image must be digest pinned (@sha256:...)")

                # compute work_unit_id
                unit_id = compute_work_unit_id({"kind": kind, "params": params})
                params["work_unit_id"] = unit_id
                obj["params"] = params

                allow_dup = bool(params.get("allow_duplicate_work_unit", False))
                if not allow_dup and unit_id in seen_unit:
                    raise SystemExit(f"duplicate work_unit_id detected (anti-dup): {unit_id}  (task_id={tid})")
                seen_unit.add(unit_id)

            if tid in seen_task_id:
                raise SystemExit(f"duplicate task_id after sanitize: {tid}")
            seen_task_id.add(tid)

            lines.append(json.dumps(obj, separators=(",",":")))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} tasks to {OUT}")

if __name__ == "__main__":
    main()
