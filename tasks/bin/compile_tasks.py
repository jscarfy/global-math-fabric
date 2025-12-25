#!/usr/bin/env python3
import json, itertools, re, hashlib
from pathlib import Path

TEMPLATE = Path("tasks/templates/tasks_template.json")
OUT = Path("tasks/pool/tasks.jsonl")

VAR_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")

def stable_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",",":"))

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def sanitize_task_id(s: str) -> str:
    s = s.replace(" ", "_")
    s = s.replace("/", "_").replace("\\", "_").replace(".", "_").replace(":", "_")
    s = re.sub(r"[^A-Za-z0-9_\-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s[:180] if len(s) > 180 else s

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

def compute_work_unit_id(kind: str, params: dict) -> str:
    unit = {
        "kind": kind,
        "git_url": params.get("git_url",""),
        "rev": params.get("rev",""),
        "subdir": params.get("subdir",""),
        "cmd": params.get("cmd",[]),
        "docker_image": params.get("docker_image",""),
        "artifacts_root": params.get("artifacts_root","")
    }
    return sha256_hex(stable_json(unit).encode("utf-8"))

def load_matrix_envs(data: dict):
    version = int(data.get("version", 1))
    if version < 3:
        # v1/v2: only cartesian matrix or empty env
        matrix = data.get("matrix", {}) or {}
        if not matrix:
            return [dict()]
        keys = list(matrix.keys())
        vals = []
        for k in keys:
            v = matrix[k]
            if not isinstance(v, list) or not v:
                raise SystemExit(f"matrix.{k} must be non-empty list")
            vals.append(v)
        return [dict(zip(keys, prod)) for prod in itertools.product(*vals)]

    # v3: prefer matrix_rows_file
    mrf = data.get("matrix_rows_file")
    if mrf:
        p = Path(mrf)
        if p.exists():
            rows = json.loads(p.read_text())
            if not isinstance(rows, list) or not rows:
                raise SystemExit("matrix_rows_file must contain a non-empty JSON list")
            # normalize: ensure shard_id exists
            envs = []
            for i, r in enumerate(rows):
                if not isinstance(r, dict):
                    raise SystemExit("matrix_rows_file rows must be objects")
                rr = dict(r)
                rr.setdefault("shard_id", f"{i:06d}")
                rr.setdefault("name", "auto")
                envs.append(rr)
            return envs

    # fallback cartesian
    matrix = data.get("matrix", {}) or {}
    if not matrix:
        return [dict()]
    keys = list(matrix.keys())
    vals = []
    for k in keys:
        v = matrix[k]
        if not isinstance(v, list) or not v:
            raise SystemExit(f"matrix.{k} must be non-empty list")
        vals.append(v)
    return [dict(zip(keys, prod)) for prod in itertools.product(*vals)]

def main():
    data = json.loads(TEMPLATE.read_text())
    defaults = data.get("defaults", {})
    tasks_tpl = data.get("tasks", [])
    if not isinstance(tasks_tpl, list) or not tasks_tpl:
        raise SystemExit("template.tasks must be a non-empty list")

    envs = load_matrix_envs(data)

    lines = []
    seen_task_id = set()
    seen_unit = set()

    for env in envs:
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
            if kind in ("lean_check","receipt_verify","ledger_audit","final_verify","audit_final_verify"):
                # compute work_unit_id for anti-dup scheduler
                unit_id = compute_work_unit_id(kind, params)
                params["work_unit_id"] = unit_id
                obj["params"] = params

                # pricing: only auto-calc for lean_check (others keep declared credit_micro_total)
                if kind == "lean_check":
                    try:
                        fc = int(env.get("file_count", params.get("file_count", 0)) or 0)
                    except Exception:
                        fc = 0
                    def _to_int(x, default=0):
                        try: return int(x)
                        except Exception: return default
                    if fc > 0:
                        base = _to_int(params.get("credit_base_micro", 500000), 500000)
                        per  = _to_int(params.get("credit_per_file_micro", 150000), 150000)
                        obj["credit_micro_total"] = base + per * fc
                        params["file_count"] = fc

                allow_dup = bool(params.get("allow_duplicate_work_unit", False))
                if not allow_dup and unit_id in seen_unit:
                    raise SystemExit(f"duplicate work_unit_id detected (anti-dup): {unit_id} (task_id={tid})")
                seen_unit.add(unit_id)

            
                for k in ["git_url","rev","cmd","docker_image"]:
                    if k not in params:
                        raise SystemExit(f"lean_check {tid} missing params.{k}")
                if "@sha256:" not in params["docker_image"]:
                    raise SystemExit(f"lean_check {tid} docker_image must be digest pinned (@sha256:...)")

                
                # pricing (credits policy v2): if file_count present, compute credit_micro_total
                try:
                    fc = int(env.get("file_count", params.get("file_count", 0)) or 0)
                except Exception:
                    fc = 0
                def _to_int(x, default=0):
                    try:
                        return int(x)
                    except Exception:
                        return default
                if fc > 0:
                    base = _to_int(params.get("credit_base_micro", 500000), 500000)
                    per  = _to_int(params.get("credit_per_file_micro", 150000), 150000)
                    obj["credit_micro_total"] = base + per * fc
                    params["file_count"] = fc
unit_id = compute_work_unit_id(kind, params)
                params["work_unit_id"] = unit_id
                obj["params"] = params

                allow_dup = bool(params.get("allow_duplicate_work_unit", False))
                if not allow_dup and unit_id in seen_unit:
                    raise SystemExit(f"duplicate work_unit_id detected (anti-dup): {unit_id} (task_id={tid})")
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
