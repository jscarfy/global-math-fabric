import os, json, urllib.request

LEAN_WORKER_URL = os.environ.get("GMF_LEAN_WORKER_URL", "http://lean_worker:8090")

def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def build_lean_source(payload: dict, proof_script: str) -> str:
    """
    payload:
      {
        "imports": ["Mathlib", "Mathlib.Data.Nat.Basic", ...]  (or [])
        "theorem_name": "t1",
        "statement": "2 + 2 = 4"
      }
    output proof_script:
      "by simp" / "by decide" / "by omega" / ...
    """
    imports = payload.get("imports") or []
    if not isinstance(imports, list):
        imports = []
    theorem_name = str(payload.get("theorem_name") or "anon")
    statement = str(payload.get("statement") or "")

    lines = []
    for imp in imports:
        imp = str(imp).strip()
        if imp:
            # allow both "Mathlib" and "Mathlib.Data.Nat.Basic"
            if imp.startswith("import "):
                lines.append(imp)
            else:
                lines.append(f"import {imp}")
    lines.append("")
    lines.append(f"theorem {theorem_name} : {statement} := {proof_script.strip()}")
    lines.append("")
    return "\n".join(lines)

def validate(payload: dict, output: dict) -> tuple[bool, str]:
    proof = str(output.get("proof_script") or "").strip()
    if not proof:
        return (False, "missing_proof_script")
    # very small guardrail: require it starts with "by" (Lean tactic/term)
    if not proof.startswith("by"):
        return (False, "proof_script_must_start_with_by")

    src = build_lean_source(payload, proof)

    req_body = _canon({"lean_source": src}).encode("utf-8")
    try:
        req = urllib.request.Request(
            LEAN_WORKER_URL + "/verify",
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        ok = bool(data.get("ok"))
        if ok:
            return (True, "ok")
        # keep reason short (avoid megabytes)
        err = str(data.get("stderr") or "")[:800]
        return (False, "lean_failed:" + err.replace("\n", " "))
    except Exception as e:
        return (False, f"lean_worker_error:{e}")
