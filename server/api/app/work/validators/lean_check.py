import os, json, urllib.request

DEFAULT_WORKERS = ["http://lean_worker:8090"]
WORKERS = os.environ.get("GMF_LEAN_WORKERS_URLS", ",".join(DEFAULT_WORKERS)).split(",")

def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def build_lean_source(payload: dict, proof_script: str) -> str:
    imports = payload.get("imports") or []
    if not isinstance(imports, list):
        imports = []
    theorem_name = str(payload.get("theorem_name") or "anon")
    statement = str(payload.get("statement") or "")

    lines = []
    for imp in imports:
        imp = str(imp).strip()
        if not imp:
            continue
        if imp.startswith("import "):
            lines.append(imp)
        else:
            lines.append(f"import {imp}")
    lines.append("")
    lines.append(f"theorem {theorem_name} : {statement} := {proof_script.strip()}")
    lines.append("")
    return "\n".join(lines)

def _call_worker(url: str, src: str) -> dict:
    body = _canon({"lean_source": src}).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/verify",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=40) as resp:
        return json.loads(resp.read().decode("utf-8"))

def validate(payload: dict, output: dict) -> tuple[bool, str, dict]:
    """
    Returns (ok, reason, meta)
    meta: {workers:[{url,ok,stderr_prefix}], quorum:"all"} etc.
    """
    proof = str(output.get("proof_script") or "").strip()
    if not proof:
        return (False, "missing_proof_script", {})
    if not proof.startswith("by"):
        return (False, "proof_script_must_start_with_by", {})

    src = build_lean_source(payload, proof)
    results = []
    oks = 0
    for url in WORKERS:
        url = url.strip()
        if not url:
            continue
        try:
            data = _call_worker(url, src)
            ok = bool(data.get("ok"))
            oks += 1 if ok else 0
            err = (str(data.get("stderr") or "")[:400]).replace("\n", " ")
            results.append({"url": url, "ok": ok, "stderr_prefix": err})
        except Exception as e:
            results.append({"url": url, "ok": False, "stderr_prefix": f"worker_error:{e}"})

    # quorum: ALL workers must accept (2-of-2) for now
    if results and oks == len(results):
        return (True, "ok", {"quorum": "all", "workers": results})
    return (False, "lean_failed_quorum", {"quorum": "all", "workers": results})
