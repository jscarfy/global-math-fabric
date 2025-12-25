#!/usr/bin/env python3
import json, subprocess, tempfile, shutil
from pathlib import Path

TASKS = Path("tasks/pool/tasks.jsonl")

def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\n{r.stdout}")
    return r.stdout

def pick_task(task_id):
    lines=[ln for ln in TASKS.read_text().splitlines() if ln.strip()]
    arr=[json.loads(ln) for ln in lines]
    for i,o in enumerate(arr):
        if o.get("task_id")==task_id:
            return arr,i
    raise SystemExit(f"task_id not found: {task_id}")

def main():
    import sys
    if len(sys.argv)!=2:
        raise SystemExit("usage: tasks/bin/pin_expected_artifacts.py <task_id>")
    task_id=sys.argv[1]

    arr,idx = pick_task(task_id)
    t=arr[idx]
    if t.get("kind")!="lean_check":
        raise SystemExit("only supports kind=lean_check")

    p=t.get("params") or {}
    git_url=p["git_url"]
    rev=p["rev"]
    subdir=p.get("subdir","")
    use_cache=bool(p.get("use_mathlib_cache", True))
    artifacts_root=p.get("artifacts_root",".lake/build/lib")
    require_artifact_hash=bool(p.get("require_artifact_hash", True))
    docker_image=p["docker_image"]

    if "@sha256:" not in docker_image:
        raise SystemExit("docker_image must be digest pinned")

    cmd_list=p.get("cmd",["lake","build"])
    if not isinstance(cmd_list,list) or not cmd_list:
        raise SystemExit("params.cmd must be non-empty list")

    td=Path(tempfile.mkdtemp(prefix="gmf_pin_"))
    repo=td/"repo"
    repo.mkdir(parents=True, exist_ok=True)

    try:
        run(["git","init"], cwd=repo)
        run(["git","remote","add","origin", git_url], cwd=repo)
        run(["git","fetch","--depth","1","origin", rev], cwd=repo)
        run(["git","checkout","FETCH_HEAD"], cwd=repo)

        bash=f"""
set +e
cd /workspace/{subdir}
LOG="/workspace/.gmf_build.log"
RES="/workspace/.gmf_result_core.json"
ARTROOT="/workspace/{subdir}/{artifacts_root}"

( {"lake exe cache get &&" if use_cache else ""} {" ".join(cmd_list)} ) >"$LOG" 2>&1
RC=$?

BLH=$(sha256sum "$LOG" | awk '{{print $1}}')

OK=false
if [ "$RC" -eq 0 ]; then OK=true; fi

ART_COUNT=0
ART_MANIFEST_SHA=""
if {"true" if require_artifact_hash else "false"}; then
  if [ -d "$ARTROOT" ]; then
    MAN="/workspace/.gmf_artifacts.manifest"
    (cd "$ARTROOT" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$MAN"
    ART_COUNT=$(wc -l < "$MAN" | tr -d ' ')
    ART_MANIFEST_SHA=$(sha256sum "$MAN" | awk '{{print $1}}')
  else
    OK=false
    RC=2
    ART_COUNT=0
    ART_MANIFEST_SHA=""
  fi
fi

cat > "$RES" <<EOF
{{"ok":$OK,"exit_code":$RC,"build_log_sha256":"$BLH","artifacts_root":"{artifacts_root}","artifacts_count":$ART_COUNT,"artifacts_manifest_sha256":"$ART_MANIFEST_SHA","docker_image":"{docker_image}"}}
EOF

exit 0
"""
        run(["docker","run","--rm",
             "-v", f"{repo}:/workspace",
             "-w", "/workspace",
             docker_image,
             "bash","-lc", bash])

        res=json.loads((repo/".gmf_result_core.json").read_text())
        am=res.get("artifacts_manifest_sha256","")
        if not am:
            raise SystemExit("artifacts_manifest_sha256 empty; build may have failed or artifacts_root missing")

        p["expected_artifacts_manifest_sha256"]=am
        # ensure hard-gate prerequisites
        p.setdefault("require_artifact_hash", True)

        # write back tasks.jsonl
        lines=[json.dumps(o, separators=(",",":")) for o in arr]
        TASKS.write_text("\n".join(lines)+"\n")
        print("Pinned expected_artifacts_manifest_sha256 for", task_id, "=", am)

    finally:
        shutil.rmtree(td, ignore_errors=True)

if __name__=="__main__":
    main()
