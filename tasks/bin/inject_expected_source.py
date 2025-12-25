#!/usr/bin/env python3
import json, subprocess, tempfile, shutil
from pathlib import Path

TASKS = Path("tasks/pool/tasks.jsonl")

def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\n{r.stdout}")
    return r.stdout.strip()

def sha256_file(p: Path) -> str:
    if not p.exists(): return ""
    return run(["python3","-c","import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())", str(p)])

def main():
    lines=[ln for ln in TASKS.read_text().splitlines() if ln.strip()]
    arr=[json.loads(ln) for ln in lines]
    out=[]
    for obj in arr:
        if obj.get("kind")!="lean_check":
            out.append(obj); continue
        p=obj.setdefault("params",{})
        git_url=p.get("git_url"); rev=p.get("rev"); subdir=p.get("subdir","")
        if not git_url or not rev:
            raise SystemExit("lean_check missing git_url or rev")

        td=Path(tempfile.mkdtemp(prefix="gmf_expected_"))
        repo=td/"repo"; repo.mkdir(parents=True, exist_ok=True)
        try:
            run(["git","init"], cwd=repo)
            run(["git","remote","add","origin", git_url], cwd=repo)
            run(["git","fetch","--depth","1","origin", rev], cwd=repo)
            run(["git","checkout","FETCH_HEAD"], cwd=repo)

            head = run(["git","rev-parse","HEAD"], cwd=repo)
            tree = run(["git","rev-parse","HEAD^{tree}"], cwd=repo)

            p["expected_git_rev"]=head
            p["expected_git_tree"]=tree

            workdir = repo if not subdir else (repo/subdir)
            if not workdir.exists():
                raise RuntimeError(f"subdir does not exist: {subdir}")

            p["expected_lean_toolchain_sha256"]=sha256_file(workdir/"lean-toolchain")
            lf = workdir/"Lakefile.lean"
            if not lf.exists(): lf = workdir/"lakefile.lean"
            p["expected_lakefile_sha256"]=sha256_file(lf)
            p["expected_lake_manifest_sha256"]=sha256_file(workdir/"lake-manifest.json")

            p.setdefault("require_source_hash", True)
        finally:
            shutil.rmtree(td, ignore_errors=True)

        out.append(obj)

    TASKS.write_text("\n".join(json.dumps(o, separators=(",",":")) for o in out) + "\n")
    print("Injected expected_git_rev/tree (+ key file hashes) into lean_check tasks.")
if __name__=="__main__":
    main()
