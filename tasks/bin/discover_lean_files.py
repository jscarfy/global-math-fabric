#!/usr/bin/env python3
import argparse, json, os, random, subprocess, tempfile, shutil
from pathlib import Path

def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\n{r.stdout}")
    return r.stdout.strip()

def shell_quote(s: str) -> str:
    # POSIX single-quote escaping: ' -> '\'' 
    return "'" + s.replace("'", "'\"'\"'") + "'"

def list_lean_files(repo_dir: Path, subdir: str, include_prefix: str, exclude_contains: list[str]) -> list[str]:
    base = repo_dir / subdir if subdir else repo_dir
    if not base.exists():
        raise RuntimeError(f"subdir does not exist: {subdir}")
    files = []
    for p in base.rglob("*.lean"):
        rel = p.relative_to(base).as_posix()
        if include_prefix and not rel.startswith(include_prefix):
            continue
        bad = False
        for ex in exclude_contains:
            if ex and ex in rel:
                bad = True; break
        if bad:
            continue
        files.append(rel)
    files.sort()
    return files

def shard(files: list[str], shard_size: int) -> list[list[str]]:
    return [files[i:i+shard_size] for i in range(0, len(files), shard_size)]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--git-url", required=True)
    ap.add_argument("--rev", required=True)
    ap.add_argument("--subdir", default="")
    ap.add_argument("--name", default="auto")
    ap.add_argument("--include-prefix", default="")   # e.g. "Mathlib/"
    ap.add_argument("--exclude-contains", default="", help="comma-separated substrings to exclude")
    ap.add_argument("--max-files", type=int, default=0)
    ap.add_argument("--shuffle", action="store_true")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--shard-size", type=int, default=20)
    ap.add_argument("--out", default="tasks/templates/matrix_rows.json")
    args = ap.parse_args()

    excl = [x.strip() for x in args.exclude_contains.split(",") if x.strip()]

    td = Path(tempfile.mkdtemp(prefix="gmf_discover_"))
    repo = td / "repo"
    repo.mkdir(parents=True, exist_ok=True)

    try:
        run(["git","init"], cwd=repo)
        run(["git","remote","add","origin", args.git_url], cwd=repo)
        run(["git","fetch","--depth","1","origin", args.rev], cwd=repo)
        run(["git","checkout","FETCH_HEAD"], cwd=repo)

        files = list_lean_files(repo, args.subdir, args.include_prefix, excl)

        if args.shuffle:
            rnd = random.Random(args.seed if args.seed else 12345)
            rnd.shuffle(files)

        if args.max_files and args.max_files > 0:
            files = files[:args.max_files]

        shards = shard(files, args.shard_size)
        rows = []
        for i, chunk in enumerate(shards):
            if not chunk:
                continue
            files_shell = " ".join(shell_quote(f) for f in chunk)
            rows.append({
                "name": args.name,
                "git_url": args.git_url,
                "rev": args.rev,
                "subdir": args.subdir,
                "shard_id": f"{i:06d}",
                "files_list_shell": files_shell,
                "file_count": len(chunk)
            })

        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(rows, indent=2) + "\n")
        print(f"Wrote {len(rows)} matrix rows to {outp} (total files={len(files)} shard_size={args.shard_size})")

    finally:
        shutil.rmtree(td, ignore_errors=True)

if __name__ == "__main__":
    main()
