#!/usr/bin/env python3
import json, hashlib
from pathlib import Path

POL_DIR = Path("ledger/policies")
OUT = POL_DIR / "registry.json"

def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    POL_DIR.mkdir(parents=True, exist_ok=True)
    items = []
    for f in sorted(POL_DIR.glob("*.md")):
        items.append({
            "name": f.name,
            "relpath": str(f),
            "sha256": sha256_file(f),
            "bytes": f.stat().st_size,
        })
    reg = {"kind":"gmf_policy_registry","version":1,"policies":items}
    OUT.write_text(json.dumps(reg, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {OUT} with {len(items)} policies")

if __name__ == "__main__":
    main()
