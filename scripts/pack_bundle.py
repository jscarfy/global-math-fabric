#!/usr/bin/env python3
import argparse, json, zipfile, os
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--wasm", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    manifest = Path(args.manifest)
    wasm = Path(args.wasm)
    out = Path(args.out)

    m = json.loads(manifest.read_text())
    if "abi" not in m:
        raise SystemExit("manifest missing abi")
    if m.get("abi") == "gmf-abi-1" and not m.get("mobile_ok", False):
        raise SystemExit("gmf-abi-1 requires mobile_ok=true (policy)")

    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(manifest, arcname="manifest.json")
        z.write(wasm, arcname="module.wasm")
    print(str(out))

if __name__ == "__main__":
    main()
