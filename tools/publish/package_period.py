#!/usr/bin/env python3
import json, hashlib, sys
from pathlib import Path
from datetime import datetime, timezone

def sha256_file(p: Path) -> str:
    h=hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()

def main():
    if len(sys.argv) < 3:
        print("Usage: package_period.py monthly YYYY-MM  |  package_period.py yearly YYYY", file=sys.stderr)
        sys.exit(2)
    kind, pid = sys.argv[1], sys.argv[2]

    if kind == "monthly":
        export_path = Path(f"ledger/reports/monthly/{pid}.monthly_canonical_export.json")
        export_audit_final = Path(f"ledger/export_audit/monthly/{pid}.export_audit_final.json")
        meta_audit_final = Path(f"ledger/meta_audit/{pid}.meta_audit_final.json")
        outdir = Path(f"releases/publish/monthly/{pid}")
        bundle_name = f"{pid}.monthly.bundle.tar.gz"
    elif kind == "yearly":
        export_path = Path(f"ledger/reports/yearly/{pid}.yearly_canonical_export.json")
        export_audit_final = Path(f"ledger/export_audit/yearly/{pid}.export_audit_final.json")
        meta_audit_final = Path(f"ledger/meta_audit/{pid}.meta_audit_final.json")
        outdir = Path(f"releases/publish/yearly/{pid}")
        bundle_name = f"{pid}.yearly.bundle.tar.gz"
    else:
        raise SystemExit("bad kind")

    for p in (export_path, export_audit_final, meta_audit_final):
        if not p.exists():
            raise SystemExit(f"missing: {p}")

    outdir.mkdir(parents=True, exist_ok=True)

    files = [
        {"role":"canonical_export", "path": str(export_path)},
        {"role":"export_audit_final", "path": str(export_audit_final)},
        {"role":"meta_audit_final(period)", "path": str(meta_audit_final)},
    ]
    for f in files:
        f["sha256"] = sha256_file(Path(f["path"]))

    manifest = {
        "version": "publish_manifest_v1",
        "kind": kind,
        "period_id": pid,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "artifacts": files,
        "verification_hints": [
            "1) Verify each JSON file signature with the corresponding verify CLI(s).",
            "2) Verify sha256 lines match checksums.sha256.",
            "3) Ensure export triple-anchor: canonical_export + export_audit_final + meta_audit_final(period)."
        ]
    }
    (outdir/"manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    # checksums
    lines=[]
    for f in files:
        lines.append(f'{f["sha256"]}  {Path(f["path"]).name}')
        # also copy into outdir for portability
        dst = outdir/Path(f["path"]).name
        dst.write_bytes(Path(f["path"]).read_bytes())
    lines.append(f'{sha256_file(outdir/"manifest.json")}  manifest.json')
    (outdir/"checksums.sha256").write_text("\n".join(lines) + "\n")

    # tarball
    import tarfile
    with tarfile.open(outdir/bundle_name, "w:gz") as tar:
        tar.add(outdir/"manifest.json", arcname="manifest.json")
        tar.add(outdir/"checksums.sha256", arcname="checksums.sha256")
        for f in files:
            tar.add(outdir/Path(f["path"]).name, arcname=Path(f["path"]).name)

    # include tarball checksum
    with (outdir/"checksums.sha256").open("a") as w:
        w.write(f'{sha256_file(outdir/bundle_name)}  {bundle_name}\n')

    print("OK:", outdir)
    print(" -", outdir/"manifest.json")
    print(" -", outdir/"checksums.sha256")
    print(" -", outdir/bundle_name)

if __name__ == "__main__":
    main()
