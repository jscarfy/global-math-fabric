# Publish Manifest (v1)

A publish bundle is a tarball + manifest that makes verification easy for future humans/bots.

Directory:
- `releases/publish/<kind>/<period_id>/`
Files:
- `manifest.json`
- `checksums.sha256`
- `bundle.tar.gz`

manifest.json includes:
- kind, period_id, generated_at
- list of artifacts with paths + sha256
- embedded server_pubkey_b64 + server_sig_b64 fields already present inside each artifact
- recommended verification steps (human-readable strings)

checksums.sha256:
- sha256sum lines for every artifact + manifest.json + bundle.tar.gz
