# lean_check result_core v1 (Deterministic Artifact Hashing)

result_core JSON (to be JCS-canonicalized):
- ok: bool
- exit_code: int
- build_log_sha256: hex string (sha256 of build log text)
- artifacts_root: string (default ".lake/build/lib")
- artifacts_count: int
- artifacts_manifest_sha256: hex string
- docker_image: string (must be pinned; prefer digest)

## artifacts_manifest_sha256
Compute a manifest file as:
- list = all regular files under artifacts_root
- for each file: record "<sha256>  <relative_path>\n"
- sort by relative_path
- concatenate into manifest bytes
- artifacts_manifest_sha256 = sha256(manifest_bytes)

This is the "root hash" of build outputs.
