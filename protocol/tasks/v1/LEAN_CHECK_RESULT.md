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

## Docker image pin rule (REQUIRED)
- docker_image MUST contain "@sha256:" (digest pin), e.g.
  "leanprovercommunity/lean@sha256:...."
- Tag-only images (":latest", ":vX.Y") are NOT allowed for long-horizon auditability.

## Source pinning fields (HOST-computed, REQUIRED by default)
- git_rev: string (resolved HEAD commit SHA)
- git_tree: string (git rev-parse HEAD^{tree})
- lean_toolchain_sha256: hex string (sha256 of lean-toolchain file bytes; "" if missing)
- lakefile_sha256: hex string (sha256 of Lakefile.lean or lakefile.lean; "" if missing)
- lake_manifest_sha256: hex string (sha256 of lake-manifest.json; "" if missing)

## Task params toggles
- require_source_hash: bool (default true)
  - if false, agreement ignores the 5 source pinning fields above.
