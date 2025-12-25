# GMF Signature Spec v1 (sigmsg_v1)

This spec defines the exact bytes signed by devices (Ed25519) to avoid serializer ambiguity.

## Encoding
- UTF-8
- Message is a sequence of lines `key=value\n` with keys in the exact order below.
- Missing value => empty after `=`
- No extra whitespace
- Arrays use comma-separated decimal (no spaces), e.g. `sample_indices=0,7,19`

## Keys in order
1. device_id
2. lease_id
3. job_id
4. policy_hash
5. sig_spec_hash
6. challenge_nonce
7. bundle_format
8. header_sha256
9. merkle_root_hex
10. num_chunks
11. sample_indices
12. output_sha256

## output_sha256
- sha256 of the UTF-8 bytes of `output` string as submitted.

## Notes
- The server must verify the signature against exactly these bytes.
