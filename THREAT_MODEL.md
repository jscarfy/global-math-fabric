# Threat Model (v1)

## Assets
- user device resources (CPU, battery, thermal)
- user consent and autonomy
- integrity of receipts/audits/finals
- correctness of published artifacts

## Adversaries
- malicious relay operators
- malicious clients submitting fake work
- network attackers (MITM)
- sybil devices attempting to farm credits

## Mitigations
- server-signed consent tokens (opt-in)
- server-signed receipts and write-once finals binding log sha256
- meta-audit consensus over anchors
- conservative run policy defaults (only-on-AC, min-battery)
- offline verification bundles (VERIFY.md + checksums + signature verification)

## Non-goals
- stealth persistence
- circumventing mobile OS scheduling limits
