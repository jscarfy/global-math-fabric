# GMF Consent Policy v1 (Immutable)

Goal: make participation explicit, reversible, and auditable.

## Principles
- Default is OFF.
- Client must show an explicit toggle + clear resource notes (battery/CPU/network).
- User can revoke at any time; after revoke, relay must reject new work from that device_id.

## Consent Token (CT)
Client produces a consent token signed by the device key:
- protocol: "gmf/consent/v1"
- device_id: sha256(device_pubkey_bytes)
- granted_at: RFC3339
- scope: ["compute","network"] (extensible)
- caps: e.g. "only_while_charging", "wifi_only", "max_cpu_percent"
- device_sig_b64: Ed25519 over sha256(JCS(consent_payload))

Relay must verify CT signature before issuing SSR.
