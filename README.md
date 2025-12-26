# Global Math Fabric (GMF)

A voluntary, opt-in distributed system where devices contribute to verifiable math/verification tasks under explicit user control.

## Non-negotiable principles
- **Opt-in only**: no silent install, no hidden background mining.
- **User control**: pause/resume anytime; configurable policies (quiet hours, only-on-AC, min-battery).
- **Transparency**: tasks and verification outputs are auditable; releases are verifiable offline.
- **Safety**: defaults are conservative to avoid battery/thermal harm.

## Quick start (friends)
1) Install binaries (from GitHub Releases) or build from source
2) `gmf_agent init --relay <RELAY> --device-name <NAME>`
3) `gmf_agent enroll`
4) `gmf_agent run`

## Commands
- `gmf_agent status` / `gmf_agent status-json`
- `gmf_agent pause` / `gmf_agent resume`
- `gmf_agent set-policy --only-on-ac true --min-battery 40 --quiet 1-7`
- `gmf_agent credits` (v1 local receipts sum)

## Mobile note
iOS/iPadOS cannot run true 24/7 computation. The project supports “available windows” (foreground / charging / scheduled background tasks) instead.
