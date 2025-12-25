# Global Math Fabric — Install & Run (Friends)

This project contributes compute **only with explicit consent**, is **visible while running**, and supports **Pause/Stop anytime**.

## Links (GitHub Pages)
Replace placeholders with your real Pages base URL:

- Windows: `PAGES_BASE/releases/windows/gmf.appinstaller`
- Windows cert (first-time trust for self-signed): `PAGES_BASE/releases/windows/gmf.cer`
- macOS Sparkle feed: `PAGES_BASE/releases/appcast.xml`

> PAGES_BASE = `https://<OWNER>.github.io/<REPO>`

---

## Windows (recommended: .appinstaller auto-update)
### First time (self-signed cert)
1) Download `gmf.cer` and install it into **Trusted People** (Current User).
2) Then open `gmf.appinstaller` to install.

After that, updates are handled by App Installer using the `.appinstaller` UpdateSettings.

### Install
- Open: `PAGES_BASE/releases/windows/gmf.appinstaller`

### Uninstall / Stop
- Stop: Use the app tray menu **Pause/Exit**
- Uninstall: Windows Settings → Apps → Installed apps → Global Math Fabric → Uninstall

---

## macOS
- Install the notarized DMG/ZIP release (your maintainer will provide).
- Auto-update is driven by Sparkle feed:
  `PAGES_BASE/releases/appcast.xml`

Stop: Quit app; revoke consent inside Settings.

---

## Android
- Install via Play internal testing link (preferred) OR your maintainer-provided build.
- When enabling background contribution, Android will show a **foreground service** notification (visibility guarantee).
- Android 13+ will ask notification permission; if denied, you may only see the service in Task Manager (not in notification drawer).

Stop: Open app → Pause/Stop, or revoke consent in Settings.

---

## Verify credits / audit (advanced)
Each device submits signed receipts; daily settlement publishes a daily root + Merkle commitments.
You can request a proof bundle and verify it independently (no trust in server required).
