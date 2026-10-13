# craft-license

License check shared by the Craft apps and the Creative Cloud launcher.

- The launcher signs in at the license panel (`license-panel/`) and saves a signed license file:
  - macOS: `~/Library/Application Support/ArtCraft/license.json`
  - Windows: `%APPDATA%\ArtCraft\license.json`
- Each Craft app calls `craft_license::enforce("PhotoCraft")` first thing in `main()`. It verifies the
  file's Ed25519 signature with the panel's public key, checks that it was issued for this computer,
  that the license has not expired and that the clock was not turned back, and refreshes it from the
  server every 6 hours (also while the app runs). Without the server the app keeps working until the
  file's `refresh_by` (7 days by default).
- When the check fails the app shows a native **License Expired** (or **License Required**) window and quits.
  If the license expires while the app is open, the user is told to save their work and the app closes
  10 minutes later.

Build the apps with the panel's public key (Panel → Proqramlar → Lisenziya açarı):

```
CRAFT_LICENSE_PUBKEY=<base64 key> cargo build --release
```

This is basic protection: a patched binary can skip the check.
