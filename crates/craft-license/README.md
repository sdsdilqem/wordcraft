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

No key is built into the apps. They fetch the panel's public key from `https://lisenziyam.az/adobe/api/key.php`
on every check and keep the last one (tied to this computer) for offline use. When the key is replaced in
Panel → Proqramlar, each app picks up the new key and a newly signed license on its next check.
`CRAFT_LICENSE_API=<url> cargo build` points a build at another server (for testing).

This is basic protection: a patched binary, or someone who blocks the server and forges the cached key,
can get past the check.
