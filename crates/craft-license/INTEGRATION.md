# Adding the check to a Craft app

Every `storytold/*` app is a Rust workspace with the same layout, so the change is the same in each
(shown for PhotoCraft; replace the names):

1. Copy this folder to `crates/craft-license/` in the app's repo (the `crates/*` glob picks it up).
2. Root `Cargo.toml`, under `[workspace.dependencies]`:
   ```toml
   craft-license = { path = "crates/craft-license" }
   ```
3. `apps/photocraft/Cargo.toml`, under `[dependencies]`:
   ```toml
   craft-license = { workspace = true }
   ```
4. `apps/photocraft/src/main.rs`, at the top of `fn main()` after the crash hook:
   ```rust
   craft_license::enforce("PhotoCraft");
   ```
5. Build with the panel's public key: set the repository variable `CRAFT_LICENSE_PUBKEY`
   (Settings → Secrets and variables → Actions → Variables) and pass it to the release build's environment.

Keep the app's `LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE` files, and note the change in `NOTICE`
("Modified to add a license check"), as the Apache-2.0 license requires for changed files.
