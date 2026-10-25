# CLAUDE.md

Guidance for AI coding assistants working in this repository.

## What this project is

An experimental, peer-to-peer, RAM-only Android messenger for a closed group of up to five people. Rust core (`rust-core/`) does the cryptography and state. Kotlin + Jetpack Compose (`app/`) does the UI. Read `README.md` for the status table and `PLAN.md` for what is left.

## Hard rules

1. **Messages are never written to disk.** No SQLite, no caches, no message files, no logs containing plaintext. Long-term identity keys and pinned contacts may be stored on the device (owner decision, 2026-10-25), but only encrypted at rest under a key held in the Android Keystore, and never in backups (rule 4). The one other file allowed is the verified, developer-signed update APK, staged in `cacheDir/update/` only to hand it to the system installer (owner-delegated decision, 2026-10-25; it is public code and holds no message, key or contact data). `UpdateInstaller` deletes it when the update screen is closed, when a receive fails, and at app start. Tor may also keep its public directory cache and guard state in `filesDir/tor` (owner-delegated decision, 2026-10-25); the onion service key is never written there, because it is rebuilt in memory from the identity vault. Deleting the identity deletes that folder. Any other persistence needs the owner's approval first.
2. **Secrets are zeroized.** Any new type holding key material or plaintext must implement `Zeroize`/`ZeroizeOnDrop`, or wrap a `SecretBytes`. Do not `Clone` secret types casually.
3. **No plaintext in logs, panics or errors.** Error messages in `CoreError` must not include key or message content.
4. **Backups stay off.** Keep `android:allowBackup="false"` and the `data_extraction_rules.xml` exclusions.
5. **`FLAG_SECURE` stays on** for every window in `MainActivity`.
6. **Do not invent crypto.** Use the existing RustCrypto crates. Do not hand-roll primitives, and do not change parameter sets without a note in `PLAN.md`.
7. **Be honest in docs.** The README and `PLAN.md` describe what works. If a feature is stubbed, say so.

## Commands

Use `mise` tasks; they are the source of truth (see `mise.toml`).

- `mise run rust:test`: Rust unit tests
- `mise run rust:lint`: `cargo fmt --check` and `clippy -D warnings`
- `mise run check`: lint plus every test suite
- `mise run android:debug`: debug APK
- `mise run android:share`: serve the debug APK on the Wi-Fi address with a QR code (Windows; Ctrl+C stops)

## Environment

- Windows 11 host, PowerShell and Git Bash. Use forward slashes in Bash, `.\gradlew.bat` in PowerShell.
- JDK 17 lives at `%LOCALAPPDATA%\Java\jdk-17.0.20.1+1`. Set `JAVA_HOME` to it for Gradle. The system JDK 11 is too old.
- Android SDK at `%LOCALAPPDATA%\Android\Sdk`. `local.properties` points Gradle there. It is git-ignored; never commit it.
- `ANDROID_HOME` is not set globally.

## Code conventions

- Rust: `cargo fmt` and `clippy -D warnings` must pass. Keep modules small and documented with a `//!` header that states the security property.
- Kotlin: Compose, Material 3, no XML layouts. Keep UI state in composables; keep crypto out of Kotlin.
- Comments explain *why* and name the security property, not what the line does.
- New crypto code needs a test for the success path and at least one failure path (tamper, wrong key, replay).

## Known gaps (do not paper over)

- `CoreBridge` calls `rust-core` through UniFFI, and the TCP transport works on loopback only. Nothing has been sent between two phones, and the native library has not been run on a device.
- The Tor transport (cargo feature `tor`, on in the Android build) is written and unit tested, and in one live test on a laptop two identities connected and exchanged messages over the real Tor network, but it has not run from the app, on a phone, or between two separate machines. Do not claim in the UI, README or tour that traffic is private from a network observer until `PLAN.md` T4 passes. The same-Wi-Fi TCP path is a test path and is not private. Do not add a central relay or cloud service as a shortcut.
- The ratchet's DH step is standard but not independently reviewed. The first-peer-key bootstrap (no DH step for the first message) is a deliberate deviation; see PLAN.md Decisions.
- `mlock` can fail silently at the call site; `SecretBytes::is_locked` reports it.
- `Chain` and `Identity` hold secrets on the stack during operations; intermediate copies are not all wiped.

## Commits and releases

- Commit messages: short imperative subject, then a body explaining why.
- Do not include a model name or AI attribution in commit messages or PR text (repository policy).
- Only the human owner decides when to publish a release.
