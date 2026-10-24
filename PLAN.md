# Plan

This plan is updated as work is done. Checked items are verified in the repo; unchecked items are not started or not verified. Each change to the plan should say what changed and why.

_Last updated: 2026-10-24._

## Done

- [x] Project scaffold: Gradle (Kotlin DSL), Android app module, `rust-core` crate
- [x] Rust memory layer: `SecretBytes` (mlock + zeroize), `Key32` (zeroize on drop)
- [x] Hybrid handshake: X25519 + ML-KEM-768, HKDF-SHA256 root key (tests: both sides agree; wrong identity disagrees)
- [x] Symmetric ratchet: ChaCha20-Poly1305, in-order, tamper and replay rejected (tests)
- [x] Signed-update verification: Ed25519, pinned developer key (tests: valid accepted, tamper and foreign key rejected)
- [x] RAM-only chat store with no persistence API
- [x] Android shell: `FLAG_SECURE`, backups disabled (manifest and extraction rules), three-card tour, chat list, chat screen with retention countdown
- [x] Debug APK builds
- [x] `mise` task file (`rust:test`, `rust:lint`, `android:*`, `check`)
- [x] Rust tests pass (10) and `clippy -D warnings` passes
- [x] Release signing config (key kept outside the repo; `keystore.properties` git-ignored)
- [x] Release APK builds, is signed, has `allowBackup=false`, is not debuggable
- [x] `README.md`, `CLAUDE.md`, `llm.txt`

- [x] Public GitHub repository and first push: https://github.com/calum/sovereign-messenger
- [x] Release APK published as a pre-release: https://github.com/calum/sovereign-messenger/releases/tag/v0.1.0-experimental (`v0.1.0-experimental`, SHA-256 in the release notes)

## In progress

- [ ] Owner testing of the pre-release (see section 8)

## Left to do

### 1. Core integration (Rust to Android)
- [x] Cross-compile `rust-core` for `aarch64-linux-android` (and `x86_64` for emulators) using the NDK already installed. Verified: `rust-core/scripts/build-android.sh` builds both; ELF machine types checked. Not yet run on a device or emulator.
- [x] Add UniFFI bindings and generate the Kotlin side. Verified: `rust-core/scripts/gen-kotlin.sh` generates `app/src/main/java/uniffi/rust_core/rust_core.kt`; the JVM test calls it.
- [x] Replace the `CoreBridge` stub with real calls into `rust-core`. Verified: debug APK builds with the bindings. Not run on a device, and no transport exists yet, so `send` only records locally.
- [ ] Confirm `mlock` behaviour on Android (it can fail under `RLIMIT_MEMLOCK`); decide how the app reports it. Partly done: `Messenger.lockReport()` reports whether a probe buffer and the stored messages are locked (no secrets). Not confirmed: no device run, so the actual Android result is unknown.
- [x] Add a JVM or instrumented test that round-trips a message through the real core. Verified: 5 JVM tests in `app/src/test` run the host `rust-core` through JNA; 7 Rust integration tests in `rust-core/tests/round_trip.rs`.

### 2. Onboarding and identity
- [ ] Identity generation on first launch (kept in RAM only, so it is lost on close; decide and document the consequence)
- [ ] QR code generator carrying the identity public key, the ephemeral handshake key, and local connection info
- [ ] QR scanner, with the scanned identity pinned (TOFU) and the pin shown to the user
- [ ] Clear error state when a pinned key changes

### 3. Transport
- [ ] Choose the Tor implementation (arti is the leading Rust option; onion-service support is experimental, so check it first)
- [ ] Local P2P socket transport behind a trait, so Tor can be swapped in
- [ ] Send and receive the handshake and ratchet messages over the transport
- [ ] Wire the chat UI to the transport

### 4. Ratchet
- [ ] Out-of-order message handling (currently rejected)
- [ ] DH ratchet step for post-compromise security

### 5. Updates and APK transfer
- [ ] Serve the signed APK peer-to-peer during the in-person meeting (Wi-Fi Direct or local Wi-Fi)
- [ ] Verify the update signature in the app before offering the install
- [ ] Decide how the developer's signing key is pinned on first contact

### 6. Hardening and review
- [ ] Review every `unsafe` block and the `mlock` calls
- [ ] Find and remove any place where plaintext could reach a log or an exception message
- [ ] Verify `FLAG_SECURE` on a real device (screenshot, screen recording, recents thumbnail)
- [ ] Add tests for the Kotlin UI logic that is not just layout
- [ ] Independent review of the cryptographic design before anyone relies on it

### 7. Usability
- [ ] Verify the tour and chat flow on a phone
- [ ] Add the discreet "Secured P2P Mesh" status indicator with real state

### 8. User testing (owner)
- [ ] Owner installs the pre-release APK and tests it for security, privacy and ease of use
- [ ] Owner reports findings; the plan is updated from them

## Decisions

- **Repository visibility:** public, labelled experimental. Owner chose this.
- **Release signing:** a self-generated release key lives in `%USERPROFILE%\.sovereign-mesh\` (outside the repo). It must be backed up; losing it means existing installs cannot be updated in place.
- **Release contents:** the first APK is a pre-release for testing. It does not yet send messages over a network, so it should not be used for real conversations.
- **Models and attribution:** commit messages and release text do not name the AI model (repository policy in `CLAUDE.md`).
- **2026-10-24, Android ABIs:** `arm64-v8a` (`aarch64-linux-android`) for phones and `x86_64` for emulators, built with NDK 27.2.12479018 clang at API 29 to match `minSdk`. Linkers are set by `rust-core/scripts/build-android.sh`, not in a checked-in `.cargo/config.toml`, so the NDK path is not hard-coded. Cost if wrong: 32-bit ABIs are absent and devices running them cannot start the app.
- **2026-10-24, UniFFI 0.32.2 (proc-macro, no UDL):** the generated Kotlin is committed under `app/src/main/java/uniffi/rust_core/` so Gradle builds without Rust. Regenerate with `mise run rust:bindings` after editing `rust-core/src/ffi.rs`. Cost if wrong: a stale binding mismatches the native library and fails at load time (UniFFI checks checksums at load, so this fails loudly, not silently).
- **2026-10-24, native library name:** the `.so` is copied to `libuniffi_rust_core.so` because UniFFI's Kotlin loads `uniffi_<crate>` through JNA. JNA is `5.16.0` (`@aar` for Android, plain jar for the JVM test). Cost if wrong: the app fails to load the library at first call.
- **2026-10-24, facade surface is small:** `Messenger` is the only object. Kotlin receives public identity bytes, handshake bytes, sealed wire messages and display strings. No private key, chain key or message key crosses into Kotlin. Cost if wrong: none for secrecy today; Kotlin `String` copies of plaintext cannot be zeroized, so plaintext lives on the Java heap while displayed.
- **2026-10-24, `wipeAll` also ends sessions:** wiping on app stop clears ratchet state, so both phones must run the handshake again after the app is backgrounded. This follows the RAM-only rule. Cost if wrong: more handshakes for the user, no security cost.
- **2026-10-24, `mlock` is reported, not enforced:** `Messenger.lockReport()` exposes whether locking worked; the core keeps running when it fails. Blocking the app would make it unusable on devices where `RLIMIT_MEMLOCK` is low, and Android devices normally have no swap file. Cost if wrong: on a device where `mlock` fails, secrets could in principle be paged out; the status is shown so the owner can judge it. Revisit after a device run.
- **2026-10-24, send does not transmit yet:** `send` returns the sealed wire message, but `CoreBridge` discards it. Cost if wrong: none; messages stay on the local phone until the transport in section 3 exists.
