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
- [ ] Cross-compile `rust-core` for `aarch64-linux-android` (and `x86_64` for emulators) using the NDK already installed
- [ ] Add UniFFI bindings and generate the Kotlin side
- [ ] Replace the `CoreBridge` stub with real calls into `rust-core`
- [ ] Confirm `mlock` behaviour on Android (it can fail under `RLIMIT_MEMLOCK`); decide how the app reports it
- [ ] Add a JVM or instrumented test that round-trips a message through the real core

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
