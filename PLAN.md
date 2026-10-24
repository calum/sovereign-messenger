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
- [x] Identity generation on first launch (kept in RAM only, so it is lost on close; decide and document the consequence). Verified: `Messenger::new` makes a fresh identity per object (test `each_messenger_generates_its_own_identity`); `SovereignApp.onCreate` creates it at process start; no code path writes it to disk. Consequence in Decisions (2026-10-24, identity lifetime).
- [ ] QR code generator carrying the identity public key, the ephemeral handshake key, and local connection info. Partly done: Rust builds and parses the payload (tests in `pairing.rs`); Kotlin encodes and renders it, and a JVM test round-trips it through ZXing (`PairingCodecTest`). Not done: the ephemeral handshake key is not in the payload (Decisions, 2026-10-24). Not seen on a device.
- [ ] QR scanner, with the scanned identity pinned (TOFU) and the pin shown to the user. Partly done: pinning, validation and the pin display are tested in Rust (`tests/pairing.rs`, 12 tests) and the pairing screen shows the fingerprint. The CameraX scanner compiles but has not been run on a device.
- [ ] Clear error state when a pinned key changes. Partly done: the core refuses the new key with a distinct `PinChanged` variant and no key in the message (tests); the warning card with explicit accept compiles. Not seen on a device.

### 3. Transport
- [x] Choose the Tor implementation. Ruling: Tor is not implemented in this pass; arti is not a dependency. Evidence and cost are in Decisions (2026-10-24, Tor ruling). Verified by reading the arti-client 0.47.0 crate metadata and the Arti 2.5.1 release notes.
- [x] Local P2P socket transport behind a trait, so Tor can be swapped in. Verified: `rust-core/src/transport.rs` (`Transport` trait, 64 KiB frame cap, TCP on the LAN). Tests: 8 in `tests/transport.rs` (loopback frames, closed peer, oversize refused on send and on prefix, truncated frame, idle, accept timeout). Loopback only; not run between two phones.
- [x] Send and receive the handshake and ratchet messages over the transport. Verified: `rust-core/src/wire.rs` frames; 3 tests in `tests/session_over_transport.rs` (handshake then ratchet both ways over TCP, tampered frame rejected, shortened length prefix fails authentication); 5 facade tests in `tests/transport_facade.rs`; 4 JVM tests in `TransportLoopbackTest.kt` through `CoreBridge`. Loopback only.
- [ ] Wire the chat UI to the transport. Partly done: `ChatScreen` sends through `CoreBridge` into `Messenger.sendOverTransport`, connects or waits on the LAN, and polls for received messages. The bridge path is tested on the JVM; the screen itself has not been run on a device, and the flow between two phones is not verified.

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

- **2026-10-24, identity lifetime:** the identity is generated when the process starts (`SovereignApp` creates `CoreBridge`, which creates `Messenger`) and is never written to disk. Closing the app discards it, so every contact must scan a new QR code after a cold start. Cost if wrong: more pairing for the user; the key is not stored anywhere, so storage cannot leak it.
- **2026-10-24, QR payload format v1:** magic `SMQR`, version byte `1`, X25519 public key (32 bytes), ML-KEM-768 encapsulation key (1184 bytes), one length byte, then a connection hint of up to 64 printable ASCII characters. Rust builds and parses the bytes (`rust-core/src/pairing.rs`); Kotlin maps each byte to one ISO-8859-1 character, encodes byte mode with error correction L, and does not interpret the payload. The payload is about 1.2 KB, so the code is dense. Cost if wrong: a new layout needs a new version byte, and old codes are refused, not misread.
- **2026-10-24, TOFU pin policy:** a scanned QR code, or the first `start_session` for a label, pins that identity under the caller's label. A different key for a pinned label is refused with `PinChanged`. A second scan of the same key is refused with `DuplicatePin`. The only way to accept a new key is an explicit `unpin` in the UI, after the fingerprint is checked in person. Pins survive `forget` and `wipe_all`, so a later QR code cannot silently replace a trusted key; they are lost when the process ends. Cost if wrong: a user must re-check fingerprints in person after each cold start; a wrong pin is shown as a fingerprint, so it can be compared.
- **2026-10-24, ephemeral handshake key is not in the QR yet:** section 2 asked for one. The handshake still uses the identity keys from section 1. Adding a separate ephemeral key now would be unused key material, which CLAUDE.md rule 6 forbids. It belongs with the transport in section 3, where handshake messages are exchanged. Cost if wrong: the QR lacks one key until section 3; a new payload version is then needed. Resolved 2026-10-24 in the transport entry below: the handshake generates its own ephemeral key.
- **2026-10-24, scanner libraries:** ZXing `com.google.zxing:core` 3.5.3 (published 2024-01-31) for encode and decode, and CameraX 1.4.2 (published 2025-03-26) for the camera. CameraX 1.6.x requires AGP 8.9.1 and compileSdk 36, which this build does not have, so it was not used. The camera permission is requested at runtime when the scanner opens, and the manifest marks the camera feature as optional. Cost if wrong: decode may be slow or fail on some phones; not tested on a device. CameraX can be bumped only with an AGP upgrade.
- **2026-10-24, pinned-key-changed behaviour:** rust-core refuses the new key before any session is created and returns `FacadeException.PinChanged`, whose message names no key. The UI shows a warning with "Keep old key" as the default and "Accept new key" as a separate tap that removes the pin; the user must then scan again. Cost if wrong: a user who taps "Accept new key" without checking in person lets an attacker replace the pin; the warning says to check first.

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
- **2026-10-24, send does not transmit yet:** superseded by the transport entries below. `send` still only seals and records locally, for in-process tests; `CoreBridge.send` now calls `sendOverTransport`.
- **2026-10-24, Tor ruling:** Ruling: Tor is not implemented in this pass, and arti is not a dependency. Why: crates.io lists `arti-client` 0.47.0 as the newest stable release. Its `onion-service-service` and `onion-service-client` features are not marked experimental, but `restricted-discovery` is, and the crate's `experimental` feature gates parts of the API. The Arti 2.5.1 release notes (2026-08-04) describe experimental congestion control and Counter Galois Onion on onion-service circuits that the project hopes to make stable. The Arti home page says onion services are ready for use but not every C Tor feature is present. The onion-services implementation matrix marks some features partial and may be out of date. Nothing was built here for `aarch64-linux-android`, so the async runtime and TLS dependency tree is unverified. Cost if wrong: the transport has no metadata protection until Tor exists. The swap is a new `Transport` implementation; the handshake and ratchet do not change.
- **2026-10-24, local transport is TCP on the LAN:** `rust-core/src/transport.rs` sends 4-byte big-endian length-prefixed frames over TCP. The phone that waits listens on `0.0.0.0:47001`; the other phone types `host:port` into the chat screen. The QR code carries no address (its connection hint is empty), so the address is entered by hand. Why: the smallest step that can be tested here, behind a trait so Tor can replace it. Cost if wrong: traffic timing and addresses are visible on the local network, though not contents; any phone on the same network can dial the listener.
- **2026-10-24, frame cap 64 KiB:** `MAX_FRAME_LEN` is enforced on send and before any body is read, so an oversize length prefix allocates nothing. A handshake frame is 1121 bytes. Cost if wrong: a longer frame is refused; raising the cap also raises the memory one peer can make the app allocate per frame.
- **2026-10-24, the handshake does not authenticate the initiator:** the initiator sends an ephemeral key and an ML-KEM ciphertext with no signature from its identity key. The responder is checked only implicitly: a wrong responder key derives a different root, so the first message does not decrypt. Anyone who has the responder's public key, which is in the QR code, can open a session on the responder's listener under the label the responder chose. Cost if wrong: a stranger on the same network can write messages into a chat. Fix before relying on it: the initiator signs its handshake with its long-term identity key, and the responder checks it against the pin for that label.
- **2026-10-24, ephemeral handshake key (section 2 item):** `handshake::initiate` generates a new X25519 ephemeral key for every handshake, so no ephemeral key needs to go in the QR code. The payload stays v1. Cost if wrong: none found; a long-lived ephemeral key would need a new payload version.
- **2026-10-24, a failed write can desynchronise a chain:** `send_message` seals first, which advances the send counter, and then writes. If the write fails, the peer never sees that counter, and its next frame is refused. The app shows the error and does not record the message. Reconnecting runs a new handshake, which starts both chains again. Cost if wrong: one message lost and a reconnect needed. Fix: commit the counter only after the write succeeds.
- **2026-10-24, blocking calls and cancellation:** `connectPeer`, `listenForPeer` and `receiveFromPeer` block the calling thread, so the app runs them on `Dispatchers.IO`. Reads poll every 500 ms, so the receive loop ends within half a second of leaving the chat. `listenForPeer` cannot be cancelled and waits up to its timeout (120 s in the app). Cost if wrong: a thread waits up to two minutes after the user leaves the screen. Wiping on stop closes the sockets, because the sessions that hold them are dropped.
