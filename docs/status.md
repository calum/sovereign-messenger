# Detailed status

The long version of where the project stands, moved out of the README to keep it short. [PLAN.md](../PLAN.md) is the checklist and the decisions log; [owner-test-list.md](owner-test-list.md) lists the checks that need a person and hardware.

Be skeptical of every claim here until it has been tested and reviewed.

## What works today

- **`rust-core/`**: a Rust library with
  - a memory layer that zeroizes secrets on drop and tries to `mlock` them,
  - a hybrid key exchange, X25519 + ML-KEM-768 (FIPS 203), plus a static-static X25519 DH that makes the responder check the initiator against its pin; all three feed one HKDF,
  - a Double Ratchet (ChaCha20-Poly1305, X25519 DH steps, HKDF-SHA256 root key) that rejects tampered and replayed messages and accepts out-of-order ones within a bounded skip,
  - Ed25519 verification of update payloads against a pinned developer key,
  - a RAM-only chat store with no persistence API.
  - a UniFFI facade (`ffi.rs`) that exposes a `Messenger` object; keys and plaintext stay in Rust.
  - a framed transport trait with a TCP implementation (64 KiB frame cap, refused oversize and truncated frames),
  - an encrypted identity vault: the long-term identity and pinned contacts are sealed (ChaCha20-Poly1305) under a data key that the Android Keystore wraps; messages and sessions are never stored,
  - a stable v3 onion address per identity, carried in the QR code (payload version 2), and a Tor transport (cargo feature `tor`, using arti 0.47 pinned) that hosts the identity's onion service with its key held only in memory. The same framing rules apply over an onion stream as over TCP.
  Pairing (QR payload built in Rust, TOFU pin, refused changed key) is covered by 12 pairing integration tests. Transport and the handshake and ratchet over it are covered by 8 transport, 4 session and 6 facade integration tests. Initiator authentication is covered by 9 integration tests (`tests/handshake_auth.rs`) and 4 unit tests in `handshake.rs`. The send counter has 2 integration tests (`tests/send_counter.rs`). There are also 43 unit and 7 round-trip integration tests. The `mise` tasks are the source of truth for running them.
- **`app/`**: an Android (Kotlin, Jetpack Compose) shell with a three-card tour, a contact list with last message, unread count and online state, a chat screen with message bubbles, sender names, times and sent/delivered/read marks, a guided add-contact flow, a settings screen, working system back navigation, `FLAG_SECURE` on every window, and backups disabled in the manifest. `CoreBridge` calls the generated UniFFI bindings for `rust-core` (arm64-v8a and x86_64 libraries are built by `rust-core/scripts/build-android.sh`). Twenty JVM tests run the real core through JNA, including a QR encode and decode round trip and a loopback message over TCP. One of them (the QR round trip) has failed intermittently in our runs; see PLAN.md.

## What does not work yet

- Nothing has been sent between two phones, over Tor or over TCP. The QR code now carries the contact's onion address; the same-Wi-Fi TCP test path still needs a typed `host:port`.
- Tor has run over the real network only in the core's live test on a laptop (two identities in one process). It has not run between two machines, from the app, or on a phone. The first publish of an onion service has taken from 18 seconds to about 5 minutes; a start with saved state took 20 seconds against 88 cold. Chats stay in memory while the app process lives (owner decision, 2026-10-29), so a quick app switch no longer costs a reconnect; if Android stops the process, chats are lost and reconnecting can take minutes.
- The initiator is authenticated by the responder's pin (static-static DH, PLAN.md, Decisions, 2026-10-24). Both phones must scan each other's QR code first. This is tested in Rust but not independently reviewed. The responder sends a fresh challenge and the initiator proves it with a confirmation tag, so a captured handshake does not replace a live session.
- The app has been installed and started on one phone (owner report). The camera scanner, the Keystore vault, Tor on Android and the chat screen have not been checked there.
- APK transfer over local Wi-Fi is written but has not run between two phones, and no developer signing key is compiled in, so no update installs. The ephemeral handshake key is not in the QR code yet (see PLAN section 2).
- The DH ratchet step is the standard Double Ratchet construction, tested in Rust, but it has not been independently reviewed. If both sides take a DH step before either sees the other's new key, the session desynchronises and must be re-handshaken.
- Nothing here has been independently reviewed. The cryptography uses third-party crates (`ml-kem`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`) that have not been audited as part of this project.

## Security status

| Property | Status |
|---|---|
| Post-quantum key exchange | Implemented in the handshake (ML-KEM-768 + X25519). Used in the live Tor test on a laptop; not yet between phones. |
| Initiator authentication | Implemented: static-static DH and a pin check in the responder. Tested; not independently reviewed. |
| Forward secrecy within a chain | Implemented (symmetric ratchet). |
| Post-compromise security | Implemented (DH ratchet step). Tested; not independently reviewed. |
| Metadata resistance / onion routing | Written, not proven. Each identity has a stable v3 onion address (in the QR code), the core hosts the onion service with the key held only in memory, and contacts dial each other over Tor. Unit tests cover framing, the in-memory key and the dial/wait rule. In one live test on a laptop (two identities in one process) it connected over the real Tor network and exchanged messages; it has not run from the app, on a phone, or between two machines, so no privacy claim is made. The same-Wi-Fi TCP path is a test path and reveals addresses on the local network. |
| RAM-only messages | Enforced in the Rust store (no persistence API). The Android app does not write message data to disk, but this is not yet verified. |
| Stored identity and contacts | Implemented, not run on a device. The identity secrets and pinned contacts are sealed by the Rust core (ChaCha20-Poly1305) under a data key that the Android Keystore wraps; app-private files, excluded from backup. Messages and sessions are never stored. Tested on the JVM with an in-memory stand-in for the Keystore; the real Keystore path (including StrongBox) has not run. Deleting the identity from the chat list erases it with no recovery. |
| Memory locking (`mlock`) | Best effort. Can fail under a low `RLIMIT_MEMLOCK`; the code records the failure instead of hiding it. Copies made on the stack during crypto operations are not all wiped. |
| Screenshot / recents protection | `FLAG_SECURE` set in `MainActivity`. Not verified on a device. |
| Crash reporting | An uncaught Kotlin error opens a report screen (error, causes, stack, phone model) with Copy and Share, in its own process, held in memory only and never written to disk. A native crash is read back from Android's exit history on the next start (last 10 minutes only). The formatter has JVM tests; the screens, the handler and the exit-history path have not run on a device or been compiled in this change. A native crash gives only a signal and description, not a stack. |
| Cloud/device backups | Disabled in the manifest and backup rules. |
| Signed updates | Signature check implemented in Rust. No update delivery path yet. |
