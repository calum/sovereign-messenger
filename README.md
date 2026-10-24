# Sovereign Mesh

> **Experimental. Not audited. Do not rely on it for anything sensitive yet.**

An experimental peer-to-peer messenger for a small, closed group of up to five people, built for Android. The goal is a messenger with no servers, no cloud, no disk storage of messages, and post-quantum key exchange, wrapped in an interface that looks like an ordinary chat app.

Right now this is a working core library, a passing test suite, and an Android app shell. **Messages are not yet sent over the network.** See [PLAN.md](PLAN.md) for what is done and what is left.

## What works today

- **`rust-core/`**: a Rust library with
  - a memory layer that zeroizes secrets on drop and tries to `mlock` them,
  - a hybrid key exchange, X25519 + ML-KEM-768 (FIPS 203), with both secrets feeding one HKDF,
  - a symmetric ratchet (ChaCha20-Poly1305) that rejects tampered and replayed messages,
  - Ed25519 verification of update payloads against a pinned developer key,
  - a RAM-only chat store with no persistence API.
  - a UniFFI facade (`ffi.rs`) that exposes a `Messenger` object; keys and plaintext stay in Rust.
  11 unit tests and 7 integration tests pass.
- **`app/`**: an Android (Kotlin, Jetpack Compose) shell with a three-card tour, a chat list, a chat screen with a RAM-retention countdown, `FLAG_SECURE` on every window, and backups disabled in the manifest. `CoreBridge` calls the generated UniFFI bindings for `rust-core` (arm64-v8a and x86_64 libraries are built by `rust-core/scripts/build-android.sh`). Five JVM tests run the real core through JNA.

## What does not work yet

- No network transport. Tor onion services are not implemented. Messages are recorded locally but are not sent to another phone.
- The app has no QR onboarding yet, so no session can be created from the UI; the native library has not been run on a device or emulator.
- No QR onboarding, no APK transfer between phones, no signed-update delivery.
- The ratchet has no Diffie-Hellman step, so it has no post-compromise recovery.
- Nothing here has been independently reviewed. The cryptography uses third-party crates (`ml-kem`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `hkdf`) that have not been audited as part of this project.

## Security status

Be skeptical of every claim in this repo until it has been tested and reviewed.

| Property | Status |
|---|---|
| Post-quantum key exchange | Implemented in the handshake (ML-KEM-768 + X25519). Not yet used by a live session. |
| Forward secrecy within a chain | Implemented (symmetric ratchet). |
| Post-compromise security | Not implemented (no DH ratchet). |
| Metadata resistance / onion routing | Not implemented. |
| RAM-only storage | Enforced in the Rust store (no persistence API). The Android app does not write message data to disk, but this is not yet verified. |
| Memory locking (`mlock`) | Best effort. Can fail under a low `RLIMIT_MEMLOCK`; the code records the failure instead of hiding it. Copies made on the stack during crypto operations are not all wiped. |
| Screenshot / recents protection | `FLAG_SECURE` set in `MainActivity`. Not verified on a device. |
| Cloud/device backups | Disabled in the manifest and backup rules. |
| Signed updates | Signature check implemented in Rust. No update delivery path yet. |

## Setup

You need:

- [mise](https://mise.jdx.dev) to run the project tasks,
- Rust (stable, via `rustup`),
- JDK 17 or newer,
- the Android SDK with platform 35, build-tools 35.0.0 and NDK 27.2.12479018.

Point Gradle at the SDK with a `local.properties` file in the repo root. Do not commit it:

```bash
sdk.dir=C\:\\Users\\<you>\\AppData\\Local\\Android\\Sdk
```

On Windows, double every backslash in that path, as above. Gradle reads `\` as an escape character.

## Building and testing

```bash
mise tasks            # list every task
mise run check        # lint and run all tests
mise run rust:test    # Rust unit tests only
mise run android:debug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

## Repository layout

```
rust-core/          Rust crypto and storage core
app/                Android app (Kotlin, Compose)
mise.toml           Project tasks
PLAN.md             What is done and what is left (kept up to date)
CLAUDE.md           Notes for AI coding assistants working on this repo
llm.txt             Short machine-readable summary of the project
```

## Reporting problems

This is a personal experiment. If you find a security problem, please open a GitHub issue marked as a security report. Do not include exploit details in public issues until there is a fix.

## Licence

No licence yet. All rights reserved until one is added.
