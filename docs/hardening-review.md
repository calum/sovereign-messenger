# Hardening review

Date: 2026-10-24; section 5 updated 2026-10-25 for the wire changes. Scope: PLAN.md section 6. Each finding says what was checked, whether it is sound, and what was done. Items that need a phone or an independent party are marked NOT VERIFIED.

## 1. `unsafe` blocks and `mlock` calls

Method: `grep -rn "unsafe|mlock|munlock" rust-core`.

Result: two `unsafe` blocks, both in `rust-core/src/secret.rs`, both calling `libc` and both behind `#[cfg(unix)]`. No other `unsafe` exists in rust-core. `mlock` and `munlock` are called only from `secret.rs`. `ffi.rs` (`lock_report`) and `store.rs` (`lock_count`) only read the lock state.

### F1. `secret.rs` `lock()`, the `mlock` call (line 47): sound

- The pointer and length come from the `Vec<u8>` owned by the `SecretBytes`. `SecretBytes::new` sets the capacity to `max(len, 1)` and fills it once, so the `Vec` is never reallocated and the locked range is the live buffer.
- On failure `mlock` returns non-zero, `lock` returns `false`, and no `munlock` is attempted later.
- An empty buffer returns `true` without a syscall. Nothing is locked, so this is harmless.
- Not exercised here. On this Windows host `cfg(unix)` is false, so `lock` always returns `false` and the tests never call `mlock`. The Android path has not been run on a device.

### F2. `secret.rs` `unlock()`, the `munlock` call (line 57): REAL PROBLEM, OPEN, NOT FIXED

- The call order is correct: the buffer is zeroized, then unlocked, and only if it was locked.
- The problem is the granularity. Linux and Android lock memory per page, and `munlock` is not reference counted. Unlocking a range clears the lock on every page it touches, including a page that another live `SecretBytes` shares.
- Stored messages are many small `SecretBytes` (`store.rs`), so they share pages. Dropping one can silently remove the lock from another that is still live.
- Concrete triggers: `Messenger.lock_report()` builds a 32-byte probe in `ffi.rs` and drops it on every call. `forget` and `wipe_all` drop stored messages.
- `SecretBytes::is_locked` is set once at construction, so after such an unlock it reports a lock that no longer holds.
- Why not fixed here: it cannot be reproduced on this host (no Linux, no WSL). Both candidate fixes change memory behaviour and need a Linux test first. Options for the owner:
  - (a) Give each secret its own page-granular allocation, so the page it locks is never shared, and keep the `munlock`.
  - (b) Stop calling `munlock`. Locked pages then stay locked until the process ends. The cost is that the locked total follows the heap high-water mark and can use up `RLIMIT_MEMLOCK`, which `is_locked` would then report.
- A Linux test would read `/proc/self/smaps` `VmFlags` (`lo`) for the page of a live secret, drop a neighbour, and check the flag. That test should exist before either fix is chosen.

### F3. `ffi.rs` `lock_report()`: part of F2

Creates and drops a `SecretBytes` on every call, which can trigger the unlock in F2. Recorded as the concrete trigger; not changed here.

### F4. `is_locked` reports at construction time only

Covered by F2. The value is a snapshot, not a live check.

## 2. Plaintext or key material in logs, panics, Debug output or exceptions

Method:

- Rust: `grep` for `println!`, `eprintln!`, `dbg!`, `format!`, `panic!`, `unwrap`, `expect`, `#[derive(...Debug)]` and `impl Debug`, plus a grep for `log::`, `tracing` and `use log`.
- Kotlin: `grep` for `Log.`, `println`, `printStackTrace`, `.message` and `Exception(` in `app/src/main/java`.

Results:

- No logging macro or logging crate exists in rust-core. There is no `log`, `tracing` or `println!` call in `rust-core/src`.
- Panic and `expect` messages are fixed strings and interpolate no data: `handshake.rs` ("OS randomness unavailable", "32 bytes is a valid HKDF length"), `ratchet.rs` and `double_ratchet.rs` (HKDF length messages). `format!` appears only to hex-encode a public-key digest (`pairing.rs`, `update.rs`) and in tests. `unwrap` appears only in tests.
- Debug output: `Key32`, `SecretBytes`, `Identity`, `Chain`, `DoubleRatchet` and `Messenger` have no `Debug` impl. Each now has a compile-time guard (section 2 tests below).
- Error types: `CoreError` and `FacadeError` have fixed-string variants with no fields, so their `Debug` output names only the variant.
- Types with derived `Debug` hold public values only: `HandshakeInit`, `IdentityPublic`, and the UniFFI records `PublicIdentity`, `HandshakeMessage`, `WireMessage`, `ScannedPeer`, `LockReport` and `VerifiedUpdate`. `VerifiedUpdate` contains the APK bytes, which are public.
- Kotlin: no `Log.`, `println`, `printStackTrace` or `.message` read exists in `app/src/main/java`. Exceptions reach the screen only through `transportStatusText` and `updateStatusText`, which return fixed sentences. `keyChangedWarning` and `PairingOutcome` carry a peer label and a public fingerprint, not key bytes.

### L1. `Key32` derived `Clone`: REAL PROBLEM, FIXED

- CLAUDE.md rule 2 says not to clone secret types casually. `Key32` derived `Clone`, and nothing in rust-core needs a copy of a key.
- RED: `secret::tests::key_material_types_do_not_implement_clone` failed with `Probe::<Key32>::CLONE` true (`assertion failed: !Probe::<Key32>::CLONE`).
- GREEN: the `Clone` derive was removed. `Key32` still derives `Zeroize` and `ZeroizeOnDrop`.

### L2. No `Debug` on secret types: guarded by a compile-time probe

- Added `secret::probe` (test only). `Probe::<T>::DEBUG` and `Probe::<T>::CLONE` are `true` only when `T` implements the trait. A positive control (`Probe::<u8>`) proves the probe is not always false.
- Tests assert that `Key32`, `SecretBytes`, `Identity`, `Chain`, `DoubleRatchet` and `Messenger` have neither `Debug` nor `Clone`. A derive added later fails its test.
- Not a runtime check of Debug output. There is no `Debug` output of a secret type to inspect, because none exists.

### L3. Plaintext copies outside zeroizing types: RESIDUAL, NOT FIXED

- `Messenger::send_over_transport(text: String)` receives the plaintext as a Rust `String` that is not zeroized. `Messenger::history` returns `String` copies to Kotlin, which cannot be zeroized (PLAN.md Decisions, 2026-10-24, "facade surface is small").
- Not fixed. Changing the UniFFI surface is larger than this pass. Recorded here as a known residual.

### L4. Stack copies of the ML-KEM seed: RESIDUAL, NOT FIXED

- `Identity::generate` copies the 64-byte seed with `.into()` into a temporary that `seed.zeroize()` does not clear. CLAUDE.md lists this as a known gap for `Identity`.
- Not fixed in this pass. A test cannot observe stack copies. A fix would keep the seed in one `B64` array and pass it by reference.

## 3. `FLAG_SECURE` on a real device: NOT VERIFIED

- The flag is still set. `app/src/main/java/org/sovereign/mesh/MainActivity.kt` line 27 calls `window.setFlags(FLAG_SECURE, FLAG_SECURE)` in `onCreate`. It was not changed.
- Not verified: screenshot, screen recording and the recents thumbnail all need a phone. This item stays unticked in PLAN.md.

## 4. Kotlin logic tests (not Compose)

Pure logic in `app/src/main/java/org/sovereign/mesh` before this pass:

- `transportStatusText` (`core/TransportStatus.kt`): 4 of 7 branches were tested. `NoSession`, `AuthFailed` and `Malformed` were not.
- `updateStatusText` (`core/UpdateStatus.kt`): 1 of 4 branches was tested (`AuthFailed`, in `UpdateGateTest`).
- `pairingOutcome` and `keyChangedWarning` (`core/Pairing.kt`): already tested in `PairingCodecTest`.
- `QrCodec`: already tested in `PairingCodecTest`.
- The retention countdown formatting, inline in `ui/ChatScreen.kt`: no test.

Changes:

- `formatRetention(seconds)` extracted from `ChatScreen.kt`. RED: `RetentionCountdownTest` failed to compile with `Unresolved reference 'formatRetention'`. GREEN after the function was added.
- `UpdateStatusTest` (4 tests) and three new `TransportStatusTest` cases. Honest note: these assert the current mapping text, which already existed, so they passed on their first run. They were not observed failing. They cover the branches that were untested.
- No Compose UI tests were added.

## 5. Cryptographic design: independent review NOT DONE

Not reviewed by anyone independent. This section lists the points the owner should send for review. Not verified here: nothing in this list has been checked against a formal model.

1. **Static-static DH in the handshake root** (`rust-core/src/handshake.rs`, `derive_root`). The root is HKDF-SHA256 over `ephemeral DH || ML-KEM secret || label || static DH`, with no salt. The static DH authenticates the initiator (the responder compares the static key with its pin). Questions: whether the fixed-length concatenation without a length prefix is unambiguous, and whether a low-order pinned key (which gives an all-zero static term) is acceptable. `was_contributory` is not used.
2. **First-peer-key bootstrap without a DH step** (`rust-core/src/double_ratchet.rs`). Both sides start from the handshake root with the same chain labels, and the first peer key is accepted without a DH step. This is a deliberate deviation from the standard Double Ratchet (PLAN.md Decisions, "DH ratchet design"). Limits (a) to (c) are listed there. Question: whether the start-up chains give the security the design claims.
3. **Skipped-key cache bounds** (`rust-core/src/ratchet.rs`). `MAX_SKIP` 100 counters per receive, `MAX_CACHED_KEYS` 100 keys per cache, oldest key evicted. Question: whether the bounds are safe against an attacker who can send forged large counters, and whether the eviction policy leaves a gap for an attacker who forces evictions.
4. **TOFU pin model and handshake replay** (`rust-core/src/ffi.rs`, `pin_or_check`, `scan_pairing`, `unpin`; `rust-core/src/handshake.rs`). Pins are made on first use, held in RAM, and survive `forget` and `wipe_all`. A different key is refused with `PinChanged`. Question: whether the first-contact pin is safe when a stranger can reach a listener before the real peer does. **Handshake replay, changed since the 2026-10-24 review (fix to be checked):** the responder sends a fresh 32-byte challenge once per connection (frame tag `0x03`), and the initiator's handshake (tag `0x01`) ends with a confirmation tag, HMAC-SHA256 keyed with the root over the public handshake values and the challenge. The challenge is also an input to the root. A captured handshake replayed to a later connection carries an old challenge, so the tag fails and no session is stored. Tests: `rust-core/tests/handshake_replay.rs`. Question for the reviewer: whether the binding, the tag construction and the one-time use of each challenge are sound. Not tested between two phones.
5. **Signed-update format and rollback, changed since the 2026-10-24 review (fix to be checked)** (`rust-core/src/update.rs`, `rust-core/src/apk_transfer.rs`). The update frame is v2: a detached 64-byte Ed25519 signature over `sovereign-p2p update v2` || version (u64 big-endian) || APK, then a 4-byte big-endian length with a 64 MiB cap. The version is inside the signed bytes, so a version edited in transit fails the signature. `verify_update` checks the signature first, then refuses any version that is not strictly greater than the installed version (`CoreError::Downgrade`), so an equal or older build is refused. The installed version comes from the app (`longVersionCode`), not from the peer. Questions for the reviewer: whether the signed message is unambiguous, whether the rollback rule holds when the installed version cannot be read (every update is refused in that case), and whether the single developer key needs rotation or key-ID support. Android's installer downgrade check was not verified and is not relied on.
6. **Two-code pairing QR** (`rust-core/src/pairing.rs`, `split`, `Assembler`). The v1 payload is sent as two QR codes. Each part has a 10-byte header (index, count `2`, and an 8-byte id: the first 8 bytes of SHA-256 over `sovereign-p2p v1 pairing part id` and the whole payload). Reassembly refuses a missing, duplicated or mismatched part, and refuses a complete set whose joined bytes do not match the id. Question for the reviewer: whether an unkeyed, truncated hash is adequate as an integrity check across parts. It is not authentication; the fingerprint compared in person is the trust step. Not scanned by a camera on a phone.

Also noted: the frame header is bound as associated data (`ratchet.rs` `aead_seal`, `double_ratchet.rs` `header_bytes`). The skipped-key cache wipe on drop is verified by a test that reads the cache in place (`skip_cache_wipe_zeroizes_every_stored_key`), not by reading freed memory.

## Verification

| Command | Result |
| --- | --- |
| `cargo test --manifest-path rust-core/Cargo.toml` | 111 passed, 0 failed (baseline was 104; 7 added) |
| `cargo clippy --manifest-path rust-core/Cargo.toml --all-targets -- -D warnings` | exit 0 |
| `cargo fmt --manifest-path rust-core/Cargo.toml -- --check` | exit 0 |
| `.\gradlew.bat :app:testDebugUnitTest --rerun-tasks` (JAVA_HOME JDK 17) | BUILD SUCCESSFUL, 33 tests, 0 failures (`PairingCodecTest.scannedPayloadPinsThroughTheCore` passed on this run) |
| `cargo test --offline` in `rust-core`, 2026-10-25 docs pass | 155 passed (count unchanged by this pass; doc comments only) |

Not verified: FLAG_SECURE on a device; `mlock` on Android or Linux (F1, F2); the independent cryptography review; any run between two phones; the update send from the Updates screen; the two-code QR scan with a camera.
