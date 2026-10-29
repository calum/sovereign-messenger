# Hardening review

Date: 2026-10-24; section 5 updated 2026-10-25 for the wire changes; F2 to F4 closed and sections 1 and 5 brought up to date 2026-10-29 (the 2026-10-24/25 text is kept where it is history, marked as such). Scope: PLAN.md section 6. Each finding says what was checked, whether it is sound, and what was done. Items that need a phone or an independent party are marked NOT VERIFIED.

## 1. `unsafe` blocks and `mlock` calls

Method: `grep -rn "unsafe|mlock|munlock" rust-core`.

Result as first written: two `unsafe` blocks, both in `rust-core/src/secret.rs`, both calling `libc` and both behind `#[cfg(unix)]`. No other `unsafe` exists in rust-core. `mlock` and `munlock` were called only from `secret.rs`. Update 2026-10-29: `munlock` is no longer called anywhere (see F2), so one `unsafe` block remains: the `mlock` call (`lock`, line 49). `ffi.rs` (`lock_report`) and `store.rs` (`lock_count`) only read the lock state.

### F1. `secret.rs` `lock()`, the `mlock` call (line 49 today): sound

- The pointer and length come from the `Vec<u8>` owned by the `SecretBytes`. `SecretBytes::new` sets the capacity to `max(len, 1)` and fills it once, so the `Vec` is never reallocated and the locked range is the live buffer.
- On failure `mlock` returns non-zero and `lock` returns `false`. (When this was written an `munlock` followed only for a locked buffer; it is gone now, see F2.)
- An empty buffer returns `true` without a syscall. Nothing is locked, so this is harmless.
- Not exercised here. On this Windows host `cfg(unix)` is false, so `lock` always returns `false` and the tests never call `mlock`. The Android path has not been run on a device.

### F2. `munlock` unlocking a neighbour's page: REAL PROBLEM, CLOSED 2026-10-24/25 by removing `munlock`

Status: closed. `SecretBytes::drop` in `secret.rs` now zeroizes the buffer and does not call `munlock`; pages stay locked until the process exits. See PLAN.md Decisions, 2026-10-24 "munlock removed (plan A1)" and 2026-10-25 "the allocator test is rewritten". The original finding is kept below because the reasoning still explains the rule.

- The problem (as found): Linux and Android lock memory per page, and `munlock` is not reference counted. Unlocking a range clears the lock on every page it touches, including a page that another live `SecretBytes` shares. Stored messages are many small `SecretBytes` (`store.rs`), so they share pages, and dropping one could silently remove the lock from another that was still live. `lock_report()` (a 32-byte probe dropped on every call), `forget` and `wipe_all` were the concrete triggers.
- The fix taken was option (b) from the original write-up: stop calling `munlock`. The cost is accepted: the locked total follows the heap high-water mark and can use up `RLIMIT_MEMLOCK`, which `SecretBytes::is_locked` reports at construction.
- Evidence: `rust-core/tests/mlock_neighbour.rs` (Linux only) allocates 1000 small secrets so some must share a page, drops one, and reads `/proc/self/smaps` to check that the neighbour's page is still locked. On Linux it passed, failed when `munlock` was put back in `drop`, and passed again after the revert (PLAN.md Decisions, 2026-10-25). It has not run on Android or on a phone.
- Option (a), a page-granular allocation per secret, was not chosen.

### F3. `ffi.rs` `lock_report()`: part of F2, CLOSED with it

`lock_report()` still creates and drops a probe `SecretBytes` on every call. Since `drop` no longer calls `munlock`, that cannot unlock anyone's page.

### F4. `is_locked` reports at construction time only: still true, no longer misleading

The value is still a snapshot taken when the buffer is made. With `munlock` gone, a lock that held at construction stays held until exit, so the snapshot no longer goes stale.

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

- `Identity::from_secrets` copies the 64-byte seed with `.into()` into a temporary that the caller's `seed.zeroize()` does not clear (`generate` now goes through it). CLAUDE.md lists this as a known gap for `Identity`.
- The vault (`rust-core/src/vault.rs`, added 2026-10-25) adds two exposures. `Messenger::data_key` returns the 32-byte data key as a `Vec<u8>` that crosses into Kotlin once, so the plaintext key sits on the Java heap while it is wrapped or unwrapped; `IdentityVault` zeroes the array straight after, but the JVM may have copied it. `restore` takes it back the same way. Separately, `Identity` now keeps the ML-KEM seed in a `SecretBytes` so it can be sealed. The serialised vault contents are built in a `Zeroizing` buffer. A reviewer should check the vault format (`version || nonce || ciphertext`, version and a fixed label as associated data, random 96-bit nonce per seal) and the claim that the number of seals under one key stays small.
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

1. **Static-static DH in the handshake root** (`rust-core/src/handshake.rs`, `derive_root`). The root is HKDF-SHA256 over `ephemeral DH || ML-KEM secret || label || static DH`, with no salt. The static DH authenticates the initiator (the responder compares the static key with its pin). Questions: whether the fixed-length concatenation without a length prefix is unambiguous, and whether a low-order pinned key (which gives an all-zero static term) is acceptable. Update 2026-10-29: `was_contributory` is now checked on both DH outputs in `initiate` and `respond`, and a low-order key is refused as `Malformed`; `pairing::decode` refuses every small-order key, not only all-zero (PLAN.md Decisions, 2026-10-29). The root layout and labels are now the `v2` ones, with a responder ephemeral DH term (PLAN.md Decisions, 2026-10-29, handshake v2); the layout described in this item is the 2026-10-24 one. The new layout is also not independently reviewed.
2. **First-peer-key bootstrap without a DH step** (`rust-core/src/double_ratchet.rs`). Both sides start from the handshake root with the same chain labels, and the first peer key is accepted without a DH step. This is a deliberate deviation from the standard Double Ratchet (PLAN.md Decisions, "DH ratchet design"). Limits (a) to (c) are listed there; limit (a), crossing first steps, was superseded 2026-10-29 by role-based stepping (only the handshake initiator steps first; PLAN.md Decisions, 2026-10-29), which is itself not independently reviewed. Limit (b), a handshake-chain message overtaken by the initiator's first step is refused, still applies. Question: whether the start-up chains give the security the design claims.
3. **Skipped-key cache bounds** (`rust-core/src/ratchet.rs`). `MAX_SKIP` 100 counters per receive, `MAX_CACHED_KEYS` 100 keys per cache, oldest key evicted. Question: whether the bounds are safe against an attacker who can send forged large counters, and whether the eviction policy leaves a gap for an attacker who forces evictions.
4. **TOFU pin model and handshake replay** (`rust-core/src/ffi.rs`, `pin_or_check`, `scan_pairing`, `unpin`; `rust-core/src/handshake.rs`). Pins are made on first use, held in RAM, and survive `forget` and `wipe_all`. A different key is refused with `PinChanged`. Question: whether the first-contact pin is safe when a stranger can reach a listener before the real peer does. **Handshake replay, changed since the 2026-10-24 review (fix to be checked):** the responder sends a fresh 32-byte challenge once per connection (frame tag `0x03`; since 2026-10-29 the frame is 65 bytes, the challenge plus a responder ephemeral X25519 public key), and the initiator's handshake (tag `0x01`) ends with a confirmation tag, HMAC-SHA256 keyed with the root over the public handshake values and the challenge. The challenge is also an input to the root. A captured handshake replayed to a later connection carries an old challenge, so the tag fails and no session is stored. Tests: `rust-core/tests/handshake_replay.rs`. Question for the reviewer: whether the binding, the tag construction and the one-time use of each challenge are sound. Not tested between two phones. Also since 2026-10-29: a session that fails to open 5 frames in a row, or hears nothing for 75 s, is declared dead and its link closed, and a small ping goes out after 25 s idle (PLAN.md Decisions, 2026-10-29).
5. **Signed-update format and rollback, changed since the 2026-10-24 review (fix to be checked)** (`rust-core/src/update.rs`, `rust-core/src/apk_transfer.rs`). The update frame is v2: a detached 64-byte Ed25519 signature over `sovereign-p2p update v2` || version (u64 big-endian) || APK, then a 4-byte big-endian length with a 64 MiB cap. The version is inside the signed bytes, so a version edited in transit fails the signature. `verify_update` checks the signature first, then refuses any version that is not strictly greater than the installed version (`CoreError::Downgrade`), so an equal or older build is refused. The installed version comes from the app (`longVersionCode`), not from the peer. Questions for the reviewer: whether the signed message is unambiguous, whether the rollback rule holds when the installed version cannot be read (every update is refused in that case), and whether the single developer key needs rotation or key-ID support. Android's installer downgrade check was not verified and is not relied on.
6. **Two-code pairing QR** (`rust-core/src/pairing.rs`, `split`, `Assembler`). The v1 payload is sent as two QR codes. Each part has a 10-byte header (index, count `2`, and an 8-byte id: the first 8 bytes of SHA-256 over `sovereign-p2p v1 pairing part id` and the whole payload). Reassembly refuses a missing, duplicated or mismatched part, and refuses a complete set whose joined bytes do not match the id. Question for the reviewer: whether an unkeyed, truncated hash is adequate as an integrity check across parts. It is not authentication; the fingerprint compared in person is the trust step. Not scanned by a camera on a phone.

Also noted: the frame header is bound as associated data (`ratchet.rs` `aead_seal`, `double_ratchet.rs` `header_bytes`). The skipped-key cache wipe on drop is verified by a test that reads the cache in place (`skip_cache_wipe_zeroizes_every_stored_key`), not by reading freed memory.

## Verification

The table is the 2026-10-24/25 record and its counts are not current; `mise run check` is the source of truth, and the 2026-10-29 fixes ran their own checks (see PLAN.md Decisions).

| Command | Result |
| --- | --- |
| `cargo test --manifest-path rust-core/Cargo.toml` | 111 passed, 0 failed (baseline was 104; 7 added) |
| `cargo clippy --manifest-path rust-core/Cargo.toml --all-targets -- -D warnings` | exit 0 |
| `cargo fmt --manifest-path rust-core/Cargo.toml -- --check` | exit 0 |
| `.\gradlew.bat :app:testDebugUnitTest --rerun-tasks` (JAVA_HOME JDK 17) | BUILD SUCCESSFUL, 33 tests, 0 failures (`PairingCodecTest.scannedPayloadPinsThroughTheCore` passed on this run) |
| `cargo test --offline` in `rust-core`, 2026-10-25 docs pass | 155 passed (count unchanged by this pass; doc comments only) |

Not verified: FLAG_SECURE on a device; `mlock` on Android (F1; the F2 neighbour test passed on Linux only); the independent cryptography review; any run between two phones; the update send from the Updates screen; the two-code QR scan with a camera.

## 6. Tor metadata review (preliminary, 2026-10-25)

This section is written from the design and the code, not from a measurement. Nothing has run over the real Tor network from the app, so every "an observer cannot" below is a design intent that T4 must check.

**What the design is.** Each phone runs one v3 onion service, with its key built in memory from the identity. Contacts are pinned in person from the QR code, which carries the onion address, so no address is ever sent over a network. A conversation is one onion stream between two phones; the handshake and ratchet run unchanged inside it. There is no exit node, no relay of ours and no server.

**An observer on the phone's network (ISP, Wi-Fi owner, mobile carrier) can learn:**
- that the phone is using Tor, and when, from the connections to Tor guards;
- roughly how much traffic flows and when (volume and timing), not which contact it is for;
- the first-launch directory download, which is large and recognisable.

**They cannot learn, if Tor works as designed:** who the phone talks to, what the contact's address is, or any message content or length beyond what Tor cell padding leaves visible.

**A Tor-level or global observer who sees both ends can** correlate timing and volume between two phones. Tor does not defend against that. A conversation between two always-on phones with short chat messages is easy to correlate. Message length is also visible in ciphertext length, rounded up to Tor's 512-byte cells; the ratchet does not pad.

**Things in this app that weaken it:**
- The onion address is stable for the life of the identity. Anyone who learns a contact's address can watch whether that service is up. The address is public by design (it is in the QR code).
- The same-Wi-Fi TCP path is still in the app as a test connection. It reveals both phones' local addresses to the network and is not private. It must not be used for real conversations.
- The APK transfer is over local Wi-Fi by design and reveals both phones to that network for the minutes it runs. It is done in person.
- Tor keeps a directory cache and guard state in `filesDir/tor`. They show that Tor was used on this phone to anyone who can read the app's files. They hold no key or message.
- The first publish of an onion service took about 5.6 minutes in the T0 run, and the service is rebuilt every launch because the in-memory keystore regenerates arti's other keys. During that time the phone cannot be called.
- A stranger who learns a contact's onion address can open connections to it and hold each one open without finishing the handshake. A responder waits 20 seconds for the initiator's handshake (60 seconds is the general limit for the dialing side), a stream queued for more than 45 seconds is dropped unread, the queue holds 8 streams after which new ones are dropped, and the app runs 4 accept workers. A few stalled callers therefore cost real contacts seconds, not minutes, but a determined flood still delays or drops legitimate calls. Arti has an onion-service proof-of-work defence for this; it is marked experimental and is not enabled. Not tested under load.
- Superseded 2026-10-29: leaving the app no longer wipes chats (see PLAN.md Decisions). Chats and sessions now live until Android stops the process. If it does, coming back needs a new handshake, the dialing side must reach the other phone's onion service again (which can take minutes), and messages do not survive.
- Android may stop the app's process in the background. The onion service then goes away until the app is open again, so a contact cannot reach a phone whose app is closed.

**To check in T4:** no LAN address in packet captures while on mobile data with Wi-Fi off; the phone reaches Ready from a cold start and from a warm start; a message sent while the other side is closed is not delivered and not stored; the unreadable-vault and delete flows leave no Tor state behind.

## 7. Independent review of the vault and Tor code (2026-10-25)

A reviewer that had only the commit range and CLAUDE.md read `53e3c95..6ddbb54` and reported six defects and two minor ones. Each was checked against the code and fixed with a test written first. They were: (1) a Tor link held only a runtime handle, so replacing or stopping the node while a session was open made the next poll panic, which aborts the app; links now keep the runtime alive and the runtime shuts down in the background, so it can be dropped from anywhere; (2) `tor_start` dropped the old node while holding the state lock; it now stops it outside the lock; (3) the vault encoder let its buffer grow and so left unwiped copies of the identity secrets in freed memory; it is now sized exactly; (4) the onion seed copy and the caller's data-key vector were not wiped; both now are; (5) stopping Tor did not stop the accept workers and identity deletion ran on the UI thread; `shutdown` now makes waiting accepts return at once, ends the sessions that ran over Tor, and deletion runs on the IO dispatcher; (6) a stalled stranger could hold a worker for a minute, see section 6; and (minor) the same identity could be pinned under two labels or your own code as a contact, and the chat screen could dial twice. The reviewer found no authentication bypass in `respond_on_link`, no way for the onion key or vault to reach disk in plaintext, no remote-reachable panic in the parsers, and no lock-order violation.

Not fixed or not tested: the data key still exists as a plain array in the UniFFI buffers and on the Java heap while it is wrapped (the owner accepted the Java-heap part); deleting the identity while a worker still holds the old node can leave arti writing to the deleted Tor folder for a few seconds; the double-dial guard has no test because it needs a call that blocks.
