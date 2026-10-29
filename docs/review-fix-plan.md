# Plan: fix the code-review findings with subagent-driven development

Source: the full review of main at `d822ed2` (2026-10-29). Finding numbers (1, 2.1 to 2.9, D) match that review.
Nothing here is done yet. Tick a box only when the task's acceptance checks have been run and passed.

## Owner decisions (2026-10-29)

- **T1:** role-based stepping. Approved.
- **T7:** add a responder ephemeral key to the handshake (wire change). Approved.
- **T9:** add the liveness ping. Approved.
- **T10:** dropped. Keep the current behaviour (contacts connect right after the scan). Finding 2.7 is accepted and only documented in `docs/status.md`.
- **T12:** CI runs the Rust checks only, including the Tor feature. No Android build in CI yet.

## How the work is run

One orchestrator (the main session) owns the plan, the branch and the merges. It never writes fix code itself. Every task goes to a fresh **implementer** subagent, then to a separate **reviewer** subagent. The reviewer gets the diff and the finding, not the implementer's summary or conclusion.

Rules for every task:

1. **Test first.** The implementer writes the failing test, shows it failing for the stated reason, then fixes. CLAUDE.md requires a success-path test and a failure-path test for new crypto code.
2. **Brief.** Each implementer prompt contains: the finding text, the files it may touch, the acceptance checks, the hard rules from `CLAUDE.md` (no plaintext in errors, zeroize, no new persistence, no invented crypto), and what it must not touch.
3. **File ownership.** Tasks in the same wave touch disjoint files, so they can run in parallel in separate worktrees (`isolation: worktree`). Tasks that share `ffi.rs` run one after another.
4. **Gates, per task:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and `mise run rust:lint:tor` plus `mise run rust:test:tor` when `tor.rs` or `ffi.rs` change. Kotlin tasks also run `mise run android:debug` and the JVM tests; those need the Android SDK, so run them on the owner's machine if this sandbox has none.
5. **Review.** The reviewer re-reads the diff against the finding and the hard rules and tries to break it. A task is done only when the reviewer reports nothing blocking. At most two fix-and-review rounds; after that the orchestrator escalates to the owner.
6. **Docs in the same change.** Anything that changes behaviour updates `PLAN.md` Decisions and, where a claim changes, `docs/status.md` (rule 7: be honest in docs).
7. **Commits.** One commit per task, short imperative subject, body explains why. No model name or AI attribution in commits or PR text (CLAUDE.md).
8. **Branch.** Work on `ccr-29e96103-3768mm`, restarted from the latest main because PR #7 is merged. Open one draft PR per wave and subscribe to it.
9. **Owner decisions.** Tasks marked **[OWNER]** stop at a written proposal. No code is written until the owner approves. Rule 6 (no invented crypto, no parameter-set change without a `PLAN.md` note) applies to T1 and T7.

## Wave 0: baseline (orchestrator, no subagent)

- [ ] Restart the branch from `origin/main`.
- [ ] Record the baseline: `mise run rust:lint`, `mise run rust:test`, `mise run rust:test:tor` all green. If the Tor build is red before any change, report that first.
- [ ] Add the throwaway crossing-messages test from the review as a permanent failing test (`rust-core/tests/ratchet_crossing.rs`) so T1 has a target.

## Wave 1: correctness (blocks everything else)

### T1. Ratchet desync when both sides send at once (finding 1) [design approved: role-based stepping]

**Files:** `rust-core/src/double_ratchet.rs`, `rust-core/src/ffi.rs` (`session_for` and its two callers), `rust-core/tests/ratchet_crossing.rs`, `PLAN.md`.

**Cause:** both sides start with no peer key and both become "pending" after the first handshake-chain message. If both then take a DH step before seeing the other's new key, the DH inputs no longer match.

**Proposed design (the implementer writes this up first, owner approves):** break the symmetry with the handshake roles. Only the initiator marks itself pending after the first handshake-chain message. The responder keeps its first ratchet key until it receives the initiator's first new key, then steps as usual. After that, "pending" is set only by receiving a new key, and a step needs "pending", so steps strictly alternate and cannot cross. `DoubleRatchet::new` takes a role (the labels already imply it). Alternative to compare in the write-up: keep the old and new DH state until a peer message authenticates.

**Acceptance:**
- `ratchet_crossing.rs` passes: crossing first texts, crossing acks, then ten messages each way in both orders, all open.
- Randomised test: 200 interleavings of sends and delivers between two ratchets, with delays and in-order delivery per direction, never ends in `Auth`.
- Existing ratchet tests still pass: tamper, replay, out-of-order within `MAX_SKIP`, failed write leaves state unchanged, post-compromise recovery.
- The module header and `PLAN.md` Decisions describe the new rule. The "known limit" text is removed or narrowed, and `docs/status.md` follows.

### T2. Recover from a dead session instead of showing it as live (finding 1, defence in depth)

Depends on T1 (shares `ffi.rs`). **Files:** `rust-core/src/ffi.rs`, `app/.../core/PeerConnections.kt`, `app/.../core/CoreBridge.kt`, tests on both sides.

- Count consecutive `Auth` failures per session in the core (a counter on `Session`, reset on any successful open). Past a small threshold (for example 5), mark the session `dead`, so the existing redial path runs a new handshake.
- The UI keeps the "message failed authentication" note until the new handshake succeeds.
- A single forged frame must not kill a session: the threshold counts only consecutive failures, and a good frame resets it.

**Acceptance:** a Rust test that corrupts N consecutive frames and sees the session go dead and `linked_peers` drop it; a test that one bad frame between good ones does not; a Kotlin test that the loop redials after the session dies.

## Wave 2: independent fixes (run in parallel, disjoint files)

### T3. APK receive gets a total deadline (finding 2.4)
**Files:** `rust-core/src/apk_transfer.rs`, its tests. Add one overall deadline for the whole transfer (in addition to the per-read timeout) and refuse once it passes. Reserve the buffer in steps as bytes arrive, not all of `len` up front, so an idle peer cannot pin 64 MiB. **Acceptance:** a test with a sender that trickles one byte per interval is cut off at the deadline; a normal large transfer still succeeds; a test that memory is not reserved before data arrives.

### T4. Reject low-order X25519 points in the handshake (finding 2.8)
**Files:** `rust-core/src/handshake.rs`, `rust-core/src/pairing.rs`, tests. Check `was_contributory()` on every DH output (ephemeral and static) and refuse with `CoreError::Malformed`. Extend the QR decode check beyond all-zero. **Acceptance:** tests with each known low-order point on both the QR and the handshake paths are refused; normal handshakes unchanged. Existing handshake tests pass.

### T5. Crash report cannot carry user text (finding 2.3)
**Files:** `app/.../CrashReport.kt`, `CrashReporting.kt`, `CrashReportTest.kt`. Print the exception message only for `FacadeException` (fixed strings) and a short allow-list of framework types; for every other type print the class name and stack only. Reword the screen text so it matches what is guaranteed. **Acceptance:** a JVM test where a `NumberFormatException` built from a fake chat message produces a report that does not contain that message; existing report tests pass.

### T6. Wipe the old Messenger when the identity is deleted (finding 2.2)
**Files:** `app/.../SovereignApp.kt`, a small test seam in `CoreBridge`. Call `wipeAll()` (and drop sessions) on the old core before `vault.delete()` and `start()`. If the bindings expose an explicit destroy, call it too. **Acceptance:** a JVM test that after `deleteIdentity` the old messenger has no peers, history or sessions, and a new identity has a different fingerprint.

## Wave 3: core hygiene in `ffi.rs` (serialised, after T2)

### T7. Handshake forward secrecy against later key compromise (finding 2.1) [approved]
The implementer writes the exact frame and HKDF layout into `PLAN.md` Decisions before coding. The responder's challenge frame carries a fresh responder ephemeral X25519 key; the initiator adds `DH(eph_i, eph_r)` to the HKDF input, so a stolen long-term key no longer opens recorded sessions. This changes the wire (the challenge frame grows from 33 to 65 bytes) and the HKDF input, so it needs a new `v2` label, a `PLAN.md` Decisions entry and updated frame docs. If the owner declines, the fallback is documentation only: state the limit in `docs/status.md` and the security table. **Acceptance if approved:** both sides agree on the root; a recorded handshake does not yield the root from the responder's long-term keys alone (test with the static secrets known); replay and wrong-challenge tests still refuse; the frame-length tests are updated.

### T8. Per-peer state hygiene and lock scope (findings 2.5 and 2.9)
**Files:** `rust-core/src/ffi.rs`, tests. Clear `read_owed` and `last_seen` in `forget`, `unpin` and `wipe_all`. In `flush_pending`, do not hold the ratchet lock across the blocking write: seal under the lock, send outside it, commit after (keep the "state advances only after a successful write" rule). **Acceptance:** a test that a read receipt owed before `forget` is not sent into a new session; a test that a receive is processed while a send is blocked on a slow transport.

### T9. Liveness check (finding 2.6)
**Files:** `rust-core/src/ffi.rs`, `wire.rs`, `envelope.rs`, tests. Add a small authenticated ping envelope (new kind byte; ids carry nothing secret) sent after a quiet interval, and mark the session dead if nothing arrives within a bound. This is a wire change: `PLAN.md` entry, and the envelope table in `envelope.rs` is updated. **Acceptance:** a silent peer is detected within the bound; normal traffic never triggers a ping; unknown kinds from an older build are still refused cleanly.

## Wave 4: pairing flow (finding 2.7)

### T10. DROPPED by the owner (finding 2.7 stays as is)

Original proposal, kept for the record:
**Files:** `app/.../ui/PairingScreen.kt`, `PeerConnections.kt`, `CoreBridge.kt`, tests. Keep the contact pinned but hold dialling and accepting until the user confirms the fingerprint match on the result step (state kept in RAM only). "They do not match" removes the contact. **Acceptance:** a JVM test that a freshly pinned contact is not dialled until confirmed; after confirmation the loop starts; the confirmed flag is not persisted (rule 1).

## Wave 5: docs and process (finding D)

### T11. Make the docs match the code
**Files:** `docs/hardening-review.md` (close F2 with a pointer to the 2026-10-24/25 decisions), `docs/status.md` (updates feature exists but is disabled with no key; identity deletion is in Settings; new ratchet rule; handshake limit or T7; test counts), `app/.../core/Navigation.kt` (stale `rememberSaveable` comment), `README.md` if a claim changes. **Acceptance:** a reviewer cross-checks each changed sentence against the code and finds no claim the code does not back.

### T12. Add CI (Rust checks only)
**Files:** `.github/workflows/ci.yml`. Run `cargo fmt --check`, clippy `-D warnings`, `cargo test`, and the Tor-feature lint and test on every push and PR. No Android build. **Acceptance:** the workflow is green on the PR that adds it. No secrets, no release steps (only the owner publishes releases).

## Order and parallelism

```
Wave 0 -> T1 -> T2 -----------> Wave 3 (T7, T8, T9 in turn) -> T11
          |                                                      ^
          +--> Wave 2 (T3, T4, T5, T6 in parallel) ---------------+
                                  T10 (after T2: both touch PeerConnections) -> T11 -> T12
```

T3, T4, T5 and T6 start as soon as Wave 0 is done, in parallel with T1, because they share no files with it. T2 and T8 to T10 wait for the files they share. T11 runs last so the docs describe the final state. T12 can run any time but is listed last so the first CI run covers all the fixes.

## Done when

- Every box above is ticked, with the reviewer's "nothing blocking" recorded for each task.
- Rust fmt, clippy and tests are green, including the Tor feature; the Kotlin build and JVM tests are green on the owner's machine.
- The crossing-messages regression test passes and stays in the suite.
- `PLAN.md` Decisions lists every behaviour change; `docs/status.md` makes no claim the code does not back.
- Owner decisions are recorded above; T10 is dropped.
- Still **not** verified by this plan: anything on a real phone or between two phones, and independent cryptography review. Those stay on `docs/owner-test-list.md`.
