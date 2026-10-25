# Remaining work plan

> **Historical.** Written on 2026-10-24. Parts are out of date: Tor is now built (not "not implemented"), identities now persist, and the branch is pushed. `PLAN.md` and `docs/owner-test-list.md` are current.

_Written 2026-10-24, after the plan/complete-remaining branch (commits 71060c3 to fda61d0). PLAN.md is the checklist; this file says how to finish what is left, in what order, and who has to do each step. Where the two disagree, PLAN.md is the record of what is verified._

## Where things stand

- All seven build sections of PLAN.md have code. Rust: 115 tests pass, clippy and fmt clean. Android: the debug build succeeds; the JVM suite is green except one intermittent QR test (see issue R1).
- Nothing has run between two phones. Everything transport-related is tested on loopback in one process.
- Nothing has been reviewed by anyone independent.
- The branch `plan/complete-remaining` is not pushed and not merged.

The work below is split by who can do it. Phase A is code I or a subagent can do now. Phases B to D need hardware, a person, or a decision from the owner, and no amount of code finishes them.

## Phase A: fix what the code can fix now

Each item lists its test first, following the project's TDD rule.

**A1. The `munlock` bug (open, real). Priority: high.**
- Problem: on Linux and Android, `munlock` is not reference counted per page. Dropping one small `SecretBytes` can unlock a live neighbour that shares its page. Triggers: `lockReport()` drops a probe each call; `forget` and `wipe_all` drop stored messages.
- Test first: a Linux-only test (`cfg(target_os = "linux")`) that reads `/proc/self/smaps` (or `mincore`) to show that dropping one lock does not unlock a live neighbour. It must fail on the current code.
- Fix options, choose one and record it in Decisions:
  - (a) allocate secrets on dedicated pages so one page never holds two secrets;
  - (b) stop calling `munlock` and report that memory is locked for the life of the process.
  - Recommendation: (b) for this release. It is simpler and removes the bug. Cost: locked pages stay locked until exit, which uses a little more RAM.
- Needs a Linux environment. This machine is Windows; use WSL or a Linux CI runner.

**A2. QR decode reliability (open, real). Priority: high.**
- Problem: `PairingCodecTest.scannedPayloadPinsThroughTheCore` failed once in the final full run. The payload is a fresh random identity each run, so some payloads decode unreliably at about 1.2 KB in ZXing byte mode at error level L.
- Test first: a loop test that encodes and decodes 200 random payloads and asserts the decode success rate is 100%. It fails today if the problem is real; if it passes, the failure was elsewhere and the test should say so.
- Likely fixes, in order: make the quiet zone and scale match ZXing's expectations in the test; move to a larger module size; or split the payload across two QR codes if decode stays unreliable. A payload split changes the wire format, so it needs a Decisions entry.
- Also needed: a real phone scan of a real code (see Phase B).

**A3. Tour copy says Tor (false claim). Priority: high, quick.**
- `TourScreen.kt` says the phone talks "over Tor onion services". There is no Tor transport. This breaks CLAUDE.md rule 7.
- Change the copy to say the phones connect directly over the local network, and that Tor is not implemented. The wording is yours to approve; I'd propose exactly that. Do not ship the current text.

**A4. Screen rotation may wipe chats (unverified). Priority: high.**
- `AndroidManifest.xml` has no `configChanges`, so rotation recreates the activity, runs `onStop`, and calls `wipeAll()`. Code reading says this happens; no device has confirmed it.
- Test first: a JVM test of the lifecycle policy (extract the decision "wipe on stop only when leaving the app, not on rotation" into a pure function and test it). Fix the policy so rotation keeps state while leaving the app still wipes.
- Note: the app must still wipe on real background. Decide what "leaving" means (`ON_STOP` with `isChangingConfigurations` false is the usual check). Record it in Decisions.

**A5. Handshake replay (open, design).**
- A captured handshake frame can be replayed to a listener to replace its session. Per the subagent that built it, this cannot forge or read messages, but it can knock a live session over.
- Fix: add a fresh per-session nonce from the responder, bound into the root key, so a replayed handshake derives a different root and is refused. That changes the handshake wire format; record it in Decisions.
- Test first: a replay test that captures a handshake and replays it to a listener that has already completed one session. It must be refused.

**A6. Ratchet bootstrap deviation (design, needs review).**
- The first message from each peer uses a bootstrap without a DH step. It is a deliberate deviation from the standard Double Ratchet. Keep it, but do not claim it is standard. Section C2 covers the review.

**A7. Signed update has no rollback field (design).**
- A validly signed older APK verifies in the app. Android refuses a downgrade for the same signing key, which is expected but unverified here.
- Fix: add a version field into the signed bytes and refuse anything not newer than the installed version. This is a new wire format; add a Decisions entry and a test that an older signed APK is refused.

**A8. Sender-side update UI is missing.**
- A phone cannot send an update from the app yet. `send_update_to` is Rust-only.
- Add a "Send update" action on the Updates screen with a file picker. Test the file-selection logic in JVM. The send itself is then a Phase B device check.

**A9. "Secured P2P Mesh" title.**
- Review the existing title against CLAUDE.md rule 7. The app does not yet back the word "secured" with an audited claim. Propose "P2P Mesh" unless you want the stronger word after review (Phase C).

**A10. Ephemeral handshake key missing from the QR payload.**
- Deferred in section 2 and resolved in section 3 by generating it per session. Confirm in PLAN.md that the QR payload is correct as v1 and that no payload change is still pending. If a v2 payload is ever needed, bump the version byte.

**A11. Handshake frame docs.** After A5, update the wire layout in `wire.rs` and `docs/hardening-review.md` in the same commit.

Exit criteria for Phase A: each item above has a passing test that failed first, `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`, and the Android JVM suite are green, and PLAN.md's Decisions record every choice.

## Phase B: device and two-phone verification (needs hardware and a person)

Nothing in this phase can be done by code alone. You need two Android phones on the same Wi-Fi network (or an emulator pair), and the release or debug APK built from the Phase A commit.

**B1. Native library loads on a device.** Install the debug APK on one phone. Open the app. Create an identity. Expected: no `UnsatisfiedLinkError`. Failure here blocks everything else.

**B2. mlock report on Android (section 1).** Read the lock report on the device. Record the result in PLAN.md. If it is not locked, decide whether that is acceptable (see A1).

**B3. QR pairing on real phones (sections 2 and 3).**
- Phone A shows its QR code; phone B scans it. Expected: a pin with the fingerprint shown.
- Repeat in reverse.
- Scan a deliberately changed code: the key-changed card must appear.
- Scan the same code twice: the duplicate-pin message must appear.
- Record scan time and success for 20 scans. This is the field test for A2.

**B4. Two-phone chat (section 3).** Both phones pair. Phone A connects or waits; phone B connects to A's address. Send messages both ways. Expected: each message arrives once, in order. Then turn Wi-Fi off on one phone mid-conversation and confirm the app reports the link is down rather than hanging.

**B5. Ratchet over the air (section 4).** Send ten messages each way, then background one phone for 30 seconds and resume. Expected: the session either continues or asks for a re-handshake, with no silent corruption.

**B6. Update transfer and install (section 5).**
- Build an update with a test signing key (not the real release key) and set that key as the developer key in a debug build.
- Send the APK from one phone to the other over Wi-Fi.
- Expected: the fingerprint shows on the Updates screen; Install is offered only after the signature check passes; a tampered file is refused; the file is deleted after install or failure.
- Note: the real release key must not be used for this test.

**B7. FLAG_SECURE (section 6, item 3).** On the device, take a screenshot, start a screen recording, and open the recents thumbnail while in a chat. Expected: all three are blocked or blank. Record the result in `docs/hardening-review.md` and tick PLAN.md item only if all three pass.

**B8. Tour and chat flow (section 7, item 1).** Walk through `docs/usability-walkthrough.md` step by step on the device. Record every step that fails in PLAN.md's section 8.

**B9. Status indicator on the device (section 7).** Check the label appears in both headers, updates within about a second when the link changes, and shows no word that the app cannot back up.

Exit criteria for Phase B: each check has a recorded result in PLAN.md with the phone model, Android version and build commit. Tick a PLAN.md item only when its check passed on a device.

## Phase C: independent review (needs a person outside this project)

**C1. Send the cryptographic design for independent review.** The points are listed in `docs/hardening-review.md`, section 5:
- the static-static DH in the handshake root;
- the first-peer-key bootstrap without a DH step (A6);
- the skipped-key cache bounds (100 keys, MAX_SKIP 100);
- the TOFU pin model and the refused key change;
- the signed update format, with the rollback fix (A7);
- the handshake replay fix (A5).

Give the reviewer the wire layouts in `wire.rs` and the test files, not just the prose. Do not describe the design as secure to the reviewer; ask them to find the weaknesses.

**C2. Act on the review.** Each finding becomes a test that fails first, then a fix, then a Decisions entry. Critical findings block any real use of the app.

**C3. Publish the review result.** Record who reviewed, what they covered, and what they found, in `docs/`. PLAN.md item "Independent review" is ticked only when this exists.

Exit criteria: a written review exists in the repo, and every finding is either fixed with a test or accepted with a Decisions entry naming the owner.

## Phase D: owner decisions and release

These are yours. I have not made them and will not without your word.

**D1. Developer signing key.** Generate the offline Ed25519 key. Put the public half in `DEVELOPER_PUBLIC_KEY`. Store the private key outside the repo, backed up, as the release key already is. Until this is done, no update can install (`DEVELOPER_PUBLIC_KEY` is `None`).

**D2. Tor or not for the next release.** Tor is not implemented. Decide whether the next release ships with LAN-only transport (the honest current state, labelled as such) or waits for Tor. Recommendation: label LAN-only and ship it as experimental, since Phase C is not done.

**D3. Chats and lifecycle.** Confirm the A4 policy: rotation keeps chats, leaving the app wipes them.

**D4. Release.** Only you publish a release (CLAUDE.md). A release needs: Phase A exit criteria met, Phase B checks passed on at least two phones, and Phase C review either done or the release labelled as unreviewed. The pre-release `v0.1.0-experimental` already says it should not be used for real conversations; keep that label on any build until Phase C is done.

**D5. Owner testing (PLAN.md section 8).** You install the pre-release, test it, and report findings. Findings feed back into this plan as new Phase A items.

## Known issues not in any phase yet

- **R1. Intermittent JVM test failure.** `PairingCodecTest.scannedPayloadPinsThroughTheCore` failed once in the final full run and passed five reruns. Covered by A2. Do not mark it "flaky" in any report until A2 says why.
- **R2. Incident.** A subagent ran `rm -rf` on `C:\Users\Calum\repos\AppData` during section 5. The directory is gone and its contents are unknown. If anything of yours was there, it is not recoverable from this repo. Check your own records for it.
- **R3. Subagent commit attribution.** The commits carry no AI attribution, following CLAUDE.md. A system reminder asked for a Co-Authored-By line. If you want one, tell me and I will amend the policy text, not the history.

## Order of work

1. A3 (copy fix) and A4 (lifecycle policy): small, high value, no hardware.
2. A1 and A2: need Linux for A1; A2 can start on Windows.
3. A5 and A7: design changes, then tests, then a Decisions entry each.
4. A8, A9, A11: small follow-ups.
5. Phase B on two phones, once a build from Phase A exists.
6. Phase C: the review, which you arrange.
7. Phase D: your decisions, then release.

Phases A and B cannot be run in parallel on the same files. A1 and A2 can run while you arrange hardware for B.

## What "done" means

The project is done for an experimental release when Phase A is green, Phase B is recorded on two phones, and Phase C has either happened or the release says plainly that it has not. Until then, the README and PLAN.md must keep saying that the code is untested between phones and unreviewed.
