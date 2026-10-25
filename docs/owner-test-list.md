# Tests for the owner to run

Things I could not run myself: they need the real Tor network, a phone, or your hardware.
Run them when you have time, in this order, and paste the output back. Each item says what
a pass looks like. New items are appended at the end; nothing here has been run yet.

Last updated: 2026-10-25 (after the first results from A1 to A3).

## A. On your laptop, in WSL (Ubuntu 24.04)

These need an unfiltered internet connection. They use the Rust core with its Tor feature.

### A1. Warm restart of the spike. DONE 2026-10-25

Why: the first publish took 5.6 minutes. This shows whether saved state makes later starts fast.

```bash
cd ~/sovereign-messenger/spikes/t0-arti
# Ctrl+C the old server first, then reuse its state folder:
./target/debug/t0-arti server /tmp/t0s
```

Result: bootstrap 11.16 s, publish 67.65 s with saved state (334 s the first time). Recorded in PLAN.md.

### A2. The real Tor test of the core. DONE 2026-10-25, all 3 PASSED

Why: this is the first time the product code (not the spike) talks to real Tor. It starts two
nodes, pairs them, dials one from the other over Tor, and sends a message each way.

```bash
cd ~/sovereign-messenger
git pull
cd rust-core
cargo test --features tor --test tor_live -- --ignored --nocapture --test-threads=1
```

Result: all three passed. The two-identity test connected over Tor (handshake 8.6 s) and a
message arrived in 143 ms. Recorded in PLAN.md ("Tor live results").

### A3. The ordinary test suite with Tor compiled in. DONE 2026-10-25, everything passes

```bash
cd ~/sovereign-messenger
git pull
cd rust-core
cargo test --features tor --no-fail-fast
```

Result: with `--no-fail-fast`, every test passes on the owner's machine, including the rewritten
allocator test (`dropping_one_secret_keeps_a_live_neighbour_on_its_page_locked`). This is the first
run of that test on a machine other than the cloud sandbox.

## B. On a phone (one phone is enough for B1 to B4)

Build the app on your Windows machine, in Git Bash, from the repo root:

```bash
mise run rust:android      # builds the core with Tor for arm64-v8a and x86_64 (about 10 minutes)
mise run android:debug     # builds the debug APK
```

Install `app/build/outputs/apk/debug/app-debug.apk`. To install it on the phone without a cable, put the phone on the same Wi-Fi as the laptop (not a guest network) and run `mise run android:share`. Scan the QR code with the phone's camera, open the link, and install. Press Ctrl+C on the laptop when you are done.

### B1. The app starts and the native library loads

Pass: the app opens with no crash. (A crash with `UnsatisfiedLinkError` is the one to report.)

### B2. The identity survives a restart

1. Open "Pair a contact" and note the fingerprint shown for this phone.
2. Close the app fully (swipe it away), reopen it, and look at the fingerprint again.
3. Restart the phone, open the app, and look once more.

Pass: the same fingerprint all three times.

### B3. Tor comes up, and how long it takes (first time and later)

1. Fresh install, Wi-Fi or mobile data on. Open the app and watch the line under the title.
2. Note how long it takes to go from `Tor: starting` to `Tor: ready`. Do not close the app.
3. Close the app, reopen it, and time `Tor: ready` again.

Paste: both times. Pass: it reaches `Tor: ready` at all. (I expect minutes the first time.)
If it says `Tor: could not start`, report it with what network you were on.

### B4. The identity can be deleted

On the chat list tap "Delete my identity", read the warning, confirm.
Pass: the fingerprint under "Pair a contact" is different afterwards, and `Tor: ready`
returns by itself after a while.

## C. On two phones

### C1. Pair in person

On phone A open "Pair a contact" and show its two QR codes; scan both on phone B with a label
for A. Do the same the other way. Pass: each phone lists the other as pinned, and the
fingerprints match what the other phone shows for itself.

### C2. Message over Tor on mobile data

1. On both phones turn Wi-Fi off and use mobile data. Open the app on both and wait for `Tor: ready`.
2. Open the chat with the other phone on both. One phone will say `Waiting for ... to connect over Tor`
   (that is the side that does not dial); the other will say `Connecting ... over Tor`.
3. When it says `Connected`, send a message each way.

Paste: how long from opening the chat to `Connected`, and whether both messages arrived.
Pass: both arrive. Do not use "Same-Wi-Fi test connection" for this.

### C3. A dropped link comes back

With the chat connected, turn airplane mode on for the phone that dials, wait 20 seconds, turn it off.
Pass: within a few minutes the status returns to connected and a new message arrives.

### C4. A closed app is not stored

Close the app fully on phone B, send a message from phone A, wait a minute, then open B.
Pass: the message does not appear on B (messages are not stored) and A shows a clear error.

### C5. The stored identity cannot be read

Needs a debug build and `adb`:

```bash
adb shell run-as org.sovereign.mesh sh -c 'echo x >> files/identity.vault'
```

Reopen the app. Pass: the chat list shows "Your saved identity could not be opened...", the app
still works with a temporary identity, and "Delete my identity" fixes it.

### C6. No local addresses leak on the Tor path (optional, needs a packet capture)

With Wi-Fi off and mobile data on, capture traffic on the phone (or the carrier-side router if you
have one) while messaging. Pass: no connection to the other phone's local address, only to Tor relays.

## D. Still open from earlier lists

- B1 to B9 in `docs/remaining-work-plan.md`, repeated over Tor for B5 onwards.
- `FLAG_SECURE`: take a screenshot and check the recents thumbnail on a real phone.
- Independent review of the cryptographic design (`docs/hardening-review.md`, section 5).
- Optional: why the Windows build of the spike stalls at 15% (firewall or antivirus on `t0-arti.exe`).
  Not needed for the Android app.

## A4. Why does the second node take about 5 minutes to publish? (20 minutes, optional)

In both runs of the two-identity test the second node to start took 320 to 350 s to be ready; every
single node took 18 to 88 s. This shows whether it is about starting two at once or about this machine.
Run the first one, wait for it to finish, then the second, and paste the `RESULT` lines of each:

```bash
cd ~/sovereign-messenger/rust-core
# One node on its own, three times in a row:
for i in 1 2 3; do cargo test --features tor --test tor_live a_restored -- --ignored --nocapture; done
```

If all three are fast (under about 90 s), the slowness comes from starting two nodes together.
If some take 5 minutes, it is how long Tor takes to publish on your connection at times.
