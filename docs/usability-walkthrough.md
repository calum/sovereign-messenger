# Usability walkthrough: tour and chat flow

_Written 2026-10-24 for PLAN.md section 7, item 1._

This is a code walkthrough. It describes what `TourScreen.kt`, `ChatListScreen.kt`, `ChatScreen.kt`, `MainActivity.kt` and `MeshIndicator.kt` do. It is not a device test. No phone or emulator was available, so nothing here shows that the flow works on a phone. Items under "Human checks" are open until someone runs the app on two phones.

## Launch

1. `MainActivity.onCreate` sets `FLAG_SECURE` on the window, then deletes any staged update APK.
2. The tour is shown first. `showTour` is a `remember` value, so it is `true` on every cold start.
3. `remember` is lost when the activity is recreated. The manifest declares no `configChanges`, so a rotation recreates the activity and shows the tour again, and the chat screen reverts to the list (see the rotation check below).

## Tour (`TourScreen.kt`)

4. Three cards in a `HorizontalPager`. The counter reads `1 / 3`, `2 / 3`, `3 / 3`.
5. Card 1, "Serverless P2P", body: "No servers, no cloud. Your phone talks directly to your friends' phones over Tor onion services." **This is wrong.** The app has no Tor transport (CLAUDE.md, "Known gaps"; PLAN.md, Decisions, "Tor ruling"). The transport is TCP on the local network. The card must be corrected before anyone relies on it.
6. Card 2, "RAM-only memory": nothing is written to flash, and chats vanish when the app closes. This matches `MainActivity.onStop`, which calls `wipeAll()`.
7. Card 3, "Scan to join": meet in person and scan each other's QR code.
8. "Next" animates to the next card. On card 3 the button reads "Get started", which calls `onFinished` and sets `showTour = false`.

## Chat list (`ChatListScreen.kt`)

9. Header: the title "Secured P2P Mesh", then the `P2pMeshIndicator` line (new in this change). The indicator reads the core every second.
10. Buttons: "Pair a contact" (opens `PairingScreen`) and "Updates" (opens `UpdateScreen`).
11. Empty list shows "No chats yet. Meet a friend in person and scan their QR code to start." Otherwise each peer label is a tappable row that opens its chat.
12. The list is read from `core.peers()` on each composition. Pins are not listed here.

## Chat screen (`ChatScreen.kt`)

13. Opening a chat starts a receive loop (`LaunchedEffect(peer, connectionEpoch)`). It calls `receiveOnce` on the IO dispatcher.
14. If there is no session for this peer, the first `receiveOnce` fails with `NoSession`. The status line then shows "No session with this contact yet." and the loop ends. This happens on opening any chat that has no connection, so a fresh chat shows an error before the user does anything.
15. Header row: "Back" and "RAM only · m:ss". The timer starts at 15:00 and counts down in the composable. It does not trigger a wipe. The wipe happens on app stop, not at 0:00.
16. Status line (optional): "Connecting...", "Waiting for the contact on port 47001...", "Connected.", or a fixed error sentence from `transportStatusText`.
17. "Connect" with a `host:port` field. It runs `core.connect` off the UI thread. On success `connectionEpoch` increments, which restarts the receive loop.
18. "Wait for contact" listens on `0.0.0.0:47001` for up to 120 s. The core call cannot be cancelled, so leaving the screen does not stop it until the timeout.
19. Message list shows `core.history(peer)`, oldest first.
20. "Send" calls `core.send` off the UI thread. On success the draft clears. On failure the draft is kept and the error shows.
21. The receive loop ends on any error, including `AuthFailed` and `Network`. It does not restart until `connectionEpoch` changes, that is, until another successful Connect or Wait.

## Leaving the app (`MainActivity.kt`)

22. "Back" sets `openPeer = null` and returns to the list. Hardware or gesture back is not handled in code, so it leaves the activity (default behaviour; not checked).
23. `onStop` calls `SovereignApp.core.wipeAll()`. That clears all sessions, history and sockets. Pins survive, by design. The list is empty when the app returns.

## Pre-conditions not walked here

- The chat flow needs both phones to have scanned each other. `PairingScreen.kt` and `PairingScanner.kt` were not read for this document.
- `UpdateScreen.kt` is not covered.

## Human checks on two phones

These are open. Each needs a device.

- Rotation: rotate on the chat screen. Check whether the chat list reappears, whether the tour shows again, and whether chats are gone. Code reading says the activity is recreated, `onStop` runs, and `wipeAll()` clears chats. If that holds, rotation loses chats.
- Tour copy: confirm card 1 is corrected. The current text says Tor.
- Opening a chat with no connection: confirm the "No session" message appears at once and reads clearly, or decide whether it should be quieter.
- Connect: enter a LAN `host:port` on the other phone and confirm "Connected." and that messages flow both ways.
- Wait for contact: confirm the 120 s timeout shows the network message, and that the other phone's Connect reaches it.
- Errors: after an `AuthFailed` or lost link, the receive loop stops. Confirm the status text is clear and that the user can reconnect without restarting the app.
- Indicator: confirm the chat list and chat screen change within about one second of a connection starting and ending, and that a connection to another contact does not show on this chat.
- Keyboard: the address field, draft field and Send button stay usable with the soft keyboard open on a small screen.
- Layout: the tour, header rows and indicator fit at phone width (about 360 dp) in portrait and landscape, with large font scale.
- Dark theme: the indicator dot and label remain readable.
- FLAG_SECURE: a screenshot and the recent-apps thumbnail are blank for every screen.
- Background: switching apps clears the chat list and chat history. Check that opening the permission dialog for the camera does not also trigger `onStop` and wipe chats mid-pairing.
- Back: system back from the chat screen and from the list, including the gesture.
- Timer: the countdown reaches 0:00 without wiping; the wipe happens only when the app stops. Confirm the text does not suggest otherwise to the user.

## Wording to review

- "Secured P2P Mesh" is the existing title. The new indicator avoids that claim: it says only "connected", "waiting for contact", "not connected" or "no session". The title should be reviewed against CLAUDE.md rule 7 before release.
- The tour card 1 text is the same issue as item 5.
