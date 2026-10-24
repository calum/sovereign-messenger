package org.sovereign.mesh.core

import uniffi.rust_core.LockReport
import uniffi.rust_core.Messenger
import uniffi.rust_core.PairingAssembler

/**
 * Kotlin side of the Rust core. The Rust `Messenger` is the only holder of
 * identity keys, ratchet state and plaintext history. This class forwards calls
 * and caches nothing: no key or message is copied into a Kotlin field.
 *
 * Network I/O runs in rust-core, which owns the TCP socket and the framing. The
 * calls that block (`connect`, `listen`, `receiveOnce`) must run off the UI
 * thread. Errors are thrown as [FacadeException]; they carry no message content.
 */
class CoreBridge(private val messenger: Messenger = Messenger()) {

    fun peers(): List<String> = messenger.peers()

    /** Peers whose session has a live socket. Read by the P2P mesh indicator. */
    fun linkedPeers(): List<String> = messenger.linkedPeers()

    /** The peer a listener is waiting for, or null. Read by the P2P mesh indicator. */
    fun listeningPeer(): String? = messenger.listeningPeer()

    /** Seals [text] and sends it over the open connection to [peer]. Blocking. */
    fun send(peer: String, text: String) {
        messenger.sendOverTransport(peer, text)
    }

    /** Dials [addr] (`host:port`) and runs the handshake with the pinned identity of [peer]. Blocking. */
    fun connect(peer: String, addr: String) {
        messenger.connectPeer(peer, addr)
    }

    /** Waits up to [timeoutSecs] for [peer] to dial [bindAddr]. Blocking; no cancel yet. */
    fun listen(peer: String, bindAddr: String, timeoutSecs: Int) {
        messenger.listenForPeer(peer, bindAddr, timeoutSecs.toUInt())
    }

    /**
     * Waits briefly for one message from [peer]. Returns false if none arrived in
     * the poll interval, so the caller can loop. Blocking.
     */
    fun receiveOnce(peer: String): Boolean = messenger.receiveFromPeer(peer)

    fun history(peer: String): List<String> = messenger.history(peer)

    fun forget(peer: String) {
        messenger.forget(peer)
    }

    /** Called on activity stop. Wipes sessions and history in rust-core. */
    fun wipeAll() {
        messenger.wipeAll()
    }

    /** Whether the OS honoured `mlock` for the core's memory. Counts only, no content. */
    fun lockReport(): LockReport = messenger.lockReport()

    /** Payload bytes for this phone's QR code. Built by rust-core; Kotlin only renders them. */
    fun ownPairingPayload(): ByteArray = messenger.ownPairingPayload("")

    /** The QR parts for this phone's code. Show each one as its own QR code. */
    fun ownPairingParts(): List<ByteArray> = messenger.ownPairingParts("")

    /** A fresh collector for one scan. Feed it every scanned part; it returns the payload when complete. */
    fun newPairingAssembler(): PairingAssembler = PairingAssembler()

    fun ownFingerprint(): String = messenger.ownFingerprint()

    /** Pins a scanned identity under [peer]. A changed key is refused and reported, never applied. */
    fun scanPairing(peer: String, payload: ByteArray): PairingOutcome =
        pairingOutcome(peer) { messenger.scanPairing(peer, payload) }

    fun pinnedPeers(): List<String> = messenger.pinnedPeers()

    fun pinFingerprint(peer: String): String? = messenger.pinFingerprint(peer)

    /** The user checked the new key in person and accepts it. The next scan pins it. */
    fun acceptNewKey(peer: String) {
        messenger.unpin(peer)
    }

    /**
     * Fingerprint of the developer key compiled into this build, shown on the update
     * screen. Null when no key is pinned; every update is then refused.
     */
    fun developerKeyFingerprint(): String? = messenger.developerKeyFingerprint()

    /**
     * Listens on [bindAddr] for one sender and returns the APK bytes only if their
     * signature verifies against the compiled-in developer key. Blocking; the caller
     * runs it off the UI thread. Throws [FacadeException] otherwise.
     */
    fun receiveUpdate(bindAddr: String, timeoutSecs: Int): ByteArray =
        messenger.receiveUpdate(bindAddr, timeoutSecs.toUInt()).apk
}
