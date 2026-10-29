package org.sovereign.mesh.core

import uniffi.rust_core.ChatMessage
import uniffi.rust_core.FacadeException
import uniffi.rust_core.LockReport
import uniffi.rust_core.Messenger
import uniffi.rust_core.PairingAssembler
import uniffi.rust_core.Presence
import uniffi.rust_core.TorRole
import uniffi.rust_core.TorStatus

/**
 * Kotlin side of the Rust core. The Rust `Messenger` is the only holder of
 * identity keys, ratchet state and plaintext history. This class forwards calls
 * and caches nothing: no key or message is copied into a Kotlin field.
 *
 * Network I/O runs in rust-core, which owns the TCP socket and the framing. The
 * calls that block (`connect`, `listen`, `receiveOnce`) must run off the UI
 * thread. Errors are thrown as [FacadeException]; they carry no message content.
 */
class CoreBridge(
    private val messenger: Messenger = Messenger(),
    private val vault: IdentityVault? = null,
) {
    /**
     * True if the last attempt to store the identity and pins failed. They are still
     * usable in memory, but a restart would lose the change. Read by the chat list.
     */
    @Volatile
    var saveFailed: Boolean = false
        private set

    /** Stores the identity and pins after a change. Messages are never stored. */
    private fun persist() {
        val v = vault ?: return
        saveFailed = !v.save(messenger)
    }

    fun peers(): List<String> = messenger.peers()

    /** Peers whose session has a live socket. Read by the P2P mesh indicator. */
    fun linkedPeers(): List<String> = messenger.linkedPeers()

    /** The peer a listener is waiting for, or null. Read by the P2P mesh indicator. */
    fun listeningPeer(): String? = messenger.listeningPeer()

    /** Seals [text] and sends it over the open connection to [peer]. Blocking. */
    fun send(peer: String, text: String) {
        messenger.sendOverTransport(peer, text)
    }

    /**
     * Queues [text] for [peer] and sends it now if the link is up; otherwise it waits in RAM
     * and goes out when the link returns. Blocking, so call it off the UI thread.
     */
    fun sendText(peer: String, text: String) {
        messenger.sendText(peer, text)
    }

    /** Sends any queued messages and owed read receipt. Returns how many messages went out. Blocking. */
    fun flushPending(peer: String): Int = messenger.flushPending(peer).toInt()

    /** The conversation with [peer], oldest first, each message with its sender side, time and state. */
    fun conversation(peer: String): List<ChatMessage> = messenger.conversation(peer)

    /** Messages from [peer] that the user has not seen yet. */
    fun unreadCount(peer: String): Int = messenger.unreadCount(peer).toInt()

    /**
     * The user is looking at the chat: marks everything seen. With [sendReceipt], [peer] is told
     * the newest message was read. Returns how many messages were newly seen. Blocking.
     */
    fun markRead(peer: String, sendReceipt: Boolean): Int = messenger.markRead(peer, sendReceipt).toInt()

    /** Whether [peer]'s link is up, and when it last was. Read from this phone's own connection. */
    fun presence(peer: String): Presence = messenger.presence(peer)

    /** Removes the contact: ends the session, drops the messages and the pin. They must be paired again. */
    fun removeContact(peer: String) {
        messenger.forget(peer)
        messenger.unpin(peer)
        persist()
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

    /** Wipes sessions and history in rust-core. Nothing calls it on a normal stop: chats stay in RAM until the process ends. */
    fun wipeAll() {
        messenger.wipeAll()
    }

    /**
     * Ends this core for good: wipes it, then releases the native Messenger. Used when the
     * identity is deleted, so the old identity, sessions and chats do not wait for the GC.
     * Any later call on this bridge fails, which is intended.
     */
    fun close() = close {}

    /** [afterWipe] runs between the wipe and the release; a test seam to see the wiped state. */
    internal fun close(afterWipe: () -> Unit) {
        try {
            messenger.wipeAll()
            afterWipe()
        } finally {
            messenger.close()
        }
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

    /** This phone's onion address. Public; it is also in the QR code. */
    fun ownOnionAddress(): String = messenger.ownOnionAddress()

    /** The onion address pinned for [peer] from their QR code, or null. */
    fun pinnedOnionAddress(peer: String): String? = messenger.pinnedOnionAddress(peer)

    /** Tor progress for the status line. Cheap; safe to poll from the UI. */
    fun torStatus(): TorStatus = messenger.torStatus()

    /** Starts Tor and this phone's onion service in the background. [stateDir] is app-private. */
    fun startTor(stateDir: String) {
        messenger.torStart(stateDir)
    }

    fun stopTor() {
        messenger.torStop()
    }

    /** Whether this phone dials [peer] or waits for the call. Only one side of a pair dials. */
    fun torRole(peer: String): TorRole = messenger.torRole(peer)

    /** Contacts being dialled right now, so one contact is never dialled twice at once. */
    private val dialling = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    /**
     * Dials [peer]'s onion address and runs the handshake. Blocking, possibly minutes. A second
     * call for the same contact while one is running is refused: two dials would each make a
     * session and the later would replace the earlier, leaving the phones on different links.
     */
    fun connectTor(peer: String) {
        if (!dialling.add(peer)) throw FacadeException.Network("already dialling")
        try {
            messenger.connectPeerTor(peer)
        } finally {
            dialling.remove(peer)
        }
    }

    /** Waits for any pinned contact to call, and returns their label. Blocking. */
    fun acceptTor(timeoutSecs: Int): String = messenger.acceptPeerTor(timeoutSecs.toUInt())

    /** Pins a scanned identity under [peer]. A changed key is refused and reported, never applied. */
    fun scanPairing(peer: String, payload: ByteArray): PairingOutcome =
        pairingOutcome(peer) { messenger.scanPairing(peer, payload) }
            .also { if (it is PairingOutcome.Pinned) persist() }

    fun pinnedPeers(): List<String> = messenger.pinnedPeers()

    fun pinFingerprint(peer: String): String? = messenger.pinFingerprint(peer)

    /** The user checked the new key in person and accepts it. The next scan pins it. */
    fun acceptNewKey(peer: String) {
        messenger.unpin(peer)
        persist()
    }

    /**
     * Fingerprint of the developer key compiled into this build, shown on the update
     * screen. Null when no key is pinned; every update is then refused.
     */
    fun developerKeyFingerprint(): String? = messenger.developerKeyFingerprint()

    /**
     * Listens on [bindAddr] for one sender and returns the APK bytes only if their
     * signature verifies over the version the sender announced, and that version is
     * strictly newer than [installedVersion] (the installed version code). Blocking;
     * the caller runs it off the UI thread. Throws [FacadeException] otherwise.
     */
    fun receiveUpdate(bindAddr: String, timeoutSecs: Int, installedVersion: Long): ByteArray =
        messenger.receiveUpdate(bindAddr, timeoutSecs.toUInt(), installedVersion.toULong()).apk

    /**
     * Forwards one developer-signed bundle to the phone at [addr]: the APK, its
     * 64-byte signature and the version. This phone does not sign. Blocking; the
     * caller runs it off the UI thread. Throws [FacadeException] on refusal or
     * network failure. The receiver verifies the bundle before it offers install.
     */
    fun sendUpdate(addr: String, timeoutSecs: Int, apk: ByteArray, version: Long, signature: ByteArray) =
        messenger.sendUpdate(addr, timeoutSecs.toUInt(), apk, version.toULong(), signature)
}

/**
 * The order of an identity reset, kept apart from the Application so a JVM test can run it.
 * Background work stops first so nothing races the wipe; the old core is wiped and released
 * before the vault goes, so no plaintext of the old identity outlives the delete; the new
 * identity starts last. Returns the first failure, or null. [release] defaults to [CoreBridge.close]; tests observe the wiped core.
 */
internal fun resetIdentity(
    old: CoreBridge,
    stopConnections: () -> Unit,
    stopTor: () -> Unit,
    deleteLocalFiles: () -> Unit,
    deleteVault: () -> Unit,
    startNew: () -> Unit,
    release: (CoreBridge) -> Unit = { it.close() },
): Throwable? {
    // Deleting wins over cleanup: every step runs, and the vault is deleted and the new
    // identity started even if an earlier step throws. The first failure is returned last,
    // never thrown, so the caller can still navigate. If startNew itself fails, SovereignApp's
    // core, tor and connections still point at the released core; the vault is already gone,
    // so the next launch starts clean.
    var first: Throwable? = null
    fun guarded(step: () -> Unit) {
        try {
            step()
        } catch (e: Throwable) {
            if (first == null) first = e
        }
    }
    guarded(stopConnections)
    guarded(stopTor)
    guarded(deleteLocalFiles)
    guarded { release(old) }
    guarded(deleteVault)
    guarded(startNew)
    return first
}

/**
 * Runs [reset] and always calls [navigate] afterwards, even if [reset] throws, so the user
 * never stays on a screen of the identity that was just deleted. Returns whether it was clean.
 */
internal fun completeReset(reset: () -> Throwable?, navigate: () -> Unit): Boolean {
    var failure: Throwable? = null
    try {
        failure = reset()
    } catch (e: Throwable) {
        failure = e
    } finally {
        navigate()
    }
    return failure == null
}
