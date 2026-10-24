package org.sovereign.mesh.core

import uniffi.rust_core.FacadeException
import uniffi.rust_core.LockReport
import uniffi.rust_core.Messenger

/**
 * Kotlin side of the Rust core. The Rust `Messenger` is the only holder of
 * identity keys, ratchet state and plaintext history. This class forwards calls
 * and caches nothing: no key or message is copied into a Kotlin field.
 *
 * `send` does not transmit yet. The wire message it seals is discarded because
 * there is no transport (PLAN section 3); the message is still recorded locally.
 */
class CoreBridge {
    private val messenger = Messenger()

    fun peers(): List<String> = messenger.peers()

    /** Returns false when there is no session with [peer] yet, so the UI can say so. */
    fun send(peer: String, text: String): Boolean =
        try {
            messenger.send(peer, text)
            true
        } catch (e: FacadeException.NoSession) {
            false
        }

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
}
