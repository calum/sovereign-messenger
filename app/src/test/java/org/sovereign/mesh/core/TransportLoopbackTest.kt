package org.sovereign.mesh.core

import java.net.ServerSocket
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.FacadeException
import uniffi.rust_core.Messenger

/**
 * Two CoreBridge objects over real loopback TCP, standing in for two phones.
 * The handshake, the ratchet and the framing all run in rust-core; this test
 * checks that the Kotlin bridge passes calls through and that history updates.
 */
class TransportLoopbackTest {

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    /** The listener thread may not be bound yet, so retry the dial briefly. */
    private fun connectWithRetry(bridge: CoreBridge, peer: String, addr: String) {
        val deadline = System.currentTimeMillis() + 5_000
        while (true) {
            try {
                bridge.connect(peer, addr)
                return
            } catch (e: FacadeException.Network) {
                if (System.currentTimeMillis() > deadline) throw e
                Thread.sleep(50)
            }
        }
    }

    @Test
    fun messagesCrossTcpAndLandInReceiverHistory() {
        val alice = CoreBridge(Messenger())
        val bob = CoreBridge(Messenger())
        assertTrue(alice.scanPairing("bob", bob.ownPairingPayload()) is PairingOutcome.Pinned)
        // The listener must pin the dialer too; an unpinned initiator is refused.
        assertTrue(bob.scanPairing("alice", alice.ownPairingPayload()) is PairingOutcome.Pinned)

        val addr = "127.0.0.1:${freePort()}"
        var listenError: Throwable? = null
        val listener = thread {
            try {
                bob.listen("alice", addr, 10)
            } catch (e: Throwable) {
                listenError = e
            }
        }
        connectWithRetry(alice, "bob", addr)
        listener.join()
        assertNull(listenError)

        alice.send("bob", "hello bob")
        assertTrue(bob.receiveOnce("alice"))
        assertEquals(listOf("hello bob"), bob.history("alice"))

        bob.send("alice", "hi alice")
        // Bob's delivery notice for "hello bob" comes first, then his message.
        assertTrue(alice.receiveOnce("bob"))
        assertTrue(alice.receiveOnce("bob"))
        assertEquals(listOf("hello bob", "hi alice"), alice.history("bob"))
    }

    @Test
    fun connectWithoutAPinnedIdentityIsRefused() {
        val alice = CoreBridge(Messenger())
        assertThrows(FacadeException.NotPinned::class.java) {
            alice.connect("bob", "127.0.0.1:9")
        }
    }

    @Test
    fun sendWithoutAnOpenConnectionIsRefused() {
        val alice = Messenger()
        val bob = Messenger()
        alice.startSession("bob", bob.ownIdentity(), bob.responderChallenge())
        val core = CoreBridge(alice)
        assertThrows(FacadeException.NoLink::class.java) {
            core.send("bob", "not on the wire")
        }
    }

    @Test
    fun dialingAClosedPortReportsNetworkError() {
        val alice = CoreBridge(Messenger())
        alice.scanPairing("bob", CoreBridge(Messenger()).ownPairingPayload())
        assertThrows(FacadeException.Network::class.java) {
            alice.connect("bob", "127.0.0.1:${freePort()}")
        }
    }
}
