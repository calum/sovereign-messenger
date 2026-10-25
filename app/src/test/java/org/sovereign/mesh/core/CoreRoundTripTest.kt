package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.rust_core.FacadeException
import uniffi.rust_core.Messenger
import uniffi.rust_core.WireMessage

/**
 * Round trip through the real rust-core, loaded on the JVM through JNA. The
 * host library path is supplied by the Gradle test task (see app/build.gradle.kts).
 * Two Messenger objects stand in for two phones.
 */
class CoreRoundTripTest {

    private fun paired(): Pair<Messenger, Messenger> {
        val alice = Messenger()
        val bob = Messenger()
        // Bob must pin Alice's key from her QR code before he accepts her handshake.
        bob.scanPairing("alice", alice.ownPairingPayload(""))
        // Bob issues the challenge first; Alice's handshake must answer it.
        val challenge = bob.responderChallenge()
        val init = alice.startSession("bob", bob.ownIdentity(), challenge)
        bob.acceptSession("alice", init, challenge)
        return alice to bob
    }

    @Test
    fun handshakeAndRatchetRoundTripBothDirections() {
        val (alice, bob) = paired()
        bob.receive("alice", alice.send("bob", "hello bob"))
        alice.receive("bob", bob.send("alice", "hi alice"))
        assertEquals(listOf("hello bob", "hi alice"), bob.history("alice"))
        assertEquals(listOf("hello bob", "hi alice"), alice.history("bob"))
    }

    @Test
    fun tamperedCiphertextRejected() {
        val (alice, bob) = paired()
        val sent = alice.send("bob", "attack at dawn")
        val flipped = sent.ciphertext.copyOf()
        flipped[0] = (flipped[0].toInt() xor 1).toByte()
        val forged = sent.copy(ciphertext = flipped)
        assertThrows(FacadeException.AuthFailed::class.java) {
            bob.receive("alice", forged)
        }
    }

    @Test
    fun replayedMessageRejected() {
        val (alice, bob) = paired()
        val sent = alice.send("bob", "once")
        bob.receive("alice", sent)
        assertThrows(FacadeException.Malformed::class.java) {
            bob.receive("alice", sent)
        }
    }

    @Test
    fun unknownPeerRejected() {
        val (alice, _) = paired()
        assertThrows(FacadeException.NoSession::class.java) {
            alice.send("carol", "nobody")
        }
    }

    @Test
    fun wipeAllClearsPeersAndHistory() {
        val (alice, bob) = paired()
        bob.receive("alice", alice.send("bob", "gone soon"))
        bob.wipeAll()
        assertEquals(emptyList<String>(), bob.peers())
        assertEquals(emptyList<String>(), bob.history("alice"))
    }
}
