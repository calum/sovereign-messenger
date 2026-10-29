package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.Messenger

/** The identity-reset sequence against the real core (JNA host library, as in CoreRoundTripTest). */
class IdentityResetTest {

    private fun bobWithChat(): CoreBridge {
        val alice = Messenger()
        val bob = Messenger()
        bob.scanPairing("alice", alice.ownPairingPayload(""))
        val challenge = bob.responderChallenge()
        val init = alice.startSession("bob", bob.ownIdentity(), challenge)
        bob.acceptSession("alice", init, challenge)
        bob.receive("alice", alice.send("bob", "old secret"))
        return CoreBridge(bob)
    }

    @Test
    fun oldCoreIsWipedBeforeVaultDeleteAndNewIdentityDiffers() {
        val old = bobWithChat()
        val oldFingerprint = old.ownFingerprint()
        assertEquals(listOf("alice"), old.peers())
        assertEquals(listOf("old secret"), old.history("alice"))

        val steps = mutableListOf<String>()
        var fresh: CoreBridge? = null
        var peersAtRelease: List<String>? = null
        var historyAtRelease: List<String>? = null
        resetIdentity(
            old = old,
            stopConnections = { steps += "connections" },
            stopTor = { steps += "tor" },
            deleteLocalFiles = { steps += "files" },
            deleteVault = { steps += "vault" },
            startNew = {
                steps += "start"
                fresh = CoreBridge(Messenger())
            },
            release = {
                steps += "wipe"
                it.wipeAll()
                peersAtRelease = it.peers()
                historyAtRelease = it.history("alice")
                it.close()
            },
        )

        assertEquals(listOf("connections", "tor", "files", "wipe", "vault", "start"), steps)
        assertTrue(peersAtRelease!!.isEmpty())
        assertTrue(historyAtRelease!!.isEmpty())
        assertNotEquals(oldFingerprint, fresh!!.ownFingerprint())
        // The released core is unusable, so nothing can keep reading the old identity.
        assertThrows(IllegalStateException::class.java) { old.peers() }
    }

    @Test
    fun defaultReleaseWipesAndClosesTheOldCore() {
        val old = bobWithChat()
        assertEquals(listOf("alice"), old.peers())
        var peersAfterWipe: List<String>? = null
        resetIdentity(old, {}, {}, {}, {}, {}, release = { it.close { peersAfterWipe = it.peers() } })
        assertEquals(emptyList<String>(), peersAfterWipe)
        assertThrows(IllegalStateException::class.java) { old.history("alice") }
    }

    @Test
    fun deleteAndStartStillRunWhenEarlierStepsThrow() {
        val old = bobWithChat()
        val oldFingerprint = old.ownFingerprint()
        val steps = mutableListOf<String>()
        var fresh: CoreBridge? = null
        val failure = run {
            resetIdentity(
                old = old,
                stopConnections = { steps += "connections" },
                stopTor = { throw RuntimeException("tor") },
                deleteLocalFiles = { steps += "files" },
                deleteVault = { steps += "vault" },
                startNew = {
                    steps += "start"
                    fresh = CoreBridge(Messenger())
                },
                release = { throw RuntimeException("wipe") },
            )
        }
        assertEquals("tor", failure!!.message)
        assertEquals(listOf("connections", "files", "vault", "start"), steps)
        assertNotEquals(oldFingerprint, fresh!!.ownFingerprint())
    }

    @Test
    fun startNewStillRunsWhenVaultDeleteThrowsEvenWithAnError() {
        val old = bobWithChat()
        var started = false
        val failure = resetIdentity(
            old = old,
            stopConnections = { throw UnsatisfiedLinkError("native") },
            stopTor = {},
            deleteLocalFiles = {},
            deleteVault = { throw RuntimeException("vault") },
            startNew = { started = true },
        )
        assertTrue(started)
        assertTrue(failure is UnsatisfiedLinkError)
    }

    @Test
    fun navigationRunsAndFailureIsReportedWithoutEscaping() {
        var navigated = false
        val clean = completeReset(reset = { RuntimeException("x") }, navigate = { navigated = true })
        assertTrue(navigated)
        assertEquals(false, clean)
        navigated = false
        completeReset(reset = { throw IllegalStateException("boom") }, navigate = { navigated = true })
        assertTrue(navigated)
        navigated = false
        assertEquals(true, completeReset(reset = { null }, navigate = { navigated = true }))
        assertTrue(navigated)
    }
}
