package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.FacadeException
import uniffi.rust_core.Messenger
import uniffi.rust_core.TorRole
import uniffi.rust_core.TorState

/**
 * The Tor calls through the real rust-core on the JVM. The host library is built without
 * the `tor` feature, so these check the surface, the roles and the honest "not built"
 * answers; nothing here reaches the Tor network.
 */
class CoreBridgeTorTest {
    private fun pairedBridges(): Pair<CoreBridge, CoreBridge> {
        val a = Messenger()
        val b = Messenger()
        a.scanPairing("b", b.ownPairingPayload(""))
        b.scanPairing("a", a.ownPairingPayload(""))
        return CoreBridge(a) to CoreBridge(b)
    }

    @Test
    fun aBuildWithoutTorReportsNotBuiltAndRefusesToStart() {
        val core = CoreBridge(Messenger())
        assertEquals(TorState.NOT_BUILT, core.torStatus().state)
        assertThrows(FacadeException.TorUnavailable::class.java) { core.startTor("/nonexistent") }
        assertThrows(FacadeException.TorUnavailable::class.java) { core.acceptTor(1) }
    }

    @Test
    fun exactlyOneSideOfAPairDials() {
        val (a, b) = pairedBridges()
        assertNotEquals(a.torRole("b"), b.torRole("a"))
        assertTrue(setOf(a.torRole("b"), b.torRole("a")) == setOf(TorRole.DIAL, TorRole.WAIT))
    }

    @Test
    fun connectingToAnUnpinnedContactIsRefused() {
        val core = CoreBridge(Messenger())
        assertThrows(FacadeException.NotPinned::class.java) { core.connectTor("nobody") }
        assertThrows(FacadeException.NotPinned::class.java) { core.torRole("nobody") }
    }

    @Test
    fun theOnionAddressesComeFromTheCore() {
        val (a, b) = pairedBridges()
        assertTrue(a.ownOnionAddress().endsWith(".onion"))
        assertEquals(b.ownOnionAddress(), a.pinnedOnionAddress("b"))
        assertEquals(null, a.pinnedOnionAddress("nobody"))
    }
}
