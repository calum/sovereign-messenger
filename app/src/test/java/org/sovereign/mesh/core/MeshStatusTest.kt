package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * The header indicator must say only what the core reports. The inputs are the
 * core's own answers: `peers()` (sessions), `linkedPeers()` (sessions with a live
 * socket) and `listeningPeer()` (the peer a listener waits for). Nothing here
 * reads Compose or the network, so it runs on the JVM.
 */
class MeshStatusTest {

    @Test
    fun noSessionAndNoListenerOnTheChatListIsNoSession() {
        val s = meshStatus(sessions = emptyList(), linked = emptyList(), listening = null)
        assertEquals(MeshLink.NO_SESSION, s.link)
        assertEquals("P2P mesh: no session", s.label)
    }

    @Test
    fun aLinkedSessionOnTheChatListIsConnected() {
        val s = meshStatus(sessions = listOf("bob"), linked = listOf("bob"), listening = null)
        assertEquals(MeshLink.CONNECTED, s.link)
        assertEquals("P2P mesh: connected", s.label)
    }

    @Test
    fun aLinkedSessionForTheOpenChatIsConnected() {
        val s = meshStatus(
            sessions = listOf("bob"),
            linked = listOf("bob"),
            listening = null,
            peer = "bob",
        )
        assertEquals(MeshLink.CONNECTED, s.link)
    }

    @Test
    fun sessionWithoutSocketIsNotConnected() {
        // An in-process session has no connection; it must not claim one.
        val s = meshStatus(
            sessions = listOf("bob"),
            linked = emptyList(),
            listening = null,
            peer = "bob",
        )
        assertEquals(MeshLink.NOT_CONNECTED, s.link)
        assertEquals("P2P mesh: not connected", s.label)
    }

    @Test
    fun listenerForTheOpenChatIsListening() {
        val s = meshStatus(
            sessions = listOf("bob"),
            linked = emptyList(),
            listening = "bob",
            peer = "bob",
        )
        assertEquals(MeshLink.LISTENING, s.link)
        assertEquals("P2P mesh: waiting for contact", s.label)
    }

    @Test
    fun listenerOnTheChatListIsListeningWithNoSessionYet() {
        val s = meshStatus(sessions = emptyList(), linked = emptyList(), listening = "bob")
        assertEquals(MeshLink.LISTENING, s.link)
    }

    @Test
    fun listenerForAnotherPeerDoesNotShowOnThisChat() {
        val s = meshStatus(
            sessions = emptyList(),
            linked = emptyList(),
            listening = "bob",
            peer = "carol",
        )
        assertEquals(MeshLink.NO_SESSION, s.link)
    }

    @Test
    fun connectionWinsOverAListenerForAnotherPeer() {
        val s = meshStatus(
            sessions = listOf("bob"),
            linked = listOf("bob"),
            listening = "carol",
        )
        assertEquals(MeshLink.CONNECTED, s.link)
    }

    @Test
    fun aConnectionToAnotherPeerDoesNotShowOnThisChat() {
        val s = meshStatus(
            sessions = listOf("bob"),
            linked = listOf("bob"),
            listening = null,
            peer = "carol",
        )
        assertEquals(MeshLink.NO_SESSION, s.link)
    }

    @Test
    fun labelsNeverClaimSecurityTheAppCannotBackUp() {
        val labels = listOf(
            meshStatus(emptyList(), emptyList(), null).label,
            meshStatus(listOf("bob"), listOf("bob"), null).label,
            meshStatus(listOf("bob"), emptyList(), null, "bob").label,
            meshStatus(emptyList(), emptyList(), "bob", "bob").label,
        )
        for (label in labels) {
            assertFalse(label, label.contains("secure", ignoreCase = true))
            assertFalse(label, label.contains("encrypt", ignoreCase = true))
        }
    }
}
