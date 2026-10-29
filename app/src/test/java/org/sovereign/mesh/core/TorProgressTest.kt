package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.TorRole
import uniffi.rust_core.TorState

class TorProgressTest {
    @Test
    fun bootstrapShowsMeasuredProgress() {
        val p = torProgress(TorState.BOOTSTRAPPING, 40)
        assertTrue(p.active)
        assertEquals(0.4f, p.fraction!!, 0.001f)
    }

    @Test
    fun startingAndPublishingAreIndeterminate() {
        assertNull(torProgress(TorState.STARTING, 0).fraction)
        assertNull(torProgress(TorState.PUBLISHING, 100).fraction)
        assertTrue(torProgress(TorState.PUBLISHING, 100).active)
    }

    @Test
    fun noBarOnceReadyOrFailed() {
        assertFalse(torProgress(TorState.READY, 100).active)
        assertFalse(torProgress(TorState.FAILED, 0).active)
    }

    @Test
    fun logsEachNewStateButNotEveryPoll() {
        val starting = TorSnapshot(TorState.STARTING, 0)
        assertNotNull(torLogEntry(TorSnapshot(TorState.STOPPED, 0), starting))
        assertNull(torLogEntry(starting, starting))
    }

    @Test
    fun logsBootstrapOnlyOnNewTenPercentStep() {
        val a = TorSnapshot(TorState.BOOTSTRAPPING, 41)
        assertNull(torLogEntry(a, TorSnapshot(TorState.BOOTSTRAPPING, 45)))
        assertEquals(
            "Connecting to the Tor network (50%)",
            torLogEntry(a, TorSnapshot(TorState.BOOTSTRAPPING, 50)),
        )
    }

    @Test
    fun contactTextFollowsTheLink() {
        assertEquals("Contact is connected over Tor", contactLinkText(TorRole.WAIT, true, true, false))
        assertTrue(contactLinkText(TorRole.DIAL, false, false, false).contains("Tor to be ready"))
        assertTrue(contactLinkText(TorRole.DIAL, true, false, true).contains("Reaching"))
        assertTrue(contactLinkText(TorRole.WAIT, true, false, false).contains("Waiting for your contact"))
    }
}
