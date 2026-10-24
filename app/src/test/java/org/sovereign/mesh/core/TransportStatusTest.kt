package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import uniffi.rust_core.FacadeException

class TransportStatusTest {

    @Test
    fun noOpenConnectionSaysNotConnected() {
        assertEquals(
            "Not connected to this contact yet.",
            transportStatusText(FacadeException.NoLink("no link")),
        )
    }

    @Test
    fun networkErrorSaysTheConnectionFailed() {
        assertEquals(
            "Connection failed or was lost.",
            transportStatusText(FacadeException.Network("network error")),
        )
    }

    @Test
    fun unpinnedContactAsksForAScan() {
        assertEquals(
            "Scan this contact's QR code first.",
            transportStatusText(FacadeException.NotPinned("not pinned")),
        )
    }

    @Test
    fun unknownErrorDoesNotEchoItsMessage() {
        val text = transportStatusText(RuntimeException("secret plaintext"))
        assertFalse(text.contains("secret plaintext"))
    }
}
