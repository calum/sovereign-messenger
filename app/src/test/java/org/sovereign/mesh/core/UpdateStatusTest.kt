package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Test
import uniffi.rust_core.FacadeException

class UpdateStatusTest {

    @Test
    fun networkErrorAsksForTheSameWifiAndRetry() {
        assertEquals(
            "No update was received. Check that both phones are on the same Wi-Fi and try again.",
            updateStatusText(FacadeException.Network("network error")),
        )
    }

    @Test
    fun malformedUpdateIsRefusedWithoutDetail() {
        assertEquals(
            "The update was malformed or its signature was the wrong length. It was refused.",
            updateStatusText(FacadeException.Malformed("malformed input")),
        )
    }

    @Test
    fun unexpectedCoreErrorSaysNothingWasInstalled() {
        assertEquals(
            "Something went wrong. No update was installed.",
            updateStatusText(FacadeException.Internal("internal state unavailable")),
        )
    }

    @Test
    fun unknownErrorDoesNotEchoItsMessage() {
        val text = updateStatusText(RuntimeException("apk-bytes-0123"))
        assertFalse(text.contains("apk-bytes-0123"))
    }

    @Test
    fun downgradeGetsItsOwnMessageThatSaysNothingWasInstalled() {
        assertEquals(
            "This update is not newer than the installed version. It was refused; nothing was installed.",
            updateStatusText(FacadeException.Downgraded("update is older than or the same as the installed version")),
        )
    }

    @Test
    fun downgradeMessageIsDistinctFromASignatureRefusal() {
        assertNotEquals(
            updateStatusText(FacadeException.AuthFailed("authentication failed")),
            updateStatusText(FacadeException.Downgraded("update is older than or the same as the installed version")),
        )
    }

    @Test
    fun downgradeTextDoesNotEchoTheCoreMessage() {
        val text = updateStatusText(FacadeException.Downgraded("version 41 key-material-0123"))
        assertFalse(text.contains("key-material-0123"))
        assertFalse(text.contains("41"))
    }
}
