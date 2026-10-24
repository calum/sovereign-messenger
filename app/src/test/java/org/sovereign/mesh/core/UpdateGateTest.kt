package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.rust_core.FacadeException
import uniffi.rust_core.Messenger

/**
 * The install gate on the Kotlin side. The developer key is compiled into rust-core
 * and is unset in this build, so every update must be refused. These tests check
 * that the refusal reaches Kotlin and that the status text names no content.
 */
class UpdateGateTest {

    @Test
    fun noDeveloperKeyMeansNoFingerprintShown() {
        assertNull(CoreBridge().developerKeyFingerprint())
    }

    @Test
    fun verifyRefusesEveryUpdateWhileNoKeyIsCompiledIn() {
        val messenger = Messenger()
        assertThrows(FacadeException.AuthFailed::class.java) {
            messenger.verifyUpdate(ByteArray(16) { 1 }, 2UL, ByteArray(64), 1UL)
        }
    }

    @Test
    fun refusalTextIsFixedAndDoesNotEchoTheError() {
        val text = updateStatusText(FacadeException.AuthFailed("secret-looking detail"))
        assertEquals(
            "The update was refused: its signature did not verify. Do not install it.",
            text,
        )
    }
}
