package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.FacadeException
import uniffi.rust_core.TorRole
import uniffi.rust_core.TorState

class TorUiTest {
    @Test
    fun everyCoreStateHasItsOwnPlainSentence() {
        val texts = TorState.values().map { torStatusText(it, 40) }
        assertEquals(texts.size, texts.toSet().size)
        assertTrue(texts.all { it.isNotBlank() })
    }

    @Test
    fun connectingShowsTheProgress() {
        assertEquals("Tor: connecting (45%)", torStatusText(TorState.BOOTSTRAPPING, 45))
    }

    @Test
    fun publishingWarnsThatTheFirstTimeIsSlow() {
        assertTrue(torStatusText(TorState.PUBLISHING, 100).contains("several minutes"))
    }

    @Test
    fun readyStatesOnlyAFactAndMakesNoPrivacyClaim() {
        val ready = torStatusText(TorState.READY, 100)
        assertEquals("Tor: ready", ready)
        for (word in listOf("secure", "private", "anonymous", "safe", "encrypted")) {
            assertFalse(torStatusText(TorState.READY, 100).contains(word, ignoreCase = true))
        }
    }

    @Test
    fun aBuildWithoutTorSaysSo() {
        assertTrue(torStatusText(TorState.NOT_BUILT, 0).contains("not included"))
    }

    @Test
    fun percentIsClampedForDisplay() {
        assertEquals("Tor: connecting (100%)", torStatusText(TorState.BOOTSTRAPPING, 250))
        assertEquals("Tor: connecting (0%)", torStatusText(TorState.BOOTSTRAPPING, -5))
    }

    @Test
    fun onlyReadyCountsAsReady() {
        assertTrue(torIsReady(TorState.READY))
        for (state in TorState.values().filter { it != TorState.READY }) {
            assertFalse("$state", torIsReady(state))
        }
    }

    @Test
    fun torUnavailableHasItsOwnErrorSentence() {
        assertEquals("Tor is not running.", transportStatusText(FacadeException.TorUnavailable("x")))
    }

    // shouldDial: the dialer connects on its own, with a backoff; the waiter never dials.

    private fun dial(
        role: TorRole? = TorRole.DIAL,
        ready: Boolean = true,
        alive: Boolean = false,
        busy: Boolean = false,
        sinceMs: Long? = null,
        failures: Int = 0,
    ) = shouldDial(role, ready, alive, busy, sinceMs, failures)

    @Test
    fun theDialerDialsAtOnceWhenTorIsReadyAndThereIsNoLink() {
        assertTrue(dial())
    }

    @Test
    fun theWaiterNeverDials() {
        assertFalse(dial(role = TorRole.WAIT))
        assertFalse(dial(role = null))
    }

    @Test
    fun noDialUntilTorIsReadyOrWhileLinkedOrBusy() {
        assertFalse(dial(ready = false))
        assertFalse(dial(alive = true))
        assertFalse(dial(busy = true))
    }

    @Test
    fun aFailedAttemptIsRetriedAfterABackoffThatGrowsAndIsCapped() {
        assertFalse(dial(sinceMs = 5_000, failures = 1))
        assertTrue(dial(sinceMs = 20_000, failures = 1))
        assertFalse(dial(sinceMs = 30_000, failures = 3))
        assertTrue(dial(sinceMs = 80_000, failures = 3))
        // Capped at two minutes however many attempts failed.
        assertTrue(dial(sinceMs = 120_000, failures = 30))
        assertFalse(dial(sinceMs = 119_000, failures = 30))
    }
}
