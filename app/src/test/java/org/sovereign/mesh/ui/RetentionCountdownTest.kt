package org.sovereign.mesh.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/** The RAM-only countdown in the chat header. Pure formatting, no Compose. */
class RetentionCountdownTest {

    @Test
    fun fullRetentionShowsFifteenMinutes() {
        assertEquals("15:00", formatRetention(15 * 60))
    }

    @Test
    fun secondsArePaddedToTwoDigits() {
        assertEquals("1:05", formatRetention(65))
    }

    @Test
    fun expiredCountdownShowsZero() {
        assertEquals("0:00", formatRetention(0))
    }
}
