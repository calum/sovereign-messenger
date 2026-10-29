package org.sovereign.mesh.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CLAUDE.md rule 7: the app must not claim privacy it has not shown. The Tor transport is written
 * but has not run between two phones, so the tour must say so and must not promise anonymity. The
 * chat list title must not use the word "Secured" until an audit backs it.
 */
class TourCopyTest {

    private val allTourText = tourCards.joinToString(" ") { "${it.title} ${it.body}" }

    @Test
    fun tourDoesNotPromiseAnonymityOrSecurity() {
        for (word in listOf("anonymous", "untraceable", "secure", "unbreakable")) {
            assertFalse("tour says \"$word\"", allTourText.contains(word, ignoreCase = true))
        }
    }

    @Test
    fun tourSaysTheTransportIsExperimentalAndUntested() {
        assertTrue(allTourText.contains("experimental"))
        assertTrue(allTourText.contains("not been tested"))
    }

    @Test
    fun tourSaysMessagesLiveInMemoryOnly() {
        assertTrue(allTourText.contains("memory"))
        assertTrue(allTourText.contains("never saved"))
    }

    @Test
    fun titleDoesNotClaimSecurity() {
        assertFalse(chatListTitle.contains("Secured", ignoreCase = true))
    }

    @Test
    fun settingsStateWhereMessagesLive() {
        assertTrue(memoryNote.contains("never saved to storage"))
    }
}
