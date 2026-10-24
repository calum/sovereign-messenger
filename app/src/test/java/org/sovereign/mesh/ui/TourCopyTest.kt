package org.sovereign.mesh.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * CLAUDE.md rule 7: the app must not claim a transport it does not have. There is
 * no Tor or onion transport, so the tour must not mention one, and the chat list
 * title must not use the word "Secured" until an audit backs it.
 */
class TourCopyTest {

    private val allTourText = tourCards.joinToString(" ") { "${it.title} ${it.body}" }

    @Test
    fun tourDoesNotClaimTorOrOnionServices() {
        assertFalse(allTourText.contains("Tor", ignoreCase = false))
        assertFalse(allTourText.contains("onion", ignoreCase = true))
    }

    @Test
    fun tourSaysPhonesConnectOverTheLocalNetwork() {
        assertTrue(tourCards.any { it.body.contains("local network") })
    }

    @Test
    fun titleDoesNotClaimSecurity() {
        assertFalse(chatListTitle.contains("Secured", ignoreCase = true))
    }
}
