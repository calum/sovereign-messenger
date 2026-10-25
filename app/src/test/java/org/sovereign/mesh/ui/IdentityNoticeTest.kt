package org.sovereign.mesh.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityNoticeTest {
    @Test
    fun nothingIsShownWhenStorageIsHealthy() {
        assertNull(identityNotice(unreadable = false, saveFailed = false))
    }

    @Test
    fun anUnreadableVaultSaysSoAndExplainsNothingIsSaved() {
        val text = identityNotice(unreadable = true, saveFailed = false)
        assertNotNull(text)
        assertTrue(text!!.contains("could not be opened"))
        assertTrue(text.contains("saves nothing"))
    }

    @Test
    fun aFailedSaveWarnsTheChangeWillBeLost() {
        val text = identityNotice(unreadable = false, saveFailed = true)
        assertTrue(text!!.contains("could not be saved"))
    }

    @Test
    fun unreadableWinsWhenBothAreTrue() {
        assertEquals(
            identityNotice(unreadable = true, saveFailed = false),
            identityNotice(unreadable = true, saveFailed = true),
        )
    }

    @Test
    fun theDeleteWarningStatesTheCostAndThatItCannotBeUndone() {
        assertTrue(deleteIdentityWarning.contains("every saved contact"))
        assertTrue(deleteIdentityWarning.contains("pair with you again in person"))
        assertTrue(deleteIdentityWarning.contains("cannot be undone"))
    }
}
