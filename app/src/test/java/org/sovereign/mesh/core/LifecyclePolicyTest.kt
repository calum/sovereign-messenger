package org.sovereign.mesh.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.sovereign.mesh.shouldWipeOnStop

/**
 * Chats are RAM-only (CLAUDE.md rule 1). They must vanish when the user leaves the
 * app, but a rotation or other configuration change also stops the activity, and
 * must not wipe chats the user is still reading.
 */
class LifecyclePolicyTest {

    @Test
    fun leavingTheAppWipesChats() {
        assertTrue(shouldWipeOnStop(isChangingConfigurations = false))
    }

    @Test
    fun rotationKeepsChats() {
        assertFalse(shouldWipeOnStop(isChangingConfigurations = true))
    }
}
