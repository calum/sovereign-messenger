package org.sovereign.mesh.ui

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class PairingNameTest {
    @Test
    fun aNewNameHasNoNote() {
        assertNull(nameNote("Sam", listOf("Ana")))
        assertNull(nameNote("  ", listOf("Ana")))
    }

    @Test
    fun anExistingNameIsAllowedButExplained() {
        assertNotNull(nameNote("ana", listOf("Ana")))
        assertNotNull(nameNote(" Ana ", listOf("Ana")))
    }
}
