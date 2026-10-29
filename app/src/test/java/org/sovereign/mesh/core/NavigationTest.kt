package org.sovereign.mesh.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Back must go to the previous screen, and only leave the app from the chat list. */
class NavigationTest {

    @Test
    fun backFromAChatReturnsToTheList() {
        val stack = push(initialStack(), Route.chat("sam"))
        assertTrue(canGoBack(stack))
        assertEquals(listOf(Route.LIST), pop(stack))
    }

    @Test
    fun backAtTheRootStaysAndTheSystemLeavesTheApp() {
        assertFalse(canGoBack(initialStack()))
        assertEquals(listOf(Route.LIST), pop(initialStack()))
    }

    @Test
    fun backRetracesTheWholePath() {
        var stack: List<String> = initialStack()
        stack = push(stack, Route.SETTINGS)
        stack = push(stack, Route.UPDATE)
        assertEquals(listOf(Route.LIST, Route.SETTINGS, Route.UPDATE), stack)
        stack = pop(stack)
        assertEquals(Route.SETTINGS, stack.last())
        stack = pop(stack)
        assertEquals(Route.LIST, stack.last())
    }

    @Test
    fun openingTheScreenAlreadyOnTopDoesNotStackIt() {
        val once = push(initialStack(), Route.PAIR)
        assertEquals(once, push(once, Route.PAIR))
    }

    @Test
    fun chatRoutesCarryTheContactName() {
        assertEquals("sam", Route.peerOf(Route.chat("sam")))
        assertEquals("a:b", Route.peerOf(Route.chat("a:b")))
        assertNull(Route.peerOf(Route.SETTINGS))
    }

    @Test
    fun removingAContactDropsTheirChatFromTheStack() {
        val stack = push(push(initialStack(), Route.chat("sam")), Route.chat("ana"))
        assertEquals(listOf(Route.LIST, Route.chat("ana")), withoutPeer(stack, "sam"))
        assertEquals(listOf(Route.LIST), withoutPeer(push(initialStack(), Route.chat("sam")), "sam"))
    }
}
