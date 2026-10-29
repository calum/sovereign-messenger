package org.sovereign.mesh.ui

import org.junit.Test
import org.junit.Assert.assertEquals

class ChatListPeersTest {
    @Test
    fun pinnedContactWithoutSessionIsListed() {
        assertEquals(listOf("bob"), chatListPeers(pinned = listOf("bob"), sessions = emptyList()))
    }

    @Test
    fun peerInBothListsAppearsOnce() {
        assertEquals(
            listOf("alice", "bob"),
            chatListPeers(pinned = listOf("bob", "alice"), sessions = listOf("bob")),
        )
    }

    @Test
    fun nothingPinnedAndNoSessionsIsEmpty() {
        assertEquals(emptyList<String>(), chatListPeers(emptyList(), emptyList()))
    }
}
