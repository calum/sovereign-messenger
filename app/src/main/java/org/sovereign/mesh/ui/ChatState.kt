package org.sovereign.mesh.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.CoreBridge
import uniffi.rust_core.ChatMessage
import uniffi.rust_core.Presence

/** Background re-read interval. Events from [org.sovereign.mesh.core.PeerConnections] refresh sooner. */
private const val POLL_MS = 1_000L

/** One contact's messages and how many of them the user has not seen. */
data class ConversationSnapshot(val messages: List<ChatMessage>, val unread: Int)

/** One contact as the chat list shows them. */
data class ContactRow(
    val name: String,
    val presence: Presence,
    val last: ChatMessage?,
    val unread: Int,
)

private fun readConversation(core: CoreBridge, peer: String) =
    ConversationSnapshot(core.conversation(peer), core.unreadCount(peer))

private fun readContacts(core: CoreBridge): List<ContactRow> =
    core.pinnedPeers()
        .map { peer ->
            ContactRow(
                name = peer,
                presence = core.presence(peer),
                last = core.conversation(peer).lastOrNull(),
                unread = core.unreadCount(peer),
            )
        }
        .sortedWith(
            compareByDescending<ContactRow> { it.last?.atMs?.toLong() ?: 0L }
                .thenBy { it.name.lowercase() },
        )

/** Re-reads from the core every second and straight away when something arrives. */
@Composable
private fun <T> rememberCoreRead(vararg keys: Any?, read: (CoreBridge) -> T, initial: T): State<T> {
    val core = SovereignApp.core
    val revision = SovereignApp.connections.revision
    return produceState(initial, core, revision, *keys) {
        while (true) {
            withContext(Dispatchers.IO) { runCatching { read(core) } }.onSuccess { value = it }
            delay(POLL_MS)
        }
    }
}

@Composable
fun rememberConversation(peer: String): State<ConversationSnapshot> =
    rememberCoreRead(peer, read = { readConversation(it, peer) }, initial = ConversationSnapshot(emptyList(), 0))

@Composable
fun rememberPresence(peer: String): State<Presence> =
    rememberCoreRead(peer, read = { it.presence(peer) }, initial = Presence(online = false, lastSeenMs = null))

@Composable
fun rememberContacts(): State<List<ContactRow>?> =
    rememberCoreRead<List<ContactRow>?>(read = { readContacts(it) }, initial = null)
