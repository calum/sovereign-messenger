package org.sovereign.mesh.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.ChatItem
import org.sovereign.mesh.core.buildChatItems
import org.sovereign.mesh.core.clockTime
import org.sovereign.mesh.core.deliveryDescription
import org.sovereign.mesh.core.deliveryMark
import org.sovereign.mesh.core.reachText
import org.sovereign.mesh.core.torIsReady
import uniffi.rust_core.ChatMessage
import uniffi.rust_core.MessageState

/**
 * One conversation. Messages sit on the left (the contact) or right (you), each run is
 * labelled with who sent it, and your own messages show whether they were sent, delivered
 * or read. A message written while the contact is away is kept in RAM and sent when they
 * return. Receiving happens app-wide in `PeerConnections`, so this screen only reads.
 */
@Composable
fun ChatScreen(peer: String, onBack: () -> Unit, onRemoved: () -> Unit) {
    val core = SovereignApp.core
    val connections = SovereignApp.connections
    val scope = rememberCoroutineScope()
    val snapshot by rememberConversation(peer)
    val presence by rememberPresence(peer)
    val now by rememberNow()
    var showWifiTest by remember { mutableStateOf(false) }
    var confirmRemove by remember { mutableStateOf(false) }

    val torReady = torIsReady(SovereignApp.tor.snapshot.state)
    val subtitle = reachText(
        name = peer,
        online = presence.online,
        lastSeenMs = presence.lastSeenMs?.toLong(),
        nowMs = now,
        dialling = connections.dialling[peer] == true,
        torReady = torReady,
    )

    // The chat counts as read only while it is on screen and the app is in front.
    LaunchedEffect(peer, snapshot.unread, SovereignApp.inForeground, SovereignApp.sendReadReceipts) {
        if (snapshot.unread > 0 && SovereignApp.inForeground) {
            withContext(Dispatchers.IO) {
                runCatching { core.markRead(peer, SovereignApp.sendReadReceipts) }
            }
            connections.refresh()
        }
    }

    Scaffold(
        topBar = {
            ScreenBar(
                onBack = onBack,
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Avatar(peer, presence.online, size = 36.dp)
                        BarTitleWithSubtitle(peer, subtitle)
                    }
                },
                actions = {
                    OverflowMenu(
                        listOf(
                            "Wi-Fi test connection" to { showWifiTest = true },
                            "Remove contact" to { confirmRemove = true },
                        ),
                    )
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .consumeWindowInsets(padding)
                .imePadding(),
        ) {
            connections.problems[peer]?.let { problem ->
                Surface(color = MaterialTheme.colorScheme.errorContainer, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        problem,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    )
                }
            }
            MessageList(
                peer = peer,
                messages = snapshot.messages,
                nowMs = now,
                modifier = Modifier.weight(1f).fillMaxWidth(),
            )
            if (!presence.online) {
                Text(
                    offlineHint(peer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
            Composer(
                peer = peer,
                onSend = { text ->
                    scope.launch {
                        withContext(Dispatchers.IO) { runCatching { core.sendText(peer, text) } }
                        connections.refresh()
                    }
                },
            )
        }
    }

    if (showWifiTest) WifiTestDialog(peer) { showWifiTest = false }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            title = { Text("Remove $peer?") },
            text = { Text(removeContactWarning(peer)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemove = false
                    scope.launch {
                        withContext(Dispatchers.IO) { core.removeContact(peer) }
                        connections.refresh()
                        onRemoved()
                    }
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun MessageList(peer: String, messages: List<ChatMessage>, nowMs: Long, modifier: Modifier) {
    val items = remember(messages, nowMs / DAY_BUCKET_MS) { buildChatItems(messages, nowMs) }
    val listState = rememberLazyListState()
    // Stays pinned to the newest message unless the user has scrolled up to read.
    var followNewest by remember { mutableStateOf(true) }
    LaunchedEffect(listState) {
        androidx.compose.runtime.snapshotFlow { listState.canScrollForward }.collect { followNewest = !it }
    }
    LaunchedEffect(items.size) {
        val last = messages.lastOrNull()
        if (items.isNotEmpty() && (followNewest || last?.outgoing == true)) {
            listState.scrollToItem(items.lastIndex)
        }
    }

    if (items.isEmpty()) {
        Box(modifier = modifier.padding(32.dp), contentAlignment = Alignment.Center) {
            Text(
                "No messages yet. Say hello to $peer.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        return
    }
    LazyColumn(state = listState, modifier = modifier.padding(horizontal = 12.dp)) {
        items(items, key = { it.key }) { item ->
            when (item) {
                is ChatItem.Day -> DaySeparator(item.label)
                is ChatItem.Bubble -> Bubble(item.message, peer, item.showSender)
            }
        }
    }
}

/** Day separators only change at midnight, so the item list is rebuilt once a day, not every tick. */
private const val DAY_BUCKET_MS = 6 * 60 * 60 * 1000L

@Composable
private fun DaySeparator(label: String) {
    Box(modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp), contentAlignment = Alignment.Center) {
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, shape = RoundedCornerShape(12.dp)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            )
        }
    }
}

@Composable
private fun Bubble(message: ChatMessage, peerName: String, showSender: Boolean) {
    val mine = message.outgoing
    Column(
        modifier = Modifier.fillMaxWidth().padding(top = if (showSender) 10.dp else 2.dp),
        horizontalAlignment = if (mine) Alignment.End else Alignment.Start,
    ) {
        if (showSender) {
            Text(
                if (mine) "You" else peerName,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            )
        }
        Surface(
            shape = RoundedCornerShape(
                topStart = 16.dp,
                topEnd = 16.dp,
                bottomStart = if (mine) 16.dp else 4.dp,
                bottomEnd = if (mine) 4.dp else 16.dp,
            ),
            color = if (mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
            modifier = Modifier.widthIn(max = 320.dp),
        ) {
            Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(message.text, style = MaterialTheme.typography.bodyLarge)
                Row(
                    modifier = Modifier.align(Alignment.End),
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    Text(
                        clockTime(message.atMs.toLong()),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    if (mine) {
                        Text(
                            deliveryMark(message.state),
                            style = MaterialTheme.typography.labelSmall,
                            color = if (message.state == MessageState.READ) {
                                MaterialTheme.colorScheme.primary
                            } else {
                                MaterialTheme.colorScheme.onSurfaceVariant
                            },
                            modifier = Modifier.semantics { contentDescription = deliveryDescription(message.state) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun Composer(peer: String, onSend: (String) -> Unit) {
    // Held in RAM for the process, so a half-written message survives rotation and leaving the chat.
    var draft by remember(peer) { mutableStateOf(SovereignApp.drafts[peer].orEmpty()) }
    fun send() {
        val text = draft.trim()
        if (text.isEmpty()) return
        draft = ""
        SovereignApp.drafts.remove(peer)
        onSend(text)
    }
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = draft,
            onValueChange = {
                draft = it
                SovereignApp.drafts[peer] = it
            },
            modifier = Modifier.weight(1f),
            placeholder = { Text("Message") },
            maxLines = 5,
            shape = RoundedCornerShape(24.dp),
            keyboardOptions = KeyboardOptions(
                capitalization = KeyboardCapitalization.Sentences,
                imeAction = ImeAction.Send,
            ),
            keyboardActions = KeyboardActions(onSend = { send() }),
        )
        FilledIconButton(onClick = { send() }, enabled = draft.isNotBlank()) {
            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
        }
    }
}

/** Explains what happens to a message written while the contact is away. */
internal fun offlineHint(name: String): String =
    "$name is offline. Messages you write now are kept on this phone and sent when they are back."

/** What the user is told before a contact is removed. */
internal fun removeContactWarning(name: String): String =
    "This deletes the conversation and the saved key for $name from this phone. " +
        "To message them again you must pair in person again."
