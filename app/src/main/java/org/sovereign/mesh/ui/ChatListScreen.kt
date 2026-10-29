package org.sovereign.mesh.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.deliveryDescription
import org.sovereign.mesh.core.deliveryMark
import org.sovereign.mesh.core.listTime
import org.sovereign.mesh.core.presenceText
import org.sovereign.mesh.core.previewText

@Composable
fun ChatListScreen(onOpenChat: (String) -> Unit, onPair: () -> Unit, onSettings: () -> Unit) {
    val contacts by rememberContacts()
    val now by rememberNow()

    Scaffold(
        topBar = {
            ScreenBar(
                onBack = null,
                title = { BarTitle(chatListTitle) },
                actions = { OverflowMenu(listOf("Settings" to onSettings)) },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onPair,
                icon = { Icon(Icons.Default.Add, contentDescription = null) },
                text = { Text("Add contact") },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            TorStatusCard(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
            identityNotice(SovereignApp.identityUnreadable, SovereignApp.core.saveFailed)?.let {
                Card(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                ) {
                    Text(
                        it,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(12.dp),
                    )
                }
            }
            val rows = contacts
            when {
                rows == null -> Unit
                rows.isEmpty() -> EmptyContacts(onPair)
                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(rows, key = { it.name }) { row ->
                        ContactItem(row, now, onClick = { onOpenChat(row.name) })
                        HorizontalDivider(modifier = Modifier.padding(start = 76.dp))
                    }
                    // Keeps the last row clear of the add button.
                    item { Box(modifier = Modifier.size(88.dp)) }
                }
            }
        }
    }
}

@Composable
private fun EmptyContacts(onPair: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("No contacts yet", style = MaterialTheme.typography.titleLarge)
        Text(
            emptyContactsHelp,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
        )
        Button(onClick = onPair) { Text("Add your first contact") }
    }
}

@Composable
private fun ContactItem(row: ContactRow, nowMs: Long, onClick: () -> Unit) {
    val online = row.presence.online
    val last = row.last
    val line = last?.let(::previewText)
        ?: presenceText(online, row.presence.lastSeenMs?.toLong(), nowMs)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Avatar(row.name, online)
        Column(modifier = Modifier.weight(1f)) {
            Text(
                row.name,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = if (row.unread > 0) FontWeight.Bold else FontWeight.Normal,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                line,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = if (row.unread > 0) FontWeight.Bold else FontWeight.Normal,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Column(horizontalAlignment = Alignment.End, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (last != null) {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (last.outgoing) {
                        Text(
                            deliveryMark(last.state),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.semantics { contentDescription = deliveryDescription(last.state) },
                        )
                    }
                    Text(
                        listTime(last.atMs.toLong(), nowMs),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (row.unread > 0) UnreadBadge(row.unread)
        }
    }
}

@Composable
private fun UnreadBadge(count: Int) {
    Surface(color = MaterialTheme.colorScheme.primary, shape = CircleShape) {
        Text(
            if (count > 99) "99+" else count.toString(),
            color = MaterialTheme.colorScheme.onPrimary,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier
                .padding(horizontal = 7.dp, vertical = 2.dp)
                .semantics { contentDescription = "$count unread" },
        )
    }
}

/**
 * Every pinned contact plus any peer with a live session. A pinned contact has no session
 * until the first connection, so listing only sessions left a freshly paired contact with
 * no way to open a chat.
 */
internal fun chatListPeers(pinned: List<String>, sessions: List<String>): List<String> =
    (pinned + sessions).distinct().sorted()

/** The chat list title. It must not say "secured" until the app can back that claim (CLAUDE.md rule 7). */
internal const val chatListTitle = "P2P Mesh"

/** Shown when nobody is paired yet. It says what to do first, and that pairing happens in person. */
internal const val emptyContactsHelp =
    "Meet a friend in person and scan each other's QR codes. " +
        "You only do this once; after that you can message them whenever you are both online."

/** What the user is told before a delete. It names the cost; there is no recovery. */
internal const val deleteIdentityWarning =
    "This erases your identity and every saved contact from this phone. " +
        "You will get a new identity, and everyone must pair with you again in person. " +
        "This cannot be undone."

/**
 * A warning about identity storage, or null when all is well. Unreadable wins over a
 * failed save because it explains why nothing is being saved at all.
 */
internal fun identityNotice(unreadable: Boolean, saveFailed: Boolean): String? = when {
    unreadable ->
        "Your saved identity could not be opened. This session uses a temporary identity and " +
            "saves nothing. Delete your identity to start again."
    saveFailed -> "Your latest change could not be saved and will be lost if the app closes."
    else -> null
}
