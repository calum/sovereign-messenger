package org.sovereign.mesh.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.torStatusText

@Composable
fun ChatListScreen(onOpenChat: (String) -> Unit, onPair: () -> Unit, onUpdate: () -> Unit) {
    val peers = SovereignApp.core.peers()
    var confirmDelete by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(chatListTitle, style = MaterialTheme.typography.titleLarge)
        }
        P2pMeshIndicator(peer = null, modifier = Modifier.padding(top = 4.dp))
        SovereignApp.tor.snapshot.let {
            Text(
                torStatusText(it.state, it.percent),
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(top = 2.dp),
            )
        }
        Button(onClick = onPair, modifier = Modifier.padding(top = 8.dp)) {
            Text("Pair a contact")
        }
        OutlinedButton(onClick = onUpdate, modifier = Modifier.padding(top = 8.dp)) {
            Text("Updates")
        }
        identityNotice(SovereignApp.identityUnreadable, SovereignApp.core.saveFailed)?.let {
            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 12.dp))
        }
        OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.padding(top = 8.dp)) {
            Text("Delete my identity")
        }

        if (confirmDelete) {
            DeleteIdentityDialog(
                onConfirm = {
                    confirmDelete = false
                    // Stopping Tor and deleting its folder can take a moment: not on the UI thread.
                    scope.launch(Dispatchers.IO) { SovereignApp.deleteIdentity() }
                },
                onDismiss = { confirmDelete = false },
            )
        }

        if (peers.isEmpty()) {
            Text(
                "No chats yet. Meet a friend in person and scan their QR code to start.",
                modifier = Modifier.padding(top = 24.dp),
            )
        } else {
            LazyColumn {
                items(peers) { peer ->
                    Text(
                        peer,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpenChat(peer) }
                            .padding(vertical = 16.dp),
                    )
                }
            }
        }
    }
}

/** Confirms before the stored identity and every contact pin are destroyed. */
@Composable
private fun DeleteIdentityDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Delete your identity?") },
        text = { Text(deleteIdentityWarning) },
        confirmButton = { TextButton(onClick = onConfirm) { Text("Delete") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** The chat list title. It must not say "secured" until the app can back that claim (CLAUDE.md rule 7). */
internal const val chatListTitle = "P2P Mesh"

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
