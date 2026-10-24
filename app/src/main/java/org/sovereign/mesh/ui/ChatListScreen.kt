package org.sovereign.mesh.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.sovereign.mesh.SovereignApp

@Composable
fun ChatListScreen(onOpenChat: (String) -> Unit, onPair: () -> Unit, onUpdate: () -> Unit) {
    val peers = SovereignApp.core.peers()

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Secured P2P Mesh", style = MaterialTheme.typography.titleLarge)
        }
        Button(onClick = onPair, modifier = Modifier.padding(top = 8.dp)) {
            Text("Pair a contact")
        }
        OutlinedButton(onClick = onUpdate, modifier = Modifier.padding(top = 8.dp)) {
            Text("Updates")
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
