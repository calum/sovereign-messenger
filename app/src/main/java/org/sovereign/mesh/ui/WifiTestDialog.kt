package org.sovereign.mesh.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
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
import kotlinx.coroutines.withContext
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.transportStatusText

/** Port this phone listens on when it waits for a contact to dial in. */
private const val LISTEN_PORT = 47001

/** How long a listen call waits before giving up. The core call cannot be cancelled. */
private const val LISTEN_SECONDS = 120

/**
 * Developer test path: connect to [peer] over the same Wi-Fi without Tor. It is not private
 * from the network, and the dialog says so. Once the link is up the app-wide receive loop
 * takes over, so nothing here receives.
 */
@Composable
fun WifiTestDialog(peer: String, onDismiss: () -> Unit) {
    val core = SovereignApp.core
    val scope = rememberCoroutineScope()
    var address by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Wi-Fi test connection") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "For testing on one network. This path does not use Tor and is not private.",
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = address,
                        onValueChange = { address = it },
                        modifier = Modifier.weight(1f),
                        placeholder = { Text("host:port") },
                        singleLine = true,
                    )
                    Button(
                        enabled = !busy && address.isNotBlank(),
                        onClick = {
                            busy = true
                            status = "Connecting…"
                            scope.launch {
                                val result = withContext(Dispatchers.IO) {
                                    runCatching { core.connect(peer, address.trim()) }
                                }
                                busy = false
                                status = result.exceptionOrNull()?.let(::transportStatusText) ?: "Connected."
                                SovereignApp.connections.refresh()
                            }
                        },
                        modifier = Modifier.padding(start = 8.dp),
                    ) { Text("Connect") }
                }
                OutlinedButton(
                    enabled = !busy,
                    onClick = {
                        busy = true
                        status = "Waiting for $peer on port $LISTEN_PORT…"
                        scope.launch {
                            val result = withContext(Dispatchers.IO) {
                                runCatching { core.listen(peer, "0.0.0.0:$LISTEN_PORT", LISTEN_SECONDS) }
                            }
                            busy = false
                            status = result.exceptionOrNull()?.let(::transportStatusText) ?: "Connected."
                            SovereignApp.connections.refresh()
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Wait for $peer to connect") }
                status?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
