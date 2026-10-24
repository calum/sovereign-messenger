package org.sovereign.mesh.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.transportStatusText

/** Seconds of RAM-only retention shown in the header. Matches the wipe-on-stop policy. */
private const val RETENTION_SECONDS = 15 * 60

/** Port this phone listens on when it waits for a contact to dial in. */
private const val LISTEN_PORT = 47001

/** How long a listen call waits before giving up. The core call cannot be cancelled. */
private const val LISTEN_SECONDS = 120

@Composable
fun ChatScreen(peer: String, onBack: () -> Unit) {
    val core = SovereignApp.core
    val scope = rememberCoroutineScope()
    var draft by remember { mutableStateOf("") }
    var address by remember { mutableStateOf("") }
    var status by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    // Bumped after each connection so the receive loop restarts on the new socket.
    var connectionEpoch by remember { mutableIntStateOf(0) }
    val messages = remember(peer) { mutableStateOf(core.history(peer)) }
    var remaining by remember { mutableIntStateOf(RETENTION_SECONDS) }

    LaunchedEffect(Unit) {
        while (remaining > 0) {
            delay(1_000)
            remaining -= 1
        }
    }

    // Receives while the connection is open. Each call blocks briefly in rust-core
    // and returns false when idle, so the loop can end as soon as it is cancelled.
    LaunchedEffect(peer, connectionEpoch) {
        while (isActive) {
            val received = withContext(Dispatchers.IO) { runCatching { core.receiveOnce(peer) } }
            val error = received.exceptionOrNull()
            if (error != null) {
                status = transportStatusText(error)
                return@LaunchedEffect
            }
            if (received.getOrNull() == true) {
                messages.value = core.history(peer)
            }
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(12.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onBack) { Text("Back") }
            Text(
                "RAM only · ${remaining / 60}:${(remaining % 60).toString().padStart(2, '0')}",
                style = MaterialTheme.typography.labelMedium,
            )
        }

        status?.let { Text(it, style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 4.dp)) }

        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
            OutlinedTextField(
                value = address,
                onValueChange = { address = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Contact address host:port") },
                singleLine = true,
            )
            Button(
                enabled = !busy && address.isNotBlank(),
                onClick = {
                    busy = true
                    status = "Connecting..."
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            runCatching { core.connect(peer, address.trim()) }
                        }
                        busy = false
                        status = result.exceptionOrNull()?.let(::transportStatusText) ?: "Connected."
                        if (result.isSuccess) connectionEpoch += 1
                    }
                },
                modifier = Modifier.padding(start = 8.dp),
            ) { Text("Connect") }
        }

        Button(
            enabled = !busy,
            onClick = {
                busy = true
                status = "Waiting for the contact on port $LISTEN_PORT..."
                scope.launch {
                    val result = withContext(Dispatchers.IO) {
                        runCatching { core.listen(peer, "0.0.0.0:$LISTEN_PORT", LISTEN_SECONDS) }
                    }
                    busy = false
                    status = result.exceptionOrNull()?.let(::transportStatusText) ?: "Connected."
                    if (result.isSuccess) connectionEpoch += 1
                }
            },
            modifier = Modifier.padding(top = 4.dp),
        ) { Text("Wait for contact") }

        LazyColumn(modifier = Modifier.weight(1f).padding(vertical = 8.dp)) {
            items(messages.value) { text ->
                Text(text, modifier = Modifier.padding(vertical = 4.dp))
            }
        }

        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = draft,
                onValueChange = { draft = it },
                modifier = Modifier.weight(1f),
                placeholder = { Text("Message") },
            )
            Button(
                onClick = {
                    val text = draft
                    if (text.isNotBlank()) {
                        scope.launch {
                            val result = withContext(Dispatchers.IO) {
                                runCatching { core.send(peer, text) }
                            }
                            val error = result.exceptionOrNull()
                            if (error == null) {
                                draft = ""
                                status = null
                            } else {
                                // Keep the draft so the user can retry after reconnecting.
                                status = transportStatusText(error)
                            }
                            messages.value = core.history(peer)
                        }
                    }
                },
                modifier = Modifier.padding(start = 8.dp),
            ) { Text("Send") }
        }
    }
}
