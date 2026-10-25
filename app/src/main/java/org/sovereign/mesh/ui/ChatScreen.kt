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
import androidx.compose.material3.TextButton
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
import org.sovereign.mesh.core.shouldDial
import org.sovereign.mesh.core.torIsReady
import org.sovereign.mesh.core.torStatusText
import org.sovereign.mesh.core.transportStatusText
import uniffi.rust_core.FacadeException
import uniffi.rust_core.TorRole

/** Seconds of RAM-only retention shown in the header. Matches the wipe-on-stop policy. */
private const val RETENTION_SECONDS = 15 * 60

/**
 * Formats the remaining retention as `m:ss`. The header shows it so the user can
 * see when the RAM-only history will be wiped; the value is a count, never content.
 */
fun formatRetention(seconds: Int): String =
    "${seconds / 60}:${(seconds % 60).toString().padStart(2, '0')}"

/** Port this phone listens on when it waits for a contact to dial in. */
private const val LISTEN_PORT = 47001

/** How long a listen call waits before giving up. The core call cannot be cancelled. */
private const val LISTEN_SECONDS = 120

/** Pause before the receive loop tries again after an error, so a dead link is not spun on. */
private const val RECEIVE_RETRY_MS = 2_000L

/** How often the dial rule is checked. The rule itself decides whether to dial. */
private const val DIAL_CHECK_MS = 1_000L

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
    var showWifiTest by remember { mutableStateOf(false) }
    // Which side of this pair dials over Tor; the other waits to be called.
    val role = remember(peer) { runCatching { core.torRole(peer) }.getOrNull() }
    // True while the link to this contact is believed to be open. The dialer redials when it drops.
    var linkAlive by remember(peer) { mutableStateOf(peer in core.linkedPeers()) }
    var dialFailures by remember(peer) { mutableIntStateOf(0) }
    val tor = SovereignApp.tor.snapshot

    LaunchedEffect(Unit) {
        while (remaining > 0) {
            delay(1_000)
            remaining -= 1
        }
    }

    // Receives while the connection is open. Each call blocks briefly in rust-core
    // and returns false when idle, so the loop can end as soon as it is cancelled. An
    // error does not end the loop: the dialer redials, the waiter is called again, and
    // either way a new session appears under the same contact, so the loop keeps trying.
    LaunchedEffect(peer, connectionEpoch) {
        while (isActive) {
            val received = withContext(Dispatchers.IO) { runCatching { core.receiveOnce(peer) } }
            val error = received.exceptionOrNull()
            if (error != null) {
                if (error is FacadeException.Network) linkAlive = false
                if (error is FacadeException.AuthFailed || error is FacadeException.Malformed) {
                    status = transportStatusText(error)
                }
                delay(RECEIVE_RETRY_MS)
                continue
            }
            if (received.getOrNull() == true) {
                messages.value = core.history(peer)
            }
        }
    }

    // The dialer connects over Tor by itself once Tor is ready, and again after the link
    // drops, backing off after each failure. The waiter never dials; the app-wide accept
    // loop takes its call. `shouldDial` holds the rule and is unit tested.
    LaunchedEffect(peer, role) {
        var lastAttempt: Long? = null
        while (isActive) {
            val now = System.currentTimeMillis()
            val ready = torIsReady(SovereignApp.tor.snapshot.state)
            if (shouldDial(role, ready, linkAlive, busy, lastAttempt?.let { now - it }, dialFailures)) {
                busy = true
                lastAttempt = now
                status = "Connecting to $peer over Tor. This can take a few minutes."
                val result = withContext(Dispatchers.IO) { runCatching { core.connectTor(peer) } }
                busy = false
                val error = result.exceptionOrNull()
                if (error == null) {
                    dialFailures = 0
                    lastAttempt = null
                    linkAlive = true
                    status = "Connected."
                    connectionEpoch += 1
                } else {
                    dialFailures += 1
                    status = transportStatusText(error) + " Trying again shortly."
                }
            }
            delay(DIAL_CHECK_MS)
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
                "RAM only · ${formatRetention(remaining)}",
                style = MaterialTheme.typography.labelMedium,
            )
        }
        P2pMeshIndicator(peer = peer, modifier = Modifier.padding(top = 4.dp))
        Text(
            torStatusText(tor.state, tor.percent),
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(top = 4.dp),
        )
        if (role == TorRole.WAIT && !linkAlive) {
            Text(
                "Waiting for $peer to connect over Tor.",
                style = MaterialTheme.typography.labelMedium,
                modifier = Modifier.padding(top = 2.dp),
            )
        }

        status?.let { Text(it, style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 4.dp)) }

        TextButton(onClick = { showWifiTest = !showWifiTest }, modifier = Modifier.padding(top = 2.dp)) {
            Text(if (showWifiTest) "Hide same-Wi-Fi test" else "Same-Wi-Fi test connection")
        }
        if (showWifiTest) {
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

        }

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
