package org.sovereign.mesh.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.CoreBridge
import org.sovereign.mesh.core.MeshLink
import org.sovereign.mesh.core.MeshStatus
import org.sovereign.mesh.core.meshStatus

/** How often the indicator re-reads the core. Cheap: each read takes the core lock briefly. */
private const val POLL_MILLIS = 1_000L

/**
 * Discreet header line for the P2P mesh. [peer] is the open chat, or null on the
 * chat list. It re-reads the core every second, so it follows real connection and
 * listener changes without any UI-side state. A failed read keeps the last value
 * rather than showing a state the core did not report.
 */
@Composable
fun P2pMeshIndicator(peer: String?, modifier: Modifier = Modifier) {
    val core = SovereignApp.core
    val status by produceState(
        initialValue = meshStatus(emptyList(), emptyList(), null, peer),
        key1 = peer,
    ) {
        while (true) {
            withContext(Dispatchers.IO) { runCatching { readMeshStatus(core, peer) } }
                .onSuccess { value = it }
            delay(POLL_MILLIS)
        }
    }

    Row(modifier = modifier, verticalAlignment = Alignment.CenterVertically) {
        Dot(status.link)
        Text(
            status.label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 6.dp),
        )
    }
}

private fun readMeshStatus(core: CoreBridge, peer: String?): MeshStatus =
    meshStatus(core.peers(), core.linkedPeers(), core.listeningPeer(), peer)

@Composable
private fun Dot(link: MeshLink) {
    val color = when (link) {
        MeshLink.CONNECTED -> MaterialTheme.colorScheme.primary
        MeshLink.LISTENING -> MaterialTheme.colorScheme.tertiary
        MeshLink.NOT_CONNECTED, MeshLink.NO_SESSION -> MaterialTheme.colorScheme.outline
    }
    Box(
        modifier = Modifier
            .size(8.dp)
            .background(color = color, shape = CircleShape),
    )
}
