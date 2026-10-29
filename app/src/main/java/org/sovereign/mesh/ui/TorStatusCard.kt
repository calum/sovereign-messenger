package org.sovereign.mesh.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.text.DateFormat
import java.util.Date
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.torProgress
import org.sovereign.mesh.core.torStatusText
import uniffi.rust_core.TorState

/**
 * Tor status with a progress bar while it starts, and a log of what it has done so the
 * user can see it is working. The bar shows only while Tor is starting; it states what
 * the core reports and makes no privacy claim.
 */
@Composable
fun TorStatusCard(modifier: Modifier = Modifier) {
    val tor = SovereignApp.tor
    val snapshot = tor.snapshot
    val progress = torProgress(snapshot.state, snapshot.percent)
    var showLog by remember { mutableStateOf(false) }
    val timeFormat = remember { DateFormat.getTimeInstance(DateFormat.MEDIUM) }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (snapshot.state == TorState.FAILED) {
                MaterialTheme.colorScheme.errorContainer
            } else {
                MaterialTheme.colorScheme.surfaceVariant
            },
        ),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(torStatusText(snapshot.state, snapshot.percent), style = MaterialTheme.typography.titleSmall)
            if (progress.active) {
                val fraction = progress.fraction
                if (fraction == null) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                } else {
                    LinearProgressIndicator(progress = { fraction }, modifier = Modifier.fillMaxWidth())
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(onClick = { showLog = !showLog }) {
                    Text(if (showLog) "Hide progress log" else "Show progress log")
                }
            }
            if (showLog) {
                if (tor.log.isEmpty()) {
                    Text("Nothing yet.", style = MaterialTheme.typography.bodySmall)
                }
                tor.log.takeLast(12).forEach {
                    Text(
                        "${timeFormat.format(Date(it.atMillis))}  ${it.text}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
    }
}
