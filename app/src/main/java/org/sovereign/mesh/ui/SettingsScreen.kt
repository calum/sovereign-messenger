package org.sovereign.mesh.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.completeReset
import org.sovereign.mesh.core.groupFingerprint
import org.sovereign.mesh.core.torStatusText

/**
 * Settings: read receipts, connection state, updates, this phone's fingerprint and the
 * destructive reset. The reset sits here, behind a confirmation, and not on the main list.
 * Settings are held in RAM and return to their defaults when the app process restarts.
 */
@Composable
fun SettingsScreen(onBack: () -> Unit, onUpdate: () -> Unit, onIdentityDeleted: () -> Unit) {
    var confirmDelete by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val tor = SovereignApp.tor.snapshot
    val fingerprint = remember { SovereignApp.core.ownFingerprint() }

    Scaffold(topBar = { ScreenBar(onBack = onBack, title = { BarTitle("Settings") }) }) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()),
        ) {
            SectionLabel("Privacy")
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { SovereignApp.sendReadReceipts = !SovereignApp.sendReadReceipts }
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Send read receipts", style = MaterialTheme.typography.bodyLarge)
                    Text(
                        readReceiptsHelp,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Switch(
                    checked = SovereignApp.sendReadReceipts,
                    onCheckedChange = { SovereignApp.sendReadReceipts = it },
                )
            }
            Text(
                memoryNote,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            HorizontalDivider()

            SectionLabel("Connection")
            Text(
                torStatusText(tor.state, tor.percent),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
            )
            P2pMeshIndicator(peer = null, modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp))
            HorizontalDivider()

            SectionLabel("This phone")
            Text(
                "Your fingerprint. A new contact reads theirs aloud and you compare.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            Text(
                groupFingerprint(fingerprint),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(onClick = onUpdate)
                    .padding(horizontal = 16.dp, vertical = 16.dp),
            ) { Text("App updates", style = MaterialTheme.typography.bodyLarge) }
            HorizontalDivider()

            SectionLabel("Danger zone")
            OutlinedButton(
                onClick = { confirmDelete = true },
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            ) { Text("Delete my identity", color = MaterialTheme.colorScheme.error) }
        }
    }

    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text("Delete your identity?") },
            text = { Text(deleteIdentityWarning) },
            confirmButton = {
                TextButton(onClick = {
                    confirmDelete = false
                    // Stopping Tor and deleting its folder can take a moment: not on the UI thread.
                    scope.launch(Dispatchers.IO) {
                        // Navigates even if a cleanup step failed: the identity is gone either way.
                        completeReset(
                            reset = { SovereignApp.deleteIdentity() },
                            navigate = { scope.launch(Dispatchers.Main) { onIdentityDeleted() } },
                        )
                    }
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
    )
}

/** What the read-receipt switch does, in one sentence a person can act on. */
internal const val readReceiptsHelp =
    "Lets a contact see that you opened their message. Turn it off and they only see delivered."

/** Where messages live, stated plainly (CLAUDE.md rule 1). */
internal const val memoryNote =
    "Messages are kept only in this phone's memory. They are lost when Android closes the app " +
        "or the phone restarts, and are never saved to storage."
