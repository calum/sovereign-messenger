package org.sovereign.mesh.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.PairingOutcome
import org.sovereign.mesh.core.keyChangedWarning
import uniffi.rust_core.FacadeException
import uniffi.rust_core.PairingAssembler

/**
 * Pairing screen: shows this phone's QR code, scans the other phone's, and
 * reports the pin. A changed key for a known contact is shown as a warning and
 * refused; it is only accepted by an explicit tap, and then the next scan pins it.
 * The fingerprint is shown so the two people can compare it in person.
 */
@Composable
fun PairingScreen(onBack: () -> Unit) {
    val core = SovereignApp.core
    // The payload is split across two QR codes (PLAN.md Decisions, 2026-10-24, QR decode).
    val parts = remember { core.ownPairingParts() }
    val ownFingerprint = remember { core.ownFingerprint() }
    var name by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var outcome by remember { mutableStateOf<PairingOutcome?>(null) }
    var pinned by remember { mutableStateOf(core.pinnedPeers()) }
    var assembler by remember { mutableStateOf<PairingAssembler?>(null) }
    var received by remember { mutableStateOf(0) }
    var total by remember { mutableStateOf(0) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Button(onClick = onBack) { Text("Back") }
        Text("Pair a contact", style = MaterialTheme.typography.titleLarge)

        Text("Your code", style = MaterialTheme.typography.titleMedium)
        parts.forEachIndexed { index, part ->
            Text("Code ${index + 1} of ${parts.size}", style = MaterialTheme.typography.bodyMedium)
            QrCode(part)
        }
        Text("Your fingerprint: $ownFingerprint", style = MaterialTheme.typography.bodyMedium)
        Text(
            "Show every code to the other person in person, one after another. " +
                "Do not send them over any network.",
            style = MaterialTheme.typography.bodySmall,
        )

        Text("Scan their code", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(
            value = name,
            onValueChange = { name = it.take(MAX_NAME_LENGTH) },
            label = { Text("Name for this contact (stays on this phone)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = {
                outcome = null
                assembler = core.newPairingAssembler()
                received = 0
                total = 0
                scanning = true
            },
            enabled = name.isNotBlank() && !scanning,
        ) {
            Text("Scan a code")
        }

        if (scanning) {
            val peer = name.trim()
            // Each decoded part goes to the assembler. Only the complete payload pins, so one
            // code alone never reaches scanPairing. A part that is refused changes nothing.
            PairingScanner(
                onPart = { part ->
                    val collector = assembler
                    if (collector != null) {
                        val full = try {
                            collector.addPart(part)
                        } catch (e: FacadeException) {
                            null
                        }
                        received = collector.received().toInt()
                        total = collector.total().toInt()
                        if (full != null) {
                            scanning = false
                            outcome = core.scanPairing(peer, full)
                            pinned = core.pinnedPeers()
                        }
                    }
                },
                onCancel = { scanning = false },
            )
            Text(
                if (total == 0) {
                    "Point the camera at one of their codes."
                } else {
                    "Scanned $received of $total codes. Keep scanning until all are read."
                },
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        when (val result = outcome) {
            null -> Unit
            is PairingOutcome.Pinned -> InfoCard(
                "Pinned. Fingerprint ${result.fingerprint}. " +
                    "Compare it with the fingerprint on their screen. " +
                    "Chats start once the transport is built (PLAN section 3).",
            )
            is PairingOutcome.AlreadyPinned -> InfoCard(
                "${result.peer} is already pinned with this code. Nothing changed.",
            )
            is PairingOutcome.Invalid -> InfoCard(
                "That is not a valid pairing code. Nothing was pinned.",
            )
            is PairingOutcome.Failed -> InfoCard(
                "Pairing failed. Nothing was pinned. Try again.",
            )
            is PairingOutcome.KeyChanged -> KeyChangedCard(
                peer = result.peer,
                onKeepOldKey = { outcome = null },
                onAcceptNewKey = {
                    core.acceptNewKey(result.peer)
                    pinned = core.pinnedPeers()
                    outcome = null
                },
            )
        }

        Text("Pinned contacts", style = MaterialTheme.typography.titleMedium)
        if (pinned.isEmpty()) {
            Text("None yet.", style = MaterialTheme.typography.bodyMedium)
        } else {
            pinned.forEach { peer ->
                Text(
                    "$peer: ${core.pinFingerprint(peer) ?: "not pinned"}",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }
}

@Composable
private fun InfoCard(text: String) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors()) {
        Text(text, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodyMedium)
    }
}

/**
 * Warning state for a changed key. The core has already refused the new key.
 * Both buttons are explicit: keeping the old key is the default.
 */
@Composable
private fun KeyChangedCard(peer: String, onKeepOldKey: () -> Unit, onAcceptNewKey: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                "Key changed",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                keyChangedWarning(peer),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onKeepOldKey) { Text("Keep old key") }
                OutlinedButton(onClick = onAcceptNewKey) { Text("Accept new key") }
            }
        }
    }
}

private const val MAX_NAME_LENGTH = 32
