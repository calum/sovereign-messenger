package org.sovereign.mesh.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.PairingOutcome
import org.sovereign.mesh.core.groupFingerprint
import org.sovereign.mesh.core.keyChangedWarning
import uniffi.rust_core.FacadeException
import uniffi.rust_core.PairingAssembler

private const val MAX_NAME_LENGTH = 32

/** The steps of adding a contact, in order. Back goes one step; at the first step it leaves. */
private enum class Step { NAME, SHOW, SCAN, RESULT }

/**
 * A note for the name field when [name] is already a contact, else null. Reusing a name is how
 * a contact whose phone was reset is paired again: the new code is checked against the saved key
 * and a different key is refused until the user accepts it. The note says so.
 */
internal fun nameNote(name: String, existing: List<String>): String? {
    val trimmed = name.trim()
    return if (trimmed.isNotEmpty() && existing.any { it.equals(trimmed, ignoreCase = true) }) {
        "You already have a contact with this name. Their new code will be checked against the saved key."
    } else {
        null
    }
}

/**
 * Adding a contact, one step at a time: name them, show your codes, scan theirs, then compare
 * fingerprints. A changed key for a known contact is shown as a warning and refused; it is only
 * accepted by an explicit tap, and then the next scan pins it.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun PairingScreen(onBack: () -> Unit, onOpenChat: (String) -> Unit) {
    val core = SovereignApp.core
    // The payload is split across two QR codes (PLAN.md Decisions, 2026-10-24, QR decode).
    val parts = remember { core.ownPairingParts() }
    val ownFingerprint = remember { core.ownFingerprint() }
    var step by remember { mutableStateOf(Step.NAME) }
    var name by remember { mutableStateOf("") }
    var outcome by remember { mutableStateOf<PairingOutcome?>(null) }
    var assembler by remember { mutableStateOf<PairingAssembler?>(null) }
    var received by remember { mutableStateOf(0) }
    var total by remember { mutableStateOf(0) }
    val existing = remember(step) { core.pinnedPeers() }
    val peer = name.trim()

    // One step back; a finished pairing has nothing to go back to, so it leaves.
    fun goBack() {
        when (step) {
            Step.NAME -> onBack()
            Step.SHOW -> step = Step.NAME
            Step.SCAN -> step = Step.SHOW
            Step.RESULT -> if (outcome is PairingOutcome.Pinned) onBack() else step = Step.SHOW
        }
    }
    BackHandler(enabled = step != Step.NAME) { goBack() }

    Scaffold(
        topBar = {
            ScreenBar(
                onBack = { goBack() },
                title = { BarTitle("Add contact") },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            when (step) {
                Step.NAME -> {
                    StepHeader(1, "Who are you adding?")
                    Text(
                        "Choose a name for them. It is only saved on this phone.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    val note = nameNote(name, existing)
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it.take(MAX_NAME_LENGTH) },
                        label = { Text("Name") },
                        singleLine = true,
                        supportingText = note?.let { { Text(it) } },
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                        keyboardActions = KeyboardActions(onNext = {
                            if (peer.isNotEmpty()) step = Step.SHOW
                        }),
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = { step = Step.SHOW },
                        enabled = peer.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Next") }
                }

                Step.SHOW -> {
                    StepHeader(2, "Show your codes to $peer")
                    Text(
                        "Hold your phone so $peer can scan each code in turn. " +
                            "Do not send these codes over any network.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    val pager = rememberPagerState(pageCount = { parts.size })
                    HorizontalPager(state = pager, modifier = Modifier.fillMaxWidth()) { index ->
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                "Code ${index + 1} of ${parts.size}" +
                                    if (parts.size > 1) " (swipe for the next)" else "",
                                style = MaterialTheme.typography.labelLarge,
                            )
                            QrCode(parts[index], modifier = Modifier.padding(horizontal = 24.dp))
                        }
                    }
                    InfoCard("Your fingerprint\n${groupFingerprint(ownFingerprint)}", monospace = true)
                    Button(
                        onClick = {
                            outcome = null
                            assembler = core.newPairingAssembler()
                            received = 0
                            total = 0
                            step = Step.SCAN
                        },
                        modifier = Modifier.fillMaxWidth(),
                    ) { Text("Scan $peer's codes") }
                }

                Step.SCAN -> {
                    StepHeader(3, "Scan $peer's codes")
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
                                    outcome = core.scanPairing(peer, full)
                                    SovereignApp.connections.refresh()
                                    step = Step.RESULT
                                }
                            }
                        },
                        onCancel = { step = Step.SHOW },
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

                Step.RESULT -> ResultStep(
                    peer = peer,
                    outcome = outcome,
                    onOpenChat = { onOpenChat(peer) },
                    onDone = onBack,
                    onTryAgain = { step = Step.SHOW },
                    onAcceptNewKey = {
                        core.acceptNewKey(it)
                        outcome = null
                        step = Step.SHOW
                    },
                )
            }
        }
    }
}

@Composable
private fun StepHeader(number: Int, title: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            "Step $number of 3",
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(title, style = MaterialTheme.typography.headlineSmall)
    }
}

@Composable
private fun ResultStep(
    peer: String,
    outcome: PairingOutcome?,
    onOpenChat: () -> Unit,
    onDone: () -> Unit,
    onTryAgain: () -> Unit,
    onAcceptNewKey: (String) -> Unit,
) {
    when (outcome) {
        null -> Unit
        is PairingOutcome.Pinned -> {
            Text("Paired with $peer", style = MaterialTheme.typography.headlineSmall)
            InfoCard("Their fingerprint\n${groupFingerprint(outcome.fingerprint)}", monospace = true)
            Text(
                "Ask $peer to read their screen's fingerprint aloud, and compare. " +
                    "If the blocks do not match, remove them from their chat menu and start again.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Button(onClick = onOpenChat, modifier = Modifier.fillMaxWidth()) { Text("Open chat with $peer") }
            OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("Done") }
        }
        is PairingOutcome.AlreadyPinned -> {
            InfoCard("${outcome.peer} is already paired with this code. Nothing changed.")
            OutlinedButton(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("Done") }
        }
        is PairingOutcome.Invalid -> {
            InfoCard("That is not a valid pairing code. Nothing was added.")
            Button(onClick = onTryAgain, modifier = Modifier.fillMaxWidth()) { Text("Try again") }
        }
        is PairingOutcome.Failed -> {
            InfoCard("Pairing failed. Nothing was added.")
            Button(onClick = onTryAgain, modifier = Modifier.fillMaxWidth()) { Text("Try again") }
        }
        is PairingOutcome.KeyChanged -> KeyChangedCard(
            peer = outcome.peer,
            onKeepOldKey = onDone,
            onAcceptNewKey = { onAcceptNewKey(outcome.peer) },
        )
    }
}

@Composable
private fun InfoCard(text: String, monospace: Boolean = false) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors()) {
        Text(
            text,
            modifier = Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (monospace) FontFamily.Monospace else null,
        )
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
