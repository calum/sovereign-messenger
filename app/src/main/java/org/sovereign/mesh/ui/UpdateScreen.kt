package org.sovereign.mesh.ui

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.updateStatusText
import org.sovereign.mesh.update.UpdateInstaller

/** Where the receive flow stands. `Verified` is the only state that enables Install. */
private sealed class UpdateState {
    object Idle : UpdateState()
    object Receiving : UpdateState()
    class Verified(val apk: ByteArray) : UpdateState()
    class Failed(val text: String) : UpdateState()
}

/**
 * Update screen: shows the installed version and the developer key fingerprint,
 * receives an APK from a phone on the same Wi-Fi, and offers Install only after
 * rust-core has verified the signature. The fingerprint is for the two people to
 * compare in person before installing; the app pins the key at build time.
 */
@Composable
fun UpdateScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val core = SovereignApp.core
    val scope = rememberCoroutineScope()
    val installed = remember { UpdateInstaller.installedVersion(context) }
    val keyFingerprint = remember { core.developerKeyFingerprint() }
    var state by remember { mutableStateOf<UpdateState>(UpdateState.Idle) }

    // Leaving the screen discards any staged APK.
    DisposableEffect(Unit) {
        onDispose { UpdateInstaller.deleteStaged(context) }
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Button(onClick = onBack) { Text("Back") }
        Text("Updates", style = MaterialTheme.typography.titleLarge)

        Text("Installed version: $installed", style = MaterialTheme.typography.bodyMedium)
        Text(
            if (keyFingerprint == null) {
                "No developer key is set in this build. Every update is refused."
            } else {
                "Developer key fingerprint: $keyFingerprint"
            },
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            "Check this fingerprint with the developer in person before you install.",
            style = MaterialTheme.typography.bodySmall,
        )

        Button(
            onClick = {
                UpdateInstaller.deleteStaged(context)
                state = UpdateState.Receiving
                scope.launch {
                    state = try {
                        val apk = withContext(Dispatchers.IO) {
                            core.receiveUpdate(
                                UpdateInstaller.LISTEN_ADDR,
                                UpdateInstaller.LISTEN_TIMEOUT_SECS,
                            )
                        }
                        UpdateState.Verified(apk)
                    } catch (e: Exception) {
                        UpdateState.Failed(updateStatusText(e))
                    }
                }
            },
            enabled = state !is UpdateState.Receiving,
        ) {
            Text("Receive update")
        }

        when (val s = state) {
            is UpdateState.Idle -> Text(
                "On the other phone, send the signed APK to this phone over Wi-Fi while this screen waits.",
                style = MaterialTheme.typography.bodySmall,
            )
            is UpdateState.Receiving -> Text(
                "Waiting for the other phone on port 47002 (up to two minutes).",
                style = MaterialTheme.typography.bodyMedium,
            )
            is UpdateState.Verified -> Text(
                "Signature verified (${s.apk.size} bytes). Install only if the fingerprint above matches.",
                style = MaterialTheme.typography.bodyMedium,
            )
            is UpdateState.Failed -> Text(s.text, style = MaterialTheme.typography.bodyMedium)
        }

        // Enabled only for a payload rust-core has verified.
        OutlinedButton(
            onClick = {
                val verified = state as? UpdateState.Verified ?: return@OutlinedButton
                state = try {
                    val file = UpdateInstaller.stage(context, verified.apk)
                    context.startActivity(UpdateInstaller.installIntent(context, file))
                    UpdateState.Idle
                } catch (e: Exception) {
                    UpdateInstaller.deleteStaged(context)
                    UpdateState.Failed("The update could not be handed to the installer. Nothing was installed.")
                }
            },
            enabled = state is UpdateState.Verified,
        ) {
            Text("Install")
        }
    }
}
