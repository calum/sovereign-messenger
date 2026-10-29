package org.sovereign.mesh.ui

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import org.sovereign.mesh.SovereignApp
import org.sovereign.mesh.core.sendStatusText
import org.sovereign.mesh.core.updateStatusText
import org.sovereign.mesh.update.UpdateInstaller

/** Where the receive flow stands. `Verified` is the only state that enables Install. */
private sealed class UpdateState {
    object Idle : UpdateState()
    object Receiving : UpdateState()
    class Verified(val apk: ByteArray) : UpdateState()
    class Failed(val text: String) : UpdateState()
}

/** Where the send flow stands. Holds no APK or signature bytes: those live only inside the send call. */
private sealed class SendState {
    object Idle : SendState()
    object Sending : SendState()
    object Sent : SendState()
    class Failed(val text: String) : SendState()
}

/** Seconds allowed for the TCP connection to the other phone. The write has its own longer limit in rust-core. */
private const val SEND_CONNECT_TIMEOUT_SECS = 10

private const val APK_MIME = "application/vnd.android.package-archive"

/**
 * Update screen: shows the installed version and the developer key fingerprint,
 * receives an APK from a phone on the same Wi-Fi, and offers Install only after
 * rust-core has verified the signature. The fingerprint is for the two people to
 * compare in person before installing; the app pins the key at build time.
 *
 * The send section forwards a bundle the developer signed on their PC (APK, .sig,
 * version). This phone never signs. The other phone verifies the bundle itself.
 */
@Composable
fun UpdateScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val core = SovereignApp.core
    val scope = rememberCoroutineScope()
    val installedName = remember { UpdateInstaller.installedVersionName(context) }
    val installedCode = remember { UpdateInstaller.installedVersion(context) }
    val keyFingerprint = remember { core.developerKeyFingerprint() }
    var state by remember { mutableStateOf<UpdateState>(UpdateState.Idle) }

    var apkUri by remember { mutableStateOf<Uri?>(null) }
    var apkName by remember { mutableStateOf<String?>(null) }
    var sigUri by remember { mutableStateOf<Uri?>(null) }
    var sigName by remember { mutableStateOf<String?>(null) }
    var versionText by remember { mutableStateOf("") }
    var peerAddress by remember { mutableStateOf("") }
    var sendState by remember { mutableStateOf<SendState>(SendState.Idle) }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        apkUri = uri
        apkName = null
        scope.launch { apkName = withContext(Dispatchers.IO) { displayName(context, uri) } }
    }
    val sigPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        sigUri = uri
        sigName = null
        scope.launch { sigName = withContext(Dispatchers.IO) { displayName(context, uri) } }
    }

    // Leaving the screen discards any staged APK.
    DisposableEffect(Unit) {
        onDispose { UpdateInstaller.deleteStaged(context) }
    }

    Scaffold(topBar = { ScreenBar(onBack = onBack, title = { BarTitle("Updates") }) }) { padding ->
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(padding)
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {

        Text("Installed version: $installedName", style = MaterialTheme.typography.bodyMedium)
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
                                installedCode,
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

        Text("Send update", style = MaterialTheme.typography.titleMedium)
        Text(
            "Sends a bundle you signed on your PC: the APK, its 64-byte .sig file, and the version. " +
                "This phone does not sign. The .sig must be the developer's signature for this exact APK and version. " +
                "The other phone checks it before it offers install.",
            style = MaterialTheme.typography.bodySmall,
        )

        OutlinedButton(
            onClick = { apkPicker.launch(arrayOf(APK_MIME)) },
            enabled = sendState !is SendState.Sending,
        ) {
            Text("Pick APK")
        }
        Text(
            apkName?.let { "APK: $it" } ?: if (apkUri != null) "Reading APK name..." else "No APK picked.",
            style = MaterialTheme.typography.bodySmall,
        )

        OutlinedButton(
            onClick = { sigPicker.launch(arrayOf("*/*")) },
            enabled = sendState !is SendState.Sending,
        ) {
            Text("Pick .sig file")
        }
        Text(
            sigName?.let { "Signature: $it" } ?: if (sigUri != null) "Reading signature name..." else "No .sig file picked.",
            style = MaterialTheme.typography.bodySmall,
        )

        OutlinedTextField(
            value = versionText,
            onValueChange = { versionText = it },
            label = { Text("Version (whole number)") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
        )

        OutlinedTextField(
            value = peerAddress,
            onValueChange = { peerAddress = it },
            label = { Text("Other phone address host:port") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Button(
            onClick = {
                val uri = apkUri ?: return@Button
                val sUri = sigUri ?: return@Button
                val name = apkName
                val version = versionText
                val addr = peerAddress.trim()
                sendState = SendState.Sending
                scope.launch {
                    sendState = try {
                        withContext(Dispatchers.IO) {
                            // Bounded reads: one byte past each cap is enough for the policy to refuse.
                            val apk = readBounded(context, uri, UpdateSendPolicy.MAX_APK_BYTES + 1)
                            val sig = readBounded(context, sUri, UpdateSendPolicy.SIGNATURE_BYTES + 1)
                            when (val check = UpdateSendPolicy.check(name, apk.size.toLong(), sig.size.toLong(), version)) {
                                is UpdateSendCheck.Refused -> SendState.Failed(check.message)
                                is UpdateSendCheck.Accepted -> {
                                    core.sendUpdate(addr, SEND_CONNECT_TIMEOUT_SECS, apk, check.version, sig)
                                    SendState.Sent
                                }
                            }
                        }
                    } catch (e: Exception) {
                        SendState.Failed(sendStatusText(e))
                    }
                }
            },
            enabled = sendState !is SendState.Sending &&
                apkUri != null && sigUri != null && peerAddress.isNotBlank(),
        ) {
            Text("Send")
        }

        when (val s = sendState) {
            is SendState.Idle -> Unit
            is SendState.Sending -> Text("Sending to the other phone...", style = MaterialTheme.typography.bodyMedium)
            is SendState.Sent -> Text(
                "Sent. The other phone verifies the signature before it offers install.",
                style = MaterialTheme.typography.bodyMedium,
            )
            is SendState.Failed -> Text(s.text, style = MaterialTheme.typography.bodyMedium)
        }
    }
    }
}

/** The picked file's display name, or null if the provider does not report one. */
private fun displayName(context: Context, uri: Uri): String? =
    context.contentResolver
        .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }

/**
 * Reads at most [limit] bytes of [uri] into memory. Nothing is copied to the app
 * cache or any file: the bytes exist only in this call and go straight to rust-core.
 * Reading stops at [limit], so an oversize file cannot grow the heap past the cap.
 */
private fun readBounded(context: Context, uri: Uri, limit: Long): ByteArray {
    val input = context.contentResolver.openInputStream(uri) ?: throw IOException("unreadable")
    input.use { stream ->
        val out = ByteArrayOutputStream()
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (total < limit) {
            val want = minOf(buf.size.toLong(), limit - total).toInt()
            val n = stream.read(buf, 0, want)
            if (n < 0) break
            out.write(buf, 0, n)
            total += n
        }
        return out.toByteArray()
    }
}
