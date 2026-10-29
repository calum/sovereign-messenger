package org.sovereign.mesh

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import org.sovereign.mesh.ui.ChatScreen
import org.sovereign.mesh.ui.ChatListScreen
import org.sovereign.mesh.ui.PairingScreen
import org.sovereign.mesh.ui.TourScreen
import org.sovereign.mesh.ui.UpdateScreen
import org.sovereign.mesh.update.UpdateInstaller

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Blocks screenshots, screen recording and the recent-apps thumbnail.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // A staged APK is deleted on every start, in case the last run ended before its cleanup.
        UpdateInstaller.deleteStaged(this)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var showTour by remember { mutableStateOf(true) }
                    var openPeer by remember { mutableStateOf<String?>(null) }
                    var showPairing by remember { mutableStateOf(false) }
                    var showUpdate by remember { mutableStateOf(false) }

                    val earlierExit = SovereignApp.earlierExitReport
                    when {
                        earlierExit != null -> CrashReportScreen(
                            report = earlierExit,
                            headline = "The app stopped last time",
                            doneLabel = "Continue",
                            onDone = { SovereignApp.earlierExitReport = null },
                        )
                        showTour -> TourScreen(onFinished = { showTour = false })
                        showPairing -> PairingScreen(onBack = { showPairing = false })
                        showUpdate -> UpdateScreen(onBack = { showUpdate = false })
                        openPeer != null -> ChatScreen(
                            peer = openPeer!!,
                            onBack = { openPeer = null },
                        )
                        else -> ChatListScreen(
                            onOpenChat = { openPeer = it },
                            onPair = { showPairing = true },
                            onUpdate = { showUpdate = true },
                        )
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        // Chats are RAM-only. Leaving the app wipes them from the core.
        if (shouldWipeOnStop(isChangingConfigurations)) {
            SovereignApp.core.wipeAll()
        }
    }
}
