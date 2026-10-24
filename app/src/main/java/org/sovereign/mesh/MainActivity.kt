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

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Blocks screenshots, screen recording and the recent-apps thumbnail.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var showTour by remember { mutableStateOf(true) }
                    var openPeer by remember { mutableStateOf<String?>(null) }
                    var showPairing by remember { mutableStateOf(false) }

                    when {
                        showTour -> TourScreen(onFinished = { showTour = false })
                        showPairing -> PairingScreen(onBack = { showPairing = false })
                        openPeer != null -> ChatScreen(
                            peer = openPeer!!,
                            onBack = { openPeer = null },
                        )
                        else -> ChatListScreen(
                            onOpenChat = { openPeer = it },
                            onPair = { showPairing = true },
                        )
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        // Chats are RAM-only. Leaving the app wipes them from the core.
        SovereignApp.core.wipeAll()
    }
}
