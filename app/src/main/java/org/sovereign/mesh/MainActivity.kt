package org.sovereign.mesh

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import org.sovereign.mesh.core.Route
import org.sovereign.mesh.core.canGoBack
import org.sovereign.mesh.core.pop
import org.sovereign.mesh.core.push
import org.sovereign.mesh.core.withoutPeer
import org.sovereign.mesh.ui.ChatListScreen
import org.sovereign.mesh.ui.ChatScreen
import org.sovereign.mesh.ui.PairingScreen
import org.sovereign.mesh.ui.SettingsScreen
import org.sovereign.mesh.ui.SovereignTheme
import org.sovereign.mesh.ui.TourScreen
import org.sovereign.mesh.ui.UpdateScreen
import org.sovereign.mesh.update.UpdateInstaller

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Blocks screenshots, screen recording and the recent-apps thumbnail.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // A staged APK is deleted on every start, in case the last run ended before its cleanup.
        UpdateInstaller.deleteStaged(this)

        setContent {
            SovereignTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val earlierExit = SovereignApp.earlierExitReport
                    when {
                        earlierExit != null -> Box(Modifier.safeDrawingPadding()) {
                            CrashReportScreen(
                                report = earlierExit,
                                headline = "The app stopped last time",
                                doneLabel = "Continue",
                                onDone = { SovereignApp.earlierExitReport = null },
                            )
                        }
                        !SovereignApp.tourSeen -> Box(Modifier.safeDrawingPadding()) {
                            TourScreen(onFinished = { SovereignApp.tourSeen = true })
                        }
                        else -> AppScreens()
                    }
                }
            }
        }
    }

    // Chats live in RAM for as long as the process does (owner decision, 2026-10-29): leaving the
    // app no longer wipes them. These two only tell the chat screen whether a message is being looked at.
    override fun onStart() {
        super.onStart()
        SovereignApp.inForeground = true
    }

    override fun onStop() {
        super.onStop()
        SovereignApp.inForeground = false
    }
}

/**
 * The screen stack. The system back gesture pops one screen; only on the chat list does it leave
 * the app. The stack lives in [SovereignApp] (RAM), so rotation keeps the user where they were.
 */
@androidx.compose.runtime.Composable
private fun AppScreens() {
    val stack = SovereignApp.navStack
    val open = { route: String -> SovereignApp.navStack = push(SovereignApp.navStack, route) }
    val back = { SovereignApp.navStack = pop(SovereignApp.navStack) }

    BackHandler(enabled = canGoBack(stack)) { back() }

    val route = stack.last()
    val peer = Route.peerOf(route)
    when {
        peer != null -> ChatScreen(
            peer = peer,
            onBack = back,
            onRemoved = { SovereignApp.navStack = withoutPeer(SovereignApp.navStack, peer) },
        )
        route == Route.PAIR -> PairingScreen(
            onBack = back,
            // Replaces the pairing screen with the new chat, so back from the chat lands on the list.
            onOpenChat = { SovereignApp.navStack = push(pop(SovereignApp.navStack), Route.chat(it)) },
        )
        route == Route.UPDATE -> UpdateScreen(onBack = back)
        route == Route.SETTINGS -> SettingsScreen(
            onBack = back,
            onUpdate = { open(Route.UPDATE) },
            onIdentityDeleted = { SovereignApp.navStack = org.sovereign.mesh.core.initialStack() },
        )
        else -> ChatListScreen(
            onOpenChat = { open(Route.chat(it)) },
            onPair = { open(Route.PAIR) },
            onSettings = { open(Route.SETTINGS) },
        )
    }
}
