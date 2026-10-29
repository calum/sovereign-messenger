package org.sovereign.mesh

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.sovereign.mesh.core.AndroidKeystoreWrapper
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.sovereign.mesh.core.CoreBridge
import org.sovereign.mesh.core.IdentityVault
import org.sovereign.mesh.core.initialStack
import org.sovereign.mesh.core.PeerConnections
import org.sovereign.mesh.core.TorController
import org.sovereign.mesh.core.VaultOpen
import uniffi.rust_core.Messenger

class SovereignApp : Application() {
    companion object {
        lateinit var core: CoreBridge
            private set

        /**
         * True when a stored identity exists but could not be opened. The app then
         * runs with a temporary RAM-only identity and saves nothing, so the stored
         * data is left untouched until the user resets it.
         */
        var identityUnreadable by mutableStateOf(false)
            private set

        /**
         * Report of a native crash or start-up failure that ended the previous run, or null.
         * Held in memory only; the user dismisses it from the first screen.
         */
        var earlierExitReport by mutableStateOf<String?>(null)

        private lateinit var vault: IdentityVault

        /** Keeps Tor and the onion service running for the current identity. */
        lateinit var tor: TorController
            private set

        /** Keeps every paired contact connected and receiving, whichever screen is open. */
        lateinit var connections: PeerConnections
            private set

        /** True once the first-run tour has been shown in this process. Held in RAM only. */
        var tourSeen by mutableStateOf(false)

        /** Whether opening a chat tells the contact their messages were read. In RAM, on by default. */
        var sendReadReceipts by mutableStateOf(true)

        /** Screens from the chat list upward. Contact names only, held in RAM, never in saved state. */
        var navStack by mutableStateOf<List<String>>(initialStack())

        /** Half-written messages per contact, in RAM, so a draft survives rotation and leaving the chat. */
        val drafts = mutableStateMapOf<String, String>()

        /** True while the activity is visible. A message only counts as read while this is true. */
        var inForeground by mutableStateOf(false)

        private lateinit var torDir: File
        private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        internal fun start(vault: IdentityVault, torDir: File) {
            this.vault = vault
            this.torDir = torDir
            when (val opened = vault.open()) {
                is VaultOpen.Ready -> {
                    core = CoreBridge(opened.messenger, vault)
                    identityUnreadable = false
                }
                VaultOpen.Unreadable -> {
                    core = CoreBridge(Messenger())
                    identityUnreadable = true
                }
            }
            tor = TorController(core, torDir)
            tor.start(appScope)
            connections = PeerConnections(core) { tor.snapshot }
            connections.start(appScope)
        }

        /**
         * Deletes the stored identity and its Keystore key, then starts with a new
         * identity. Every contact pin is lost and must be paired again in person.
         */
        fun deleteIdentity() {
            // Tor runs under the old identity's onion address, so it stops first. Its folder
            // holds only public directory data and guard state, but it goes with the identity.
            connections.stop()
            drafts.clear()
            tor.stop()
            torDir.deleteRecursively()
            vault.delete()
            start(vault, torDir)
        }
    }

    override fun onCreate() {
        super.onCreate()
        // First, so that any failure below ends in a readable report instead of a silent close.
        CrashReporting.install(this)
        // The report screen runs in its own process and must not open the vault or start Tor.
        if (CrashReporting.isCrashProcess()) return
        earlierExitReport = CrashReporting.earlierExit(this)
        // App-private storage; excluded from backup by data_extraction_rules.xml.
        // Tor's public directory cache and guard state live in app-private files; no key or message does.
        start(IdentityVault(filesDir, AndroidKeystoreWrapper()), File(filesDir, "tor"))
    }
}
