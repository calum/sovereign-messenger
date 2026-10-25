package org.sovereign.mesh

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.sovereign.mesh.core.AndroidKeystoreWrapper
import org.sovereign.mesh.core.CoreBridge
import org.sovereign.mesh.core.IdentityVault
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

        private lateinit var vault: IdentityVault

        internal fun start(vault: IdentityVault) {
            this.vault = vault
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
        }

        /**
         * Deletes the stored identity and its Keystore key, then starts with a new
         * identity. Every contact pin is lost and must be paired again in person.
         */
        fun deleteIdentity() {
            vault.delete()
            start(vault)
        }
    }

    override fun onCreate() {
        super.onCreate()
        // App-private storage; excluded from backup by data_extraction_rules.xml.
        start(IdentityVault(filesDir, AndroidKeystoreWrapper()))
    }
}
