package org.sovereign.mesh.core

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import uniffi.rust_core.Messenger

/** What [IdentityVault.open] found. */
sealed interface VaultOpen {
    /** A usable messenger. [restored] is false on the first launch and after a delete. */
    class Ready(val messenger: Messenger, val restored: Boolean) : VaultOpen

    /**
     * Stored data exists but cannot be opened (wrong or lost Keystore key, changed
     * file, half-written state). Nothing was deleted or overwritten; the caller runs
     * RAM-only with a temporary identity until the user chooses to reset.
     */
    data object Unreadable : VaultOpen
}

/**
 * Keeps the long-term identity and pinned contacts across launches (owner decision
 * 2026-10-25). Two files in app-private storage, both excluded from backup:
 * `identity.vault` is the identity and pins sealed by rust-core, and `identity.key`
 * is the data key wrapped by the Keystore. Kotlin sees the plaintext data key only
 * while it wraps or unwraps it, and zeroes the array straight after. Messages are
 * never stored. A refusal never deletes or overwrites a stored file.
 */
class IdentityVault(private val dir: File, private val wrapper: KeyWrapper) {
    private val vaultFile = File(dir, VAULT_NAME)
    private val keyFile = File(dir, KEY_NAME)

    fun open(): VaultOpen = try {
        if (vaultFile.exists()) restore() else create()
    } catch (e: Exception) {
        VaultOpen.Unreadable
    }

    /**
     * Seals the current identity and pins and replaces the stored vault atomically.
     * Call after every pin change. Returns false if it could not be written, or if
     * [messenger] has no vault; the in-memory state is unaffected either way.
     */
    fun save(messenger: Messenger): Boolean {
        val tmp = File(dir, "$VAULT_NAME.tmp")
        return try {
            writeAtomically(tmp, vaultFile, messenger.exportVault())
            true
        } catch (e: Exception) {
            tmp.delete()
            false
        }
    }

    /** Deletes the stored identity and destroys the Keystore key. The next [open] starts fresh. */
    fun delete() {
        vaultFile.delete()
        keyFile.delete()
        File(dir, "$VAULT_NAME.tmp").delete()
        File(dir, "$KEY_NAME.tmp").delete()
        wrapper.deleteKey()
    }

    private fun restore(): VaultOpen {
        // A vault with no wrapped key cannot be opened and cannot be rebuilt: leave it alone.
        if (!keyFile.exists()) return VaultOpen.Unreadable
        val key = wrapper.unwrap(keyFile.readBytes())
        try {
            return VaultOpen.Ready(Messenger.restore(key, vaultFile.readBytes()), restored = true)
        } finally {
            key.fill(0)
        }
    }

    private fun create(): VaultOpen {
        // A key file with no vault is an interrupted first launch: no identity was
        // ever shown or used, so nothing is lost by starting again.
        keyFile.delete()
        val messenger = Messenger.createPersistent()
        val key = messenger.dataKey()
        try {
            writeAtomically(File(dir, "$KEY_NAME.tmp"), keyFile, wrapper.wrap(key))
        } finally {
            key.fill(0)
        }
        if (!save(messenger)) {
            keyFile.delete()
            return VaultOpen.Unreadable
        }
        return VaultOpen.Ready(messenger, restored = false)
    }

    private fun writeAtomically(tmp: File, target: File, bytes: ByteArray) {
        FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private companion object {
        const val VAULT_NAME = "identity.vault"
        const val KEY_NAME = "identity.key"
    }
}
