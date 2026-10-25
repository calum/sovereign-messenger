package org.sovereign.mesh.core

import java.io.File
import java.nio.file.Files
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import uniffi.rust_core.Messenger

/**
 * The identity vault against the real rust-core, with an in-memory AES-GCM wrapper
 * standing in for the Android Keystore (which does not exist on the JVM). What these
 * tests prove: the files on disk hold no plaintext key, a refusal never deletes or
 * overwrites what is stored, and a restart gets back the same identity and pins.
 */
class IdentityVaultTest {
    private lateinit var dir: File

    /** Wraps with a real AES-GCM key held in memory, and records every plaintext it was given. */
    private class FakeWrapper : KeyWrapper {
        var key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val seenPlain = mutableListOf<ByteArray>()
        var deleted = false
        var failUnwrap = false

        override fun wrap(plain: ByteArray): ByteArray {
            seenPlain += plain.copyOf()
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
            return c.iv + c.doFinal(plain)
        }

        override fun unwrap(wrapped: ByteArray): ByteArray {
            check(!failUnwrap) { "keystore refused" }
            val c = Cipher.getInstance("AES/GCM/NoPadding")
                .apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, wrapped.copyOfRange(0, 12))) }
            return c.doFinal(wrapped, 12, wrapped.size - 12)
        }

        override fun deleteKey() {
            deleted = true
        }
    }

    @Before
    fun setUp() {
        dir = Files.createTempDirectory("vault-test").toFile()
    }

    @After
    fun tearDown() {
        dir.deleteRecursively()
    }

    private fun ready(open: VaultOpen): VaultOpen.Ready = open as VaultOpen.Ready

    @Test
    fun firstLaunchCreatesAnIdentityAndStoresIt() {
        val vault = IdentityVault(dir, FakeWrapper())
        val first = ready(vault.open())
        assertFalse(first.restored)
        assertTrue(File(dir, "identity.vault").isFile)
        assertTrue(File(dir, "identity.key").isFile)
    }

    @Test
    fun restartRestoresTheSameIdentityAndPins() {
        val wrapper = FakeWrapper()
        val first = ready(IdentityVault(dir, wrapper).open())
        val bob = Messenger()
        first.messenger.scanPairing("bob", bob.ownPairingPayload(""))
        assertTrue(IdentityVault(dir, wrapper).save(first.messenger))

        val second = ready(IdentityVault(dir, wrapper).open())
        assertTrue(second.restored)
        assertEquals(first.messenger.ownFingerprint(), second.messenger.ownFingerprint())
        assertEquals(listOf("bob"), second.messenger.pinnedPeers())
    }

    @Test
    fun aPinNotSavedIsNotRestored() {
        val wrapper = FakeWrapper()
        val first = ready(IdentityVault(dir, wrapper).open())
        first.messenger.scanPairing("bob", Messenger().ownPairingPayload(""))
        // No save: the app is killed before it persists.
        val second = ready(IdentityVault(dir, wrapper).open())
        assertTrue(second.messenger.pinnedPeers().isEmpty())
    }

    @Test
    fun theDataKeyIsNotOnDiskInTheClear() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        assertEquals(1, wrapper.seenPlain.size)
        val plain = wrapper.seenPlain.single()
        assertEquals(32, plain.size)
        for (name in listOf("identity.key", "identity.vault")) {
            val bytes = File(dir, name).readBytes()
            assertFalse("$name contains the data key", indexOf(bytes, plain) >= 0)
        }
    }

    @Test
    fun theWrappedKeyAloneCannotOpenTheVaultWithoutTheKeystore() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        // A different Keystore key (a wiped or replaced phone) cannot unwrap.
        val other = FakeWrapper()
        assertTrue(IdentityVault(dir, other).open() is VaultOpen.Unreadable)
    }

    @Test
    fun aTamperedVaultFileIsUnreadableAndLeftInPlace() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        val file = File(dir, "identity.vault")
        val bytes = file.readBytes().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 1).toByte() }
        file.writeBytes(bytes)

        assertTrue(IdentityVault(dir, wrapper).open() is VaultOpen.Unreadable)
        assertArrayEquals("a refusal must not touch the file", bytes, file.readBytes())
        assertTrue(File(dir, "identity.key").isFile)
    }

    @Test
    fun aKeystoreFailureIsUnreadableAndDeletesNothing() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        wrapper.failUnwrap = true
        assertTrue(IdentityVault(dir, wrapper).open() is VaultOpen.Unreadable)
        assertTrue(File(dir, "identity.vault").isFile)
        assertTrue(File(dir, "identity.key").isFile)
    }

    @Test
    fun aVaultWithNoWrappedKeyIsUnreadable() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        File(dir, "identity.key").delete()
        assertTrue(IdentityVault(dir, wrapper).open() is VaultOpen.Unreadable)
        assertTrue(File(dir, "identity.vault").isFile)
    }

    @Test
    fun aKeyWithNoVaultMeansCreationWasInterruptedSoItStartsFresh() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        File(dir, "identity.vault").delete()
        val again = ready(IdentityVault(dir, wrapper).open())
        assertFalse(again.restored)
        assertTrue(File(dir, "identity.vault").isFile)
    }

    @Test
    fun deleteRemovesTheFilesAndTheKeystoreKey() {
        val wrapper = FakeWrapper()
        ready(IdentityVault(dir, wrapper).open())
        IdentityVault(dir, wrapper).delete()
        assertFalse(File(dir, "identity.vault").exists())
        assertFalse(File(dir, "identity.key").exists())
        assertTrue(wrapper.deleted)
        // After a delete the next open is a first launch with a new identity.
        val fresh = ready(IdentityVault(dir, wrapper).open())
        assertFalse(fresh.restored)
    }

    @Test
    fun anIdentityAfterDeleteIsADifferentIdentity() {
        val wrapper = FakeWrapper()
        val before = ready(IdentityVault(dir, wrapper).open()).messenger.ownFingerprint()
        IdentityVault(dir, wrapper).delete()
        val after = ready(IdentityVault(dir, wrapper).open()).messenger.ownFingerprint()
        assertNotEquals(before, after)
    }

    @Test
    fun saveLeavesNoTempFileBehind() {
        val wrapper = FakeWrapper()
        val opened = ready(IdentityVault(dir, wrapper).open())
        assertTrue(IdentityVault(dir, wrapper).save(opened.messenger))
        assertEquals(setOf("identity.vault", "identity.key"), dir.list()!!.toSet())
    }

    @Test
    fun saveReportsFailureWhenTheDirectoryIsGone() {
        val wrapper = FakeWrapper()
        val opened = ready(IdentityVault(dir, wrapper).open())
        dir.deleteRecursively()
        assertFalse(IdentityVault(dir, wrapper).save(opened.messenger))
    }

    @Test
    fun aMessengerWithoutAVaultCannotBeSaved() {
        assertFalse(IdentityVault(dir, FakeWrapper()).save(Messenger()))
    }

    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int {
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }
}
