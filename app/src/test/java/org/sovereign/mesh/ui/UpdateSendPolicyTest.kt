package org.sovereign.mesh.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The sender's checks on the picked APK, signature and version. Pure Kotlin: the
 * checks run before any bytes are read into memory, so a refusal costs nothing.
 * A refusal message names the problem and never the file's contents.
 */
class UpdateSendPolicyTest {

    private val cap = 64L * 1024 * 1024
    private val sig = 64L

    private fun accepted(result: UpdateSendCheck): Long {
        assertTrue("expected Accepted, got $result", result is UpdateSendCheck.Accepted)
        return (result as UpdateSendCheck.Accepted).version
    }

    private fun refused(result: UpdateSendCheck): String {
        assertTrue("expected Refused, got $result", result is UpdateSendCheck.Refused)
        return (result as UpdateSendCheck.Refused).message
    }

    @Test
    fun validBundleIsAcceptedAndVersionParsed() {
        assertEquals(12L, accepted(UpdateSendPolicy.check("app-release.apk", 1_000, sig, "12")))
    }

    @Test
    fun apkExtensionIsCaseInsensitive() {
        assertEquals(3L, accepted(UpdateSendPolicy.check("APP.APK", 1_000, sig, " 3 ")))
    }

    @Test
    fun missingOrNonApkNameRefused() {
        for (name in listOf(null, "", "   ", "notes.txt", "apk.zip", ".apk", "release.apk.bak")) {
            refused(UpdateSendPolicy.check(name, 1_000, sig, "1"))
        }
    }

    @Test
    fun emptyApkRefused() {
        refused(UpdateSendPolicy.check("app.apk", 0, sig, "1"))
    }

    @Test
    fun apkAtCapAcceptedAndOverCapRefused() {
        assertEquals(1L, accepted(UpdateSendPolicy.check("app.apk", cap, sig, "1")))
        val msg = refused(UpdateSendPolicy.check("app.apk", cap + 1, sig, "1"))
        assertTrue(msg.contains("64 MiB"))
    }

    @Test
    fun signatureMustBeExactly64Bytes() {
        assertEquals(1L, accepted(UpdateSendPolicy.check("app.apk", 1_000, 64, "1")))
        refused(UpdateSendPolicy.check("app.apk", 1_000, 63, "1"))
        refused(UpdateSendPolicy.check("app.apk", 1_000, 65, "1"))
        refused(UpdateSendPolicy.check("app.apk", 1_000, 0, "1"))
    }

    @Test
    fun versionMustBeAPositiveWholeNumber() {
        for (text in listOf("", "0", "-1", "abc", "1.5", "1e3", "+")) {
            refused(UpdateSendPolicy.check("app.apk", 1_000, sig, text))
        }
        assertEquals(Long.MAX_VALUE, accepted(UpdateSendPolicy.check("app.apk", 1_000, sig, Long.MAX_VALUE.toString())))
    }

    @Test
    fun refusalMessagesNameNoFileContent() {
        val msg = refused(UpdateSendPolicy.check("secret-notes.txt", 1_000, sig, "1"))
        assertFalse(msg.contains("secret-notes"))
        assertFalse(refused(UpdateSendPolicy.check("app.apk", 1_000, 10, "1")).contains("app.apk"))
    }
}
