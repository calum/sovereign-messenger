package org.sovereign.mesh

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CrashReportTest {
    private val env = "App 0.2.0, Android 16 (API 36), Google Pixel 6, ABI arm64-v8a"

    @Test
    fun namesTheErrorItsCauseAndThePhone() {
        val error = IllegalStateException("outer", UnsatisfiedLinkError("dlopen failed: librust_core.so"))
        val report = CrashReport.forThrowable("main", error, env)
        assertTrue(report.contains(env))
        assertTrue(report.contains("Thread: main"))
        assertTrue(report.contains("java.lang.IllegalStateException\n")) // message withheld: not on the allow-list
        assertFalse(report.contains("outer"))
        assertTrue(report.contains("Caused by: java.lang.UnsatisfiedLinkError: dlopen failed: librust_core.so"))
        assertTrue(report.contains("    at "))
    }

    @Test
    fun errorWithoutMessageStillShowsItsClass() {
        assertTrue(CrashReport.forThrowable("t", NullPointerException(), env).contains("java.lang.NullPointerException\n"))
    }

    @Test
    fun aMessageThatThrowsDoesNotHideTheCrash() {
        val hostile = object : RuntimeException() {
            override val message: String get() = throw IllegalStateException("boom")
        }
        assertTrue(CrashReport.forThrowable("t", hostile, env).contains("CrashReportTest"))
    }

    @Test
    fun aCauseLoopTerminates() {
        val a = RuntimeException("a")
        val b = RuntimeException("b", a)
        a.initCause(b)
        val report = CrashReport.forThrowable("t", a, env)
        assertEquals(1, Regex("Caused by: java.lang.RuntimeException\n").findAll(report).count())
    }

    @Test
    fun aHugeReportIsCut() {
        val report = CrashReport.forThrowable("t", RuntimeException("x".repeat(100_000)), env)
        assertTrue(report.length < CrashReport.MAX_CHARS + 100)
        assertFalse(report.contains("x".repeat(600)))
    }

    @Test
    fun earlierExitCarriesThePhoneAndWhatAndroidRecorded() {
        val report = CrashReport.forEarlierExit("Android recorded a native crash (signal or status 11): SIGSEGV", env)
        assertTrue(report.contains(env))
        assertTrue(report.contains("SIGSEGV"))
    }

    private val chat = "meet me at the old bridge at nine"

    @Test
    fun aMessageBuiltFromChatTextIsLeftOut() {
        val report = CrashReport.forThrowable("t", NumberFormatException("For input string: \"$chat\""), env)
        assertFalse(report.contains(chat))
        assertTrue(report.contains("java.lang.NumberFormatException\n"))
    }

    @Test
    fun chatTextInANestedCauseIsLeftOut() {
        val inner = NumberFormatException("For input string: \"$chat\"")
        val report = CrashReport.forThrowable("t", RuntimeException("wrapped $chat", IllegalStateException(chat, inner)), env)
        assertFalse(report.contains(chat))
        assertTrue(report.contains("Caused by: java.lang.NumberFormatException\n"))
    }

    @Test
    fun aCoreErrorMessageIsStillShown() {
        // The core's errors carry fixed strings only, so their text stays useful in a report.
        val report = CrashReport.forThrowable("t", uniffi.rust_core.FacadeException.Malformed("peer not found"), env)
        assertTrue(report.contains("peer not found"))
    }
}
