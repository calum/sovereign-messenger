package org.sovereign.mesh

/**
 * Turns a failure into plain text the user can read, copy and send. Pure Kotlin so the JVM tests
 * cover it. It records class names and stack frames for every throwable. It prints a message only
 * for the core's FacadeException (fixed strings, CLAUDE.md rule 3) and a short allow-list of
 * linker and VM errors whose text cannot hold user input. Any other message, such as a
 * NumberFormatException quoting a chat line, is left out, so the report cannot carry user text.
 * It is built in memory and never written to disk.
 */
object CrashReport {
    // The report travels in an Intent extra, which has a size limit, and a person has to read it.
    const val MAX_CHARS = 16_000
    private const val MAX_CAUSES = 6
    private const val MAX_FRAMES = 40
    private const val MAX_MESSAGE = 500

    fun forThrowable(threadName: String, error: Throwable, environment: String): String {
        val out = StringBuilder()
        out.appendLine("Sovereign Mesh crash report")
        out.appendLine(environment)
        out.appendLine("Thread: $threadName")
        out.appendLine()
        val seen = HashSet<Throwable>() // a cause chain can loop back on itself
        var current: Throwable? = error
        var depth = 0
        while (current != null && seen.add(current) && depth < MAX_CAUSES) {
            out.appendLine(if (depth == 0) describe(current) else "Caused by: ${describe(current)}")
            val frames = current.stackTrace
            frames.take(MAX_FRAMES).forEach { out.appendLine("    at $it") }
            if (frames.size > MAX_FRAMES) out.appendLine("    ... ${frames.size - MAX_FRAMES} more")
            current = current.cause
            depth++
        }
        return cap(out.toString())
    }

    /** For an earlier run that ended without Kotlin getting to say why, such as a native crash. */
    fun forEarlierExit(what: String, environment: String): String = cap(
        "Sovereign Mesh crash report\n$environment\n\n" +
            "The previous run of the app ended abnormally and could not report why itself.\n$what\n",
    )

    // Matched by name so this file stays pure Kotlin. Nested FacadeException types are named
    // "uniffi.rust_core.FacadeException$Xxx".
    private const val FACADE_PREFIX = "uniffi.rust_core.FacadeException"
    private val MESSAGE_SAFE = setOf(
        "java.lang.UnsatisfiedLinkError",
        "java.lang.NoClassDefFoundError",
        "java.lang.ClassNotFoundException",
        "java.lang.OutOfMemoryError",
        "java.lang.StackOverflowError",
    )

    private fun messageIsSafe(error: Throwable): Boolean {
        val name = error.javaClass.name
        return name == FACADE_PREFIX || name.startsWith("$FACADE_PREFIX$") || name in MESSAGE_SAFE
    }

    private fun describe(error: Throwable): String {
        val name = error.javaClass.name
        if (!messageIsSafe(error)) return name
        // A message that itself throws must not hide the crash it belongs to.
        val message = try {
            error.message?.take(MAX_MESSAGE)
        } catch (_: Throwable) {
            null
        }
        return if (message.isNullOrBlank()) name else "$name: $message"
    }

    private fun cap(text: String): String =
        if (text.length <= MAX_CHARS) text else text.take(MAX_CHARS) + "\n... report cut at $MAX_CHARS characters\n"
}
