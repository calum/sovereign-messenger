package org.sovereign.mesh

import android.app.ActivityManager
import android.app.Application
import android.app.ApplicationExitInfo
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Makes sure a failure always ends in a message the user can find and share instead of the app
 * silently closing. The report is handed to [CrashActivity] in an Intent extra and never written
 * to disk (CLAUDE.md rule 1). [CrashActivity] runs in its own process, because the crashed
 * process is about to die and may be in a broken state.
 */
object CrashReporting {
    private const val EXTRA_REPORT = "report"
    private const val RECENT_EXIT_MS = 10 * 60 * 1000L

    fun isCrashProcess(): Boolean = Application.getProcessName()?.endsWith(":crash") == true

    /** Call first thing in [Application.onCreate], before anything that can fail. */
    fun install(app: Application) {
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, error ->
            // A failure inside the report screen itself must not start another report screen.
            if (!isCrashProcess()) {
                try {
                    val report = CrashReport.forThrowable(thread.name, error, environment(app))
                    app.startActivity(
                        Intent(app, CrashActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                            .putExtra(EXTRA_REPORT, report),
                    )
                } catch (_: Throwable) {
                    // Nothing more can be done here; the previous handler still ends the process.
                }
            }
            previous?.uncaughtException(thread, error)
        }
    }

    /**
     * A native crash (a signal inside the Rust library) never reaches the handler above. Android
     * remembers why each process ended, so the next start reads that back. Only recent exits
     * count, because nothing here is stored to remember that one was already shown.
     */
    fun earlierExit(context: Context): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null
        return try {
            val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val exit = manager.getHistoricalProcessExitReasons(context.packageName, 0, 5)
                .firstOrNull { it.processName == context.packageName } // newest first
                ?.takeIf { System.currentTimeMillis() - it.timestamp < RECENT_EXIT_MS }
                ?.takeIf {
                    it.reason == ApplicationExitInfo.REASON_CRASH_NATIVE ||
                        it.reason == ApplicationExitInfo.REASON_INITIALIZATION_FAILURE
                } ?: return null
            val kind = if (exit.reason == ApplicationExitInfo.REASON_CRASH_NATIVE) "native crash" else "start-up failure"
            CrashReport.forEarlierExit(
                "Android recorded a $kind (signal or status ${exit.status}): ${exit.description ?: "no description"}",
                environment(context),
            )
        } catch (_: Throwable) {
            null
        }
    }

    internal fun reportFrom(intent: Intent): String =
        intent.getStringExtra(EXTRA_REPORT) ?: "The app stopped, but no report was passed on."

    private fun environment(context: Context): String {
        val version = try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName
        } catch (_: Throwable) {
            "unknown"
        }
        return "App ${version}, Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}), " +
            "${Build.MANUFACTURER} ${Build.MODEL}, ABI ${Build.SUPPORTED_ABIS.firstOrNull()}"
    }
}

/** Shows a report with Copy and Share. Used after a crash and for an earlier native crash. */
@Composable
fun CrashReportScreen(report: String, headline: String, onDone: () -> Unit, doneLabel: String) {
    val context = androidx.compose.ui.platform.LocalContext.current
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(headline, style = MaterialTheme.typography.titleLarge)
        Text(
            "Please send this to the developer. It lists the error type, where it happened in the code, and the phone model. No messages or keys are included.",
            style = MaterialTheme.typography.bodyMedium,
        )
        Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())) {
            SelectionContainer {
                Text(report, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText("Sovereign Mesh crash report", report))
            }) { Text("Copy") }
            OutlinedButton(onClick = {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "Sovereign Mesh crash report")
                    .putExtra(Intent.EXTRA_TEXT, report)
                context.startActivity(Intent.createChooser(send, "Share crash report"))
            }) { Text("Share") }
            Button(onClick = onDone) { Text(doneLabel) }
        }
    }
}

/** Runs in its own process (see the manifest) and so never touches the app's core or vault. */
class CrashActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Same rule as MainActivity: no screenshots or recents thumbnail of any window.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val report = CrashReporting.reportFrom(intent)
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    CrashReportScreen(
                        report = report,
                        headline = "Sovereign Mesh stopped",
                        doneLabel = "Close",
                        onDone = { finishAndRemoveTask() },
                    )
                }
            }
        }
    }
}
