package org.sovereign.mesh.update

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Stages a verified APK in the app's private cache and hands it to the system
 * installer. Only bytes that rust-core has already verified reach this object.
 *
 * Security property: the file lives in `cacheDir/update/`, which is app-private
 * and is the only directory the FileProvider exposes. It is deleted when the
 * update screen is left, when a receive fails, and when the app starts. Nothing
 * is written unless the signature check passed.
 */
object UpdateInstaller {
    /** The receiving phone listens on all interfaces at the update port (47002). */
    const val LISTEN_ADDR = "0.0.0.0:47002"

    /** How long the receiver waits for a sender before giving up. */
    const val LISTEN_TIMEOUT_SECS = 120

    private const val DIR = "update"
    private const val FILE = "update.apk"
    private const val MIME = "application/vnd.android.package-archive"

    /** Writes the verified bytes to the staging file and returns it. */
    fun stage(context: Context, verifiedApk: ByteArray): File {
        val dir = File(context.cacheDir, DIR).apply { mkdirs() }
        val file = File(dir, FILE)
        file.writeBytes(verifiedApk)
        return file
    }

    /** Deletes the staged APK, if any. Safe to call when nothing is staged. */
    fun deleteStaged(context: Context) {
        File(File(context.cacheDir, DIR), FILE).delete()
    }

    /** An ACTION_VIEW intent for the installer, with a read grant on the staged file only. */
    fun installIntent(context: Context, file: File): Intent {
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.updates", file)
        return Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, MIME)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

    /** The installed version name, for display only. Not used for the downgrade check. */
    fun installedVersionName(context: Context): String =
        try {
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "unknown"
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            "unknown"
        }

    /**
     * The installed version code, which rust-core compares against the signed update
     * version. Fails closed: if the package cannot be read, Long.MAX_VALUE is returned,
     * so no update is strictly newer and every update is refused as a downgrade.
     */
    fun installedVersion(context: Context): Long =
        try {
            context.packageManager.getPackageInfo(context.packageName, 0).longVersionCode
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            Long.MAX_VALUE
        }
}
