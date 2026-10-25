package org.sovereign.mesh.ui

/** The result of checking a picked update bundle before it is read into memory. */
sealed class UpdateSendCheck {
    /** The bundle may be sent. [version] is the parsed integer the developer signed. */
    data class Accepted(val version: Long) : UpdateSendCheck()

    /** The bundle is refused. [message] names the problem and never includes file content. */
    data class Refused(val message: String) : UpdateSendCheck()
}

/**
 * Pure checks on a bundle the developer signed on their PC: the APK, its 64-byte
 * signature file, and the version. No Android imports, so it runs on the JVM.
 *
 * Why these checks exist here: they refuse obvious mistakes (a wrong file, an
 * oversize APK, a truncated signature) before the bytes are read. The phone does
 * not sign and does not trust these checks for security; rust-core verifies the
 * signature on the receiving phone, so a forged bundle fails there whatever this
 * says.
 */
object UpdateSendPolicy {

    /** Must match the APK cap in rust-core (`MAX_APK_LEN`). */
    const val MAX_APK_BYTES: Long = 64L * 1024 * 1024

    /** Ed25519 signatures are exactly this long. */
    const val SIGNATURE_BYTES: Long = 64L

    fun check(name: String?, apkSize: Long, sigSize: Long, versionText: String): UpdateSendCheck {
        val trimmed = name?.trim().orEmpty()
        if (trimmed.length <= APK_SUFFIX.length || !trimmed.lowercase().endsWith(APK_SUFFIX)) {
            return UpdateSendCheck.Refused("Pick an .apk file. The file you picked is not an Android package.")
        }
        if (apkSize <= 0L) {
            return UpdateSendCheck.Refused("The APK is empty. Pick the built APK and try again.")
        }
        if (apkSize > MAX_APK_BYTES) {
            return UpdateSendCheck.Refused("The APK is larger than 64 MiB and cannot be sent.")
        }
        if (sigSize != SIGNATURE_BYTES) {
            return UpdateSendCheck.Refused(
                "The signature file must be exactly 64 bytes. Pick the .sig file the developer made for this APK.",
            )
        }
        val version = versionText.trim().toLongOrNull()
        if (version == null || version <= 0L) {
            return UpdateSendCheck.Refused("The version must be a positive whole number.")
        }
        return UpdateSendCheck.Accepted(version)
    }

    private const val APK_SUFFIX = ".apk"
}
