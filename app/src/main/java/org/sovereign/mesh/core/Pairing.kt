package org.sovereign.mesh.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.ReaderException
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import uniffi.rust_core.FacadeException
import uniffi.rust_core.ScannedPeer

/**
 * QR encoding and decoding for pairing payloads. The payload bytes come from
 * rust-core and go back to it unchanged. Each byte maps to one ISO-8859-1
 * character, so ZXing keeps the data in byte mode and does not re-encode it.
 * Kotlin only renders and reads frames; it never interprets the payload.
 */
object QrCodec {
    fun encode(payload: ByteArray): BitMatrix {
        val hints = mapOf(
            EncodeHintType.CHARACTER_SET to "ISO-8859-1",
            // Low correction keeps the code smaller; the ML-KEM key makes the payload large.
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
        )
        return QRCodeWriter().encode(
            String(payload, Charsets.ISO_8859_1),
            BarcodeFormat.QR_CODE,
            0,
            0,
            hints,
        )
    }

    /** Returns the payload bytes from one camera frame, or null if no code is visible. */
    fun decode(frame: LuminanceSource): ByteArray? {
        val reader = MultiFormatReader()
        reader.setHints(
            mapOf(
                DecodeHintType.CHARACTER_SET to "ISO-8859-1",
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            ),
        )
        return try {
            reader.decode(BinaryBitmap(HybridBinarizer(frame))).text.toByteArray(Charsets.ISO_8859_1)
        } catch (e: ReaderException) {
            null
        }
    }
}

/**
 * What the scanner reports to the UI. Carries the fingerprint and the connection
 * hint for display only; no key bytes and no error text from rust-core.
 */
sealed interface PairingOutcome {
    data class Pinned(val fingerprint: String, val connectionHint: String) : PairingOutcome

    /** The peer's pinned key differs from the scanned key. The new key was refused. */
    data class KeyChanged(val peer: String) : PairingOutcome

    data class AlreadyPinned(val peer: String) : PairingOutcome

    data object Invalid : PairingOutcome

    data object Failed : PairingOutcome
}

/** Maps a core pin attempt to a UI outcome. Each core error gets its own state. */
inline fun pairingOutcome(peer: String, attempt: () -> ScannedPeer): PairingOutcome =
    try {
        attempt().let { PairingOutcome.Pinned(it.fingerprint, it.connectionHint) }
    } catch (e: FacadeException.PinChanged) {
        PairingOutcome.KeyChanged(peer)
    } catch (e: FacadeException.DuplicatePin) {
        PairingOutcome.AlreadyPinned(peer)
    } catch (e: FacadeException.Malformed) {
        PairingOutcome.Invalid
    } catch (e: FacadeException) {
        PairingOutcome.Failed
    }

/** Warning text for a changed key. Names the contact, never shows key material. */
fun keyChangedWarning(peer: String): String =
    "The key for \"$peer\" has changed. The new key was refused. " +
        "Check it with them in person before you accept it."
