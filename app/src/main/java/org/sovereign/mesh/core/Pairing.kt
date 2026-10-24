package org.sovereign.mesh.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.encoder.Encoder
import uniffi.rust_core.FacadeException
import uniffi.rust_core.ScannedPeer

/**
 * QR encoding and decoding for pairing payloads. The payload bytes come from
 * rust-core and go back to it unchanged. Each byte maps to one ISO-8859-1
 * character, so ZXing keeps the data in byte mode and does not re-encode it.
 * Kotlin only renders and reads frames; it never interprets the payload.
 */
object QrCodec {
    /** How many versions above the smallest a code may be bumped to. */
    private const val MAX_VERSION_BUMP = 3

    /**
     * Encodes one part as a QR matrix. ZXing's detector cannot find some of the
     * smallest symbols (PLAN.md Decisions, 2026-10-24, QR decode), so each code is
     * read back here with the same reader the scanner uses. If the smallest
     * version does not read back, the next larger version is tried. The bytes do
     * not change; only the symbol grows, and only for the rare code that needs it.
     */
    fun encode(payload: ByteArray): BitMatrix {
        val text = String(payload, Charsets.ISO_8859_1)
        val smallest = Encoder.encode(text, ErrorCorrectionLevel.L, encodeHints(null)).version.versionNumber
        var matrix: BitMatrix? = null
        for (bump in 0..MAX_VERSION_BUMP) {
            val version = smallest + bump
            if (version > MAX_QR_VERSION) break
            matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, encodeHints(version))
            if (decode(render(matrix))?.contentEquals(payload) == true) return matrix
        }
        // Nothing read back. Return the last symbol; the scanner will refuse it, and nothing is pinned.
        return checkNotNull(matrix)
    }

    // Low correction keeps each code smaller. Each code carries one part of the payload (about half of it).
    private fun encodeHints(version: Int?): Map<EncodeHintType, Any> = buildMap {
        put(EncodeHintType.CHARACTER_SET, "ISO-8859-1")
        put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L)
        if (version != null) put(EncodeHintType.QR_VERSION, version)
    }

    private const val MAX_QR_VERSION = 40

    /** Renders a matrix as a camera would see it: dark modules on a light quiet zone. */
    private fun render(matrix: BitMatrix, scale: Int = 4): LuminanceSource {
        val quiet = 4
        val side = (matrix.width + 2 * quiet) * scale
        val pixels = ByteArray(side * side) { 0xFF.toByte() }
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (!matrix.get(x, y)) continue
                for (dy in 0 until scale) for (dx in 0 until scale) {
                    pixels[((y + quiet) * scale + dy) * side + (x + quiet) * scale + dx] = 0
                }
            }
        }
        return PlanarYUVLuminanceSource(pixels, side, side, 0, 0, side, side, false)
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
