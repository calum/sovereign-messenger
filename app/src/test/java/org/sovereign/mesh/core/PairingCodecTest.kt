package org.sovereign.mesh.core

import com.google.zxing.LuminanceSource
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.BitMatrix
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.rust_core.FacadeException
import uniffi.rust_core.Messenger
import uniffi.rust_core.PairingAssembler

/**
 * The QR path end to end on the JVM: payload parts from rust-core, each encoded
 * with ZXing, rendered to pixels, decoded again, collected until complete, and
 * pinned through the real core. No camera is involved; the camera only supplies
 * luminance frames.
 */
class PairingCodecTest {

    /** Renders each module as a square block with a quiet zone, like a camera frame would see it. */
    private fun luminanceOf(matrix: BitMatrix, scale: Int = 4): LuminanceSource {
        val quiet = 4
        val side = (matrix.width + 2 * quiet) * scale
        val pixels = ByteArray(side * side) { 0xFF.toByte() }
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (!matrix.get(x, y)) continue
                for (dy in 0 until scale) for (dx in 0 until scale) {
                    val px = (x + quiet) * scale + dx
                    val py = (y + quiet) * scale + dy
                    pixels[py * side + px] = 0
                }
            }
        }
        return PlanarYUVLuminanceSource(pixels, side, side, 0, 0, side, side, false)
    }

    private fun blankFrame(side: Int): LuminanceSource =
        PlanarYUVLuminanceSource(ByteArray(side * side) { 0xFF.toByte() }, side, side, 0, 0, side, side, false)

    /** One QR code's worth of bytes: encode, render, and decode through ZXing. */
    private fun throughQr(part: ByteArray): ByteArray? = QrCodec.decode(luminanceOf(QrCodec.encode(part)))

    @Test
    fun partsFromRustSurviveQrRoundTrip() {
        val parts = Messenger().ownPairingParts("10.0.0.2:7000")
        assertEquals(2, parts.size)
        for (part in parts) {
            assertArrayEquals(part, throughQr(part))
        }
    }

    /**
     * R1/A2: one scan that fails in ten minutes is a field bug. Each payload is a
     * fresh identity, so 200 of them sample the sizes a real pairing produces.
     * Every part must decode, and the parts must reassemble to a payload.
     */
    @Test
    fun twoHundredFreshPayloadsDecodeEveryTime() {
        val failures = mutableListOf<Int>()
        repeat(200) { i ->
            val parts = Messenger().ownPairingParts("10.0.0.2:7000")
            val asm = PairingAssembler()
            var full: ByteArray? = null
            for (part in parts) {
                val decoded = throughQr(part)
                if (decoded == null || !decoded.contentEquals(part)) {
                    failures += i
                    return@repeat
                }
                full = asm.addPart(decoded)
            }
            if (full == null) failures += i
        }
        assertEquals("payloads that failed to decode: $failures", emptyList<Int>(), failures)
    }

    @Test
    fun blankFrameDecodesToNothing() {
        assertNull(QrCodec.decode(blankFrame(300)))
    }

    @Test
    fun allPartsPinThroughTheCore() {
        val alice = Messenger()
        val bob = Messenger()
        val asm = PairingAssembler()
        var full: ByteArray? = null
        for (part in bob.ownPairingParts("")) {
            full = asm.addPart(throughQr(part)!!)
        }

        val outcome = pairingOutcome("bob") { alice.scanPairing("bob", full!!) }

        assertEquals(PairingOutcome.Pinned(bob.ownFingerprint(), ""), outcome)
    }

    /** A single QR code is half a pairing. It must not pin, and the core must refuse it as a payload. */
    @Test
    fun singlePartAloneDoesNotPin() {
        val alice = Messenger()
        val bob = Messenger()
        val part = throughQr(bob.ownPairingParts("")[0])!!
        val asm = PairingAssembler()

        assertNull(asm.addPart(part))
        assertEquals(1, asm.received().toInt())
        assertNull(alice.pinFingerprint("bob"))
        assertEquals(
            PairingOutcome.Invalid,
            pairingOutcome("bob") { alice.scanPairing("bob", part) },
        )
    }

    @Test
    fun differentKeyForPinnedNameShowsKeyChanged() {
        val alice = Messenger()
        val bob = Messenger()
        val mallory = Messenger()
        alice.scanPairing("bob", joinParts(bob.ownPairingParts("")))

        val outcome = pairingOutcome("bob") { alice.scanPairing("bob", joinParts(mallory.ownPairingParts(""))) }

        assertEquals(PairingOutcome.KeyChanged("bob"), outcome)
        assertEquals(bob.ownFingerprint(), alice.pinFingerprint("bob"))
    }

    @Test
    fun rescanOfSameIdentityIsAlreadyPinned() {
        val alice = Messenger()
        val bob = Messenger()
        val payload = joinParts(bob.ownPairingParts(""))
        alice.scanPairing("bob", payload)

        val outcome = pairingOutcome("bob") { alice.scanPairing("bob", payload) }

        assertEquals(PairingOutcome.AlreadyPinned("bob"), outcome)
    }

    @Test
    fun mappingMaintainsDistinctStates() {
        assertEquals(
            PairingOutcome.Invalid,
            pairingOutcome("bob") { throw FacadeException.Malformed("x") },
        )
        assertEquals(
            PairingOutcome.Failed,
            pairingOutcome("bob") { throw FacadeException.Internal("x") },
        )
    }

    @Test
    fun keyChangedWarningNamesThePeerButNoKeyMaterial() {
        val text = keyChangedWarning("bob")
        assertTrue(text.contains("bob"))
        assertTrue(Regex("[0-9a-f]{8}").find(text) == null)
        assertEquals(true, text.contains("refused"))
    }

    /** Test helper: collects every part of one identity into the full payload, as the scanner does. */
    private fun joinParts(parts: List<ByteArray>): ByteArray {
        val asm = PairingAssembler()
        var full: ByteArray? = null
        for (part in parts) full = asm.addPart(part)
        return full!!
    }
}
