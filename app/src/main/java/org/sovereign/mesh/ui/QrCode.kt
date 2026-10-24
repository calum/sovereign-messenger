package org.sovereign.mesh.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import org.sovereign.mesh.core.QrCodec

/**
 * Draws a pairing payload as a QR code. The bytes come from rust-core; this
 * composable only turns them into black and white modules. The code is always
 * drawn on white, even in dark theme, because scanners need the contrast.
 */
@Composable
fun QrCode(payload: ByteArray, modifier: Modifier = Modifier) {
    val matrix = remember(payload) { QrCodec.encode(payload) }
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .background(Color.White),
    ) {
        val cell = size.width / matrix.width
        for (y in 0 until matrix.height) {
            for (x in 0 until matrix.width) {
                if (matrix.get(x, y)) {
                    drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell, cell))
                }
            }
        }
    }
}
