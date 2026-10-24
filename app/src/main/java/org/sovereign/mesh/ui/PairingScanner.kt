package org.sovereign.mesh.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.zxing.PlanarYUVLuminanceSource
import org.sovereign.mesh.core.QrCodec
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Camera scanner for a pairing code. CameraX supplies frames; ZXing (through
 * [QrCodec]) finds the payload bytes. The first code found is handed to
 * [onPayload] once, and rust-core decides whether to pin it.
 * The camera is used only while this composable is on screen.
 */
@Composable
fun PairingScanner(onPayload: (ByteArray) -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    val askPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
    }
    LaunchedEffect(Unit) {
        if (!granted) askPermission.launch(Manifest.permission.CAMERA)
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        if (granted) {
            CameraPreview(onPayload)
        } else {
            Text(
                "Camera permission is needed to scan a code. Allow it, or cancel.",
                modifier = Modifier.padding(vertical = 8.dp),
            )
        }
        Button(onClick = onCancel, modifier = Modifier.padding(top = 8.dp)) {
            Text("Cancel scan")
        }
    }
}

@Composable
private fun CameraPreview(onPayload: (ByteArray) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val latestOnPayload by rememberUpdatedState(onPayload)
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    val providerHolder = remember { arrayOfNulls<ProcessCameraProvider>(1) }
    val delivered = remember { AtomicBoolean(false) }
    var unavailable by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        onDispose {
            providerHolder[0]?.unbindAll()
            analysisExecutor.shutdown()
        }
    }

    if (unavailable) {
        Text("No usable back camera on this phone. Scanning is not available.")
        return
    }

    AndroidView(
        modifier = Modifier.fillMaxWidth().aspectRatio(3f / 4f),
        factory = { ctx ->
            val previewView = PreviewView(ctx)
            val mainExecutor = ContextCompat.getMainExecutor(ctx)
            val future = ProcessCameraProvider.getInstance(ctx)
            future.addListener(
                {
                    val provider = future.get()
                    providerHolder[0] = provider
                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }
                    val analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                        .also { useCase ->
                            useCase.setAnalyzer(analysisExecutor) { frame ->
                                analyse(frame) { payload ->
                                    if (delivered.compareAndSet(false, true)) {
                                        mainExecutor.execute { latestOnPayload(payload) }
                                    }
                                }
                            }
                        }
                    try {
                        provider.unbindAll()
                        provider.bindToLifecycle(
                            lifecycleOwner,
                            CameraSelector.DEFAULT_BACK_CAMERA,
                            preview,
                            analysis,
                        )
                    } catch (e: IllegalArgumentException) {
                        // No back camera. Report it; the error text names no key or content.
                        unavailable = true
                    }
                },
                mainExecutor,
            )
            previewView
        },
    )
}

/** Copies the luminance plane out of the frame (respecting its row stride) and decodes it. */
private fun analyse(frame: ImageProxy, onFound: (ByteArray) -> Unit) {
    try {
        val plane = frame.planes[0]
        val width = frame.width
        val height = frame.height
        val luma = ByteArray(width * height)
        val buffer = plane.buffer.duplicate()
        for (row in 0 until height) {
            buffer.position(row * plane.rowStride)
            buffer.get(luma, row * width, width)
        }
        QrCodec.decode(PlanarYUVLuminanceSource(luma, width, height, 0, 0, width, height, false))
            ?.let(onFound)
    } finally {
        frame.close()
    }
}
