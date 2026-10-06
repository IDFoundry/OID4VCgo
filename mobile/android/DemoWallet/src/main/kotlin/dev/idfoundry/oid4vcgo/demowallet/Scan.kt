package dev.idfoundry.oid4vcgo.demowallet

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage

/** Whether [text] is a link the wallet opens: a Credential Offer or a presentation request. */
/** An mdoc's device engagement QR code ("mdoc:…", ISO/IEC 18013-5 §8.2.2.3), for reader mode. */
fun mdocEngagement(text: String?): Uri? = text?.trim()?.let(Uri::parse)?.takeIf { it.scheme.equals("mdoc", ignoreCase = true) }

fun walletLink(text: String?): Uri? =
    text?.trim()?.let(Uri::parse)?.takeIf { it.scheme == WalletModel.OFFER_SCHEME || it.scheme == WalletModel.REQUEST_SCHEME }

/**
 * Scans QR codes live with the camera, or reads one from an image —
 * a photo or screenshot — with ML Kit's bundled model, which needs no
 * Play services. The first wallet link found is opened.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(onLink: (Uri) -> Unit, onClose: () -> Unit, accept: (String?) -> Uri? = ::walletLink, what: String = "offer or request") {
    BackHandler(onBack = onClose)
    val context = LocalContext.current
    var permitted by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    var message by remember { mutableStateOf<String?>(null) }
    val askCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { permitted = it }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        uri ?: return@rememberLauncherForActivityResult
        readImage(context, uri, accept, onFound = onLink, onNone = { message = "No $what QR code in that image." })
    }
    LaunchedEffect(Unit) { if (!permitted) askCamera.launch(Manifest.permission.CAMERA) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Scan a QR code") },
                navigationIcon = { IconButton(onClose) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            if (permitted) CameraScanner(onLink, accept) else Text("The camera isn't allowed: choose an image instead.", Modifier.align(Alignment.Center))
            Button(
                { pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                Modifier.align(Alignment.BottomCenter).fillMaxWidth().padding(16.dp).testTag("scan-image"),
            ) { Text(message ?: "Choose an image") }
        }
    }
}

@Composable
private fun CameraScanner(onLink: (Uri) -> Unit, accept: (String?) -> Uri?) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val scanner = remember { BarcodeScanning.getClient(BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()) }
    var found by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { scanner.close() } }
    AndroidView(
        factory = { ctx ->
            val view = PreviewView(ctx)
            val future = ProcessCameraProvider.getInstance(ctx)
            future.addListener({
                val provider = future.get()
                val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
                analysis.setAnalyzer(ContextCompat.getMainExecutor(ctx)) { proxy ->
                    val image = proxy.image
                    if (image == null || found) {
                        proxy.close()
                        return@setAnalyzer
                    }
                    scanner.process(InputImage.fromMediaImage(image, proxy.imageInfo.rotationDegrees))
                        .addOnSuccessListener { codes ->
                            codes.firstNotNullOfOrNull { accept(it.rawValue) }?.let {
                                if (!found) {
                                    found = true
                                    onLink(it)
                                }
                            }
                        }
                        .addOnCompleteListener { proxy.close() }
                }
                provider.unbindAll()
                provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
            }, ContextCompat.getMainExecutor(ctx))
            view
        },
        modifier = Modifier.fillMaxSize(),
        onRelease = { runCatching { ProcessCameraProvider.getInstance(context).get().unbindAll() } },
    )
}

private fun readImage(context: Context, uri: Uri, accept: (String?) -> Uri?, onFound: (Uri) -> Unit, onNone: () -> Unit) {
    val image = runCatching { InputImage.fromFilePath(context, uri) }.getOrNull() ?: return onNone()
    val scanner = BarcodeScanning.getClient(BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
    scanner.process(image)
        .addOnSuccessListener { codes -> codes.firstNotNullOfOrNull { accept(it.rawValue) }?.let(onFound) ?: onNone() }
        .addOnFailureListener { onNone() }
        .addOnCompleteListener { scanner.close() }
}
