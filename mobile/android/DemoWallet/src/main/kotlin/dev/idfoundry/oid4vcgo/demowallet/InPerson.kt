package dev.idfoundry.oid4vcgo.demowallet

import android.graphics.Bitmap
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import dev.idfoundry.oid4vcwallet.MdocPresentation
import dev.idfoundry.oid4vcwallet.ProximityException
import dev.idfoundry.oid4vcwallet.ProximityPermissions
import dev.idfoundry.oid4vcwallet.ProximityPresentation
import dev.idfoundry.oid4vcwallet.ProximityReaderIdentity
import dev.idfoundry.oid4vcwallet.ProximityReaderSession
import dev.idfoundry.oid4vcwallet.WalletException
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.security.cert.X509Certificate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

/** A request reader mode makes: a document type and its elements. */
data class ReaderPreset(val title: String, val docType: String, val elements: Map<String, List<String>>)

/** Reader mode's requests: the passport-vdc Photo ID, an mDL, and the test services' mdoc. */
val readerPresets: List<ReaderPreset> = run {
    val photoID = "org.iso.23220.photoid.1" to "org.iso.23220.1"
    val mdl = "org.iso.18013.5.1.mDL" to "org.iso.18013.5.1"
    val identity = listOf("family_name", "given_name", "portrait", "age_over_18")
    listOf(
        ReaderPreset("Photo ID: over 18?", photoID.first, mapOf(photoID.second to listOf("age_over_18"))),
        ReaderPreset("Photo ID: name, photo and age", photoID.first, mapOf(photoID.second to identity)),
        ReaderPreset("Driving licence: over 18?", mdl.first, mapOf(mdl.second to listOf("age_over_18"))),
        ReaderPreset("Driving licence: name, photo and age", mdl.first, mapOf(mdl.second to identity)),
        ReaderPreset("Test mdoc: name", "org.example.test.1", mapOf("org.example.test.1" to listOf("family_name", "given_name"))),
    )
}

/** An element identifier as a label: "age_over_18" → "Age over 18". */
fun elementLabel(identifier: String): String = identifier.replace('_', ' ').replaceFirstChar { it.uppercase() }

/** [text] as a QR code, [size] pixels square, dark on white. */
fun qrBitmap(text: String, size: Int = 768): Bitmap {
    val matrix = QRCodeWriter().encode(
        text, BarcodeFormat.QR_CODE, size, size,
        mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M, EncodeHintType.MARGIN to 2),
    )
    val pixels = IntArray(size * size) { i -> if (matrix[i % size, i / size]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
    return Bitmap.createBitmap(pixels, size, size, Bitmap.Config.ARGB_8888)
}

/** Asks for [permissions], then runs [then]; [denied] if the holder refuses. */
@Composable
fun rememberBluetoothPermissions(permissions: List<String>, then: () -> Unit, denied: () -> Unit): () -> Unit {
    val context = LocalContext.current
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { granted ->
        if (granted.values.all { it }) then() else denied()
    }
    return {
        val missing = ProximityPermissions.missing(context, permissions)
        if (missing.isEmpty()) then() else launcher.launch(missing.toTypedArray())
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun InPersonScaffold(
    title: String,
    onBack: (() -> Unit)?,
    bottomBar: @Composable () -> Unit = {},
    content: @Composable () -> Unit,
) {
    onBack?.let { BackHandler(onBack = it) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    onBack?.let { IconButton(it, Modifier.testTag("in-person-back")) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } }
                },
            )
        },
        bottomBar = bottomBar,
    ) { padding -> Column(Modifier.padding(padding).fillMaxSize()) { content() } }
}

/** The holder's side: the QR code, the reader's request, and the outcome. */
@Composable
fun InPersonScreen(model: WalletModel) {
    var certificates by remember { mutableStateOf<List<X509Certificate>?>(null) }
    certificates?.let { chain ->
        return ReaderCertificatesScreen(chain, onBack = { certificates = null })
    }
    val state = model.inPersonState
    InPersonScaffold("Share in person", onBack = { model.closeInPerson() }) {
        when (state) {
            null, ProximityPresentation.State.WaitingForReader, ProximityPresentation.State.Connected ->
                QRCodeView(model.inPerson?.qrCode.orEmpty(), connected = state == ProximityPresentation.State.Connected)
            is ProximityPresentation.State.RequestReceived -> InPersonConsent(model, state.request, onCertificates = { certificates = it })
            ProximityPresentation.State.Responding -> Waiting("Sharing…")
            else -> InPersonOutcome(state, onDone = { model.closeInPerson() })
        }
    }
}

@Composable
private fun QRCodeView(qrCode: String, connected: Boolean) {
    val bitmap = remember(qrCode) { if (qrCode.isEmpty()) null else qrBitmap(qrCode) }
    Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        if (connected) {
            CircularProgressIndicator()
            Spacer(Modifier.height(16.dp))
            Text("Reader connected: waiting for its request…", Modifier.testTag("in-person-status"))
        } else {
            bitmap?.let {
                Image(it.asImageBitmap(), "QR code for the reader", Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(Color.White).testTag("in-person-qr"))
            }
            Spacer(Modifier.height(16.dp))
            Text("Show this QR code to the reader. Nothing is shared until you agree.", Modifier.testTag("in-person-status"))
        }
    }
}

@Composable
private fun Waiting(text: String) {
    Column(Modifier.fillMaxSize(), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        CircularProgressIndicator()
        Spacer(Modifier.height(16.dp))
        Text(text)
    }
}

/** Who is asking, what for, and the holder's choice of elements. */
@Composable
private fun InPersonConsent(model: WalletModel, request: ProximityPresentation.Request, onCertificates: (List<X509Certificate>) -> Unit) {
    // The first document the wallet can answer; the request's first otherwise.
    val documentIndex = request.documents.indexOfFirst { it.credentials.isNotEmpty() }.takeIf { it >= 0 } ?: 0
    val document = request.documents.getOrNull(documentIndex)
    val credential = document?.credentials?.firstOrNull()
    val chosen = remember(request) { mutableStateMapOf<String, Boolean>().apply { document?.elements?.forEach { put(it.namespace + "/" + it.identifier, true) } } }
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        item { ReaderCard(request.reader, onCertificates) }
        model.notice?.let { item { Text(it, Modifier.padding(vertical = 8.dp), color = Color(0xFFE65100)) } }
        if (document == null || credential == null) {
            item {
                Text(
                    "You have nothing this reader asks for${document?.let { " (${it.doctype})" }.orEmpty()}.",
                    Modifier.padding(vertical = 16.dp).testTag("in-person-nothing"),
                )
            }
        } else {
            item {
                Text("It asks for, from ${credential.display?.name ?: document.doctype}:", Modifier.padding(top = 16.dp, bottom = 8.dp), fontWeight = FontWeight.SemiBold)
            }
            items(document.elements, key = { it.namespace + "/" + it.identifier }) { e ->
                val key = e.namespace + "/" + e.identifier
                Row(Modifier.fillMaxWidth().clickable { chosen[key] = !(chosen[key] ?: false) }.testTag("in-person-element"), verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(chosen[key] ?: false, { chosen[key] = it })
                    Column(Modifier.weight(1f)) {
                        Text(elementLabel(e.identifier))
                        if (e.retain) Text("The reader says it will keep this", style = MaterialTheme.typography.bodySmall, color = Color(0xFFE65100))
                    }
                }
            }
        }
        item {
            Row(Modifier.fillMaxWidth().padding(vertical = 16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton({ model.declineInPerson() }, Modifier.weight(1f).testTag("in-person-decline")) { Text("Decline") }
                val selected = document?.elements?.filter { chosen[it.namespace + "/" + it.identifier] == true }.orEmpty()
                Button(
                    { if (credential != null) model.respondInPerson(documentIndex, credential.id, selected) },
                    Modifier.weight(1f).testTag("in-person-share"),
                    enabled = credential != null && selected.isNotEmpty(),
                ) { Text("Share") }
            }
        }
    }
}

/** The reader as the wallet knows it: its name and how far it's verified. */
@Composable
private fun ReaderCard(reader: ProximityReaderIdentity, onCertificates: (List<X509Certificate>) -> Unit) {
    val (badge, color) = when (reader.status) {
        ProximityReaderIdentity.Status.Trusted -> "Verified reader" to Color(0xFF2E7D32)
        ProximityReaderIdentity.Status.Untrusted -> "Unverified: its certificate isn't from a reader authority you trust" to Color(0xFFE65100)
        ProximityReaderIdentity.Status.Unauthenticated -> "Unknown reader: it didn't identify itself" to Color(0xFFE65100)
        ProximityReaderIdentity.Status.Invalid -> "Its identity doesn't check out" to Color(0xFFC62828)
    }
    Card(Modifier.fillMaxWidth().padding(top = 16.dp)) {
        Column(Modifier.padding(16.dp)) {
            val name = reader.name.ifEmpty { "A nearby reader" }
            Text(if (reader.status == ProximityReaderIdentity.Status.Trusted) name else "“$name”", style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("in-person-reader"))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(if (reader.status == ProximityReaderIdentity.Status.Trusted) Icons.Default.CheckCircle else Icons.Default.Warning, null, tint = color, modifier = Modifier.size(18.dp))
                Spacer(Modifier.width(6.dp))
                Text(badge, color = color, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("in-person-trust"))
            }
            if (reader.chain.isNotEmpty()) {
                TextButton({ onCertificates(reader.chain) }, Modifier.testTag("in-person-certificates")) { Text("Reader certificate") }
            }
        }
    }
}

@Composable
private fun InPersonOutcome(state: ProximityPresentation.State, onDone: () -> Unit) {
    val text = when (state) {
        is ProximityPresentation.State.Presented -> "Shared with the reader." + if (state.linkable) " That copy had been shown to another verifier before." else ""
        ProximityPresentation.State.Declined -> "Declined: nothing was shared."
        ProximityPresentation.State.ReaderEnded -> "The reader ended the session."
        ProximityPresentation.State.Cancelled -> "Cancelled."
        is ProximityPresentation.State.Failed -> when (val e = state.error) {
            is ProximityException -> e.description
            is WalletException -> WalletModel.describe(e)
            else -> e.toString()
        }
        else -> ""
    }
    Column(Modifier.fillMaxSize().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        Text(text, Modifier.testTag("in-person-outcome"))
        Spacer(Modifier.height(24.dp))
        Button(onDone, Modifier.testTag("in-person-done")) { Text("Done") }
    }
}

/** A reader's certificate chain, leaf first, each certificate in full. */
@Composable
fun ReaderCertificatesScreen(chain: List<X509Certificate>, onBack: () -> Unit) {
    InPersonScaffold("Reader certificate", onBack) {
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
            items(chain.withIndex().toList()) { (i, c) ->
                Text(if (i == 0) "Reader" else if (i == chain.lastIndex) "Root" else "Intermediate", Modifier.padding(top = 16.dp), fontWeight = FontWeight.SemiBold)
                CertificateDetails(c)
                HorizontalDivider(Modifier.padding(top = 12.dp))
            }
        }
    }
}

private val dateFormat: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault())

@Composable
private fun CertificateDetails(c: X509Certificate) {
    @Composable
    fun row(label: String, value: String) = Labeled(label, value, Modifier.padding(vertical = 2.dp))
    row("Subject", c.subjectX500Principal.name)
    row("Issuer", c.issuerX500Principal.name)
    row("Valid", "${dateFormat.format(c.notBefore.toInstant())} to ${dateFormat.format(c.notAfter.toInstant())}")
    row("Serial number", c.serialNumber.toString(16))
    c.subjectAlternativeNames?.takeIf { it.isNotEmpty() }?.let { names -> row("Alternative names", names.joinToString { it[1].toString() }) }
    c.extendedKeyUsage?.takeIf { it.isNotEmpty() }?.let { ekus ->
        row("Extended key usage", ekus.joinToString { if (it == "1.0.18013.5.1.6") "mdoc reader authentication ($it)" else it })
    }
    c.keyUsage?.let { bits ->
        val names = listOf("digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly")
        row("Key usage", names.filterIndexed { i, _ -> bits.getOrElse(i) { false } }.joinToString())
    }
    if (c.basicConstraints >= 0) row("Certificate authority", "yes")
    row("Signature algorithm", c.sigAlgName)
    val oids = (c.criticalExtensionOIDs.orEmpty().map { "$it (critical)" } + c.nonCriticalExtensionOIDs.orEmpty()).sorted()
    if (oids.isNotEmpty()) row("Extensions", oids.joinToString("\n"))
    Text(
        "SHA-256 ${java.security.MessageDigest.getInstance("SHA-256").digest(c.encoded).joinToString(":") { "%02X".format(it) }}",
        style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 4.dp),
    )
}

/**
 * The Verify tab, reader mode: choose what to ask for, scan the holder's
 * QR code, see what it verified. Back leaves a reading for the choice,
 * and the choice for the wallet.
 */
@Composable
fun ReaderScreen(model: WalletModel, bottomBar: @Composable () -> Unit, onLeave: () -> Unit) {
    var preset by remember { mutableStateOf<ReaderPreset?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var denied by remember { mutableStateOf(false) }
    val startScan = rememberBluetoothPermissions(ProximityPermissions.reader, then = {
        // An engagement handed over by link needs no scan.
        val given = model.engagementToRead
        if (given != null) preset?.let { model.read(given, it) } else scanning = true
    }, denied = { denied = true })
    if (scanning && preset != null) {
        return ScanScreen(
            onLink = { uri -> scanning = false; model.read(uri.toString(), preset!!) },
            onClose = { scanning = false }, accept = ::mdocEngagement, what = "mdoc",
        )
    }
    val state = model.readingState
    if (model.reading == null) BackHandler(onBack = onLeave)
    val back = if (model.reading != null) ({ model.closeReading(); preset = null }) else null
    InPersonScaffold("Verify in person", onBack = back, bottomBar = bottomBar) {
        when {
            !model.readerAvailable -> Text(
                "Verifying needs a reader in the configuration: see mobile/android/DemoWallet/README.md.",
                Modifier.padding(16.dp).testTag("reader-unavailable"),
            )
            model.reading == null -> LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
                item {
                    Text(
                        if (model.engagementToRead != null) "Read the holder's phone: what to ask for" else "What to ask for",
                        Modifier.padding(vertical = 16.dp), fontWeight = FontWeight.SemiBold,
                    )
                }
                if (denied) item { Text("Allow nearby devices to verify in person.", color = Color(0xFFC62828)) }
                model.notice?.let { item { Text(it, color = Color(0xFFE65100)) } }
                items(readerPresets) { p ->
                    Card(Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable { preset = p; startScan() }.testTag("reader-preset")) {
                        Column(Modifier.padding(16.dp)) {
                            Text(p.title)
                            Text(p.elements.values.flatten().joinToString { elementLabel(it) }, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            state == null || state == ProximityReaderSession.State.Connecting -> Waiting("Connecting to the holder's phone…")
            state == ProximityReaderSession.State.WaitingForResponse -> Waiting("Waiting for the holder to agree…")
            else -> ReaderOutcome(state, model.readingPreset, onDone = { model.closeReading(); preset = null })
        }
    }
}

@Composable
private fun ReaderOutcome(state: ProximityReaderSession.State, preset: ReaderPreset?, onDone: () -> Unit) {
    LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp)) {
        when (state) {
            is ProximityReaderSession.State.Verified -> {
                val v = state.result
                item {
                    Row(Modifier.padding(vertical = 16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.CheckCircle, null, tint = Color(0xFF2E7D32))
                        Spacer(Modifier.width(8.dp))
                        Text("Verified", style = MaterialTheme.typography.titleLarge, modifier = Modifier.testTag("reader-outcome"))
                    }
                }
                for ((namespace, elements) in v.claims) {
                    val o = elements as? JsonObject ?: continue
                    for ((identifier, value) in o) item { ReaderClaim(identifier, value) }
                    // What was asked for and withheld.
                    val missing = preset?.elements?.get(namespace).orEmpty().filter { it !in o }
                    if (missing.isNotEmpty()) item { Labeled("Not shared", missing.joinToString { elementLabel(it) }) }
                }
                item { HorizontalDivider(Modifier.padding(vertical = 8.dp)) }
                item { Labeled("Document", v.doctype) }
                item { Labeled("Issued by", "${v.issuer} (trusted via ${v.trustAnchor})") }
                item { Labeled("Valid", "${dateFormat.format(v.validFrom)} to ${dateFormat.format(v.validUntil)}") }
                item { Labeled("Holder's device", if (v.deviceAuth == "mac") "authenticated (MAC)" else "authenticated (signature)") }
                v.statusList?.let { item { Labeled("Revocation", "not checked: ${it.uri} #${it.index}") } }
            }
            ProximityReaderSession.State.Declined -> item { Text("The holder declined.", Modifier.padding(vertical = 24.dp).testTag("reader-outcome")) }
            ProximityReaderSession.State.Cancelled -> item { Text("Cancelled.", Modifier.padding(vertical = 24.dp).testTag("reader-outcome")) }
            is ProximityReaderSession.State.Failed -> item {
                val e = state.error
                Text(
                    when (e) {
                        is ProximityException -> e.description
                        is WalletException -> "Not verified: ${WalletModel.describe(e)}"
                        else -> e.toString()
                    },
                    Modifier.padding(vertical = 24.dp).testTag("reader-outcome"), color = Color(0xFFC62828),
                )
            }
            else -> {}
        }
        item { Button(onDone, Modifier.padding(vertical = 16.dp).testTag("reader-done")) { Text("Done") } }
    }
}

@Composable
private fun ReaderClaim(identifier: String, value: JsonElement) {
    val image = remember(value) { Claims.image(value, identifier) }
    if (image != null) {
        Column(Modifier.padding(vertical = 4.dp)) {
            Text(elementLabel(identifier), style = MaterialTheme.typography.labelMedium)
            Image(image.asImageBitmap(), elementLabel(identifier), Modifier.size(120.dp).clip(RoundedCornerShape(8.dp)))
        }
    } else {
        Labeled(elementLabel(identifier), Claims.text(value), Modifier.testTag("reader-claim"))
    }
}

/**
 * The Present tab: what presenting in person does, and the button that
 * shows the QR code. The session itself (InPersonScreen) opens over it.
 */
@Composable
fun PresentScreen(model: WalletModel, bottomBar: @Composable () -> Unit, onLeave: () -> Unit) {
    val share = rememberShareInPerson(model)
    val mdocs = model.credentials.count { it.format == "mso_mdoc" }
    BackHandler(onBack = onLeave)
    InPersonScaffold("Share in person", onBack = null, bottomBar = bottomBar) {
        Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Show a QR code to a reader nearby. It connects over Bluetooth and asks for what it needs; you see who is asking, and choose what to share.")
            Text(
                when (mdocs) {
                    0 -> "You hold no mdoc to share in person yet."
                    1 -> "1 mdoc can be shared in person."
                    else -> "$mdocs mdocs can be shared in person."
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            model.notice?.let { Text(it, color = Color(0xFFE65100)) }
            Button(share, Modifier.fillMaxWidth().testTag("share-in-person"), enabled = model.configured) { Text("Show QR code") }
        }
    }
}

/** Starts sharing in person once the Bluetooth permissions are granted. */
@Composable
fun rememberShareInPerson(model: WalletModel): () -> Unit =
    rememberBluetoothPermissions(
        ProximityPermissions.holder,
        then = { model.shareInPerson() },
        denied = { model.notice = "Allow nearby devices to share in person." },
    )

/** Keeps the screen awake while it shows a QR code. */
@Composable
fun KeepScreenOn() {
    val view = androidx.compose.ui.platform.LocalView.current
    LaunchedEffect(Unit) { view.keepScreenOn = true }
    androidx.compose.runtime.DisposableEffect(Unit) { onDispose { view.keepScreenOn = false } }
}
