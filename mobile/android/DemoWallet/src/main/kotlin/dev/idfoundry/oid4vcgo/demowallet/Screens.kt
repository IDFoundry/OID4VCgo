package dev.idfoundry.oid4vcgo.demowallet

import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.RadioButtonChecked
import androidx.compose.material.icons.filled.RadioButtonUnchecked
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import coil3.compose.AsyncImage
import dev.idfoundry.oid4vcwallet.CredentialDetail
import dev.idfoundry.oid4vcwallet.CredentialStatus
import dev.idfoundry.oid4vcwallet.CredentialSummary
import dev.idfoundry.oid4vcwallet.Logo
import dev.idfoundry.oid4vcwallet.Offer
import dev.idfoundry.oid4vcwallet.PathElement
import dev.idfoundry.oid4vcwallet.Presentation
import dev.idfoundry.oid4vcwallet.WalletConfiguration
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import java.time.Duration
import java.time.Instant

/** The app: the home screen, a credential's page, and the offer, request and scanner over them. */
@Composable
fun DemoApp(model: WalletModel, authorize: suspend (String) -> String, openBrowser: (Uri) -> Unit) {
    // Test tags as resource IDs: the UI tests (DemoWalletUITests) find
    // views by them, as the iOS demo's by accessibility identifiers.
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) { Box(Modifier.semantics { testTagsAsResourceId = true }) {
        var shown by remember { mutableStateOf<String?>(null) }
        var scanning by remember { mutableStateOf(false) }
        val credential = shown?.let { id -> model.credentials.firstOrNull { it.id == id } }
        when {
            scanning -> ScanScreen(onLink = { scanning = false; model.open(it) }, onClose = { scanning = false })
            model.requestPhase != WalletModel.RequestPhase.IDLE -> RequestScreen(model, openBrowser)
            model.phase == WalletModel.Phase.Offered || model.phase == WalletModel.Phase.Receiving -> OfferScreen(model, authorize)
            credential != null -> CredentialScreen(model, credential, onBack = { shown = null })
            else -> HomeScreen(model, onCredential = { shown = it }, onScan = { scanning = true })
        }
        model.linkToConfirm?.let { link ->
            val request = link.scheme == WalletModel.REQUEST_SCHEME
            AlertDialog(
                onDismissRequest = { model.linkToConfirm = null },
                title = { Text(if (request) "Open this presentation request?" else "Open this credential offer?") },
                text = {
                    Text("Another app opened this link. Opening it contacts the ${if (request) "verifier" else "issuer"} it names; nothing is shared until you agree.")
                },
                confirmButton = { TextButton({ model.confirmLink() }, Modifier.testTag("open-link")) { Text("Open") } },
                dismissButton = { TextButton({ model.linkToConfirm = null }) { Text("Cancel") } },
            )
        }
    } }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(model: WalletModel, onCredential: (String) -> Unit, onScan: () -> Unit) {
    val context = LocalContext.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("OID4VC Demo") },
                navigationIcon = { SettingsMenu(model) },
                actions = {
                    TextButton({
                        val text = context.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString()
                        text?.let { model.open(Uri.parse(it.trim())) }
                    }) { Text("Paste") }
                    IconButton(onScan, Modifier.testTag("scan")) { Icon(Icons.Default.QrCodeScanner, "Scan") }
                },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) { home(model, onCredential) }
    }
}

/** The settings: which copy of a credential a presentation uses. */
@Composable
private fun SettingsMenu(model: WalletModel) {
    var open by remember { mutableStateOf(false) }
    IconButton({ open = true }, Modifier.testTag("settings")) { Icon(Icons.Default.Settings, "Settings") }
    DropdownMenu(open, { open = false }) {
        Text("Copies", Modifier.padding(horizontal = 16.dp, vertical = 8.dp), style = MaterialTheme.typography.labelLarge)
        for ((policy, label) in listOf(
            WalletConfiguration.CopyPolicy.PER_PRESENTATION to "New copy for every presentation",
            WalletConfiguration.CopyPolicy.PER_VERIFIER to "Same copy for the same verifier",
        )) {
            val chosen = model.copyPolicy == policy
            DropdownMenuItem(
                text = { Text(label) },
                leadingIcon = { Icon(if (chosen) Icons.Default.RadioButtonChecked else Icons.Default.RadioButtonUnchecked, null) },
                onClick = {
                    model.chooseCopyPolicy(policy)
                    open = false
                },
                modifier = Modifier.testTag("copy-policy-${policy.name}"),
            )
        }
    }
}

/** The home screen's rows: why the wallet can't run, the last outcome, what's pending, and the credentials by holder. */
private fun LazyListScope.home(model: WalletModel, onCredential: (String) -> Unit) {
    model.unavailable?.let { item { Banner(it, Color(0xFFC62828), "unavailable") } }
    if (!model.configured && model.unavailable == null) {
        item { Banner("Not configured: launch with a configuration (see mobile/android/DemoWallet/README.md).", null, "not-configured") }
    }
    status(model)
    if (model.pending.isNotEmpty()) {
        item { SectionHeader("Waiting for the issuer") }
        items(model.pending, key = { it.id }) { PendingRow(model, it) }
    }
    if (model.credentials.isEmpty()) {
        item { SectionHeader("Credentials") }
        item { Text("No credentials yet", Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant) }
    }
    for ((holder, group) in model.credentialsByHolder) {
        item { HolderHeader(holder) }
        items(group, key = { it.id }) { c -> CredentialRow(c, Modifier.clickable { onCredential(c.id) }.testTag("credential")) }
    }
}

private fun LazyListScope.status(model: WalletModel) {
    model.notice?.let { item { Banner(it, Color(0xFFE65100), "notice") } }
    when (val phase = model.phase) {
        is WalletModel.Phase.Done -> item { Banner(phase.text, null, "status") }
        is WalletModel.Phase.Failed -> item { Banner(phase.text, Color(0xFFC62828), "status") }
        WalletModel.Phase.UntrustedVerifier -> item { UntrustedVerifier() }
        else -> {}
    }
}

@Composable
fun Banner(text: String, color: Color?, tag: String) {
    Text(text, Modifier.fillMaxWidth().padding(16.dp).testTag(tag), color = color ?: MaterialTheme.colorScheme.onSurface)
}

@Composable
fun SectionHeader(text: String) {
    Text(text, Modifier.padding(start = 16.dp, top = 20.dp, bottom = 6.dp), style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary)
}

/**
 * A refused presentation request from a verifier the wallet doesn't
 * trust: prominent, since that's the point. Nothing about the request is
 * shown — its contents, and the name it claims, are only trustworthy if
 * its signature is, which is what failed.
 */
@Composable
fun UntrustedVerifier() {
    var details by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth().padding(12.dp), colors = CardDefaults.cardColors(containerColor = Color(0x14C62828))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, null, tint = Color(0xFFC62828))
                Spacer(Modifier.width(8.dp))
                Text("Verifier not trusted", Modifier.testTag("untrusted-verifier"), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold, color = Color(0xFFC62828))
            }
            Text("The identity of this verifier couldn't be established, so your wallet didn't open its request.")
            Text("Nothing was shared.", Modifier.testTag("nothing-shared"), fontWeight = FontWeight.Bold)
            TextButton({ details = !details }) { Text(if (details) "Hide details" else "Details") }
            if (details) {
                Labeled("Verifier authentication", "Failed")
                Labeled("Request signed by", "A certificate your wallet doesn't recognise")
                Labeled("Request opened", "No")
                Labeled("Credentials shared", "None")
            }
        }
    }
}

@Composable
fun Labeled(label: String, value: String, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.width(12.dp))
        Text(value)
    }
}

/** Whose credentials a group holds: the holder's photo, name and date of birth. */
@Composable
fun HolderHeader(holder: Holder?) {
    if (holder == null) {
        SectionHeader("Credentials")
        return
    }
    Row(Modifier.padding(start = 16.dp, top = 20.dp, bottom = 6.dp).testTag("holder"), verticalAlignment = Alignment.CenterVertically) {
        holder.portrait?.let {
            Image(it.asImageBitmap(), null, Modifier.size(40.dp, 50.dp).clip(RoundedCornerShape(4.dp)), contentScale = ContentScale.Crop)
            Spacer(Modifier.width(12.dp))
        }
        Column {
            Text(holder.name ?: "Unnamed holder", style = MaterialTheme.typography.titleSmall)
            holder.birthDate?.let { Text("Born $it", style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** A credential as a card in the issuer's colours: its logo, name, issuer, and expiry or revocation. */
@Composable
fun CredentialRow(summary: CredentialSummary, modifier: Modifier = Modifier) {
    val d = summary.display
    val text = cssColor(d?.textColor) ?: MaterialTheme.colorScheme.onSurface
    Card(
        modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
        colors = CardDefaults.cardColors(containerColor = cssColor(d?.backgroundColor) ?: MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            LogoImage(d?.logo ?: d?.issuerLogo)
            Column(Modifier.padding(start = 12.dp)) {
                Text(Credentials.title(summary), style = MaterialTheme.typography.titleMedium, color = text)
                Text(d?.issuerName ?: summary.credentialIssuer, style = MaterialTheme.typography.bodySmall, color = text.copy(alpha = 0.8f))
                val problem = Credentials.problem(summary)
                if (problem != null) {
                    Text(problem, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold, color = Color(0xFFE53935))
                } else {
                    summary.validUntil?.let { Text("Expires ${Credentials.date(it)}", style = MaterialTheme.typography.bodySmall, color = text.copy(alpha = 0.8f)) }
                }
                Credentials.copies(summary)?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = if (summary.copiesLeft == 0) Color(0xFFFB8C00) else text.copy(alpha = 0.8f))
                }
                Text("${Credentials.format(summary)} · received ${Credentials.dateTime(summary.receivedAt)}",
                    style = MaterialTheme.typography.labelSmall, color = text.copy(alpha = 0.7f))
            }
        }
    }
}

/** An issuer's logo, loaded from its https or data: URL. */
@Composable
fun LogoImage(logo: Logo?) {
    logo ?: return
    AsyncImage(logo.uri, logo.altText, Modifier.size(32.dp), contentScale = ContentScale.Fit)
}

/** A deferred credential: what it's waiting for, and a way to ask now. */
@Composable
fun PendingRow(model: WalletModel, pending: WalletModel.PendingCredential) {
    val state = pending.state
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(pending.configurationID, Modifier.testTag("pending"), style = MaterialTheme.typography.titleSmall)
            val detail = when (state) {
                WalletModel.PendingCredential.State.Waiting -> "The issuer is reviewing it · checking every ${maxOf(pending.intervalSeconds, 1.0).toInt()} s"
                WalletModel.PendingCredential.State.Checking -> "Checking…"
                WalletModel.PendingCredential.State.Denied -> "Denied by the issuer"
                is WalletModel.PendingCredential.State.Failed -> "Couldn't check: ${state.message}"
            }
            Text(detail, Modifier.testTag("pending-state"), style = MaterialTheme.typography.bodySmall,
                color = if (state == WalletModel.PendingCredential.State.Denied) Color(0xFFC62828) else MaterialTheme.colorScheme.onSurfaceVariant)
        }
        if (state == WalletModel.PendingCredential.State.Denied) {
            OutlinedButton({ model.dismiss(pending.id) }, Modifier.testTag("dismiss")) { Text("Dismiss") }
        } else {
            if (state is WalletModel.PendingCredential.State.Failed) {
                OutlinedButton({ model.abandon(pending.id) }, Modifier.testTag("give-up")) { Text("Give up") }
                Spacer(Modifier.width(8.dp))
            }
            OutlinedButton({ model.checkAgain(pending.id) }, Modifier.testTag("check-again"),
                enabled = state != WalletModel.PendingCredential.State.Checking) { Text("Check again") }
        }
    }
}

/** A Credential Offer: who's offering, what, and the PIN if it needs one. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OfferScreen(model: WalletModel, authorize: suspend (String) -> String) {
    val offer = model.offer ?: return
    val receiving = model.phase == WalletModel.Phase.Receiving
    // Cancelling is for an offer just being shown: once receiving, the
    // issuer's page is over this screen, and the receive carries on.
    BackHandler(enabled = !receiving) { model.cancelOffer() }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Credential offer") },
                actions = { TextButton({ model.cancelOffer() }) { Text("Cancel") } },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
            // Only the issuer's address is checked here (its TLS
            // certificate): its name and logos are its own claim until the
            // credential arrives and is checked against the issuers this
            // wallet trusts. So the address leads, and no logo is fetched.
            item { SectionHeader("From") }
            item {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    Text(Credentials.host(offer.credentialIssuer), Modifier.testTag("offer-issuer"), style = MaterialTheme.typography.titleMedium)
                    offer.issuerName?.let { Text("Calls itself “$it”", style = MaterialTheme.typography.bodySmall) }
                    Text("Not verified yet: an issuer names itself. The credential is checked against the issuers this wallet trusts when it arrives.",
                        Modifier.padding(top = 6.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            item { SectionHeader("Credentials") }
            items(offer.credentials, key = { it.configurationID }) { c ->
                Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp)) {
                    Text(c.name ?: c.vct ?: c.doctype ?: c.configurationID)
                    c.description?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                }
            }
            val tx = offer.txCode
            if (offer.grant == Offer.Grant.PRE_AUTHORIZED_CODE && tx != null) {
                item { SectionHeader(tx.description ?: "PIN") }
                item {
                    OutlinedTextField(
                        model.pin, { model.pin = it }, Modifier.fillMaxWidth().padding(horizontal = 16.dp).testTag("pin"),
                        label = { Text("PIN") }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = if (tx.inputMode == "text") KeyboardType.Text else KeyboardType.NumberPassword),
                    )
                }
            }
            model.offerError?.let { item { Banner(it, Color(0xFFC62828), "offer-error") } }
            item {
                Button({ model.startReceive(authorize) }, Modifier.fillMaxWidth().padding(16.dp).testTag("receive"), enabled = !receiving) {
                    Text(if (receiving) "Receiving…" else if (model.offerError == null) "Receive" else "Try again")
                }
            }
        }
    }
}

/** One credential: what it is, its status and copies, and its claims. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CredentialScreen(model: WalletModel, summary: CredentialSummary, onBack: () -> Unit) {
    BackHandler(onBack = onBack)
    var detail by remember { mutableStateOf<CredentialDetail?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    LaunchedEffect(summary.id) { detail = model.detail(summary) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(Credentials.title(summary)) },
                navigationIcon = { IconButton(onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
                actions = { TextButton({ confirmDelete = true }, Modifier.testTag("delete")) { Text("Delete") } },
            )
        },
    ) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(horizontal = 16.dp), contentPadding = padding) {
            item { SectionHeader("Credential") }
            item { Labeled("Format", summary.format) }
            item { Labeled("Issuer", summary.display?.issuerName ?: summary.credentialIssuer) }
            item { Labeled("Received", Credentials.dateTime(summary.receivedAt)) }
            summary.validUntil?.let { item { Labeled(if (summary.isExpired()) "Expired" else "Expires", Credentials.date(it)) } }
            item { StatusSection(model, summary) }
            item { CopiesSection(model, summary) }
            detail?.let { d ->
                item { SectionHeader("Claims") }
                claimRows(d.claims, emptyList())
            }
        }
    }
    if (confirmDelete) {
        DeleteDialog(onDelete = { confirmDelete = false; model.delete(summary); onBack() }, onCancel = { confirmDelete = false })
    }
}

@Composable
private fun DeleteDialog(onDelete: () -> Unit, onCancel: () -> Unit) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Delete this credential?") },
        text = { Text("It and its keys leave this device. You'd need the issuer to receive it again.") },
        confirmButton = { TextButton(onDelete, Modifier.testTag("confirm-delete")) { Text("Delete") } },
        dismissButton = { TextButton(onCancel) { Text("Cancel") } },
    )
}

/** Runs [work], taking at least half a second, so a quick answer is still seen. */
private suspend fun <T> atLeastHalfASecond(work: suspend () -> T): T {
    val started = System.currentTimeMillis()
    val result = work()
    delay(maxOf(0, 500 - (System.currentTimeMillis() - started)))
    return result
}

/** The status, with Check status: a spinner while it runs, then "Checked just now" or why it couldn't. */
@Composable
private fun StatusSection(model: WalletModel, summary: CredentialSummary) {
    var checking by remember { mutableStateOf(false) }
    var checkError by remember { mutableStateOf<String?>(null) }
    var justChecked by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Column {
        SectionHeader("Status")
        StatusRow(summary.status)
        OutlinedButton({
            checking = true
            checkError = null
            justChecked = false
            scope.launch {
                val error = atLeastHalfASecond { model.checkStatus(summary.id) }
                checking = false
                checkError = error
                justChecked = error == null
            }
        }, Modifier.fillMaxWidth().testTag("check-status"), enabled = !checking) {
            Busy(checking, "  Checking with the issuer…", "Check status")
        }
        checkError?.let { Text("Couldn't check: $it", Modifier.testTag("check-error"), color = Color(0xFFC62828), style = MaterialTheme.typography.bodySmall) }
        if (justChecked && checkError == null) {
            Text("Checked with the issuer just now", Modifier.testTag("check-done"), color = Color(0xFF2E7D32), style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** The copies left, with Refresh copies when the issuance kept a refresh token. */
@Composable
private fun CopiesSection(model: WalletModel, summary: CredentialSummary) {
    var refreshing by remember { mutableStateOf(false) }
    var outcome by remember { mutableStateOf<WalletModel.RefreshOutcome?>(null) }
    val scope = rememberCoroutineScope()
    if (summary.copies <= 1 && !summary.refreshable && outcome == null) return
    Column {
        SectionHeader("Copies")
        Text(Credentials.copies(summary) ?: "${summary.copiesLeft} of ${summary.copies} copies unused", Modifier.testTag("credential-copies"))
        if (summary.refreshable) {
            OutlinedButton({
                refreshing = true
                outcome = null
                scope.launch {
                    outcome = atLeastHalfASecond { model.refreshCopies(summary.id) }
                    refreshing = false
                }
            }, Modifier.fillMaxWidth().testTag("refresh-copies"), enabled = !refreshing) {
                Busy(refreshing, "  Getting fresh copies from the issuer…", "Refresh copies")
            }
        }
        outcome?.let { RefreshOutcomeText(it) }
    }
}

@Composable
private fun Busy(busy: Boolean, busyText: String, idleText: String) {
    if (busy) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
    Text(if (busy) busyText else idleText)
}

@Composable
private fun RefreshOutcomeText(o: WalletModel.RefreshOutcome) {
    val (text, color) = when (o) {
        is WalletModel.RefreshOutcome.Refreshed -> "Got ${o.copies} fresh ${if (o.copies == 1) "copy" else "copies"} just now" to Color(0xFF2E7D32)
        WalletModel.RefreshOutcome.Deferred -> "The issuer will send fresh copies later: they're waiting on the home screen" to Color(0xFFE65100)
        WalletModel.RefreshOutcome.ReissueRequired -> "This credential can't be refreshed any more: receive it again from the issuer" to Color(0xFFE65100)
        is WalletModel.RefreshOutcome.Failed -> "Couldn't refresh: ${o.reason}" to Color(0xFFC62828)
    }
    Text(text, Modifier.testTag("refresh-done"), color = color, style = MaterialTheme.typography.bodySmall)
}

/** A claim tree as rows: nested objects flattened to dotted paths. */
fun LazyListScope.claimRows(value: JsonElement, path: List<String>) {
    if (value is JsonObject) {
        for (key in value.keys.sorted().filter { it !in Claims.hidden || path.isNotEmpty() }) claimRows(value[key]!!, path + key)
        return
    }
    val label = path.joinToString(" · ")
    val image = Claims.image(value, path.lastOrNull().orEmpty())
    item {
        if (image != null) {
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Image(image.asImageBitmap(), null, Modifier.size(120.dp, 160.dp).clip(RoundedCornerShape(6.dp)).testTag("portrait"))
            }
        } else {
            Labeled(label, Claims.text(value), Modifier.testTag("claim"))
        }
    }
}

/** A credential's status: what its issuer's status list said, and how long ago that was checked, counting up. */
@Composable
fun StatusRow(status: CredentialStatus?) {
    var now by remember { mutableStateOf(Instant.now()) }
    LaunchedEffect(status) {
        while (true) {
            delay(1000)
            now = Instant.now()
        }
    }
    val (word, color) = when (val v = status?.value) {
        null -> "Status unknown" to MaterialTheme.colorScheme.onSurfaceVariant
        CredentialStatus.Value.Valid -> "Valid" to Color(0xFF2E7D32)
        CredentialStatus.Value.Revoked -> "Revoked by the issuer" to Color(0xFFC62828)
        CredentialStatus.Value.Suspended -> "Suspended by the issuer" to Color(0xFFE65100)
        is CredentialStatus.Value.Other -> "Status ${v.value}" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Column(Modifier.padding(vertical = 6.dp).testTag("credential-status")) {
        Text(word, style = MaterialTheme.typography.titleMedium, color = color)
        Text(status?.let { "Checked ${ago(it.checkedAt, now)}" } ?: "Not checked yet", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun ago(then: Instant, now: Instant): String {
    val s = maxOf(0, Duration.between(then, now).seconds)
    return when {
        s < 60 -> "$s s ago"
        s < 3600 -> "${s / 60} min ago"
        s < 86400 -> "${s / 3600} h ago"
        else -> "${s / 86400} days ago"
    }
}

/** A presentation request: who's asking, which credentials can answer, and exactly what sharing them discloses. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RequestScreen(model: WalletModel, openBrowser: (Uri) -> Unit) {
    val p = model.presentation ?: return
    val sharing = model.requestPhase == WalletModel.RequestPhase.SHARING
    BackHandler(enabled = !sharing) { model.decline(openBrowser) }
    Scaffold(topBar = { TopAppBar(title = { Text("Share credentials") }) }) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(top = padding.calculateTopPadding(), bottom = 24.dp)) {
            item { VerifierHeader(p.verifier) }
            if (!p.isAnswerable) item { Banner("You have no credential this verifier accepts.", null, "unanswerable") }
            p.queries.filter { it.credentials.isNotEmpty() }.forEach { candidates(model, it) }
            disclosures(model, p)
            item { ShareActions(model, sharing, openBrowser) }
        }
    }
}

/** One query: what it asks beyond the Verifier's registration, if anything, and the credentials that can answer it. */
private fun LazyListScope.candidates(model: WalletModel, query: Presentation.Query) {
    item { SectionHeader(if (query.multiple) "Choose the credentials to share" else "Choose a credential to share") }
    if (query.unregistered.isNotEmpty() || query.unregisteredAll) {
        item { Text(Credentials.overAsking(query), Modifier.padding(horizontal = 16.dp).testTag("over-asking"), color = Color(0xFFE65100)) }
    }
    items(query.credentials, key = { query.queryID + it.id }) { c ->
        CandidateCard(c, Holder.of(model.candidateClaims[c.id]), model.isSelected(c.id, query.queryID), query.multiple) {
            model.toggle(c.id, query)
        }
    }
}

/** What sharing the selection discloses, by credential, with each claim's value; or why it can't be shared. */
private fun LazyListScope.disclosures(model: WalletModel, p: Presentation) {
    model.previewError?.let {
        item { Banner("Can't share this selection: $it", Color(0xFFC62828), "preview-error") }
        return
    }
    for (d in model.disclosures) {
        val holder = Holder.of(model.candidateClaims[d.credentialID])
        val title = p.queries.flatMap { it.credentials }.firstOrNull { it.id == d.credentialID }?.let(Credentials::title) ?: "credential"
        item { SectionHeader("Will share · " + (holder?.name?.let { "$it · $title" } ?: title)) }
        items(d.claims) { path -> DisclosedRow(path, model.candidateClaims[d.credentialID], Credentials.isUnregistered(path, d.queryID, p)) }
    }
}

/** Share, prominent, and Decline under it. */
@Composable
private fun ShareActions(model: WalletModel, sharing: Boolean, openBrowser: (Uri) -> Unit) {
    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Button({ model.share(openBrowser) }, Modifier.fillMaxWidth().height(52.dp).testTag("share"), enabled = model.canShare) {
            Text(if (sharing) "Sharing…" else "Share", fontWeight = FontWeight.Bold)
        }
        OutlinedButton({ model.decline(openBrowser) }, Modifier.fillMaxWidth().height(52.dp).testTag("decline"), enabled = !sharing) {
            Text("Decline", color = Color(0xFFC62828))
        }
    }
}

/** Who's asking, at the top of the consent screen: the Verifier's name, its registration, and its client_id under Details. */
@Composable
fun VerifierHeader(verifier: Presentation.Verifier) {
    var details by remember { mutableStateOf(false) }
    Column(Modifier.padding(16.dp)) {
        Text(verifier.name, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text("is asking for your credentials", color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(8.dp))
        RegistrationRows(verifier.registration)
        TextButton({ details = !details }) { Text(if (details) "Hide details" else "Details") }
        if (details) Labeled("Client ID", verifier.clientID)
        HorizontalDivider()
    }
}

/** A Verifier's registration: who registered it and for what, or that its registration didn't verify. */
@Composable
private fun RegistrationRows(r: Presentation.Registration) {
    when (r.status) {
        Presentation.Registration.Status.VERIFIED -> {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.testTag("registered")) {
                Icon(Icons.Default.CheckCircle, null, tint = Color(0xFF2E7D32))
                Text(" Registered with ${r.registrar?.let(Credentials::host) ?: "a registrar"}", color = Color(0xFF2E7D32))
            }
            r.name?.let { Labeled("Registered as", it) }
            r.purpose?.let { Labeled("Purpose", it) }
            if (r.claims.isNotEmpty()) Labeled("Registered to ask for", r.claims.joinToString(", ") { Claims.path(it) })
        }
        Presentation.Registration.Status.INVALID ->
            Text("Its registration couldn't be verified", Modifier.testTag("registration-invalid"), color = Color(0xFFE65100))
        Presentation.Registration.Status.NONE ->
            Text("Not registered with a registrar this wallet knows", Modifier.testTag("not-registered"),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** A credential that can answer a query, as a card in its issuer's colours, with its selection mark. */
@Composable
fun CandidateCard(summary: CredentialSummary, holder: Holder?, selected: Boolean, multiple: Boolean, onToggle: () -> Unit) {
    val d = summary.display
    val text = cssColor(d?.textColor) ?: MaterialTheme.colorScheme.onSurface
    Card(
        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp).clickable(onClick = onToggle).testTag("candidate"),
        colors = CardDefaults.cardColors(containerColor = cssColor(d?.backgroundColor) ?: MaterialTheme.colorScheme.surfaceVariant),
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            ChoiceMark(selected, multiple, text)
            Spacer(Modifier.width(12.dp))
            val portrait = holder?.portrait
            if (portrait != null) {
                Image(portrait.asImageBitmap(), null, Modifier.size(44.dp, 56.dp).clip(RoundedCornerShape(6.dp)), contentScale = ContentScale.Crop)
            } else {
                LogoImage(d?.logo ?: d?.issuerLogo)
            }
            Column(Modifier.padding(start = 12.dp)) {
                Text(Credentials.title(summary), style = MaterialTheme.typography.titleMedium, color = text)
                holder?.let { Text(it.line, Modifier.testTag("candidate-holder"), color = text) }
                Text("${d?.issuerName ?: summary.credentialIssuer} · ${Credentials.format(summary)} · received ${Credentials.date(summary.receivedAt)}",
                    style = MaterialTheme.typography.bodySmall, color = text.copy(alpha = 0.8f))
                LinkabilityHint(summary, text)
            }
        }
    }
}

/** A candidate's choice mark: a checkbox for a query taking several credentials, a radio button otherwise. */
@Composable
private fun ChoiceMark(selected: Boolean, multiple: Boolean, text: Color) {
    val icon = when {
        !selected -> Icons.Default.RadioButtonUnchecked
        multiple -> Icons.Default.CheckCircle
        else -> Icons.Default.RadioButtonChecked
    }
    Icon(icon, if (selected) "Selected" else "Not selected", tint = if (selected) text else text.copy(alpha = 0.45f))
}

/** Whether presenting a candidate would be linkable, or this verifier has seen it before. */
@Composable
private fun LinkabilityHint(summary: CredentialSummary, text: Color) {
    if (summary.linkableHere == true) {
        Text("Every copy has been shown elsewhere: this verifier and another could link you", Modifier.testTag("linkable-here"),
            style = MaterialTheme.typography.bodySmall, color = Color(0xFFFB8C00))
    } else if (summary.shownToVerifier == true) {
        Text("This verifier has seen this credential before", Modifier.testTag("shown-before"),
            style = MaterialTheme.typography.bodySmall, color = text.copy(alpha = 0.8f))
    }
}

/** One claim sharing discloses: its path and the value the verifier will see, or the photo. */
@Composable
fun DisclosedRow(path: List<PathElement>, claims: JsonElement?, unregistered: Boolean) {
    val label = Claims.path(path)
    val value = claims?.let { Claims.resolve(path, it) }
    Column(Modifier.padding(horizontal = 16.dp, vertical = 2.dp).testTag("disclosed")) {
        val image = value?.let { Claims.image(it, Claims.lastKey(path)) }
        when {
            image != null -> Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text(label)
                Image(image.asImageBitmap(), null, Modifier.size(60.dp, 80.dp).clip(RoundedCornerShape(4.dp)))
            }
            value != null -> Labeled(label, Claims.text(value))
            else -> Text(label)
        }
        if (unregistered) {
            Text("Not in its registration", Modifier.testTag("disclosed-unregistered"), style = MaterialTheme.typography.labelSmall, color = Color(0xFFE65100))
        }
    }
}
