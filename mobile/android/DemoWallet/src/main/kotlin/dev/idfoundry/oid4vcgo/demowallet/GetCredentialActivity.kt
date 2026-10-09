package dev.idfoundry.oid4vcgo.demowallet

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.provider.selectedEntryId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest

/**
 * What Credential Manager launches when the holder picks one of the
 * wallet's credentials for a page's or app's Digital Credentials API
 * request: the consent screen for its OpenID4VP request, answered back
 * to the platform. The counterpart of the iOS demo's document provider
 * extension, for OpenID4VP requests.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
class GetCredentialActivity : ComponentActivity() {
    private val model: WalletModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        model.attach(this)
        model.start(null, provider = true)
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull()
        val asked = option?.let { openid4vp(it.requestJson) }
        if (request == null || asked == null) return fail()
        // A caller whose origin can't be established isn't answered.
        val origin = callerOrigin(request.callingAppInfo) ?: return fail()
        if (savedInstanceState == null) {
            model.startDCAPI(asked.first, asked.second.toString().toByteArray(), origin, request.selectedEntryId) { data ->
                when {
                    data != null -> answer(asked.first, data)
                    // A request that couldn't be opened: its screen stays,
                    // for the holder to read and close.
                    showsError() -> Unit
                    else -> fail()
                }
            }
        }
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Content()
            }
        }
    }

    /** The consent screen once the request is open, else where opening it is. */
    @Composable
    private fun Content() {
        if (model.requestPhase != WalletModel.RequestPhase.IDLE) {
            RequestScreen(model, openBrowser = {})
            return
        }
        when (val phase = model.phase) {
            is WalletModel.Phase.Failed -> Column(Modifier.padding(24.dp)) {
                Text(phase.text)
                TextButton(::fail) { Text("Close") }
            }
            WalletModel.Phase.UntrustedVerifier -> Column {
                UntrustedVerifier()
                TextButton(::fail, Modifier.padding(horizontal = 12.dp)) { Text("Close") }
            }
            else -> Text("Opening the request…", Modifier.padding(24.dp))
        }
    }

    /** Whether the request couldn't be opened, and the screen says why. */
    private fun showsError(): Boolean =
        model.phase is WalletModel.Phase.Failed || model.phase == WalletModel.Phase.UntrustedVerifier

    /**
     * The calling page's origin, which the browser vouches for when it's
     * one the privileged list names; an app's own identity otherwise.
     * Null where neither can be established: getOrigin refusing the
     * caller, or an app with no signing certificate.
     */
    private fun callerOrigin(caller: CallingAppInfo): String? {
        val privileged = resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }
        val browserOrigin = runCatching { caller.getOrigin(privileged) }.getOrElse { return null }
        return browserOrigin ?: appOrigin(caller.signingInfoCompat.signingCertificateHistory.firstOrNull()?.toByteArray())
    }

    /** The request's first OpenID4VP request: its protocol and data. */
    private fun openid4vp(requestJson: String): Pair<String, JsonObject>? {
        val all = runCatching { Json.parseToJsonElement(requestJson).jsonObject["requests"]?.jsonArray }.getOrNull() ?: return null
        return all.mapNotNull { it as? JsonObject }.firstNotNullOfOrNull { r ->
            val protocol = r["protocol"]?.jsonPrimitive?.content ?: return@firstNotNullOfOrNull null
            val data = r["data"] as? JsonObject ?: return@firstNotNullOfOrNull null
            if (protocol.startsWith("openid4vp-v1-")) protocol to data else null
        }
    }

    /**
     * An app's origin, from its signing certificate, as Android names
     * one; null without one, rather than an origin every such app shares.
     */
    private fun appOrigin(certificate: ByteArray?): String? {
        if (certificate == null || certificate.isEmpty()) return null
        val hash = MessageDigest.getInstance("SHA-256").digest(certificate)
        return "android:apk-key-hash:" + Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun answer(protocol: String, data: String) {
        val response = JsonObject(mapOf("protocol" to kotlinx.serialization.json.JsonPrimitive(protocol), "data" to Json.parseToJsonElement(data)))
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(DigitalCredential(response.toString())))
        setResult(RESULT_OK, result)
        finish()
    }

    private fun fail() {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException("the wallet couldn't answer"))
        setResult(RESULT_OK, result)
        finish()
    }
}
