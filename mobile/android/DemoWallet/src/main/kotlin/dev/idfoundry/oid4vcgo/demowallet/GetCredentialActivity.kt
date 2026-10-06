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
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
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
        // The calling page's origin, which the browser vouches for when
        // it's one the privileged list names; an app's own identity
        // otherwise.
        val origin = request.callingAppInfo.getOrigin(resources.openRawResource(R.raw.privileged_browsers).bufferedReader().readText())
            ?: appOrigin(request.callingAppInfo.signingInfoCompat.signingCertificateHistory.firstOrNull()?.toByteArray())
        if (savedInstanceState == null) {
            model.startDCAPI(asked.first, asked.second.toString().toByteArray(), origin, request.selectedEntryId) { data ->
                if (data == null) fail() else answer(asked.first, data)
            }
        }
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                if (model.requestPhase != WalletModel.RequestPhase.IDLE) {
                    RequestScreen(model, openBrowser = {})
                } else {
                    when (val phase = model.phase) {
                        is WalletModel.Phase.Failed -> Text(phase.text, Modifier.padding(24.dp))
                        WalletModel.Phase.UntrustedVerifier -> UntrustedVerifier()
                        else -> Text("Opening the request…", Modifier.padding(24.dp))
                    }
                }
            }
        }
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

    /** An app's origin, from its signing certificate, as Android names one. */
    private fun appOrigin(certificate: ByteArray?): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(certificate ?: ByteArray(0))
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
