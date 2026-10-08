# Presenting to Chrome

Answer a web page's OpenID4VP request over the Digital Credentials API,
as a Credential Manager provider.

> **Status:** this has run end to end in Chrome on the Android emulator
> (API 37, with Google Play), not yet on a device. The check that the
> request really comes through Credential Manager from the browser it
> names is still open: until it's settled, treat the reported origin as
> what the platform says, not as proven. Watch OID4VCgo's
> [MOBILE.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/MOBILE.md)
> for both.

A page in Chrome can ask for a credential with the W3C Digital
Credentials API, using OpenID4VP (OpenID4VP 1.0 Appendix A). Android's
Credential Manager shows the holder the matching credentials from the
wallets that registered them, and launches the chosen wallet's provider
activity with the request. The wallet answers through
`Wallet.startDCAPIPresentation`; the response goes back through
Credential Manager to the page, encrypted to it, with no network
request from the wallet.

Chrome sends OpenID4VP, mdocs included: `org-iso-mdoc` is Safari's
route on iOS. The library's `startMdocPresentation` exists for it, but
nothing on Android sends it today.

It needs Google Play services, and the `androidx.credentials` and
`androidx.credentials.registry` libraries, which are still alpha.

## Register the credentials

Credential Manager matches a page's request against what each wallet
registered: register every presentable credential, with its claims,
whenever the credentials change. `OpenId4VpRegistry`'s default matcher
is Google's, so the app writes none. The claims' values are only for the
system's chooser; nothing is presented until the holder agrees in the
app.

```kotlin
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.util.Base64
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import dev.idfoundry.oid4vcwallet.Presentation
import dev.idfoundry.oid4vcwallet.Wallet
import java.security.MessageDigest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Registers the wallet's SD-JWT VCs, with their top-level claims, with
 * Credential Manager. Registering again replaces what was registered.
 */
suspend fun registerWithCredentialManager(context: Context, wallet: Wallet, icon: Bitmap) {
    val entries = wallet.credentials()
        .filter { it.format == "dc+sd-jwt" && it.vct != null && it.holderKeyPresent != false }
        .map { c ->
            val claims = wallet.credential(c.id).claims as? JsonObject ?: JsonObject(emptyMap())
            val fields = claims.mapNotNull { (key, value) ->
                val text = (value as? JsonPrimitive)?.content ?: return@mapNotNull null
                SdJwtClaim(listOf(key), text, setOf(VerificationFieldDisplayProperties(key, text)), true)
            }
            val display = VerificationEntryDisplayProperties(
                c.display?.name ?: c.vct!!, c.display?.issuerName ?: c.credentialIssuer, icon, null, null, null,
            )
            SdJwtEntry(c.vct!!, fields, setOf(display), c.id)
        }
    RegistryManager.create(context).registerCredentials(OpenId4VpRegistry(entries, "com.example.wallet"))
}
```

The demo wallet's `DigitalCredentials.kt` registers mdocs too, with
`MdocEntry`.

## Answer in the provider activity

Credential Manager launches the activity whose intent filter has the
`androidx.credentials.registry.provider.action.GET_CREDENTIAL` action,
with the request in its intent. The activity:

1. takes the request's OpenID4VP part (`protocol` starting
   `openid4vp-v1-`, and its `data`);
2. works out the caller's origin: a browser's, which
   `CallingAppInfo.getOrigin` returns when the browser is on the
   privileged-browsers list you give it (the demo carries Chrome's
   entries from Google's list), or else an app's own,
   `android:apk-key-hash:` and its signing certificate's SHA-256;
3. starts the presentation, asks the holder, and responds or declines:
   either gives `Presented.dcapiResponse`, which goes back to the platform.

```kotlin
/**
 * Answers the Digital Credentials API request in a provider activity's
 * `intent`: `confirm` shows the holder the presentation and returns
 * whether they agree. Returns the result to set on the activity.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
suspend fun answerCredentialRequest(
    intent: Intent,
    wallet: Wallet,
    privilegedBrowsers: String,
    confirm: suspend (Presentation) -> Boolean,
): Intent {
    val result = Intent()
    val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
    val option = request?.credentialOptions?.filterIsInstance<GetDigitalCredentialOption>()?.firstOrNull()
    val asked = option?.let { openid4vpRequest(it.requestJson) }
    if (request == null || asked == null) {
        PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException("no OpenID4VP request"))
        return result
    }
    val (protocol, data) = asked
    val origin = request.callingAppInfo.getOrigin(privilegedBrowsers)
        ?: appOrigin(request.callingAppInfo.signingInfoCompat.signingCertificateHistory.firstOrNull()?.toByteArray())
    val presentation = wallet.startDCAPIPresentation(protocol, data.toString().toByteArray(), origin)
    val presented = if (presentation.isAnswerable && confirm(presentation)) {
        presentation.respond(presentation.defaultSelection())
    } else {
        presentation.decline()
    }
    val response = JsonObject(mapOf(
        "protocol" to JsonPrimitive(protocol),
        "data" to Json.parseToJsonElement(presented.dcapiResponse ?: "{}"),
    ))
    PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(DigitalCredential(response.toString())))
    return result
}

/** The request's first OpenID4VP request: its protocol and data. */
private fun openid4vpRequest(requestJson: String): Pair<String, JsonObject>? {
    val requests = runCatching { Json.parseToJsonElement(requestJson).jsonObject["requests"]?.jsonArray }.getOrNull() ?: return null
    return requests.mapNotNull { it as? JsonObject }.firstNotNullOfOrNull { r ->
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
```

The activity sets the returned intent with `setResult(RESULT_OK, …)` and
finishes. The demo's `GetCredentialActivity` does this with a consent
screen. Launched by Credential Manager rather than the holder, it should
skip the app's launch work: a key sweep then would delete the keys of an
issuance the app has in progress.

## Trust

- A signed request is checked against `WalletConfiguration.verifierRoots`,
  and its `expected_origins` must include the origin: another site
  can't replay it.
- An unsigned request has only its origin for identity.
  `WalletConfiguration.requireSignedDCAPIRequests` refuses those before
  the holder sees them; HAIP requires wallets to support them, so set it
  only where every Verifier must be a known one.
- Each presentation is recorded as shown to the page's origin, for
  linkability, as for a link's Verifier.
