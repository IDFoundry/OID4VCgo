package dev.idfoundry.oid4vcwallet

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Build
import android.util.Base64
import androidx.annotation.VisibleForTesting
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import androidx.credentials.registry.provider.selectedEntryId
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest
import java.time.Instant
import kotlinx.serialization.json.Json as KJson

/**
 * Credential Manager's side of the Digital Credentials API: what an app
 * needs so Chrome, or another app, can ask the wallet for a credential.
 *
 * 1. [register] the wallet's credentials after every change, so the
 *    system's chooser offers them for the requests they can answer.
 * 2. Declare an exported activity with an intent filter for
 *    `androidx.credentials.registry.provider.action.GET_CREDENTIAL`.
 *    Credential Manager starts it when the holder picks one. Being
 *    exported, any app can start it too: [request] answers only
 *    Credential Manager.
 * 3. In it, read the [request], show it for the holder's consent with
 *    [Request.startPresentation] (or [Request.startMdocPresentation]),
 *    and finish with `setResult(Activity.RESULT_OK, intent)`, where
 *    intent is [response], or [failure] when the wallet won't answer.
 *
 * Android answers Chrome's requests over OpenID4VP (`openid4vp-v1-*`),
 * for mdocs as well as SD-JWT VCs: the registry's default matcher is
 * OpenID4VP's. `org-iso-mdoc` (ISO/IEC TS 18013-7 Annex C) is Safari's
 * route, so iOS's, and is only answered here for a web origin.
 */
@OptIn(ExperimentalDigitalCredentialApi::class)
public object DigitalCredentials {
    /** The `org-iso-mdoc` protocol identifier. */
    public const val MDOC_PROTOCOL: String = "org-iso-mdoc"

    /** The OpenID4VP protocol identifiers' prefix (`openid4vp-v1-unsigned`, `-signed`, `-multisigned`). */
    public const val OPENID4VP_PROTOCOL_PREFIX: String = "openid4vp-v1-"

    /** How [register] describes the wallet's credentials to the system. */
    public data class RegistrationOptions(
        /**
         * The registry's ID; registering again under it replaces what
         * it held. Null: the app's package name.
         */
        val registryID: String? = null,
        /**
         * Whether to register each claim's value as well as its name.
         * By default only names are registered. Values let the matcher
         * answer a query that asks for a particular value, and let the
         * system's chooser show them, but they are then held by the
         * system's registry, before any consent — every value, an
         * mdoc's portrait (as base64) among them. OID4VCWallet 0.34.1
         * and earlier registered them by default.
         */
        val claimValues: Boolean = false,
        /** Each credential's icon in the chooser; null: a swatch of its card colour. */
        val icon: ((CredentialSummary) -> Bitmap)? = null,
    )

    /**
     * Registers the wallet's presentable credentials with Credential
     * Manager — each [CredentialSummary.presentable] SD-JWT VC and mdoc
     * whose key is on the device, with its claims — replacing what was registered before,
     * and returns how many. Call it after every issuance, deletion and
     * restore. It throws where the device has no Credential Manager
     * registry (no Google Play services, say): the wallet then works as
     * before, but isn't offered for Digital Credentials API requests.
     * Nothing is presented by registering: the holder still consents in
     * the app.
     */
    public suspend fun register(context: Context, wallet: Wallet, options: RegistrationOptions = RegistrationOptions()): Int {
        val now = Instant.now()
        val entries = wallet.credentials().filter { it.presentable && !it.isExpired(now) && it.holderKeyPresent != false }.mapNotNull { c ->
            val claims = if (c.format == "dc+sd-jwt" || c.format == "mso_mdoc") wallet.credential(c.id).claims else return@mapNotNull null
            entry(c, claims, options)
        }
        RegistryManager.create(context).registerCredentials(OpenId4VpRegistry(entries, options.registryID ?: context.packageName))
        return entries.size
    }

    /**
     * A Digital Credentials API request Credential Manager handed the
     * wallet's activity, from the page or app at [origin].
     */
    public class Request internal constructor(
        /** Its protocol: `openid4vp-v1-…`, or [MDOC_PROTOCOL]. */
        public val protocol: String,
        /** The request's data member, as JSON. */
        public val data: String,
        /**
         * The caller's origin, as Credential Manager vouches for it: a web
         * origin for a browser on the privileged-browsers list, else
         * `android:apk-key-hash:` and the calling app's signing
         * certificate's SHA-256, base64url.
         */
        public val origin: String,
        /** The credential the holder picked in the system's chooser, if it says. */
        public val selectedCredentialID: String?,
    ) {
        /** Whether it's an `org-iso-mdoc` request, for [startMdocPresentation]. */
        public val isMdoc: Boolean get() = protocol == MDOC_PROTOCOL

        /** Opens an OpenID4VP request for the holder's consent. */
        public suspend fun startPresentation(wallet: Wallet): Presentation {
            check(!isMdoc) { "an org-iso-mdoc request: use startMdocPresentation" }
            return wallet.startDCAPIPresentation(protocol, data.toByteArray(), origin)
        }

        /**
         * Opens an `org-iso-mdoc` request for the holder's consent. Only
         * a web origin can be bound to one: an app's origin fails with
         * [WalletException.Code.invalidInput].
         */
        public suspend fun startMdocPresentation(wallet: Wallet): MdocPresentation {
            check(isMdoc) { "an OpenID4VP request: use startPresentation" }
            return wallet.startMdocPresentation(data.toByteArray(), origin)
        }
    }

    /**
     * An app trusted to start the wallet's provider activity: one that
     * runs Credential Manager's chooser, and so vouches for the request's
     * caller and origin.
     */
    public class CredentialManagerApp(
        /** Its package name. */
        public val packageName: String,
        /** The SHA-256 of each signing certificate it may be signed with. */
        public val certificateSHA256: List<ByteArray>,
    )

    /**
     * Google Play services, which runs Credential Manager's chooser for
     * the registry the wallet [register]s with, signed with Google's
     * release key (the one Google's privileged-browsers list names for
     * Chrome's release build).
     */
    public val GOOGLE_PLAY_SERVICES: CredentialManagerApp = CredentialManagerApp(
        "com.google.android.gms",
        listOf(fingerprint("F0:FD:6C:5B:41:0F:25:CB:25:C3:B5:33:46:C8:97:2F:AE:30:F8:EE:74:11:DF:91:04:80:AD:6B:2D:60:DB:83")),
    )

    /**
     * The Digital Credentials API request [activity] was started with:
     * its first OpenID4VP request, else its first `org-iso-mdoc` one.
     *
     * Null unless Credential Manager started the activity: the
     * platform's own (the framework, or the system's
     * `com.android.credentialmanager` selector, signed with the
     * platform's key), or one of [credentialManagerApps]. Another app
     * signed with the platform's key isn't Credential Manager.
     * The request, its caller and the caller's origin all come from the
     * activity's intent, which any app can fill in when it starts an
     * exported activity: only Credential Manager's is vouched for. An
     * activity started without a result expected has no caller to check
     * either. Null too when the request has none the wallet answers, or
     * when the caller's origin can't be established — a browser not on
     * [privilegedBrowsers] (Credential Manager's JSON allowlist of
     * browsers trusted to report a page's origin, such as the one Google
     * publishes for Chrome), or an app without a signing certificate. A
     * wallet answers a null with [failure].
     */
    public fun request(
        activity: Activity,
        privilegedBrowsers: String,
        credentialManagerApps: List<CredentialManagerApp> = listOf(GOOGLE_PLAY_SERVICES),
    ): Request? {
        val caller = activity.callingPackage ?: return null
        if (!isCredentialManager(activity.packageManager, caller, credentialManagerApps)) return null
        return request(activity.intent, privilegedBrowsers)
    }

    /**
     * The platform's own Credential Manager callers: the framework
     * (`android`) and AOSP's Credential Manager selector, which launches
     * a provider's PendingIntent on Android 14 and later.
     */
    internal val PLATFORM_CREDENTIAL_MANAGER_PACKAGES: Set<String> = setOf("android", "com.android.credentialmanager")

    /**
     * Whether [caller] is the platform's Credential Manager — one of
     * [PLATFORM_CREDENTIAL_MANAGER_PACKAGES], installed on the system
     * image and signed with the platform's key — or one of [apps], by its
     * signing certificate. Any other app signed with the platform's key
     * (on some builds, many are) isn't trusted to vouch for a caller's
     * origin.
     */
    internal fun isCredentialManager(pm: PackageManager, caller: String, apps: List<CredentialManagerApp>): Boolean {
        if (isPlatformCredentialManager(pm, caller)) return true
        return apps.any { app -> app.packageName == caller && app.certificateSHA256.any { signedWith(pm, caller, it) } }
    }

    private fun isPlatformCredentialManager(pm: PackageManager, caller: String): Boolean {
        if (caller !in PLATFORM_CREDENTIAL_MANAGER_PACKAGES) return false
        if (caller != "android" && pm.checkSignatures("android", caller) != PackageManager.SIGNATURE_MATCH) return false
        val flags = runCatching { pm.getApplicationInfo(caller, 0).flags }.getOrNull() ?: return false
        return flags and ApplicationInfo.FLAG_SYSTEM != 0
    }

    private fun signedWith(pm: PackageManager, packageName: String, sha256: ByteArray): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            return pm.hasSigningCertificate(packageName, sha256, PackageManager.CERT_INPUT_SHA256)
        }
        @Suppress("DEPRECATION")
        val signatures = runCatching { pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES).signatures }.getOrNull() ?: return false
        // An app signed by several keys isn't the one key's.
        val only = signatures.singleOrNull() ?: return false
        return MessageDigest.getInstance("SHA-256").digest(only.toByteArray()).contentEquals(sha256)
    }

    /** A certificate fingerprint written as colon-separated hex, as bytes. */
    internal fun fingerprint(hex: String): ByteArray =
        hex.split(':').map { it.toInt(16).toByte() }.toByteArray()

    /** The request in [intent], once its caller is vouched for: see [request]. */
    internal fun request(intent: Intent, privilegedBrowsers: String): Request? {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return null
        val option = request.credentialOptions.filterIsInstance<GetDigitalCredentialOption>().firstOrNull() ?: return null
        val (protocol, data) = firstSupported(option.requestJson) ?: return null
        val origin = callerOrigin(request.callingAppInfo, privilegedBrowsers) ?: return null
        return Request(protocol, data, origin, request.selectedEntryId)
    }

    /**
     * The result intent answering [request] with an OpenID4VP
     * presentation's [Presentation.Presented.dcapiResponse].
     */
    public fun response(request: Request, dcapiResponse: String): Intent = result(request.protocol, KJson.parseToJsonElement(dcapiResponse))

    /** The result intent answering [request] with an `org-iso-mdoc` presentation's response. */
    public fun response(request: Request, response: MdocPresentation.Response): Intent =
        result(request.protocol, KJson.parseToJsonElement(response.responseData()))

    /**
     * The result intent for a request the wallet doesn't answer:
     * declined, unparseable, or refused. The caller learns only that
     * there's no credential.
     */
    public fun failure(message: String = "the wallet didn't answer"): Intent {
        val result = Intent()
        PendingIntentHandler.setGetCredentialException(result, GetCredentialUnknownException(message))
        return result
    }

    private fun result(protocol: String, data: JsonElement): Intent {
        val response = JsonObject(mapOf("protocol" to JsonPrimitive(protocol), "data" to data))
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(DigitalCredential(response.toString())))
        return result
    }

    /**
     * The request in [requestJson] the wallet answers, with its protocol
     * and data: the first OpenID4VP one, else the first `org-iso-mdoc`
     * one — a page offering both is answered over OpenID4VP, Android's
     * route.
     */
    internal fun firstSupported(requestJson: String): Pair<String, String>? {
        val all = runCatching { KJson.parseToJsonElement(requestJson).jsonObject["requests"]?.jsonArray }.getOrNull() ?: return null
        val requests = all.mapNotNull { r ->
            val o = r as? JsonObject ?: return@mapNotNull null
            val protocol = (o["protocol"] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return@mapNotNull null
            val data = o["data"] as? JsonObject ?: return@mapNotNull null
            protocol to data.toString()
        }
        return requests.firstOrNull { it.first.startsWith(OPENID4VP_PROTOCOL_PREFIX) } ?: requests.firstOrNull { it.first == MDOC_PROTOCOL }
    }

    /**
     * The caller's origin: the page's, which the browser vouches for when
     * it's on [privilegedBrowsers]; an app's own identity otherwise. Null
     * where neither can be established.
     */
    @VisibleForTesting
    internal fun callerOrigin(caller: CallingAppInfo, privilegedBrowsers: String): String? {
        val browserOrigin = runCatching { caller.getOrigin(privilegedBrowsers) }.getOrElse { return null }
        if (browserOrigin != null) return browserOrigin
        val signing = caller.signingInfoCompat
        // An app signed by several keys has no one origin. Otherwise its
        // current key: the history runs from the original to the current
        // one, and an app that rotated away from a compromised key mustn't
        // share its origin with what that key still signs. Before API 28
        // there's no history: the compat layer reports the app's signers
        // in its place, and never multiple signers.
        // SigningInfoCompat's own property, set on every API level (from
        // the app's signatures below 28): lint takes it for
        // android.content.pm.SigningInfo.hasMultipleSigners, which is 28's.
        @SuppressLint("NewApi")
        val multipleSigners = signing.hasMultipleSigners
        if (multipleSigners) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P && signing.signingCertificateHistory.size > 1) return null
        return appOrigin(signing.signingCertificateHistory.lastOrNull()?.toByteArray())
    }

    /**
     * An app's origin, from its signing certificate, as Android names
     * one; null without one, rather than an origin every such app shares.
     */
    internal fun appOrigin(certificate: ByteArray?): String? {
        if (certificate == null || certificate.isEmpty()) return null
        val hash = MessageDigest.getInstance("SHA-256").digest(certificate)
        return "android:apk-key-hash:" + Base64.encodeToString(hash, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    // The SD-JWT VC's own top-level claims, not about the holder.
    private val sdJwtHidden = setOf("cnf", "iss", "iat", "exp", "nbf", "vct", "status", "_sd_alg")

    private fun entry(c: CredentialSummary, claims: JsonElement, options: RegistrationOptions): DigitalCredentialEntry? {
        val display = setOf(
            VerificationEntryDisplayProperties(
                c.display?.name ?: c.vct ?: c.doctype ?: c.configurationID,
                c.display?.issuerName ?: host(c.credentialIssuer) ?: c.credentialIssuer,
                options.icon?.invoke(c) ?: swatch(c.display?.backgroundColor),
                null, null, null,
            ),
        )
        return when (c.format) {
            "dc+sd-jwt" -> c.vct?.let { vct ->
                val fields = (claims as? JsonObject)?.filterKeys { it !in sdJwtHidden }?.map { (key, value) ->
                    SdJwtClaim(listOf(key), if (options.claimValues) matchValue(value) else null, field(key, value, options), true)
                }.orEmpty()
                SdJwtEntry(vct, fields, display, c.id)
            }
            "mso_mdoc" -> c.doctype?.let { doctype ->
                val fields = (claims as? JsonObject)?.flatMap { (namespace, elements) ->
                    (elements as? JsonObject)?.map { (identifier, value) ->
                        MdocField(namespace, identifier, if (options.claimValues) matchValue(value) else null, field(identifier, value, options))
                    }.orEmpty()
                }.orEmpty()
                MdocEntry(doctype, fields, display, c.id)
            }
            else -> null
        }
    }

    /** [url]'s host; null where it has none or isn't a URL. */
    private fun host(url: String): String? = runCatching<String?> { java.net.URI(url).host }.getOrNull()

    private fun field(name: String, value: JsonElement, options: RegistrationOptions) =
        setOf(VerificationFieldDisplayProperties(name, if (options.claimValues) text(value) else null))

    /** A claim's value as the matcher compares it: text, a number or a boolean; anything else as its text. */
    internal fun matchValue(v: JsonElement): Any {
        val p = v as? JsonPrimitive ?: return text(v)
        if (p is JsonNull) return text(v)
        return if (p.isString) p.content else p.content.toLongOrNull() ?: p.content.toDoubleOrNull() ?: p.content.toBooleanStrictOrNull() ?: p.content
    }

    /** A claim's value as the chooser shows it. */
    internal fun text(v: JsonElement): String = when (v) {
        is JsonNull -> "—"
        is JsonPrimitive -> when {
            v.isString -> if (v.content.length > 80) v.content.take(77) + "…" else v.content
            v.booleanOrNull != null -> if (v.booleanOrNull == true) "yes" else "no"
            else -> v.content
        }
        is JsonArray -> v.joinToString(", ") { text(it) }
        is JsonObject -> "{…}"
    }

    /** A swatch of a card's CSS colour (#rgb or #rrggbb), for the chooser. */
    private fun swatch(css: String?): Bitmap {
        val b = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888)
        Canvas(b).drawColor(cssColor(css) ?: DEFAULT_COLOR)
        return b
    }

    /** A CSS hex colour as ARGB; null for anything else. */
    internal fun cssColor(css: String?): Int? {
        var hex = css?.trim()?.takeIf { it.startsWith("#") }?.drop(1) ?: return null
        if (hex.length == 3) hex = hex.map { "$it$it" }.joinToString("")
        if (hex.length != 6) return null
        return hex.toIntOrNull(16)?.let { (0xFF shl 24) or it }
    }

    private const val DEFAULT_COLOR = 0xFF12107C.toInt()
}
