package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.Log
import androidx.compose.ui.graphics.toArgb
import androidx.credentials.registry.digitalcredentials.mdoc.MdocEntry
import androidx.credentials.registry.digitalcredentials.mdoc.MdocField
import androidx.credentials.registry.digitalcredentials.openid4vp.OpenId4VpRegistry
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtClaim
import androidx.credentials.registry.digitalcredentials.sdjwt.SdJwtEntry
import androidx.credentials.registry.provider.RegistryManager
import androidx.credentials.registry.provider.digitalcredentials.DigitalCredentialEntry
import androidx.credentials.registry.provider.digitalcredentials.VerificationEntryDisplayProperties
import androidx.credentials.registry.provider.digitalcredentials.VerificationFieldDisplayProperties
import dev.idfoundry.oid4vcwallet.CredentialSummary
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant

/**
 * Tells Credential Manager which credentials the wallet can present over
 * the Digital Credentials API, so Chrome offers the app when a page asks
 * for one: each presentable SD-JWT VC and mdoc, with its claims, which
 * Google's OpenID4VP matcher (OpenId4VpRegistry's default) matches a
 * request's DCQL query against. The values are only for the system's
 * chooser; nothing is presented until the holder agrees in the app.
 * The counterpart of the iOS demo's DocumentRegistrations.
 */
object DigitalCredentials {
    /** The registry's ID: registering again replaces what it held. */
    private const val REGISTRY_ID = "dev.idfoundry.oid4vcgo.demowallet"

    suspend fun sync(context: Context, credentials: List<CredentialSummary>, claims: Map<String, JsonElement>) {
        val now = Instant.now()
        val entries = credentials.filter { !it.isExpired(now) && it.holderKeyPresent != false }.mapNotNull { c ->
            when (c.format) {
                "dc+sd-jwt" -> c.vct?.let { sdJwtEntry(c, it, claims[c.id]) }
                "mso_mdoc" -> c.doctype?.let { mdocEntry(c, it, claims[c.id]) }
                else -> null
            }
        }
        try {
            RegistryManager.create(context).registerCredentials(OpenId4VpRegistry(entries, REGISTRY_ID))
            Log.i("DemoWallet", "registered ${entries.size} credential(s) with Credential Manager")
        } catch (e: Exception) {
            // No Play services, or Credential Manager without the
            // registry: Chrome won't offer the app, and nothing else
            // changes.
            Log.w("DemoWallet", "registering credentials with Credential Manager: $e")
        }
    }

    private fun display(c: CredentialSummary): Set<VerificationEntryDisplayProperties> = setOf(
        VerificationEntryDisplayProperties(
            Credentials.title(c), c.display?.issuerName ?: Credentials.host(c.credentialIssuer), icon(c), null, null, null,
        ),
    )

    private fun field(name: String, value: JsonElement) = setOf(VerificationFieldDisplayProperties(name, Claims.text(value)))

    private fun sdJwtEntry(c: CredentialSummary, vct: String, claims: JsonElement?): DigitalCredentialEntry {
        val o = claims as? JsonObject
        val fields = o?.filterKeys { it !in Claims.hidden }?.map { (key, value) ->
            SdJwtClaim(listOf(key), primitive(value), field(key, value), true)
        }.orEmpty()
        return SdJwtEntry(vct, fields, display(c), c.id)
    }

    private fun mdocEntry(c: CredentialSummary, doctype: String, claims: JsonElement?): DigitalCredentialEntry {
        val namespaces = claims as? JsonObject
        val fields = namespaces?.flatMap { (namespace, elements) ->
            (elements as? JsonObject)?.map { (identifier, value) -> MdocField(namespace, identifier, primitive(value), field(identifier, value)) }.orEmpty()
        }.orEmpty()
        return MdocEntry(doctype, fields, display(c), c.id)
    }

    /** A claim's value as the matcher compares it: text, a number or a boolean; anything else as its text. */
    private fun primitive(v: JsonElement): Any {
        val p = v as? JsonPrimitive ?: return Claims.text(v)
        return if (p.isString) p.content else p.content.toLongOrNull() ?: p.content.toDoubleOrNull() ?: p.content.toBooleanStrictOrNull() ?: p.content
    }

    /** A swatch of the issuer's colour, for the system's chooser. */
    private fun icon(c: CredentialSummary): Bitmap {
        val b = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888)
        Canvas(b).drawColor((cssColor(c.display?.backgroundColor) ?: androidx.compose.ui.graphics.Color(0xFF12107C)).toArgb())
        return b
    }
}
