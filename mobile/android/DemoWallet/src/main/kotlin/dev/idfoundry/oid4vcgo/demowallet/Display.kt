package dev.idfoundry.oid4vcgo.demowallet

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.compose.ui.graphics.Color
import dev.idfoundry.oid4vcwallet.CredentialStatus
import dev.idfoundry.oid4vcwallet.CredentialSummary
import dev.idfoundry.oid4vcwallet.PathElement
import dev.idfoundry.oid4vcwallet.Presentation
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Base64

/**
 * Whose credential this is, from its claims: the holder's name, date of
 * birth and photo, wherever the format keeps them (an SD-JWT VC's
 * top-level claims, an mdoc's namespaces).
 */
data class Holder(val name: String?, val birthDate: String?, val portrait: Bitmap?) {
    /** "Jane Citizen · born 1990-01-01". */
    val line: String get() = listOfNotNull(name, birthDate?.let { "born $it" }).joinToString(" · ")

    companion object {
        fun of(claims: JsonElement?): Holder? {
            claims ?: return null
            val names = listOf(find(listOf("given_name", "given_names"), claims), find(listOf("family_name"), claims))
                .mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString && p.content.isNotEmpty() }?.content }
            val name = names.takeIf { it.isNotEmpty() }?.joinToString(" ")
            val birth = birthDate(find(listOf("birth_date", "birthdate"), claims))
            val portrait = listOf("portrait", "picture").firstNotNullOfOrNull { key -> find(listOf(key), claims)?.let { Claims.image(it, key) } }
            if (name == null && birth == null && portrait == null) return null
            return Holder(name, birth, portrait)
        }

        /**
         * A date of birth as text: an SD-JWT VC's string, or ISO/IEC TS
         * 23220-2's birth_date structure ({birth_date, approximate_mask}),
         * its masked digits shown as "x".
         */
        fun birthDate(v: JsonElement?): String? = when (v) {
            is JsonPrimitive -> v.takeIf { it.isString }?.content
            is JsonObject -> {
                val date = (v["birth_date"] as? JsonPrimitive)?.content
                val mask = (v["approximate_mask"] as? JsonPrimitive)?.content
                if (date == null) {
                    null
                } else if (mask == null || mask.length != 8) {
                    date
                } else {
                    // The mask covers YYYYMMDD; the date is YYYY-MM-DD.
                    val digits = mask.iterator()
                    date.map { c -> if (c == '-') c else if (digits.hasNext() && digits.next() == '1') 'x' else c }.joinToString("")
                }
            }
            else -> null
        }

        /** The first value under any of [keys], searching objects depth-first. */
        fun find(keys: List<String>, v: JsonElement): JsonElement? {
            val o = v as? JsonObject ?: return null
            keys.firstNotNullOfOrNull { o[it] }?.let { return it }
            return o.keys.sorted().firstNotNullOfOrNull { find(keys, o[it]!!) }
        }
    }
}

/** Claims as text and images. */
object Claims {
    /** The SD-JWT VC's own top-level claims, not about the holder. */
    val hidden = setOf("cnf", "iss", "iat", "exp", "nbf", "vct", "status", "_sd_alg")

    /** An image claim: a data: URL (an SD-JWT VC's picture), or base64 bytes under a name like an mdoc's portrait. */
    fun image(v: JsonElement, key: String): Bitmap? {
        val s = (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return null
        val encoded = when {
            s.startsWith("data:image/") && ',' in s -> s.substringAfter(',')
            listOf("portrait", "picture", "photo", "image").any { key.lowercase().contains(it) } -> s
            else -> return null
        }
        val bytes = runCatching { Base64.getDecoder().decode(encoded) }.getOrNull() ?: return null
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }

    fun text(v: JsonElement): String = when (v) {
        is JsonNull -> "—"
        is JsonPrimitive -> when {
            v.isString -> if (v.content.length > 80) v.content.take(77) + "…" else v.content
            v.booleanOrNull != null -> if (v.booleanOrNull == true) "yes" else "no"
            v.longOrNull != null -> v.longOrNull.toString()
            else -> v.doubleOrNull?.toString() ?: v.content
        }
        is JsonArray -> v.joinToString(", ") { text(it) }
        is JsonObject -> "{…}"
    }

    /** The value at [path] in [claims]: null selects every element of an array. */
    fun resolve(path: List<PathElement>, claims: JsonElement): JsonElement? {
        val first = path.firstOrNull() ?: return claims
        val rest = path.drop(1)
        return when {
            first is PathElement.Key && claims is JsonObject -> claims[first.key]?.let { resolve(rest, it) }
            first is PathElement.Index && claims is JsonArray -> claims.getOrNull(first.index)?.let { resolve(rest, it) }
            first is PathElement.All && claims is JsonArray -> claims.mapNotNull { resolve(rest, it) }.takeIf { it.isNotEmpty() }?.let(::JsonArray)
            else -> null
        }
    }

    fun lastKey(path: List<PathElement>): String = path.lastOrNull { it is PathElement.Key }?.let { (it as PathElement.Key).key }.orEmpty()

    fun path(elements: List<PathElement>): String = elements.joinToString(" · ") {
        when (it) {
            is PathElement.Key -> it.key
            is PathElement.Index -> it.index.toString()
            PathElement.All -> "*"
        }
    }
}

/** How a credential reads to its holder. */
object Credentials {
    private val date = DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withZone(ZoneId.systemDefault())
    private val dateTime = DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT).withZone(ZoneId.systemDefault())

    fun date(i: java.time.Instant): String = date.format(i)

    fun dateTime(i: java.time.Instant): String = dateTime.format(i)

    /** The credential's format, as a holder would name it. */
    fun format(c: CredentialSummary): String = when (c.format) {
        "dc+sd-jwt" -> "SD-JWT VC"
        "mso_mdoc" -> "mdoc"
        else -> c.format
    }

    fun title(c: CredentialSummary): String = c.display?.name ?: c.vct ?: c.doctype ?: c.configurationID

    /** Why the credential can't be relied on, if it can't. */
    fun problem(c: CredentialSummary): String? = when {
        c.holderKeyPresent == false -> "Its key isn't on this device: it can't be presented"
        c.isExpired() -> "Expired"
        c.status?.value == CredentialStatus.Value.Revoked -> "Revoked by the issuer"
        c.status?.value == CredentialStatus.Value.Suspended -> "Suspended by the issuer"
        else -> null
    }

    /** How many fresh copies are left: each presentation uses one no Verifier has seen. */
    fun copies(c: CredentialSummary): String? = when {
        c.linkable -> "Copies have been shown to several verifiers: they could link these presentations"
        c.copiesLeft == 0 -> "Every copy has been shared: the next new verifier could link you with another"
        c.copies <= 1 -> null
        else -> "${c.copiesLeft} of ${c.copies} copies unused"
    }

    /** What a query asks beyond the Verifier's registration, in words. */
    fun overAsking(q: Presentation.Query): String =
        if (q.unregisteredAll) "Asks for every claim, beyond what it's registered for"
        else "Asks for more than it's registered for: " + q.unregistered.joinToString(", ") { Claims.path(it) }

    /** Whether disclosing [path], for [query], is beyond the Verifier's registration. */
    fun isUnregistered(path: List<PathElement>, query: String, p: Presentation): Boolean {
        val q = p.queries.firstOrNull { it.queryID == query } ?: return false
        return q.unregisteredAll || path in q.unregistered
    }

    /** The host of a URL, or the text itself. */
    fun host(url: String?): String = url?.let { runCatching { java.net.URI(it).host }.getOrNull() } ?: url.orEmpty()
}

/** A CSS hex colour (#rgb or #rrggbb), as issuers' display metadata gives them; null for anything else. */
fun cssColor(css: String?): Color? {
    var hex = css?.trim()?.takeIf { it.startsWith("#") }?.drop(1) ?: return null
    if (hex.length == 3) hex = hex.map { "$it$it" }.joinToString("")
    val v = hex.takeIf { it.length == 6 }?.toLongOrNull(16) ?: return null
    return Color(0xFF000000 or v)
}
