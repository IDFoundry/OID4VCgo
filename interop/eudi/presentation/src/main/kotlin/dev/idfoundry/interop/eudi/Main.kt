// The wallet side of interop/eudi/run-wallet.sh. It answers one
// OpenID4VP request from OID4VCgo's cmd/conformance-verifier and exits:
// eudi-lib-jvm-openid4vp-kt resolves and validates the request and
// sends (or, over the Digital Credentials API, assembles) the response;
// the vp_token in it is built here, an SD-JWT VC with
// eudi-lib-jvm-sdjwt-kt or an mdoc DeviceResponse with Multipaz, from a
// credential issued here for the run with interop/eudi/scripts/setup's
// throwaway issuer keys.
//
//   redirect --uri URI ...   answer a request by reference (openid4vp://)
//   dcapi --request FILE ... answer a Digital Credentials API request
//
// The outcome is written as JSON to --out. A --variant other than "ok"
// makes the vp_token, or the response, one the verifier must refuse.
package dev.idfoundry.interop.eudi

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    if (args.isEmpty()) usage()
    val opts = Options.parse(args.drop(1))
    Security.addProvider(BouncyCastleProvider())
    val outcome =
        runBlocking {
            when (args[0]) {
                "redirect" -> Redirect(opts).run()
                "dcapi" -> DcApi(opts).run()
                else -> usage()
            }
        }
    File(opts.required("out")).writeText(Json.encodeToString(JsonObject.serializer(), outcome))
    System.err.println(outcome)
}

private fun usage(): Nothing {
    System.err.println("usage: driver redirect|dcapi --out FILE [--key value]...; see Main.kt")
    exitProcess(2)
}

/** --key value command-line options. */
class Options(
    private val values: Map<String, String>,
) {
    fun required(key: String): String = values[key] ?: run {
        System.err.println("--$key is required")
        exitProcess(2)
    }

    fun optional(
        key: String,
        default: String,
    ): String = values[key] ?: default

    companion object {
        fun parse(args: List<String>): Options {
            require(args.size % 2 == 0) { "options come in --key value pairs" }
            return Options(
                args.chunked(2).associate { (k, v) ->
                    require(k.startsWith("--")) { "expected an option, got $k" }
                    k.removePrefix("--") to v
                },
            )
        }
    }
}

/** What --variant makes the wallet do wrong, if anything. */
enum class Variant(
    val arg: String,
) {
    /** A presentation the verifier must accept. */
    OK("ok"),

    /** A credential whose status list entry is invalid (index 1). */
    REVOKED("revoked"),

    /** A credential issued under a CA the verifier doesn't trust. */
    UNTRUSTED_ISSUER("untrusted-issuer"),

    /** Holder binding to another nonce: the KB-JWT's, or the mdoc SessionTranscript's. */
    WRONG_NONCE("wrong-nonce"),

    /** Holder binding to another audience: the KB-JWT's aud, or the SessionTranscript's client_id or origin. */
    WRONG_AUDIENCE("wrong-audience"),

    /** An SD-JWT VC presented without its Key Binding JWT. */
    NO_KEY_BINDING("no-key-binding"),

    /** A claim disclosed that the query didn't ask for. */
    EXTRA_CLAIM("extra-claim"),

    /** The same response posted again after it was answered. */
    REPLAY("replay"),

    /** The holder declines: the wallet answers access_denied. */
    DECLINE("decline"),
    ;

    companion object {
        fun of(arg: String): Variant = entries.firstOrNull { it.arg == arg } ?: error("unknown --variant $arg")
    }
}

/** setup's wallet config: the credential's keys, claims and status list. */
class WalletFile(
    path: String,
) {
    private val json: JsonObject = Json.parseToJsonElement(File(path).readText()).jsonObject

    fun string(key: String): String = json[key]?.jsonPrimitive?.content ?: error("$key missing from the wallet config")

    fun obj(key: String): JsonObject = json[key]?.jsonObject ?: error("$key missing from the wallet config")

    val isMdoc: Boolean get() = json["credential_format"]?.jsonPrimitive?.content == "mso_mdoc"
}

fun failed(
    stage: String,
    error: Any?,
): JsonObject =
    buildJsonObject {
        put("resolved", stage != "resolve")
        put("stage", stage)
        put("error", error.toString())
    }
