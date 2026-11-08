package dev.idfoundry.interop.eudi

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.openid4vp.Consensus
import eu.europa.ec.eudi.openid4vp.CoseAlgorithm
import eu.europa.ec.eudi.openid4vp.DispatchOutcome
import eu.europa.ec.eudi.openid4vp.EncryptionParameters
import eu.europa.ec.eudi.openid4vp.OpenId4VPConfig
import eu.europa.ec.eudi.openid4vp.OpenId4Vp
import eu.europa.ec.eudi.openid4vp.Resolution
import eu.europa.ec.eudi.openid4vp.ResolvedRequestObject
import eu.europa.ec.eudi.openid4vp.ResponseEncryptionConfiguration
import eu.europa.ec.eudi.openid4vp.ResponseMode
import eu.europa.ec.eudi.openid4vp.SignedRequestConfiguration
import eu.europa.ec.eudi.openid4vp.SupportedClientIdPrefix
import eu.europa.ec.eudi.openid4vp.SupportedRequestUriMethods
import eu.europa.ec.eudi.openid4vp.VerifiablePresentation
import eu.europa.ec.eudi.openid4vp.VerifiablePresentations
import eu.europa.ec.eudi.openid4vp.VpFormatsSupported
import eu.europa.ec.eudi.openid4vp.dcql.DCQL
import io.ktor.client.HttpClient
import io.ktor.client.engine.java.Java
import io.ktor.client.plugins.HttpSend
import io.ktor.client.plugins.plugin
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.content.OutgoingContent
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.File
import java.security.SecureRandom

/** The wallet's OpenID4VP configuration, shared by both flows. */
private fun walletConfig(opts: Options): OpenId4VPConfig {
    val verifierAnchors = parseCertificates(File(opts.required("verifier-ca")).readText())
    val requestUriMethods =
        when (val m = opts.optional("request-uri-methods", "both")) {
            "both" -> SupportedRequestUriMethods.Default
            "get" -> SupportedRequestUriMethods.Get
            "post" -> SupportedRequestUriMethods.Post()
            else -> error("unknown --request-uri-methods $m")
        }
    val encryptionMethods = opts.optional("enc", "A128GCM,A256GCM").split(",").map(EncryptionMethod::parse)
    return OpenId4VPConfig(
        supportedClientIdPrefixes = listOf(SupportedClientIdPrefix.X509Hash { chain -> chainsTo(chain, verifierAnchors) }),
        vpFormatsSupported =
            VpFormatsSupported(
                sdJwtVc = VpFormatsSupported.SdJwtVc(listOf(JWSAlgorithm.ES256), listOf(JWSAlgorithm.ES256)),
                msoMdoc = VpFormatsSupported.MsoMdoc(listOf(CoseAlgorithm(-7)), listOf(CoseAlgorithm(-7))),
            ),
        responseEncryptionConfiguration = ResponseEncryptionConfiguration.Supported(listOf(JWEAlgorithm.ECDH_ES), encryptionMethods),
        signedRequestConfiguration =
            SignedRequestConfiguration(
                supportedAlgorithms = listOf(JWSAlgorithm.ES256),
                supportedRequestUriMethods = requestUriMethods,
            ),
    )
}

/** A fresh apu: the wallet's ECDH-ES PartyUInfo. */
private fun encryptionParameters(): EncryptionParameters =
    EncryptionParameters.DiffieHellman(Base64URL.encode(ByteArray(16).also { SecureRandom().nextBytes(it) }))

/**
 * The vp_token for [request]'s one Credential Query, built as a wallet
 * built on openid4vp-kt builds it: the library leaves it to the caller.
 * [audience] is what the presentation is bound to: the Client
 * Identifier, or over the Digital Credentials API the origin (Appendix
 * A.4: origin:<origin> as a Key Binding JWT's aud, the bare origin in
 * an mdoc SessionTranscript). [otherAudience] is the plausible wrong
 * one [Variant.WRONG_AUDIENCE] binds to instead. [transcript] builds
 * the mdoc SessionTranscript for a nonce and audience.
 */
private suspend fun presentations(
    request: ResolvedRequestObject,
    opts: Options,
    audience: String,
    otherAudience: String,
    transcript: suspend (nonce: String, audience: String) -> org.multipaz.cbor.DataItem,
): VerifiablePresentations {
    val variant = Variant.of(opts.optional("variant", "ok"))
    val wallet = WalletFile(opts.required("wallet"))
    val holder = parseKeyPair(wallet.string("holder_private_key_pem"))
    val nonce = if (variant == Variant.WRONG_NONCE) "not-the-request-nonce" else request.nonce
    val boundTo = if (variant == Variant.WRONG_AUDIENCE) otherAudience else audience
    val query = Json.encodeToJsonElement(DCQL.serializer(), request.query).jsonObject
    val credentialQuery = query.getValue("credentials").jsonArray.single().jsonObject
    val id = credentialQuery.getValue("id").jsonPrimitive.content
    val paths = credentialQuery.getValue("claims").jsonArray.map { c -> c.jsonObject.getValue("path").jsonArray.map { it.jsonPrimitive.content } }
    val presentation =
        when (val format = credentialQuery.getValue("format").jsonPrimitive.content) {
            "dc+sd-jwt" -> {
                val aud = if (request.responseMode is ResponseMode.DCApiJwt || request.responseMode is ResponseMode.DCApi) "origin:$boundTo" else boundTo
                sdJwtVcPresentation(wallet, variant, holder, paths.map { it.single() }, nonce, aud)
            }

            "mso_mdoc" -> {
                val docType = credentialQuery.getValue("meta").jsonObject.getValue("doctype_value").jsonPrimitive.content
                val namespace = paths.map { it.first() }.distinct().single()
                mdocPresentation(wallet, variant, holder, docType, namespace, paths.map { it[1] }, transcript(nonce, boundTo))
            }

            else -> {
                error("unsupported format $format")
            }
        }
    return VerifiablePresentations(mapOf(eu.europa.ec.eudi.openid4vp.dcql.QueryId(id) to listOf(VerifiablePresentation.Generic(presentation))))
}

private fun ResolvedRequestObject.jwkThumbprint(): ByteArray? = responseEncryptionSpecification?.recipientKey?.computeThumbprint()?.decode()

private fun ResolvedRequestObject.describe(): JsonObject =
    buildJsonObject {
        put("resolved", true)
        put("client_id", client.id.clientId)
        put("response_mode", responseMode.toString())
        put("encryption", responseEncryptionSpecification?.let { "${it.encryptionAlgorithm}/${it.encryptionMethod}" } ?: "none")
    }

/** Answers a request by reference: an openid4vp:// URI (--uri). */
class Redirect(
    private val opts: Options,
) {
    /** Every POST body the wallet sent, by URL, to replay one. */
    private val posted = mutableListOf<Pair<String, ByteArray>>()

    private val http =
        HttpClient(Java) {
            engine { config { sslContext(sslContextTrusting(parseCertificates(File(opts.required("tls-ca")).readText()))) } }
        }.also { client ->
            client.plugin(HttpSend).intercept { request ->
                val body = request.body
                if (request.method == HttpMethod.Post && body is OutgoingContent.ByteArrayContent) {
                    posted += request.url.buildString() to body.bytes()
                }
                execute(request)
            }
        }

    suspend fun run(): JsonObject {
        val variant = Variant.of(opts.optional("variant", "ok"))
        val openId4Vp = OpenId4Vp.overRedirects(walletConfig(opts), http)
        val request =
            // 0.17.0 throws, rather than returning Resolution.Invalid,
            // for a request_uri that isn't https (see README.md).
            when (
                val resolution =
                    runCatching { openId4Vp.resolveRequestUri(opts.required("uri")) }
                        .getOrElse { return failed("resolve", "threw ${it::class.simpleName}: ${it.message}") }
            ) {
                is Resolution.Invalid -> return failed("resolve", resolution.error)
                is Resolution.Success -> resolution.requestObject
            }
        val responseUri =
            when (val mode = request.responseMode) {
                is ResponseMode.DirectPostJwt -> mode.responseURI.toString()
                is ResponseMode.DirectPost -> mode.responseURI.toString()
                else -> return failed("dispatch", "unexpected response mode $mode")
            }
        val clientId = request.client.id.clientId
        val consensus =
            if (variant == Variant.DECLINE) {
                Consensus.NegativeConsensus
            } else {
                Consensus.PositiveConsensus(
                    presentations(request, opts, clientId, "x509_hash:not-this-verifier") { nonce, cid ->
                        sessionTranscript(cid, nonce, request.jwkThumbprint(), responseUri)
                    },
                )
            }
        val outcome = openId4Vp.dispatch(request, consensus, encryptionParameters())
        return buildJsonObject {
            request.describe().forEach { (k, v) -> put(k, v) }
            when (outcome) {
                is DispatchOutcome.VerifierResponse.Accepted -> {
                    put("dispatch", "accepted")
                    put("redirect_uri", outcome.redirectURI?.toString())
                }

                is DispatchOutcome.VerifierResponse.Rejected -> {
                    put("dispatch", "rejected")
                    put("redirect_uri", outcome.redirectURI?.toString())
                }

                is DispatchOutcome.RedirectURI -> {
                    put("dispatch", "redirect")
                }
            }
            if (variant == Variant.REPLAY) {
                val (url, body) = posted.last { it.first == responseUri }
                val replay =
                    http.post(url) {
                        contentType(ContentType.Application.FormUrlEncoded)
                        setBody(body)
                    }
                put("replay_status", replay.status.value)
            }
        }
    }
}

/**
 * Answers a Digital Credentials API request: --request is the JSON a
 * page would pass to navigator.credentials.get (protocol and data),
 * --origin the origin the platform reports. The answer (the data the
 * platform returns to the page) is in the outcome's "response".
 */
class DcApi(
    private val opts: Options,
) {
    suspend fun run(): JsonObject {
        val variant = Variant.of(opts.optional("variant", "ok"))
        val dcRequest = Json.parseToJsonElement(File(opts.required("request")).readText()).jsonObject
        val protocol = opts.optional("protocol", dcRequest.getValue("protocol").jsonPrimitive.content)
        val origin = opts.required("origin")
        val openId4Vp = OpenId4Vp.overDcApi(walletConfig(opts))
        val request =
            when (val resolution = openId4Vp.resolveRequestObject(protocol, origin, dcRequest.getValue("data").jsonObject)) {
                is Resolution.Invalid -> return failed("resolve", resolution.error)
                is Resolution.Success -> resolution.requestObject
            }
        val consensus =
            if (variant == Variant.DECLINE) {
                Consensus.NegativeConsensus
            } else {
                // The plausible mistake over the Digital Credentials API:
                // binding to the Client Identifier, as over redirects.
                Consensus.PositiveConsensus(
                    presentations(request, opts, origin, request.client.id.clientId) { nonce, o ->
                        sessionTranscript(o, nonce, request.jwkThumbprint(), null)
                    },
                )
            }
        val response = openId4Vp.assembleResponse(request, consensus, encryptionParameters())
        return buildJsonObject {
            request.describe().forEach { (k, v) -> put(k, v) }
            put("response", response)
        }
    }
}
