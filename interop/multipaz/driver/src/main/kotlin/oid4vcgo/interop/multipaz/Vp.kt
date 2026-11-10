package oid4vcgo.interop.multipaz

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.presentment.digitalCredentialsPresentment
import org.multipaz.presentment.uriSchemePresentment
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.util.toBase64Url
import org.multipaz.verification.JsonVerifiedPresentation
import org.multipaz.verification.MdocVerifiedPresentation
import org.multipaz.verification.VerificationSession
import org.multipaz.verification.VerificationUtil
import org.multipaz.verification.VerifiedPresentation
import org.multipaz.verification.VerifierIdentity
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.net.URLEncoder
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.time.Clock

private const val VP_ORIGIN = "https://verifier.interop.example"
private const val PID_VCT = "urn:eudi:pid:1"
private const val SD_JWT = "dc+sd-jwt"
private const val MSO_MDOC = "mso_mdoc"

/** The claims every OpenID4VP Verifier asks for, of the PID or the mDL. */
private val VP_CLAIMS = listOf("family_name", "given_name")

/**
 * OpenID4VP 1.0 between Multipaz and OID4VCgo: Multipaz's wallet
 * presenting to cmd/conformance-verifier, cross-device and over the
 * Digital Credentials API, and walletflow presenting to Multipaz's
 * Verifier (VerificationSession) the same two ways; SD-JWT VC PIDs and
 * mDLs, with controls.
 */
class VpCases(
    private val peer: Peer,
    private val pki: Pki,
    private val holder: Holder,
    private val issuerTrust: TrustManager,
    private val tls: Tls,
) : Checks() {
    suspend fun run(): Int {
        mpzWalletCases()
        goWalletCases()
        return failed
    }

    private suspend fun mpzWalletCases() {
        println("### OpenID4VP: Multipaz wallet → OID4VCgo's verifier (cmd/conformance-verifier)")
        for ((format, method) in listOf(SD_JWT to "get", MSO_MDOC to "post")) {
            check("$format, cross-device, request_uri_method $method: verified") {
                val outcome = mpzWalletCrossDevice(format, method)
                verified(outcome, format)
            }
        }
        for (format in listOf(SD_JWT, MSO_MDOC)) {
            check("$format, Digital Credentials API (openid4vp-v1-signed): verified") {
                verified(mpzWalletDCAPI(format), format)
            }
        }
        check("control: the verifier refuses a PID from an issuer it doesn't trust") {
            val outcome = mpzWalletCrossDevice(SD_JWT, "get", trust = "other")
            refusal(outcome["error"]?.jsonPrimitive?.content, outcome.toString(), "trusted root")
        }

    }

    private suspend fun goWalletCases() {
        println("### OpenID4VP: OID4VCgo's wallet (walletflow) → Multipaz verifier (VerificationSession)")
        Verifier(tls, pki).use { verifier ->
            for (format in listOf(SD_JWT, MSO_MDOC)) {
                check("$format, cross-device, signed x509_hash request, direct_post.jwt: Multipaz verified it") {
                    val (answer, result) = verifier.ask(peer, format, "mpz")
                    answer.error ?: checkPresentation(result.get(30, TimeUnit.SECONDS), format)
                }
            }
            check("control: the wallet refuses a Verifier under a CA it doesn't trust") {
                refusal(verifier.ask(peer, SD_JWT, "other").first, "untrusted verifier")
            }
            check("control: the wallet refuses an x509_hash client_id naming another certificate than the request's") {
                refusal(verifier.ask(peer, SD_JWT, "mpz", clientIdOf = pki.otherReader).first, "x509_hash")
            }
        }
        for (format in listOf(SD_JWT, MSO_MDOC)) {
            check("$format, Digital Credentials API (openid4vp-v1-signed): Multipaz verified it") {
                goWalletDCAPI(format)
            }
        }
    }

    /** null if [outcome], cmd/conformance-verifier's, verified [format]'s claims, or why not. */
    private fun verified(outcome: JsonObject, format: String): String? {
        if (outcome["status"]?.jsonPrimitive?.content != "verified") return "the verifier said $outcome"
        val credential = outcome["credentials"]!!.jsonObject.values.single().jsonObject
        // An mdoc's claims are by namespace.
        val claims = if (format == MSO_MDOC) credential[DrivingLicense.MDL_NAMESPACE]!!.jsonObject.keys else credential.keys
        val want = if (format == MSO_MDOC) REQUESTED_MDOC else VP_CLAIMS.toSet()
        return if (claims.containsAll(want)) null else "verified only $claims"
    }

    /**
     * Multipaz's wallet answers cmd/conformance-verifier's cross-device
     * request (its openid4vp: link), and the verifier's outcome is
     * redeemed with the response_code it returned.
     */
    private suspend fun mpzWalletCrossDevice(format: String, method: String, trust: String = "mpz"): JsonObject {
        val base = startVerifier(format, trust)
        val link = tls.get("$base/authorize?request_uri_method=$method").headers().firstValue("Location").orElseThrow()
        val redirect = uriSchemePresentment(
            source = holder.source(mac = false),
            uri = link,
            appId = null,
            origin = null,
            httpClientEngineFactory = tls.ktor,
        ) ?: error("the verifier returned no redirect_uri")
        val redeemed = tls.get(redirect.replace("?response_code=", "/redeem?response_code="))
        return Json.parseToJsonElement(redeemed.body()).jsonObject
    }

    /** Multipaz's wallet answers cmd/conformance-verifier's DC API request. */
    private suspend fun mpzWalletDCAPI(format: String): JsonObject {
        val base = startVerifier(format, "mpz")
        val request = Json.parseToJsonElement(
            tls.post("$base/dcapi/request?origin=" + URLEncoder.encode(VP_ORIGIN, Charsets.UTF_8), "{}").body()
        ).jsonObject
        val answer = digitalCredentialsPresentment(
            protocol = request["protocol"]!!.jsonPrimitive.content,
            data = request["data"]!!.jsonObject,
            appId = null,
            origin = VP_ORIGIN,
            preselectedDocuments = emptyList(),
            source = holder.source(mac = false),
        )
        val id = request["id"]!!.jsonPrimitive.content
        return Json.parseToJsonElement(tls.post("$base/dcapi/response/$id", answer["data"]!!.toString()).body()).jsonObject
    }

    private fun startVerifier(format: String, trust: String): String {
        val started = peer.call("verifier_start", "format" to format, "trust" to trust, "origin" to VP_ORIGIN)
        started.error?.let { error("verifier_start: $it") }
        return started.string("base_url")!!
    }

    /** walletflow answers Multipaz's Verifier over the DC API. */
    private suspend fun goWalletDCAPI(format: String): String? {
        val session = VerificationUtil.generateVerificationSessionForDcql(
            requestTypes = listOf(VerificationSession.RequestType.DC_OPENID4VP),
            dcql = dcql(format),
            verifierIdentities = listOf(identity(pki)),
            origin = VP_ORIGIN,
        )
        val request = session.getDcRequest()["requests"]!!.jsonArray.single().jsonObject
        val protocol = request["protocol"]!!.jsonPrimitive.content
        val answer = peer.call(
            "wallet_dcapi", "protocol" to protocol, "data" to request["data"].toString(),
            "origin" to VP_ORIGIN, "verifier_ca" to "mpz",
        )
        answer.error?.let { return "the wallet: $it" }
        val record = session.processDcResponse(buildJsonObject {
            put("protocol", JsonPrimitive(protocol))
            put("data", Json.parseToJsonElement(answer.string("data")!!))
        })
        return checkPresentation(record.verify(Clock.System.now(), null, null), format)
    }

    /** null if [presentations] are one [format] credential with the claims asked for, under OID4VCgo's IACA. */
    private suspend fun checkPresentation(presentations: List<VerifiedPresentation>, format: String): String? {
        val presentation = presentations.singleOrNull() ?: return "${presentations.size} presentations"
        val claims = when (presentation) {
            is JsonVerifiedPresentation -> presentation.issuerSignedClaims.map { it.claimPath.last().jsonPrimitive.content }
            is MdocVerifiedPresentation -> presentation.issuerSignedClaims.map { it.dataElementName }
        }.toSet()
        return when {
            !claims.containsAll(VP_CLAIMS) -> "verified only $claims"
            format == SD_JWT && "birthdate" in claims -> "birthdate disclosed, which wasn't asked for"
            !issuerTrust.verify(presentation.documentSignerCertChain!!.certificates).isTrusted ->
                "the issuer's chain doesn't reach OID4VCgo's IACA"
            else -> null
        }
    }
}

/** The mDL elements the cmd/conformance-verifier asks for. */
private val REQUESTED_MDOC = setOf("family_name", "given_name", "age_over_18")

/** A DCQL query for [format]'s [VP_CLAIMS]. */
private fun dcql(format: String): String {
    val credential = if (format == MSO_MDOC) {
        """{"id": "mdl", "format": "$MSO_MDOC", "meta": {"doctype_value": "${DrivingLicense.MDL_DOCTYPE}"},
           "claims": [${VP_CLAIMS.joinToString { """{"path": ["${DrivingLicense.MDL_NAMESPACE}", "$it"]}""" }}]}"""
    } else {
        """{"id": "pid", "format": "$SD_JWT", "meta": {"vct_values": ["$PID_VCT"]},
           "claims": [${VP_CLAIMS.joinToString { """{"path": ["$it"]}""" }}]}"""
    }
    return """{"credentials": [$credential]}"""
}

/**
 * Multipaz's reader certificate as an x509_hash Verifier, its client_id
 * the hash of [clientIdOf]'s certificate: the reader's own, unless a
 * control names another.
 */
private suspend fun identity(pki: Pki, clientIdOf: AsymmetricKey.X509Certified = pki.reader): VerifierIdentity {
    val leaf = clientIdOf.certChain.certificates.first()
    return VerifierIdentity(pki.reader, "x509_hash:" + Crypto.digest(Algorithm.SHA256, leaf.encoded.toByteArray()).toBase64Url())
}

/**
 * Multipaz's cross-device Verifier: a VerificationSession, served over
 * HTTPS on loopback (the request object at /request, the response at
 * /response), with the peer's TLS certificate for localhost.
 */
private class Verifier(tls: Tls, private val pki: Pki) : AutoCloseable {
    private val server = HttpsServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
        httpsConfigurator = HttpsConfigurator(tls.server)
    }
    private val base = "https://localhost:${server.address.port}"
    private var session: VerificationSession? = null
    private var result = CompletableFuture<List<VerifiedPresentation>>()

    init {
        server.createContext("/request") { exchange -> exchange.use { serveRequest(it) } }
        server.createContext("/response") { exchange -> exchange.use { serveResponse(it) } }
        server.start()
    }

    /**
     * Has walletflow (the peer, trusting Verifiers under [verifierCA])
     * answer a new request for [format], its client_id naming
     * [clientIdOf]'s certificate; the result is Multipaz's verification
     * of the response, once it arrives.
     */
    suspend fun ask(
        peer: Peer,
        format: String,
        verifierCA: String,
        clientIdOf: AsymmetricKey.X509Certified = pki.reader,
    ): Pair<Reply, CompletableFuture<List<VerifiedPresentation>>> {
        val identity = identity(pki, clientIdOf)
        result = CompletableFuture()
        session = VerificationUtil.generateVerificationSessionForDcql(
            requestTypes = listOf(VerificationSession.RequestType.OPENID4VP_URI_SCHEME),
            dcql = dcql(format),
            verifierIdentities = listOf(identity),
            origin = base,
            responseUri = "$base/response",
        )
        val link = "openid4vp://?client_id=" + URLEncoder.encode(identity.clientId, Charsets.UTF_8) +
            "&request_uri=" + URLEncoder.encode("$base/request", Charsets.UTF_8)
        return peer.call("wallet_present", "request" to link, "verifier_ca" to verifierCA) to result
    }

    private fun serveRequest(exchange: HttpExchange) {
        val request = session!!.find<VerificationSession.OpenID4VPUriSchemeRequest>().openID4VPRequest
        val jwt = Json.parseToJsonElement(request).jsonObject["request"]!!.jsonPrimitive.content
        exchange.responseHeaders.add("Content-Type", "application/oauth-authz-req+jwt")
        val body = jwt.toByteArray()
        exchange.sendResponseHeaders(200, body.size.toLong())
        exchange.responseBody.write(body)
    }

    private fun serveResponse(exchange: HttpExchange) {
        val form = exchange.requestBody.readAllBytes().decodeToString().split("&").associate {
            val (name, value) = it.split("=", limit = 2)
            URLDecoder.decode(name, Charsets.UTF_8) to URLDecoder.decode(value, Charsets.UTF_8)
        }
        try {
            val presentations = runBlocking {
                session!!.processOpenID4VPUriSchemeResponse(form).verify(Clock.System.now(), null, null)
            }
            result.complete(presentations)
        } catch (e: Exception) {
            result.completeExceptionally(e)
        }
        val body = "{}".toByteArray()
        exchange.responseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(200, body.size.toLong())
        exchange.responseBody.write(body)
    }

    override fun close() = server.stop(0)
}
