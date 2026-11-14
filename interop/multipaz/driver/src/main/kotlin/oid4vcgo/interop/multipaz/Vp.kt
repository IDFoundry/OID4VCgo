package oid4vcgo.interop.multipaz

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpTimeout
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
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.JsonWebSignature
import org.multipaz.crypto.X509Cert
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.presentment.digitalCredentialsPresentment
import org.multipaz.presentment.uriSchemePresentment
import org.multipaz.revocation.CachingRevocationChecker
import org.multipaz.revocation.RevocationCheckState
import org.multipaz.revocation.RevocationStatus
import org.multipaz.storage.ephemeral.EphemeralStorage
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
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import kotlin.time.Clock

private const val VP_ORIGIN = "https://verifier.interop.example"
private const val PID_VCT = "urn:eudi:pid:1"
private const val SD_JWT = "dc+sd-jwt"
private const val MSO_MDOC = "mso_mdoc"

/** Why Multipaz's Verifier refuses a Key Binding JWT with another nonce. */
private const val KB_NONCE_REFUSED = "IllegalStateException: Failed verification of nonce"

/** Why Multipaz's Verifier refuses an mdoc DeviceSignature over another session transcript. */
private const val DEVICE_SIGNATURE_REFUSED = "IllegalStateException: Device authentication signature failed to verify"

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
    private val issuerRoot: X509Cert,
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
                var answer: Reply? = null
                check("$format, cross-device, signed x509_hash request, direct_post.jwt: Multipaz verified it") {
                    val (a, result) = verifier.ask(peer, format, "mpz")
                    answer = a
                    a.error ?: checkPresentation(result.get(30, TimeUnit.SECONDS), format)
                }
                check("observed: $format, cross-device, the Verifier's response encryption key is as Multipaz sends it today") {
                    observed("client_metadata.jwks", answer?.observed?.get("verifier_jwks"), Observed.VERIFIER_JWKS)
                }
            }
            check("control: the wallet refuses a Verifier under a CA it doesn't trust") {
                refusal(verifier.ask(peer, SD_JWT, "other").first, "untrusted verifier")
            }
            check("control: the wallet refuses an x509_hash client_id naming another certificate than the request's") {
                refusal(verifier.ask(peer, SD_JWT, "mpz", clientIdOf = pki.otherReader).first, "x509_hash")
            }
            // Negative presentations: walletflow answers the session's
            // request changed in one claim and signed again, and
            // Multipaz's Verifier checks the response against its
            // session, as it would a presentation made for another
            // request. The cases above, which pass, differ in that
            // claim alone.
            check("control: Multipaz's Verifier refuses an SD-JWT VC whose Key Binding JWT names another nonce") {
                val (a, result) = verifier.ask(peer, SD_JWT, "mpz", served = Served(pki.reader, ::otherNonce))
                a.error?.let { return@check "the wallet: $it" }
                refusal(verifierError(result), "verified", KB_NONCE_REFUSED)
            }
            check("control: Multipaz's Verifier refuses an mdoc whose DeviceSignature is over another session transcript (another nonce)") {
                val (a, result) = verifier.ask(peer, MSO_MDOC, "mpz", served = Served(pki.reader, ::otherNonce))
                a.error?.let { return@check "the wallet: $it" }
                refusal(verifierError(result), "verified", DEVICE_SIGNATURE_REFUSED)
            }
            // README finding 2: the Key Binding JWT's aud isn't checked.
            // The request names another Verifier the wallet trusts, under
            // the same root, which signs it, so the KB-JWT's aud is that
            // Verifier's client_id; noted while Multipaz accepts it, and
            // failed once it doesn't, so the finding is revisited.
            known("Multipaz's Verifier accepts an SD-JWT VC whose Key Binding JWT names another Verifier as aud (README finding 2)") {
                val siblingId = x509Hash(pki.sibling)
                val served = Served(pki.sibling) { claims -> JsonObject(claims + ("client_id" to JsonPrimitive(siblingId))) }
                val (a, result) = verifier.ask(peer, SD_JWT, "mpz", served = served)
                a.error?.let { return@known "the wallet: $it" }
                verifierError(result)?.let {
                    return@known "Multipaz's Verifier now refuses it ($it): README finding 2 has changed; make this a control"
                }
                checkPresentation(result.get(), SD_JWT)?.let { return@known it }
                reason = "verified, the KB-JWT's aud $siblingId, the session's client_id ${x509Hash(pki.reader)}"
                null
            }
            // Status: Multipaz's Verifier hands its app each verified
            // presentation's status list reference
            // (VerifiedPresentation.revocationStatus) and leaves checking
            // it to the app, which does so with Multipaz's
            // RevocationChecker: it fetches the list, which OID4VCgo's
            // statuslist publishes (the peer's status.go), verifies its
            // signature under OID4VCgo's IACA, and reads the entry. The
            // issuer then revokes the credential (the peer's status_set,
            // statuslist.Allocator.SetStatus), and walletflow presents it
            // again: the control differs from the case before it in that
            // status alone. The credential is made valid again after, for
            // the cases that follow.
            for (format in listOf(SD_JWT, MSO_MDOC)) {
                check("$format: Multipaz's RevocationChecker reads its Token Status List entry, as OID4VCgo's issuer publishes it, VALID") {
                    val (a, result) = verifier.ask(peer, format, "mpz")
                    a.error ?: revocation(result.get(30, TimeUnit.SECONDS), RevocationCheckState.VALID)
                }
                check("control: $format revoked by its issuer after the presentation above: Multipaz's RevocationChecker reads it INVALID") {
                    peer.call("status_set", "format" to format, "status" to "INVALID").error?.let { return@check "status_set: $it" }
                    try {
                        val (a, result) = verifier.ask(peer, format, "mpz")
                        a.error ?: revocation(result.get(30, TimeUnit.SECONDS), RevocationCheckState.INVALID)
                    } finally {
                        peer.call("status_set", "format" to format, "status" to "VALID")
                    }
                }
            }
        }
        for (format in listOf(SD_JWT, MSO_MDOC)) {
            var answer: Reply? = null
            check("$format, Digital Credentials API (openid4vp-v1-signed): Multipaz verified it") {
                goWalletDCAPI(format) { answer = it }
            }
            check("observed: $format, Digital Credentials API, the Verifier's response encryption key is as Multipaz sends it today") {
                observed("client_metadata.jwks", answer?.observed?.get("verifier_jwks"), Observed.VERIFIER_JWKS_DCAPI)
            }
        }
    }

    /**
     * null if Multipaz's RevocationChecker, given [presentations]' one
     * revocation status and OID4VCgo's IACA, reads [want] from a list
     * whose signature it verified, or why not. It fetches the list
     * afresh (bypassCache), as a Verifier checking a presentation now
     * would once its cache had expired.
     */
    private suspend fun revocation(presentations: List<VerifiedPresentation>, want: RevocationCheckState): String? {
        val presentation = presentations.singleOrNull() ?: return "${presentations.size} presentations"
        val status = presentation.revocationStatus as? RevocationStatus.StatusList
            ?: return "Multipaz found no status list reference: ${presentation.revocationStatus}"
        val result = HttpClient(tls.ktor) { install(HttpTimeout) }.use { client ->
            CachingRevocationChecker(EphemeralStorage(), client)
                .check(status, issuerCert = issuerRoot, onlyTrusted = true, bypassCache = true)
        }
        reason = "${status.uri.substringAfter("/statuslists/")} index ${status.idx}: ${result.state}, its signature verified"
        return when {
            result.state != want ->
                "Multipaz read ${result.state} (signature verified: ${result.isTrusted}${result.error?.let { "; $it" } ?: ""}), want $want"
            !result.isTrusted -> "Multipaz read ${result.state} without verifying the list's signature"
            else -> null
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

    /** walletflow answers Multipaz's Verifier over the DC API, handing [answered] the peer's answer. */
    private suspend fun goWalletDCAPI(format: String, answered: (Reply) -> Unit): String? {
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
        answered(answer)
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
private suspend fun identity(pki: Pki, clientIdOf: AsymmetricKey.X509Certified = pki.reader): VerifierIdentity =
    VerifierIdentity(pki.reader, x509Hash(clientIdOf))

/** The x509_hash client_id of [key]'s certificate. */
private suspend fun x509Hash(key: AsymmetricKey.X509Certified): String =
    "x509_hash:" + Crypto.digest(Algorithm.SHA256, key.certChain.certificates.first().encoded.toByteArray()).toBase64Url()

/** Why Multipaz's Verifier refused the response, as "Exception: message", or null if it verified it. */
private fun verifierError(result: CompletableFuture<List<VerifiedPresentation>>): String? =
    try {
        result.get(30, TimeUnit.SECONDS)
        null
    } catch (e: ExecutionException) {
        val cause = e.cause ?: e
        "${cause::class.simpleName}: ${cause.message}"
    }

/** A request's claims with another nonce. */
private fun otherNonce(claims: JsonObject) = JsonObject(claims + ("nonce" to JsonPrimitive("not-" + claims["nonce"]!!.jsonPrimitive.content)))

/** How the request a control serves differs from its session's: its claims changed by [change], signed by [signer]. */
private class Served(val signer: AsymmetricKey.X509CertifiedExplicit, val change: (JsonObject) -> JsonObject)

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
    private var requestJwt = ""
    private var result = CompletableFuture<List<VerifiedPresentation>>()

    init {
        server.createContext("/request") { exchange -> exchange.use { serveRequest(it) } }
        server.createContext("/response") { exchange -> exchange.use { serveResponse(it) } }
        server.start()
    }

    /**
     * Has walletflow (the peer, trusting Verifiers under [verifierCA])
     * answer a new request for [format], its client_id naming
     * [clientIdOf]'s certificate, or, if [served], the session's request
     * changed and signed as it says; the result is Multipaz's
     * verification of the response, once it arrives.
     */
    suspend fun ask(
        peer: Peer,
        format: String,
        verifierCA: String,
        clientIdOf: AsymmetricKey.X509Certified = pki.reader,
        served: Served? = null,
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
        val original = Json.parseToJsonElement(
            session!!.find<VerificationSession.OpenID4VPUriSchemeRequest>().openID4VPRequest,
        ).jsonObject["request"]!!.jsonPrimitive.content
        requestJwt = served?.let {
            val info = JsonWebSignature.getInfo(original)
            JsonWebSignature.sign(it.signer.privateKey as EcPrivateKey, Algorithm.ESP256, it.change(info.claimsSet), info.type, it.signer.certChain)
        } ?: original
        val clientId = JsonWebSignature.getInfo(requestJwt).claimsSet["client_id"]!!.jsonPrimitive.content
        val link = "openid4vp://?client_id=" + URLEncoder.encode(clientId, Charsets.UTF_8) +
            "&request_uri=" + URLEncoder.encode("$base/request", Charsets.UTF_8)
        return peer.call("wallet_present", "request" to link, "verifier_ca" to verifierCA) to result
    }

    private fun serveRequest(exchange: HttpExchange) {
        val jwt = requestJwt
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
