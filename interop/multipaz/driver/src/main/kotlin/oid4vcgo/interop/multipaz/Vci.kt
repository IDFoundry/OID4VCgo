package oid4vcgo.interop.multipaz

import io.ktor.client.HttpClient
import io.ktor.client.plugins.HttpResponseValidator
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import org.multipaz.asn1.OID
import org.multipaz.cbor.Cbor
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.cose.CoseSign1
import org.multipaz.cose.Cose
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.openid4vci.credential.CredentialFactoryMdl
import org.multipaz.openid4vci.credential.CredentialFactoryMdocPid
import org.multipaz.openid4vci.credential.CredentialFactoryRegistry
import org.multipaz.openid4vci.credential.CredentialFactorySdjwtPid
import org.multipaz.openid4vci.server.configureRouting
import org.multipaz.provisioning.AuthorizationChallenge
import org.multipaz.provisioning.AuthorizationResponse
import org.multipaz.provisioning.CredentialKeyAttestation
import org.multipaz.provisioning.KeyBindingInfo
import org.multipaz.provisioning.openid4vci.OpenID4VCI
import org.multipaz.provisioning.openid4vci.OpenID4VCIBackend
import org.multipaz.provisioning.openid4vci.OpenID4VCIClientPreferences
import org.multipaz.provisioning.openid4vci.OpenID4VCILocalBackend
import org.multipaz.rpc.backend.BackendEnvironment
import org.multipaz.sdjwt.SdJwt
import org.multipaz.securearea.KeyAttestation
import org.multipaz.webtoken.buildJwt
import kotlin.time.Duration.Companion.hours
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.SecureAreaProvider
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.server.common.ServerConfiguration
import org.multipaz.server.common.ServerEnvironment
import org.multipaz.server.common.installServerEnvironment
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.util.toBase64
import java.io.File
import java.net.ServerSocket
import kotlin.reflect.KClass
import kotlin.reflect.cast

/** The peer's attester files for Multipaz's wallet: trusted, and not. */
private const val ATTESTER = "mpz-attester"
private const val UNTRUSTED_ATTESTER = "mpz-other-attester"

/** What a control that wasn't refused did. */
private const val ISSUED = "a credential was issued"

/**
 * OpenID4VCI 1.0 between Multipaz and OID4VCgo, pre-authorized code
 * under HAIP (a Wallet Attestation and its PoP, DPoP, Key Attestation
 * proofs): Multipaz's wallet (OpenID4VCI.createClientFromOffer, with
 * its local wallet backend) obtaining PIDs from cmd/conformance-issuer,
 * and walletflow obtaining an mDL and a PID from Multipaz's issuer,
 * which the driver runs in process; with controls.
 */
class VciCases(
    private val peer: Peer,
    private val pki: Pki,
    private val tls: Tls,
    private val dir: File,
) : Checks() {
    suspend fun run(): Int {
        mpzWalletCases()
        goWalletCases()
        return failed
    }

    private suspend fun mpzWalletCases() {
        println("### OpenID4VCI: Multipaz wallet → OID4VCgo's issuer (cmd/conformance-issuer)")
        val started = peer.call("issuer_start")
        started.error?.let {
            bad("the issuer didn't start: $it")
            return
        }
        val issuer = OurIssuer(File(started.string("data")!!, "driver.json"))
        for (config in listOf(issuer.sdjwtConfiguration, issuer.mdocConfiguration)) {
            check("$config, authorization code (PAR, PKCE, scope): issued to Multipaz's wallet (Wallet Attestation, DPoP, Key Attestation), under OID4VCgo's CA") {
                val credential = receive(issuer, config, ATTESTER, preAuthorized = false).getOrThrow()
                issuer.checkIssued(config, credential)
            }
        }
        // Redeeming a pre-authorized code, Multipaz's wallet always asks
        // for the configuration by authorization_details, which the
        // issuer grants with credential_identifiers (OpenID4VCI 1.0
        // §6.2), but then requests it by credential_configuration_id,
        // which §8.2 forbids once the token named identifiers.
        check("control: the issuer refuses a pre-authorized request by credential_configuration_id when the token granted credential_identifiers") {
            val result = receive(issuer, issuer.sdjwtConfiguration, ATTESTER)
            refusal(result.exceptionOrNull()?.message, ISSUED, "use credential_identifier")
        }
        check("control: the issuer refuses a Wallet Attestation from an attester it doesn't trust") {
            val result = receive(issuer, issuer.sdjwtConfiguration, UNTRUSTED_ATTESTER)
            refusal(result.exceptionOrNull()?.message, ISSUED, "no matching attester key")
        }
        // Multipaz's local backend's own Wallet Attestations are valid
        // for 2000 days; the issuer accepts one valid for at most a day.
        check("control: the issuer refuses a Wallet Attestation valid for 2000 days, as Multipaz's local backend makes them") {
            val result = receive(issuer, issuer.sdjwtConfiguration, ATTESTER, multipazLifetime = true)
            refusal(result.exceptionOrNull()?.message, ISSUED, "client attestation verification failed")
        }
    }

    /**
     * Multipaz's wallet takes an offer of [config] from OID4VCgo's
     * issuer, a pre-authorized code's or, unless [preAuthorized], an
     * authorization code's (approved on the issuer's consent page),
     * attested by [attester] (its key and certificate, from the peer),
     * and returns the credential, or why not: with the issuer's error,
     * if it answered with one. Its Wallet Attestations are valid for an
     * hour, unless [multipazLifetime].
     */
    private suspend fun receive(
        issuer: OurIssuer,
        config: String,
        attester: String,
        multipazLifetime: Boolean = false,
        preAuthorized: Boolean = true,
    ): Result<ByteString> {
        val offer = issuer.offer(config, preAuthorized)
        val attestationKey = signer(attester)
        val local = OpenID4VCILocalBackend(
            clientAssertionKey = AsymmetricKey.anonymous(Crypto.createEcPrivateKey(EcCurve.P256)),
            attestationKey = attestationKey,
            clientId = issuer.clientId,
            walletName = "Multipaz interop wallet",
            walletLink = "https://github.com/openwallet-foundation/multipaz",
        )
        val backend = if (multipazLifetime) local else HourLongAttestations(local, attestationKey, issuer.clientId)
        var issuerError: String? = null
        val preferences = OpenID4VCIClientPreferences(
            clientId = issuer.clientId,
            redirectUrl = issuer.redirectUri,
            locales = listOf("en-US"),
            signingAlgorithms = listOf(Algorithm.ESP256),
        )
        val secureArea = SoftwareSecureArea.create(EphemeralStorage())
        val http = HttpClient(tls.ktorTrusting(issuer.tlsTrustPEM)) {
            install(HttpTimeout)
            HttpResponseValidator {
                validateResponse { response ->
                    if (!response.status.isSuccess()) issuerError = "${response.status.value} ${response.bodyAsText()}"
                }
            }
        }
        val environment = Environment(mapOf(
            HttpClient::class to http,
            OpenID4VCIBackend::class to backend,
            OpenID4VCIClientPreferences::class to preferences,
            SecureAreaProvider::class to SecureAreaProvider(Dispatchers.Default) { secureArea },
        ))
        return runCatching {
            withContext(environment) { obtain(issuer, offer, preferences, secureArea) }
        }.recoverCatching { e -> throw IllegalStateException("${e.message}: ${issuerError ?: "no error response"}", e) }
    }

    private suspend fun obtain(
        issuer: OurIssuer,
        offer: String,
        preferences: OpenID4VCIClientPreferences,
        secureArea: SoftwareSecureArea,
    ): ByteString {
        val client = OpenID4VCI.createClientFromOffer(offer, preferences)
        for (challenge in client.getAuthorizationChallenges()) {
            check(challenge is AuthorizationChallenge.OAuth) { "the offer asks for $challenge" }
            client.authorize(AuthorizationResponse.OAuth(challenge.id, issuer.consent(tls, challenge.url)))
        }
        client.getKeyBindingChallenge()
        val key = secureArea.createKey(null, CreateKeySettings())
        val credentials = client.obtainCredentials(
            KeyBindingInfo.Attestation(listOf(CredentialKeyAttestation("k1", key.attestation)))
        )
        return credentials.certifications.single().issuerData
    }

    /** The peer's attester [name]: its key and certificate chain. */
    private fun signer(name: String): AsymmetricKey.X509Certified {
        val chain = X509CertChain(pems(File(dir, "$name-cert.pem").readText()).map { X509Cert.fromPem(it) })
        val key = EcPrivateKey.fromPem(File(dir, "$name-key.pem").readText(), chain.certificates.first().ecPublicKey)
        return AsymmetricKey.X509CertifiedExplicit(chain, key)
    }

    private suspend fun goWalletCases() {
        println("### OpenID4VCI: OID4VCgo's wallet (walletflow) → Multipaz issuer (in process)")
        MpzIssuer(tls, dir, pki).use { issuer ->
            for ((scope, label) in listOf("mDL" to "mDL", "core" to "PID")) {
                check("$label (scope $scope): issued to walletflow (Wallet Attestation, DPoP, Key Attestation), verified") {
                    val offers = issuer.offers(scope)
                    val problems = offers.mapNotNull { (configuration, offer) ->
                        val got = peer.call("wallet_receive", "request" to offer, "data" to issuer.rootPEM)
                        got.error?.let { "$configuration: $it" }
                    }
                    problems.firstOrNull()
                }
            }
            check("control: Multipaz's issuer refuses a Wallet Attestation from an attester it doesn't trust") {
                val (_, offer) = issuer.offers("mDL").first()
                refusal(peer.call("wallet_receive", "request" to offer, "data" to issuer.rootPEM, "trust" to "other"), "CA not registered")
            }
        }
    }
}

/**
 * Multipaz's local backend with its Wallet Attestations valid for an
 * hour, not its own 2000 days: OpenID4VCIBackend is the Wallet
 * Provider's side, which sets their lifetime; the wallet's protocol
 * (the PoP, DPoP, the requests) stays Multipaz's.
 */
private class HourLongAttestations(
    private val local: OpenID4VCIBackend,
    private val key: AsymmetricKey.X509Certified,
    private val clientId: String,
) : OpenID4VCIBackend by local {
    override suspend fun createJwtWalletAttestation(keyAttestation: KeyAttestation): String =
        buildJwt(type = "oauth-client-attestation+jwt", key = key, expiresIn = 1.hours) {
            put("iss", key.subject)
            put("sub", clientId)
            put("cnf", buildJsonObject { put("jwk", keyAttestation.publicKey.toJwk()) })
        }
}

/** The Multipaz client's BackendEnvironment: these interfaces and nothing else. */
private class Environment(private val interfaces: Map<KClass<*>, Any>) : BackendEnvironment {
    override fun <T : Any> getInterface(clazz: KClass<T>): T? = interfaces[clazz]?.let { clazz.cast(it) }
}

/**
 * cmd/conformance-issuer as interop/eudi/scripts/setup-issuer configures
 * it: driver.json's offers listener, client, and trust anchors.
 */
private class OurIssuer(driver: File) {
    private val json = Json.parseToJsonElement(driver.readText()).jsonObject
    private fun string(name: String) = json[name]!!.jsonPrimitive.content

    val clientId = string("client_id")
    val redirectUri = string("redirect_uri")
    val subject = string("subject")
    val tlsTrustPEM = string("tls_trust_pem")
    val sdjwtConfiguration = string("sdjwt_configuration_id")
    val mdocConfiguration = string("mdoc_configuration_id")
    private val offersURL = string("offers_url")
    private val issuerCA = X509Cert.fromPem(string("issuer_ca_pem"))
    private val iaca = X509Cert.fromPem(string("iaca_pem"))

    /** A pre-authorized code offer of [config], or an authorization code one, by value. */
    fun offer(config: String, preAuthorized: Boolean): String {
        val body = buildJsonObject {
            put("grant", if (preAuthorized) "pre-authorized_code" else "authorization_code")
            putJsonArray("credential_configuration_ids") { add(JsonPrimitive(config)) }
        }
        val response = java.net.http.HttpClient.newHttpClient().send(
            java.net.http.HttpRequest.newBuilder(java.net.URI(offersURL)).header("Content-Type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body.toString())).build(),
            java.net.http.HttpResponse.BodyHandlers.ofString(),
        )
        check(response.statusCode() == 200) { "offers: ${response.statusCode()} ${response.body()}" }
        return Json.parseToJsonElement(response.body()).jsonObject["uri"]!!.jsonPrimitive.content
    }

    /**
     * The End-User approves the authorization request at [url] on the
     * issuer's consent page, as subject; the answer is the redirect
     * back to the wallet, with its code.
     */
    fun consent(tls: Tls, url: String): String {
        val browser = java.net.http.HttpClient.newBuilder().sslContext(tls.trusting(tlsTrustPEM))
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()
        val page = browser.send(
            java.net.http.HttpRequest.newBuilder(java.net.URI(url)).GET().build(),
            java.net.http.HttpResponse.BodyHandlers.ofString(),
        )
        check(page.statusCode() == 200) { "the consent page answered ${page.statusCode()}: ${page.body().take(300)}" }
        val handle = checkNotNull(Regex("""name="handle" value="([^"]+)"""").find(page.body())?.groupValues?.get(1)) {
            "no interaction handle on the consent page"
        }
        val scopes = Regex("""name="scope" value="([^"]+)"""").findAll(page.body()).map { it.groupValues[1] }.toList()
        val fields = listOf("handle" to handle, "subject" to subject, "decision" to "approve") + scopes.map { "scope" to it }
        val decision = browser.send(
            java.net.http.HttpRequest.newBuilder(java.net.URI(url).resolve("/authorize/decision"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                    fields.joinToString("&") { (k, v) -> "$k=${java.net.URLEncoder.encode(v, Charsets.UTF_8)}" }
                )).build(),
            java.net.http.HttpResponse.BodyHandlers.ofString(),
        )
        return checkNotNull(decision.headers().firstValue("Location").orElse(null)) {
            "the consent decision answered ${decision.statusCode()} without a redirect: ${decision.body().take(300)}"
        }
    }

    /** null if [credential], issued for [config], is signed under its trust anchor, or why not. */
    suspend fun checkIssued(config: String, credential: ByteString): String? {
        val (chain, anchor) = if (config == mdocConfiguration) {
            val issuerAuth = CoseSign1.fromDataItem(Cbor.decode(credential.toByteArray())["issuerAuth"])
            val x5chain = issuerAuth.unprotectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN)]!!
            val chain = X509CertChain.fromDataItem(x5chain)
            Cose.coseSign1Check(chain.certificates.first().ecPublicKey, null, issuerAuth, issuerAuth.algorithm())
            chain to iaca
        } else {
            val sdJwt = SdJwt.fromCompactSerialization(credential.toByteArray().decodeToString())
            val chain = sdJwt.x5c ?: return "the SD-JWT VC has no x5c"
            sdJwt.verify(chain.certificates.first().ecPublicKey)
            chain to issuerCA
        }
        // The chain's signatures, up to and including the anchor's.
        return try {
            X509CertChain(chain.certificates + anchor).validate()
            null
        } catch (e: Exception) {
            "the credential's chain doesn't reach OID4VCgo's CA: ${e.message}"
        }
    }
}

private fun CoseSign1.algorithm(): Algorithm =
    Algorithm.fromCoseAlgorithmIdentifier(protectedHeaders[CoseNumberLabel(Cose.COSE_LABEL_ALG)]!!.asNumber.toInt())

/**
 * Multipaz's issuer, from its published library, in process: its
 * routes on Netty, over TLS with the peer's localhost certificate,
 * issuing the mDL and the PID, signed with [Pki]'s document signer,
 * trusting the peer's Wallet Provider for Wallet Attestations and Key
 * Attestations.
 */
private class MpzIssuer(private val tls: Tls, dir: File, private val pki: Pki) : AutoCloseable {
    private val port = ServerSocket(0, 0, java.net.InetAddress.getLoopbackAddress()).use { it.localPort }
    private val base = "https://localhost:$port"
    private val server: EmbeddedServer<*, *>

    init {
        val ca = X509Cert.fromPem(File(dir, "go-attester-ca.pem").readText())
        val caName = ca.subject.components[OID.COMMON_NAME.oid]!!.value
        val trusted = buildJsonObject { put(caName, ca.encoded.toByteArray().toBase64()) }
        val config = File(dir, "mpz-issuer.json")
        config.writeText(buildJsonObject {
            put("server_port", port)
            put("base_url", base)
            put("database_engine", "ephemeral")
            put("trusted_client_attestations", trusted)
            put("trusted_key_attestations", trusted)
            put("server_identities", buildJsonObject {
                val ds = pki.ds as AsymmetricKey.X509CertifiedExplicit
                put("credential_signing", JsonObject(ds.privateKey.toJwk() + ("x5c" to ds.certChain.toX5c(excludeRoot = false))))
            })
        }.toString())
        val environment = ServerEnvironment.create(ServerConfiguration(arrayOf("-config", config.path))) {
            val registry = CredentialFactoryRegistry(listOf(CredentialFactoryMdl(), CredentialFactoryMdocPid(), CredentialFactorySdjwtPid()))
            registry.initialize()
            add(CredentialFactoryRegistry::class, registry)
        }
        server = embeddedServer(Netty, configure = {
            sslConnector(tls.keyStore, "tls", { CharArray(0) }, { CharArray(0) }) {
                host = java.net.InetAddress.getLoopbackAddress().hostAddress
                this.port = this@MpzIssuer.port
            }
        }) {
            installServerEnvironment(environment)
            configureRouting(environment)
        }.start(wait = false)
    }

    /** The issuer's signing root: [Pki]'s IACA. */
    val rootPEM: String = pki.iaca.toPem()

    /** The pre-authorized code offers for [scope], with no tx_code: configuration ID to offer. */
    fun offers(scope: String): List<Pair<String, String>> {
        val body = buildJsonObject {
            put("access_token", "Erika:Mustermann:1971-09-01")
            put("expires_in", 600)
            put("refresh_token", "unused")
            put("scope", scope)
            put("tx_kind", "none")
        }
        val response = tls.post("$base/preauthorized_offer", body.toString())
        check(response.statusCode() == 200) { "/preauthorized_offer: ${response.statusCode()} ${response.body()}" }
        return Json.parseToJsonElement(response.body()).jsonArray.map {
            val offer = it.jsonObject
            offer["configuration_id"]!!.jsonPrimitive.content to offer["offer"]!!.jsonPrimitive.content
        }
    }

    override fun close() = server.stop(0, 0)
}

/** The PEM blocks in [text]. */
private fun pems(text: String): List<String> =
    Regex("-----BEGIN CERTIFICATE-----[\\s\\S]+?-----END CERTIFICATE-----").findAll(text).map { it.value }.toList()
