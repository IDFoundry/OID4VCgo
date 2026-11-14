package oid4vcgo.interop.eudi

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.JSONObjectUtils
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.PositiveDuration
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/**
 * OID4VCgo's Wallet Provider (walletprovider.Provider, run by
 * interop/walletprovider), reached through its agent: the wallet's side
 * of the provider's v1 protocol, a loopback service registered as one
 * wallet instance (interop/internal/interopwp), as the Swift and Kotlin
 * libraries' HttpWalletProvider is on a device. The provider issues
 * every Wallet Attestation and Key Attestation; only the platform
 * evidence the agent sends it is a stand-in.
 */
class ProviderAgent(
    private val url: String,
) {
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build()

    private fun post(
        path: String,
        body: Map<String, Any?>,
    ): String {
        val request =
            HttpRequest
                .newBuilder(URI(url.trimEnd('/') + path))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSONObjectUtils.toJSONString(body)))
                .build()
        val response = http.send(request, HttpResponse.BodyHandlers.ofString())
        check(response.statusCode() == 200) { "the Wallet Provider refused $path: HTTP ${response.statusCode()} ${response.body().take(300)}" }
        return Json
            .parseToJsonElement(response.body())
            .jsonObject
            .getValue("jwt")
            .jsonPrimitive.content
    }

    /** A Wallet Attestation for [clientId] binding [instanceKey]. */
    fun walletAttestation(
        clientId: String,
        instanceKey: ECKey,
    ): String = post("/wallet-attestation", mapOf("client_id" to clientId, "instance_key" to instanceKey.toPublicJWK().toJSONObject()))

    /** A Key Attestation of [attested] carrying [nonce], for the issuance whose instance key is [instanceKey]. */
    fun keyAttestation(
        instanceKey: ECKey,
        attested: List<ECKey>,
        nonce: Nonce?,
    ): KeyAttestationJWT =
        KeyAttestationJWT(
            post(
                "/key-attestation",
                mapOf(
                    "instance_key" to instanceKey.toPublicJWK().toJSONObject(),
                    "keys" to attested.map { it.toPublicJWK().toJSONObject() },
                    "nonce" to nonce?.value,
                ),
            ),
        )
}

/**
 * Wallet Attestation client authentication with an attestation from
 * [agent]'s provider, for a fresh Client Instance Key, which it returns
 * too: the issuance's instance key, which the provider recorded and its
 * Key Attestations for the issuance name.
 */
fun providerWalletAttestation(
    clientId: String,
    agent: ProviderAgent,
): Pair<ClientAuthentication.AttestationBased, ECKey> {
    val instanceKey = newKey()
    val provisioned =
        ProvisionClientAttestation.Provisioned(
            ClientAttestationJWT(agent.walletAttestation(clientId, instanceKey)),
            ecSigner(instanceKey, instanceKey.toPublicJWK()),
        )
    val auth =
        ClientAuthentication.AttestationBased(
            clientId,
            object : ProvisionClientAttestation {
                override val algorithm: JwsAlgorithm = ES256
                override val popAlgorithm: JwsAlgorithm = ES256

                override suspend fun invoke(
                    authorizationServer: HttpsUrl,
                    preferredClientStatusPeriod: PositiveDuration?,
                ): ProvisionClientAttestation.Provisioned = provisioned
            },
        )
    return auth to instanceKey
}

/** Revokes every instance the provider whose admin listener is at [adminUrl] registered. */
fun revokeAtProvider(adminUrl: String) {
    val response =
        HttpClient.newHttpClient().send(
            HttpRequest
                .newBuilder(URI(adminUrl.trimEnd('/') + "/revoke"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build(),
            HttpResponse.BodyHandlers.ofString(),
        )
    check(response.statusCode() == 200) { "the Wallet Provider didn't revoke: HTTP ${response.statusCode()} ${response.body().take(200)}" }
}
