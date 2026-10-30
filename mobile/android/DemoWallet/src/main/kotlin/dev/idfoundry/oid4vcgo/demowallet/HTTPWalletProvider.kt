package dev.idfoundry.oid4vcgo.demowallet

import dev.idfoundry.oid4vcwallet.KeyAttestationRequest
import dev.idfoundry.oid4vcwallet.KeyEvidence
import dev.idfoundry.oid4vcwallet.KeyPurpose
import dev.idfoundry.oid4vcwallet.StoreException
import dev.idfoundry.oid4vcwallet.WalletAttestationRequest
import dev.idfoundry.oid4vcwallet.WalletProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.HttpURLConnection
import java.net.URI
import java.util.Base64

/**
 * The Wallet Provider's backend, over the passport-vdc demo Wallet
 * Provider's HTTP API: POST /attestation-challenge, answered with
 * {"challenge"}, and /wallet-attestation and /key-attestation, answered
 * with {"attestation"}.
 *
 * Each instance and holder key is made over a challenge from the
 * provider, so Android Keystore attests it, and its attestation chain
 * goes to the provider with it, which verifies it before attesting the
 * key. A provider without the challenge endpoint (an older passport-vdc,
 * or mobile/cmd/testservices) gives no challenge, and the keys go
 * without chains, attested unverified.
 */
class HTTPWalletProvider(private val baseURL: String) : WalletProvider {
    override suspend fun attestationChallenge(purpose: KeyPurpose): ByteArray? {
        // DPoP keys aren't attested to anyone.
        if (purpose == KeyPurpose.DPOP) return null
        val answer = post("attestation-challenge", JsonObject(mapOf("purpose" to JsonPrimitive(purpose.rawValue))), allowMissing = true)
            ?: return null
        val challenge = field(answer, "challenge") ?: throw StoreException("the Wallet Provider gave no challenge")
        return runCatching { Base64.getUrlDecoder().decode(challenge) }.getOrNull()
            ?: throw StoreException("the Wallet Provider's challenge isn't base64url")
    }

    override suspend fun walletAttestation(request: WalletAttestationRequest): String {
        val body = mutableMapOf<String, JsonElement>("client_id" to JsonPrimitive(request.clientID), "instance_key" to parse(request.instanceKey.jwk))
        if (request.instanceKey.certificateChain.isNotEmpty()) body["instance_key_certificate_chain"] = chain(request.instanceKey)
        return attestation("wallet-attestation", JsonObject(body))
    }

    override suspend fun keyAttestation(request: KeyAttestationRequest): String {
        val body = mutableMapOf<String, JsonElement>(
            "keys" to JsonArray(request.keys.map { parse(it.jwk) }),
            "nonce" to JsonPrimitive(request.nonce),
        )
        if (request.keys.any { it.certificateChain.isNotEmpty() }) body["certificate_chains"] = JsonArray(request.keys.map(::chain))
        return attestation("key-attestation", JsonObject(body))
    }

    private fun parse(bytes: ByteArray): JsonElement = Json.parseToJsonElement(bytes.decodeToString())

    // A key's chain as x5c does it: each certificate's DER, base64.
    private fun chain(key: KeyEvidence): JsonArray =
        JsonArray(key.certificateChain.map { JsonPrimitive(Base64.getEncoder().encodeToString(it)) })

    private suspend fun attestation(path: String, body: JsonObject): String =
        post(path, body)?.let { field(it, "attestation") } ?: throw StoreException("the Wallet Provider refused $path")

    private fun field(answer: String, name: String): String? =
        runCatching { Json.parseToJsonElement(answer).jsonObject[name]?.jsonPrimitive?.content }.getOrNull()

    // The answer's body; null for a 404 when allowMissing. An IOException
    // (no network, a timeout) reaches the wallet as a network failure,
    // which it reports as retryable.
    private suspend fun post(path: String, body: JsonObject, allowMissing: Boolean = false): String? = withContext(Dispatchers.IO) {
        val connection = URI(baseURL.trimEnd('/') + "/" + path).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = 15_000
            connection.readTimeout = 15_000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            when (connection.responseCode) {
                200 -> connection.inputStream.use { it.readBytes().decodeToString() }
                404 -> if (allowMissing) null else throw StoreException("the Wallet Provider has no $path")
                else -> {
                    // The provider says why: a key attestation it refused, say.
                    val why = connection.errorStream?.use { it.readBytes().decodeToString() }?.let { field(it, "error") }
                    throw StoreException("the Wallet Provider refused $path" + (why?.let { ": $it" } ?: ""))
                }
            }
        } finally {
            connection.disconnect()
        }
    }
}
