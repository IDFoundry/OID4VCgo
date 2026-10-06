package dev.idfoundry.oid4vcgo.demowallet

import dev.idfoundry.oid4vcwallet.StoreException
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

/**
 * The Wallet Provider's backend, over the passport-vdc demo Wallet
 * Provider's HTTP API: POST /wallet-attestation and /key-attestation,
 * answered with {"attestation"}. A production provider would first prove
 * the app genuine with Key Attestation or Play Integrity.
 */
class HTTPWalletProvider(private val baseURL: String) : WalletProvider {
    override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
        post("wallet-attestation", JsonObject(mapOf("client_id" to JsonPrimitive(clientID), "instance_key" to parse(instanceKey))))

    override suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String =
        post("key-attestation", JsonObject(mapOf("keys" to JsonArray(keys.map(::parse)), "nonce" to JsonPrimitive(nonce))))

    private fun parse(bytes: ByteArray): JsonElement = Json.parseToJsonElement(bytes.decodeToString())

    // An IOException (no network, a timeout) reaches the wallet as a
    // network failure, which it reports as retryable.
    private suspend fun post(path: String, body: JsonObject): String = withContext(Dispatchers.IO) {
        val connection = URI(baseURL.trimEnd('/') + "/" + path).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = 15_000
            connection.readTimeout = 15_000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            if (connection.responseCode != 200) throw StoreException("the Wallet Provider refused $path")
            val answer = connection.inputStream.use { it.readBytes().decodeToString() }
            runCatching { Json.parseToJsonElement(answer).jsonObject["attestation"]?.jsonPrimitive?.content }.getOrNull()
                ?: throw StoreException("the Wallet Provider refused $path")
        } finally {
            connection.disconnect()
        }
    }
}
