package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.delay
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/** What runs on the host JVM: nothing here loads the Go library. */
class HostTest {
    @Test
    fun walletExceptionParsing() {
        fun parse(text: String) = WalletException.from(Exception(text))
        val pin = parse("[protocol:invalid_grant] walletflow: token: wrong tx_code")
        assertEquals(WalletException.Code.protocol, pin.code)
        assertEquals("invalid_grant", pin.protocolError)
        assertTrue(pin.isRetryable)
        assertEquals("That code or PIN wasn't accepted.", pin.description)
        assertEquals("[protocol:invalid_grant] walletflow: token: wrong tx_code", pin.toString())

        val network = parse("[network] dial tcp: refused")
        assertEquals(WalletException.Code.network, network.code)
        assertNull(network.protocolError)
        assertTrue(network.isRetryable)

        assertTrue(parse("[unavailable] the issuer refused the request (HTTP 503)").isRetryable)
        assertTrue(parse("[protocol:invalid_nonce] stale").isRetryable)
        assertFalse(parse("[protocol:invalid_client] no").isRetryable)
        assertFalse(parse("[delivery_unknown] maybe").isRetryable)
        assertFalse(parse("[credential_denied] no").isRetryable)
        val plain = parse("no code")
        assertEquals(WalletException.Code.internal, plain.code)
        assertEquals("no code", plain.message)
    }

    /** The suspending provider bridge: Go blocks its thread while the provider answers. */
    @Test
    fun providerBridge() {
        val slow = WalletProviderAdapter(object : WalletProvider {
            override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String {
                delay(50)
                return "wa-$clientID-${instanceKey.size}"
            }

            override suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String {
                if (nonce == "fail") throw StoreException("provider down")
                return "ka-${keys.size}-$nonce"
            }
        })
        assertEquals("wa-c-12", slow.walletAttestation("c", """{"kty":"EC"}""".toByteArray()).decodeToString())
        assertEquals("ka-2-n", slow.keyAttestation("""[{"a":1},{"b":2}]""".toByteArray(), "n").decodeToString())
        expectFailure { slow.keyAttestation("[]".toByteArray(), "fail") }
        expectFailure { slow.keyAttestation("{}".toByteArray(), "n") }

        // An IOException reaches Go marked as a network failure.
        val offline = WalletProviderAdapter(object : WalletProvider {
            override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String = throw IOException("offline")
            override suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String = ""
        })
        try {
            offline.walletAttestation("c", "{}".toByteArray())
            fail("an offline provider answered")
        } catch (e: StoreException) {
            assertTrue(e.message, e.message!!.startsWith("[network] "))
        }
    }

    @Test
    fun origin() {
        assertEquals("https://verifier.example", MdocPresentation.origin("https://verifier.example/"))
        assertEquals("https://verifier.example", MdocPresentation.origin("https://Verifier.Example:443/path?q"))
        assertEquals("https://verifier.example:8443", MdocPresentation.origin("https://verifier.example:8443/"))
        assertEquals("http://localhost", MdocPresentation.origin("http://localhost:80"))
        assertNull(MdocPresentation.origin("not a url"))
    }

    private fun expectFailure(body: () -> Unit) {
        try {
            body()
            fail("expected a failure")
        } catch (e: Exception) {
            // As expected.
        }
    }
}
