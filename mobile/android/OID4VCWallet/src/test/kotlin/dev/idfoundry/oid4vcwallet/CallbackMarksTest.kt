package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import kotlin.time.Duration.Companion.seconds

/**
 * How the adapters mark a callback's failure for Go — a Wallet
 * Provider's refusal with its error code, the holder's cancellation —
 * and the sentences the holder is shown for them.
 */
class CallbackMarksTest {
    private fun failure(call: () -> Unit): StoreException {
        try {
            call()
        } catch (e: StoreException) {
            return e
        }
        fail("the call succeeded")
        throw AssertionError()
    }

    @Test
    fun aRefusalCarriesTheProvidersErrorCode() {
        fun refusing(code: String?) = WalletProviderAdapter(object : WalletProvider {
            override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
                throw WalletProviderRefusedException(403, code, null, "/v1/wallet-attestation")

            override suspend fun keyAttestation(instanceKey: ByteArray, keys: List<ByteArray>, nonce: String): String = ""
        })
        assertEquals(
            "[refused:instance_revoked] the Wallet Provider refused /v1/wallet-attestation: HTTP 403 instance_revoked",
            failure { refusing("instance_revoked").walletAttestation("c", "{}".toByteArray()) }.message,
        )
        // Without a code, nothing to carry: unmarked.
        assertEquals(
            "the Wallet Provider refused /v1/wallet-attestation: HTTP 403",
            failure { refusing(null).walletAttestation("c", "{}".toByteArray()) }.message,
        )
    }

    private class CancellingStore(private val failure: Exception) : KeyStore {
        override fun createKey(purpose: KeyPurpose): String = "k"
        override fun publicKey(id: String): ByteArray? = null
        override fun sign(id: String, digest: ByteArray): ByteArray = throw failure
        override fun deleteKey(id: String) {}
    }

    @Test
    fun theHoldersCancellationIsMarked() {
        val cancelled = failure { KeyStoreAdapter(CancellingStore(HolderCancelledException("the holder cancelled: Cancel"))).sign("k", ByteArray(32)) }
        assertTrue(cancelled.message, cancelled.message!!.startsWith("[cancelled] "))
        // Wrapped by the app's own store, still the holder's.
        val wrapped = failure {
            KeyStoreAdapter(CancellingStore(StoreException("sign failed", HolderCancelledException("dismissed")))).sign("k", ByteArray(32))
        }
        assertEquals("[cancelled] dismissed", wrapped.message)
        val other = failure { KeyStoreAdapter(CancellingStore(StoreException("keystore busy"))).sign("k", ByteArray(32)) }
        assertEquals("keystore busy", other.message)

        val agreement = KeyAgreementAdapter(object : KeyAgreement {
            override fun agree(id: String, peerPublicKey: ByteArray): ByteArray = throw HolderCancelledException("dismissed")
        })
        assertEquals("[cancelled] dismissed", failure { agreement.agree("k", ByteArray(65)) }.message)
    }

    @Test
    fun holderFacingText() {
        fun parse(text: String) = WalletException.from(Exception(text))
        val suspended = parse("[platform:instance_not_active] wallet attestation: the Wallet Provider refused")
        assertEquals(WalletException.Code.platform, suspended.code)
        assertEquals("instance_not_active", suspended.protocolError)
        assertEquals("This wallet is suspended by its provider. Contact them, or try again later.", suspended.description)
        val storage = parse("[platform] x").description
        assertNotEquals(storage, parse("[platform:instance_revoked] x").description)
        assertNotEquals(storage, parse("[platform:invalid_signed_request] x").description)
        assertEquals("The wallet's provider refused the request.", parse("[platform:evidence_rejected] x").description)
        assertEquals(WalletException.Code.cancelled, parse("[cancelled] sign with key: the holder cancelled").code)
        assertEquals("The service's identity couldn't be confirmed, so nothing was sent to it.", parse("[tls_pin] mismatch").description)
    }

    /** The key store's options for a device below API 30 drop what it can't make; from 30, unchanged. */
    @Test
    fun optionsForDevice() {
        val base = AndroidKeystoreKeyStore.Options(holderAuthenticationTimeout = 30.seconds)
        assertEquals(base, AndroidKeystoreKeyStore.Options.forDevice(base, sdkInt = 30))
        val below = AndroidKeystoreKeyStore.Options.forDevice(base, sdkInt = 29)
        assertFalse(below.holderUserAuthentication)
        assertEquals(kotlin.time.Duration.ZERO, below.holderAuthenticationTimeout)
        assertEquals(base.strongBox, below.strongBox)
        assertEquals(base.aliasPrefix, below.aliasPrefix)
    }
}
