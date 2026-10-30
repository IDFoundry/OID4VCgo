package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Key attestation evidence through the adapters: each key is made over
 * the Wallet Provider's challenge, and reaches the provider with its ID
 * and attestation chain.
 */
class KeyEvidenceTest {
    /** A key store whose "attestation chain" is the challenge it was made over. */
    private class FakeKeyStore : KeyStore {
        val points = mutableMapOf<String, ByteArray>()
        val challenges = mutableMapOf<String, ByteArray?>()
        private var n = 0

        override fun createKey(purpose: KeyPurpose): String = createKey(purpose, null)

        override fun createKey(purpose: KeyPurpose, attestationChallenge: ByteArray?): String {
            val id = "k${n++}"
            val gen = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            val pub = gen.generateKeyPair().public as ECPublicKey
            points[id] = byteArrayOf(4) + fixed(pub.w.affineX) + fixed(pub.w.affineY)
            challenges[id] = attestationChallenge
            return id
        }

        override fun publicKey(id: String): ByteArray? = points[id]

        override fun sign(id: String, digest: ByteArray): ByteArray = throw UnsupportedOperationException()

        override fun deleteKey(id: String) {
            points.remove(id)
        }

        override fun attestationChain(id: String): List<ByteArray>? = challenges[id]?.let { listOf(it, byteArrayOf(9)) }

        fun jwk(id: String): ByteArray {
            val p = points.getValue(id)
            val enc = Base64.getUrlEncoder().withoutPadding()
            val x = enc.encodeToString(p.copyOfRange(1, 33))
            val y = enc.encodeToString(p.copyOfRange(33, 65))
            return """{"kty":"EC","crv":"P-256","x":"$x","y":"$y"}""".toByteArray()
        }

        private fun fixed(n: BigInteger): ByteArray {
            val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(32 - b.size) + b
        }
    }

    /** A provider with evidence: it gives a challenge per purpose and records what it's asked to attest. */
    private class EvidenceProvider : WalletProvider {
        var walletRequest: WalletAttestationRequest? = null
        var keyRequest: KeyAttestationRequest? = null
        val asked = mutableListOf<KeyPurpose>()

        override suspend fun attestationChallenge(purpose: KeyPurpose): ByteArray? {
            asked += purpose
            return if (purpose == KeyPurpose.DPOP) null else "challenge-${purpose.rawValue}".toByteArray()
        }

        override suspend fun walletAttestation(request: WalletAttestationRequest): String {
            walletRequest = request
            return "wa"
        }

        override suspend fun keyAttestation(request: KeyAttestationRequest): String {
            keyRequest = request
            return "ka"
        }
    }

    @Test
    fun challengeAndChainReachTheProvider() {
        val store = FakeKeyStore()
        val provider = EvidenceProvider()
        val created = CreatedKeys()
        val keys = KeyStoreAdapter(store, provider, created)
        val wp = WalletProviderAdapter(provider, store, created)

        val instance = keys.createKey("instance")
        val dpop = keys.createKey("dpop")
        val h1 = keys.createKey("holder")
        val h2 = keys.createKey("holder")
        assertEquals(listOf(KeyPurpose.INSTANCE, KeyPurpose.DPOP, KeyPurpose.HOLDER, KeyPurpose.HOLDER), provider.asked)
        assertArrayEquals("challenge-holder".toByteArray(), store.challenges[h1])
        assertNull("no challenge for a DPoP key", store.challenges[dpop])

        assertEquals("wa", wp.walletAttestation("client", store.jwk(instance)).decodeToString())
        val instanceEvidence = provider.walletRequest!!.instanceKey
        assertEquals("client", provider.walletRequest!!.clientID)
        assertEquals(instance, instanceEvidence.keyID)
        assertArrayEquals("challenge-instance".toByteArray(), instanceEvidence.certificateChain.first())

        val batch = "[" + store.jwk(h1).decodeToString() + "," + store.jwk(h2).decodeToString() + "]"
        assertEquals("ka", wp.keyAttestation(batch.toByteArray(), "n").decodeToString())
        val request = provider.keyRequest!!
        assertEquals("n", request.nonce)
        assertEquals(listOf(h1, h2), request.keys.map { it.keyID })
        assertEquals(listOf(2, 2), request.keys.map { it.certificateChain.size })
        // The JWK reaches the provider as Go gave it.
        assertEquals(store.jwk(h1).decodeToString(), request.keys[0].jwk.decodeToString())
    }

    @Test
    fun unknownKeysCarryNoEvidence() {
        val store = FakeKeyStore()
        val provider = EvidenceProvider()
        val created = CreatedKeys()
        val keys = KeyStoreAdapter(store, provider, created)
        val wp = WalletProviderAdapter(provider, store, created)
        val other = FakeKeyStore().let { it.jwk(it.createKey(KeyPurpose.HOLDER)) }
        val deleted = keys.createKey("holder")
        val deletedJWK = store.jwk(deleted)
        keys.deleteKey(deleted)

        wp.keyAttestation("[${other.decodeToString()},${deletedJWK.decodeToString()},{\"kty\":\"EC\"}]".toByteArray(), "n")
        for (k in provider.keyRequest!!.keys) {
            assertNull(k.keyID)
            assertTrue(k.certificateChain.isEmpty())
        }
    }

    @Test
    fun keysOnlyProviderStillWorks() {
        // A provider written before the evidence: it never sees it.
        val store = FakeKeyStore()
        val provider = object : WalletProvider {
            override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String = "wa-$clientID"

            override suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String = "ka-${keys.size}-$nonce"
        }
        val created = CreatedKeys()
        val keys = KeyStoreAdapter(store, provider, created)
        val wp = WalletProviderAdapter(provider, store, created)
        val h = keys.createKey("holder")
        assertNull("no challenge, no attestation", store.challenges[h])
        assertEquals("wa-c", wp.walletAttestation("c", store.jwk(h)).decodeToString())
        assertEquals("ka-1-n", wp.keyAttestation("[${store.jwk(h).decodeToString()}]".toByteArray(), "n").decodeToString())

        // One that implements neither version fails, not loops.
        val none = WalletProviderAdapter(object : WalletProvider {})
        try {
            none.keyAttestation("[]".toByteArray(), "n")
            fail("a provider with no keyAttestation answered")
        } catch (e: StoreException) {
            // As expected.
        }
    }

    @Test
    fun challengeFailures() {
        fun adapter(challenge: suspend (KeyPurpose) -> ByteArray?) = KeyStoreAdapter(
            FakeKeyStore(),
            object : WalletProvider {
                override suspend fun attestationChallenge(purpose: KeyPurpose): ByteArray? = challenge(purpose)
            },
        )
        // Android Keystore takes 1 to 128 bytes.
        adapter { ByteArray(128) }.createKey("holder")
        for (bad in listOf(ByteArray(0), ByteArray(129))) {
            try {
                adapter { bad }.createKey("holder")
                fail("a ${bad.size}-byte challenge was taken")
            } catch (e: StoreException) {
                // As expected.
            }
        }
        // An IOException reaches Go marked as a network failure.
        try {
            adapter { throw IOException("offline") }.createKey("holder")
            fail("an offline provider gave a challenge")
        } catch (e: StoreException) {
            assertTrue(e.message, e.message!!.startsWith("[network] "))
        }
    }

    @Test
    fun jwkPoints() {
        val store = FakeKeyStore()
        val id = store.createKey(KeyPurpose.HOLDER)
        assertArrayEquals(store.points[id], jwkPoint(store.jwk(id)))
        assertNull(jwkPoint("""{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}""".toByteArray()))
        assertNull(jwkPoint("""{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}""".toByteArray()))
        assertNull(jwkPoint("""{"kty":"EC","crv":"P-256","x":"!!","y":"!!"}""".toByteArray()))
        assertNull(jwkPoint("""{"kty":"EC","crv":"P-256","x":1,"y":2}""".toByteArray()))
        assertNull(jwkPoint("not json".toByteArray()))
        assertNull(jwkPoint("[]".toByteArray()))
    }

    @Test
    fun createdKeysAreBounded() {
        val created = CreatedKeys(limit = 2)
        created.add(byteArrayOf(1), "a")
        created.add(byteArrayOf(2), "b")
        created.add(byteArrayOf(3), "c")
        assertNull(created.id(byteArrayOf(1)))
        assertEquals("c", created.id(byteArrayOf(3)))
        created.remove("c")
        assertNull(created.id(byteArrayOf(3)))
    }
}
