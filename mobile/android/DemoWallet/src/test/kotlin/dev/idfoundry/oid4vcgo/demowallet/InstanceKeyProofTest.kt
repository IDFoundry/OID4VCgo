package dev.idfoundry.oid4vcgo.demowallet

import dev.idfoundry.oid4vcwallet.KeyAttestationRequest
import dev.idfoundry.oid4vcwallet.KeyEvidence
import dev.idfoundry.oid4vcwallet.KeyPurpose
import dev.idfoundry.oid4vcwallet.KeyStore
import dev.idfoundry.oid4vcwallet.StoreException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

/**
 * The passport-vdc demo provider's instance_key_proof, against the vector
 * its walletprovider's TestInstanceKeyProofVector pins: RFC 7515 Appendix
 * A.3's key signed the proof over the keys of RFC 6979 Appendix A.2.5 and
 * RFC 7517 Appendix A.1.
 */
class InstanceKeyProofTest {
    private val instanceJWK = """{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"""
    private val keys = listOf(
        """{"kty":"EC","crv":"P-256","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y","y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"}""",
        """{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}""",
    ).map { it.toByteArray() }
    private val nonce = "c_nonce-1"

    @Test
    fun buildsTheProvidersMessage() {
        assertEquals(
            "passport-vdc instance key proof\nc_nonce-1\nDOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0\ncn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s",
            InstanceKeyProof.message(nonce, keys).decodeToString(),
        )
    }

    /** The vector's proof, which the provider accepts, is SHA256withECDSA's DER signature over the message: the form sign makes. */
    @Test
    fun verifiesTheVectorsProof() {
        assertTrue(verifies(publicKey(instanceJWK), "MEYCIQD3hKubHciPPGC2x6WZLtuhc58iY5pssh591RVz9e33KAIhANKO1vLKLem_45EFQHIa2Hpz3xmKQM62tQKv-7HWgMqU"))
    }

    /** The instance key the library names by its ID signs, through the key store. */
    @Test
    fun signsWithTheNamedInstanceKey() {
        val store = SoftwareKeys()
        store.createKey(KeyPurpose.HOLDER)
        val id = store.createKey(KeyPurpose.INSTANCE)
        val proof = InstanceKeyProof.sign(request(KeyEvidence(jwk(store.publicKey(id)!!), id, emptyList())), store)
        assertFalse("the proof isn't unpadded base64url", proof.any { it in "+/=" })
        assertTrue(verifies(store.public(id), proof))
    }

    @Test
    fun refusesAnInstanceKeyTheWalletCantName() {
        assertThrows(StoreException::class.java) {
            InstanceKeyProof.sign(request(KeyEvidence(instanceJWK.toByteArray(), null, emptyList())), SoftwareKeys())
        }
    }

    private fun request(instanceKey: KeyEvidence) = KeyAttestationRequest(instanceKey, keys.map { KeyEvidence(it, null, emptyList()) }, nonce)

    private fun verifies(key: PublicKey, proof: String): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(InstanceKeyProof.message(nonce, keys))
            verify(Base64.getUrlDecoder().decode(proof))
        }

    private fun jwk(point: ByteArray): ByteArray {
        val encode = Base64.getUrlEncoder().withoutPadding()
        val x = encode.encodeToString(point.copyOfRange(1, 33))
        val y = encode.encodeToString(point.copyOfRange(33, 65))
        return """{"kty":"EC","crv":"P-256","x":"$x","y":"$y"}""".toByteArray()
    }

    private fun publicKey(jwk: String): PublicKey {
        val members = Json.parseToJsonElement(jwk).jsonObject
        fun coordinate(name: String) = BigInteger(1, Base64.getUrlDecoder().decode(members.getValue(name).jsonPrimitive.content))
        val p256 = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(coordinate("x"), coordinate("y")), p256))
    }

    /** P-256 software keys, signing a digest as AndroidKeystoreKeyStore does: NONEwithECDSA, DER. */
    private class SoftwareKeys : KeyStore {
        private val pairs = mutableMapOf<String, KeyPair>()

        fun public(id: String): PublicKey = pairs.getValue(id).public

        override fun createKey(purpose: KeyPurpose): String {
            val id = "${purpose.rawValue}-${pairs.size}"
            pairs[id] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            return id
        }

        // A P-256 SubjectPublicKeyInfo ends with the uncompressed point.
        override fun publicKey(id: String): ByteArray? = pairs[id]?.public?.encoded?.takeLast(65)?.toByteArray()

        override fun sign(id: String, digest: ByteArray): ByteArray =
            Signature.getInstance("NONEwithECDSA").run {
                initSign(pairs.getValue(id).private)
                update(digest)
                sign()
            }

        override fun deleteKey(id: String) {
            pairs.remove(id)
        }
    }
}
