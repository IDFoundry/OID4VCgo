package dev.idfoundry.oid4vcwallet

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * Android Keystore keys through the wallet: Go signs with them and checks
 * the signatures (CheckKeyStore). The holder-key tests need a secure
 * lock screen (CI sets a PIN on the emulator).
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreKeyStoreTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val prefix = "org.idfoundry.oid4vcgo.test.${System.nanoTime()}."

    private fun store(
        strongBox: AndroidKeystoreKeyStore.StrongBox = AndroidKeystoreKeyStore.StrongBox.PREFERRED,
        holderAuth: Boolean = false,
        authenticator: HolderAuthenticator? = null,
    ) = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(strongBox, holderAuth, prefix), authenticator)

    @After
    fun cleanUp() {
        store().deleteKeys(emptySet())
    }

    @Test
    fun checkKeyStore(): Unit = runBlocking {
        val keys = store()
        assertEquals(KeyPurpose.entries.toList(), OID4VC.checkKeyStore(keys))
        assertTrue("every key was deleted", keys.keyIDs().isEmpty())
    }

    @Test
    fun keysAreInSecureHardware() {
        val keys = store()
        val id = keys.createKey(KeyPurpose.DPOP)
        val level = keys.securityLevel(id)
        // An emulator's Keystore is software; a device's is the TEE or StrongBox.
        val hardware = level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT || level == KeyProperties.SECURITY_LEVEL_STRONGBOX
        assertTrue("security level $level", hardware || isEmulator)
        val pub = keys.publicKey(id)!!
        assertEquals(65, pub.size)
        assertEquals(4.toByte(), pub[0])
        assertNull(keys.publicKey("no-such-key"))
    }

    /**
     * A key made with a challenge carries an Android Key Attestation
     * chain: the leaf certifies the key, and its attestation extension
     * holds the challenge. One made without has none.
     */
    @Test
    fun keyMadeWithAChallengeIsAttested() {
        val keys = store()
        val challenge = "wallet-provider-challenge-${System.nanoTime()}".toByteArray()
        for (purpose in KeyPurpose.entries) {
            val id = keys.createKey(purpose, challenge)
            val chain = keys.attestationChain(id)!!.map {
                CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(it)) as X509Certificate
            }
            assertTrue("a chain to a root, not one certificate", chain.size > 1)
            assertArrayEquals(spki(keys.publicKey(id)!!), chain[0].publicKey.encoded)
            for (i in 0 until chain.size - 1) chain[i].verify(chain[i + 1].publicKey)
            val extension = chain[0].getExtensionValue("1.3.6.1.4.1.11129.2.1.17")!!
            assertTrue("the challenge is in the attestation", contains(extension, challenge))
        }
        assertNull("no challenge, no attestation", keys.attestationChain(keys.createKey(KeyPurpose.HOLDER)))
        assertNull(keys.attestationChain("no-such-key"))
        expectFailure("took a 129-byte challenge") { keys.createKey(KeyPurpose.HOLDER, ByteArray(129)) }
        expectFailure("took an empty challenge") { keys.createKey(KeyPurpose.HOLDER, ByteArray(0)) }
    }

    /** The wallet finds a key by its public key, for the Wallet Provider's evidence. */
    @Test
    fun keyIDByPublicKey() {
        val keys = store()
        val id = keys.createKey(KeyPurpose.HOLDER)
        assertEquals(id, keys.keyID(keys.publicKey(id)!!))
        assertNull(keys.keyID(ByteArray(65).also { it[0] = 4 }))
    }

    private fun contains(haystack: ByteArray, needle: ByteArray): Boolean =
        (0..haystack.size - needle.size).any { i -> needle.indices.all { haystack[i + it] == needle[it] } }

    /** StrongBox is required only where the device has it; elsewhere creating a key fails. */
    @Test
    fun strongBoxRequired() {
        val has = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val keys = store(AndroidKeystoreKeyStore.StrongBox.REQUIRED)
        val result = runCatching { keys.createKey(KeyPurpose.INSTANCE) }
        assertEquals("StrongBox present: $has", has, result.isSuccess)
        // Android 11 reports secure hardware, not which.
        val expected = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) KeyProperties.SECURITY_LEVEL_STRONGBOX else KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        result.getOrNull()?.let { assertEquals(expected, keys.securityLevel(it)) }
    }

    /** A holder key requiring the holder signs only once its signature is authenticated. */
    // Per-use authentication is API 30's.
    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.R)
    fun holderKeyNeedsAuthentication() {
        assumeTrue("needs a secure lock screen", context.getSystemService(KeyguardManager::class.java).isDeviceSecure)
        val digest = sha256().digest("presentation".toByteArray())

        // Without an authenticator, holder keys could never sign: refused up front.
        try {
            store(holderAuth = true)
            fail("made a store whose holder keys can never sign")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message, e.message!!.contains("authenticator"))
        }

        // An authenticator that doesn't authenticate: Keystore refuses the signature.
        val fake = store(holderAuth = true, authenticator = { })
        val id = fake.createKey(KeyPurpose.HOLDER)
        expectFailure("signed without the holder") { fake.sign(id, digest) }

        // Instance and DPoP keys sign silently, even when holder keys need the holder.
        val dpop = fake.createKey(KeyPurpose.DPOP)
        assertTrue(fake.sign(dpop, digest).isNotEmpty())
    }

    /** Below API 30, holder keys can't require the holder each time: the store refuses to pretend. */
    @Test
    @SdkSuppress(maxSdkVersion = Build.VERSION_CODES.Q)
    fun holderAuthenticationNeedsAPI30() {
        try {
            store(holderAuth = true)
            fail("made a store whose holder keys can't require the holder")
        } catch (e: IllegalStateException) {
            assertTrue(e.message, e.message!!.contains("API 30"))
        }
        // Without it, keys work: the app authenticates the holder itself.
        val keys = store(holderAuth = false)
        val id = keys.createKey(KeyPurpose.HOLDER)
        assertTrue(keys.sign(id, sha256().digest(byteArrayOf(1))).isNotEmpty())
    }

    @Test
    fun sweepKeepsOnlyWhatsAsked() {
        val keys = store()
        val kept = keys.createKey(KeyPurpose.HOLDER)
        keys.createKey(KeyPurpose.INSTANCE)
        keys.createKey(KeyPurpose.DPOP)
        assertEquals(2, keys.deleteKeys(setOf(kept)))
        assertEquals(listOf(kept), keys.keyIDs())
        // Another prefix's keys are never touched.
        val other = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = "org.idfoundry.oid4vcgo.othertest.${System.nanoTime()}."))
        val theirs = other.createKey(KeyPurpose.DPOP)
        keys.deleteKeys(emptySet())
        assertEquals(listOf(theirs), other.keyIDs())
        other.deleteKeys(emptySet())
    }

    /** From API 31, a holder key made to agree keys agrees the secret the peer computes, and still signs. */
    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.S)
    fun holderKeyAgreesKeys() {
        val keys = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix, holderKeyAgreement = true))
        val id = keys.createKey(KeyPurpose.HOLDER)
        val peer = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val peerPub = peer.public as ECPublicKey
        val point = byteArrayOf(4) + fixed(peerPub.w.affineX) + fixed(peerPub.w.affineY)
        val z = keys.agree(id, point)
        val holderPub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki(keys.publicKey(id)!!)))
        val want = KeyAgreement.getInstance("ECDH").apply {
            init(peer.private)
            doPhase(holderPub, true)
        }.generateSecret()
        assertArrayEquals(want, z)
        assertTrue(keys.sign(id, sha256().digest(byteArrayOf(1))).isNotEmpty())
        // Instance and DPoP keys never agree keys.
        val dpop = keys.createKey(KeyPurpose.DPOP)
        expectUnsupported { keys.agree(dpop, point) }
    }

    /** A holder key made without key agreement reports it, so the wallet signs. */
    @Test
    fun signOnlyHolderKeyDoesntAgree() {
        val keys = store()
        val id = keys.createKey(KeyPurpose.HOLDER)
        expectUnsupported { keys.agree(id, ByteArray(65).also { it[0] = 4 }) }
    }

    private fun expectUnsupported(body: () -> Unit) {
        try {
            body()
            fail("agreed with a key that can't")
        } catch (e: KeyAgreementUnsupportedException) {
            // As expected.
        }
    }

    private fun fixed(n: BigInteger): ByteArray {
        val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - b.size) + b
    }

    // An uncompressed P-256 point as a SubjectPublicKeyInfo.
    private fun spki(point: ByteArray): ByteArray =
        "3059301306072a8648ce3d020106082a8648ce3d030107034200".chunked(2).map { it.toInt(16).toByte() }.toByteArray() + point

    @Test
    fun malformedIDs() {
        expectFailure("accepted a malformed ID") { store().sign("../x", ByteArray(32)) }
    }

    private val isEmulator = android.os.Build.HARDWARE in setOf("ranchu", "goldfish") || android.os.Build.FINGERPRINT.contains("generic")

    private fun expectFailure(what: String, body: () -> Unit) {
        try {
            body()
            fail(what)
        } catch (e: Exception) {
            // As expected.
        }
    }
}

private fun sha256(): MessageDigest = MessageDigest.getInstance("SHA-256")
