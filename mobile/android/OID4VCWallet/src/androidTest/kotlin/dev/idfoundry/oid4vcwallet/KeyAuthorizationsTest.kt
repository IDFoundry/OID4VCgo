package dev.idfoundry.oid4vcwallet

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.time.Duration.Companion.seconds

/**
 * What Keystore says it enforces on each key AndroidKeystoreKeyStore
 * makes, read from the key's attestation (the AuthorizationList tags of
 * Android's Key Attestation schema): that every key needs the device
 * unlocked, that only holder keys need the holder and with which
 * authenticators, and that each key does only what its purpose needs.
 * The key's own KeyInfo says less: it has no unlocked-device flag.
 */
@RunWith(AndroidJUnit4::class)
class KeyAuthorizationsTest {
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val prefix = "org.idfoundry.oid4vcgo.authtest.${System.nanoTime()}."
    private val challenge = "authorizations-${System.nanoTime()}".toByteArray()

    private fun store(
        holderAuth: Boolean = false,
        agree: Boolean = false,
        timeout: kotlin.time.Duration = kotlin.time.Duration.ZERO,
    ) = AndroidKeystoreKeyStore(
        AndroidKeystoreKeyStore.Options(
            holderUserAuthentication = holderAuth,
            aliasPrefix = prefix,
            holderKeyAgreement = agree,
            holderAuthenticationTimeout = timeout,
        ),
        if (holderAuth) HolderAuthenticator { } else null,
    )

    @After
    fun cleanUp() {
        store().deleteKeys(emptySet())
    }

    /** Key [purpose]'s authorizations, from its attestation. */
    private fun AndroidKeystoreKeyStore.authorizations(purpose: KeyPurpose): Authorizations {
        val id = createKey(purpose, challenge)
        val leaf = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(attestationChain(id)!!.first())) as X509Certificate
        return Authorizations.of(leaf)
    }

    @Test
    fun everyKeyIsAP256SigningKey() {
        val keys = store()
        for (purpose in KeyPurpose.entries) {
            val a = keys.authorizations(purpose)
            assertEquals("$purpose algorithm", setOf(KM_ALGORITHM_EC), a.ints(TAG_ALGORITHM))
            assertEquals("$purpose curve", setOf(KM_EC_CURVE_P_256), a.ints(TAG_EC_CURVE))
            assertEquals("$purpose purposes", setOf(KM_PURPOSE_SIGN), a.ints(TAG_PURPOSE))
            assertTrue("$purpose digests ${a.ints(TAG_DIGEST)}", KM_DIGEST_SHA_2_256 in a.ints(TAG_DIGEST))
            assertEquals("$purpose generated in Keystore", setOf(KM_ORIGIN_GENERATED), a.ints(TAG_ORIGIN))
        }
    }

    /** From API 28, every key needs the device unlocked, as iOS's WhenUnlockedThisDeviceOnly. */
    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.P)
    fun everyKeyNeedsTheDeviceUnlocked() {
        val keys = store()
        for (purpose in KeyPurpose.entries) {
            val a = keys.authorizations(purpose)
            // The tag is in the attestation schema from version 3 (Keymaster 4).
            assumeTrue("attestation version ${a.version}", a.version >= 3)
            assertTrue("$purpose needs the device unlocked", a.has(TAG_UNLOCKED_DEVICE_REQUIRED))
        }
    }

    /** Without holderUserAuthentication, no key needs the holder: the app asks them itself. */
    @Test
    fun noKeyNeedsTheHolderWhenOff() {
        val keys = store(holderAuth = false)
        for (purpose in KeyPurpose.entries) {
            val a = keys.authorizations(purpose)
            assertTrue("$purpose needs no authentication", a.has(TAG_NO_AUTH_REQUIRED))
            assertNull("$purpose authenticator types", a.int(TAG_USER_AUTH_TYPE))
        }
    }

    /**
     * Holder keys need the holder's strong biometric or screen lock for
     * each signature; instance and DPoP keys still sign silently.
     */
    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.R)
    fun holderKeysNeedTheHolderForEachSignature() {
        assumeTrue(NEEDS_LOCK_SCREEN, context.getSystemService(KeyguardManager::class.java).isDeviceSecure)
        val keys = store(holderAuth = true)
        val holder = keys.authorizations(KeyPurpose.HOLDER)
        assertFalse("the holder key needs authentication", holder.has(TAG_NO_AUTH_REQUIRED))
        assertEquals("biometric or screen lock", HW_AUTH_PASSWORD or HW_AUTH_FINGERPRINT, holder.int(TAG_USER_AUTH_TYPE))
        assertNull("per signature, not for a window", holder.int(TAG_AUTH_TIMEOUT))
        for (purpose in listOf(KeyPurpose.INSTANCE, KeyPurpose.DPOP)) {
            val a = keys.authorizations(purpose)
            assertTrue("$purpose signs silently", a.has(TAG_NO_AUTH_REQUIRED))
            assertNull("$purpose authenticator types", a.int(TAG_USER_AUTH_TYPE))
        }
    }

    /** holderAuthenticationTimeout makes the holder key usable for that window after authenticating. */
    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.R)
    fun timeBoundHolderKeyHasItsWindow() {
        assumeTrue(NEEDS_LOCK_SCREEN, context.getSystemService(KeyguardManager::class.java).isDeviceSecure)
        val holder = store(holderAuth = true, timeout = 90.seconds).authorizations(KeyPurpose.HOLDER)
        assertFalse(holder.has(TAG_NO_AUTH_REQUIRED))
        assertEquals(HW_AUTH_PASSWORD or HW_AUTH_FINGERPRINT, holder.int(TAG_USER_AUTH_TYPE))
        assertEquals(90, holder.int(TAG_AUTH_TIMEOUT))
    }

    /** Only holder keys, and only with holderKeyAgreement, may agree keys. */
    @Test
    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.S)
    fun onlyHolderKeysAgreeKeys() {
        val keys = store(agree = true)
        assertEquals(setOf(KM_PURPOSE_SIGN, KM_PURPOSE_AGREE_KEY), keys.authorizations(KeyPurpose.HOLDER).ints(TAG_PURPOSE))
        for (purpose in listOf(KeyPurpose.INSTANCE, KeyPurpose.DPOP)) {
            assertEquals("$purpose purposes", setOf(KM_PURPOSE_SIGN), keys.authorizations(purpose).ints(TAG_PURPOSE))
        }
    }

    /** The attestation names this app as the key's owner. */
    @Test
    fun attestationNamesThisApp() {
        val app = store().authorizations(KeyPurpose.INSTANCE).raw(TAG_ATTESTATION_APPLICATION_ID)
        assertNotNull("an application ID", app)
        val name = context.packageName.toByteArray()
        assertTrue("names ${context.packageName}", (0..app!!.size - name.size).any { i -> name.indices.all { app[i + it] == name[it] } })
    }
}

/**
 * An attestation's KeyDescription, its two AuthorizationLists merged:
 * which list a tag is in says where it's enforced, which these tests
 * don't ask.
 */
private class Authorizations(val version: Int, private val tags: Map<Int, ByteArray>) {
    fun has(tag: Int) = tag in tags

    /** The tag's explicit content, DER. */
    fun raw(tag: Int): ByteArray? = tags[tag]

    /** An INTEGER or ENUMERATED tag's value. */
    fun int(tag: Int): Int? = tags[tag]?.let { Der(it).next().int() }

    /** A SET OF INTEGER tag's values, or an INTEGER tag's one. */
    fun ints(tag: Int): Set<Int> {
        val value = Der(tags[tag] ?: return emptySet()).next()
        return if (value.tag == 0x31) Der(value.content).all().map { it.int() }.toSet() else setOf(value.int())
    }

    companion object {
        fun of(leaf: X509Certificate): Authorizations {
            // An extension value is an OCTET STRING around the KeyDescription.
            val extension = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") ?: error("no attestation extension")
            val description = Der(Der(extension).next().content).next()
            val fields = Der(description.content).all()
            val tags = HashMap<Int, ByteArray>()
            // softwareEnforced, then hardwareEnforced (TEE or StrongBox).
            for (list in fields.subList(6, 8)) for (e in Der(list.content).all()) tags[e.contextTag()] = e.content
            return Authorizations(fields[0].int(), tags)
        }
    }
}

/** A DER reader, enough for an attestation's KeyDescription. */
private class Der(private val bytes: ByteArray) {
    private var pos = 0

    class Value(val tag: Int, val tagNumber: Int, val content: ByteArray) {
        fun int(): Int = BigInteger(content).toInt()

        /** An AuthorizationList entry's tag: [n] EXPLICIT, constructed context-specific. */
        fun contextTag(): Int {
            check(tag and 0xE0 == 0xA0) { "not a constructed context-specific tag: $tag" }
            return tagNumber
        }
    }

    fun all(): List<Value> = buildList { while (pos < bytes.size) add(next()) }

    fun next(): Value {
        val tag = bytes[pos++].toInt() and 0xFF
        var number = tag and 0x1F
        if (number == 0x1F) {
            // High tag number: base 128, most significant first.
            number = 0
            do {
                val b = bytes[pos++].toInt() and 0xFF
                number = (number shl 7) or (b and 0x7F)
            } while (b and 0x80 != 0)
        }
        var length = bytes[pos++].toInt() and 0xFF
        if (length and 0x80 != 0) {
            val n = length and 0x7F
            length = 0
            repeat(n) { length = (length shl 8) or (bytes[pos++].toInt() and 0xFF) }
        }
        val content = bytes.copyOfRange(pos, pos + length)
        pos += length
        return Value(tag, number, content)
    }
}

// Android Key Attestation's AuthorizationList tags and KeyMint's values
// (https://source.android.com/docs/security/features/keystore/attestation).
private const val TAG_PURPOSE = 1
private const val TAG_ALGORITHM = 2
private const val TAG_DIGEST = 5
private const val TAG_EC_CURVE = 10
private const val TAG_NO_AUTH_REQUIRED = 503
private const val TAG_USER_AUTH_TYPE = 504
private const val TAG_AUTH_TIMEOUT = 505
private const val TAG_UNLOCKED_DEVICE_REQUIRED = 509
private const val TAG_ORIGIN = 702
private const val TAG_ATTESTATION_APPLICATION_ID = 709

private const val KM_PURPOSE_SIGN = 2
private const val KM_PURPOSE_AGREE_KEY = 6
private const val KM_ALGORITHM_EC = 3
private const val KM_EC_CURVE_P_256 = 1
private const val KM_DIGEST_SHA_2_256 = 4
private const val KM_ORIGIN_GENERATED = 0
private const val HW_AUTH_PASSWORD = 1
private const val HW_AUTH_FINGERPRINT = 2

private const val NEEDS_LOCK_SCREEN = "needs a secure lock screen"
