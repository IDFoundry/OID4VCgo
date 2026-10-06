package dev.idfoundry.oid4vcwallet

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

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
    fun checkKeyStore() = runBlocking {
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

    /** StrongBox is required only where the device has it; elsewhere creating a key fails. */
    @Test
    fun strongBoxRequired() {
        val has = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val keys = store(AndroidKeystoreKeyStore.StrongBox.REQUIRED)
        val result = runCatching { keys.createKey(KeyPurpose.INSTANCE) }
        assertEquals("StrongBox present: $has", has, result.isSuccess)
        result.getOrNull()?.let { assertEquals(KeyProperties.SECURITY_LEVEL_STRONGBOX, keys.securityLevel(it)) }
    }

    /** A holder key requiring the holder signs only once its signature is authenticated. */
    @Test
    fun holderKeyNeedsAuthentication() {
        assumeTrue("needs a secure lock screen", context.getSystemService(KeyguardManager::class.java).isDeviceSecure)
        val digest = MessageDigest.getInstance("SHA-256").digest("presentation".toByteArray())

        val noAuthenticator = store(holderAuth = true)
        val id = noAuthenticator.createKey(KeyPurpose.HOLDER)
        expectFailure("signed without an authenticator") { noAuthenticator.sign(id, digest) }

        // An authenticator that doesn't authenticate: Keystore refuses the signature.
        val fake = store(holderAuth = true, authenticator = { })
        expectFailure("signed without the holder") { fake.sign(id, digest) }

        // Instance and DPoP keys sign silently, even when holder keys need the holder.
        val dpop = fake.createKey(KeyPurpose.DPOP)
        assertTrue(fake.sign(dpop, digest).isNotEmpty())
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
        val other = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(aliasPrefix = "org.idfoundry.oid4vcgo.othertest.${System.nanoTime()}."))
        val theirs = other.createKey(KeyPurpose.DPOP)
        keys.deleteKeys(emptySet())
        assertEquals(listOf(theirs), other.keyIDs())
        other.deleteKeys(emptySet())
    }

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
