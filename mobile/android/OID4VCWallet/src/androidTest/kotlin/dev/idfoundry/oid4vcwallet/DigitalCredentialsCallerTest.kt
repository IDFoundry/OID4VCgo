package dev.idfoundry.oid4vcwallet

import android.content.pm.PackageManager
import android.content.pm.Signature
import android.content.pm.SigningInfo
import android.os.Build
import androidx.annotation.RequiresApi
import androidx.credentials.provider.CallingAppInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/**
 * DigitalCredentials' checks on who is asking: whether the app that
 * started the provider activity is Credential Manager, and which origin
 * the request is answered for. The test app itself, signed with the
 * debug key, stands in for both the caller and the apps the allowlists
 * name.
 *
 * SigningInfo is API 28's: it appears only in [Signing]'s signatures, not
 * this class's, which JUnit reflects over on API 26 too.
 */
@RunWith(AndroidJUnit4::class)
class DigitalCredentialsCallerTest {
    private val context = InstrumentationRegistry.getInstrumentation().context
    private val pm: PackageManager = context.packageManager
    private val pkg: String = context.packageName

    @RequiresApi(Build.VERSION_CODES.P)
    private object Signing {
        fun of(pm: PackageManager, pkg: String): SigningInfo =
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo!!

        fun caller(pm: PackageManager, pkg: String, origin: String?): CallingAppInfo = CallingAppInfo(pkg, of(pm, pkg), origin)

        @RequiresApi(Build.VERSION_CODES.VANILLA_ICE_CREAM)
        fun signedBy(pkg: String, signers: List<Signature>): CallingAppInfo =
            CallingAppInfo(pkg, SigningInfo(SigningInfo.VERSION_SIGNING_BLOCK_V2, signers, emptyList(), null), null)
    }

    private val certificate: Signature by lazy {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            Signing.of(pm, pkg).apkContentsSigners.single()
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures!!.single()
        }
    }

    private val sha256: ByteArray by lazy { MessageDigest.getInstance("SHA-256").digest(certificate.toByteArray()) }

    private fun caller(origin: String?): CallingAppInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) Signing.caller(pm, pkg, origin)
        else CallingAppInfo(pkg, listOf(certificate), origin)

    /** A privileged-browsers allowlist naming [packageName] signed with [fingerprint]. */
    private fun allowlist(packageName: String, fingerprint: ByteArray): String {
        val hex = fingerprint.joinToString(":") { "%02X".format(it) }
        return """{"apps":[{"type":"android","info":{"package_name":"$packageName",""" +
            """"signatures":[{"build":"release","cert_fingerprint_sha256":"$hex"}]}}]}"""
    }

    private fun wrong(bytes: ByteArray): ByteArray = bytes.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

    @Test
    fun anAppIsNotCredentialManagerByDefault() {
        // Debug-signed, not with the platform's key, and on no list.
        assertFalse(DigitalCredentials.isCredentialManager(pm, pkg, emptyList()))
        assertFalse(DigitalCredentials.isCredentialManager(pm, pkg, listOf(DigitalCredentials.GOOGLE_PLAY_SERVICES)))
    }

    @Test
    fun credentialManagerByPackageAndCertificate() {
        val pinned = DigitalCredentials.CredentialManagerApp(pkg, listOf(sha256))
        assertTrue(DigitalCredentials.isCredentialManager(pm, pkg, listOf(pinned)))
        // Any one of an app's pinned certificates will do.
        val rotated = DigitalCredentials.CredentialManagerApp(pkg, listOf(wrong(sha256), sha256))
        assertTrue(DigitalCredentials.isCredentialManager(pm, pkg, listOf(rotated)))
    }

    @Test
    fun credentialManagerNeedsItsCertificate() {
        // The right package, signed with another key: an app squatting
        // on Credential Manager's package name.
        val otherKey = DigitalCredentials.CredentialManagerApp(pkg, listOf(wrong(sha256)))
        assertFalse(DigitalCredentials.isCredentialManager(pm, pkg, listOf(otherKey)))
        assertFalse(DigitalCredentials.isCredentialManager(pm, pkg, listOf(DigitalCredentials.CredentialManagerApp(pkg, emptyList()))))
        // The right certificate under another package name.
        val otherPackage = DigitalCredentials.CredentialManagerApp("$pkg.other", listOf(sha256))
        assertFalse(DigitalCredentials.isCredentialManager(pm, pkg, listOf(otherPackage)))
    }

    @Test
    fun aPrivilegedBrowserVouchesForItsPage() {
        val origin = "https://verifier.example"
        assertEquals(origin, DigitalCredentials.callerOrigin(caller(origin), allowlist(pkg, sha256)))
    }

    @Test
    fun anUnprivilegedBrowsersPageHasNoOrigin() {
        val origin = "https://verifier.example"
        // Neither the page's origin nor, falling back, the app's own.
        assertNull(DigitalCredentials.callerOrigin(caller(origin), allowlist(pkg, wrong(sha256))))
        assertNull(DigitalCredentials.callerOrigin(caller(origin), allowlist("$pkg.other", sha256)))
        assertNull(DigitalCredentials.callerOrigin(caller(origin), """{"apps":[]}"""))
        assertNull(DigitalCredentials.callerOrigin(caller(origin), "not JSON"))
    }

    @Test
    fun anAppIsItsSigningKey() {
        val appOrigin = DigitalCredentials.appOrigin(certificate.toByteArray())
        assertNotNull(appOrigin)
        assertTrue(appOrigin!!.startsWith("android:apk-key-hash:"))
        assertEquals(appOrigin, DigitalCredentials.callerOrigin(caller(null), allowlist(pkg, wrong(sha256))))
    }

    /**
     * From API 28 the platform reports such an app's several signers;
     * before it, the compat layer reports them as its certificate history
     * instead, and never multiple signers, so the wallet counts them.
     */
    @Test
    fun anAppSignedBySeveralKeysHasNoOrigin() {
        val other = Signature(ByteArray(64) { it.toByte() })
        val caller = when {
            Build.VERSION.SDK_INT < Build.VERSION_CODES.P -> CallingAppInfo(pkg, listOf(certificate, other), null)
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM -> Signing.signedBy(pkg, listOf(certificate, other))
            // API 28–34 has no public way to make a SigningInfo.
            else -> null
        }
        assumeTrue(caller != null)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            assertTrue(caller!!.signingInfoCompat.hasMultipleSigners)
        } else {
            assertEquals(2, caller!!.signingInfoCompat.signingCertificateHistory.size)
        }
        assertNull(DigitalCredentials.callerOrigin(caller, allowlist(pkg, sha256)))
    }
}
