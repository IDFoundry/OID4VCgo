package dev.idfoundry.oid4vcwallet

import android.annotation.SuppressLint
import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import java.security.KeyStore as JavaKeyStore

/**
 * Authenticates the holder for one signature by a holder key: a key
 * that needs the holder's biometrics or screen lock for each use. The
 * key store calls it on Go's thread, which waits.
 * [BiometricPromptAuthenticator] is the standard one.
 */
public fun interface HolderAuthenticator {
    /**
     * Returns once [signature] is authorized — after BiometricPrompt
     * succeeds with it as the CryptoObject — and throws if the holder
     * cancels.
     */
    public suspend fun authenticate(signature: Signature)
}

// API 30's: it allows biometrics or the screen lock (setAllowedAuthenticators),
// as the per-use holder keys it's for do, which need 30 too.
/**
 * The system's biometric prompt over the app's current activity
 * (`activity`'s, null when none is showing), allowing a strong biometric
 * or the screen lock, as Face ID or the passcode on iOS.
 *
 * A prompt shown while the wallet signs stays until the holder answers
 * or dismisses it: cancelling the coroutine that started the presentation
 * doesn't dismiss it yet.
 */
@RequiresApi(Build.VERSION_CODES.R)
public class BiometricPromptAuthenticator(
    private val activity: () -> Activity?,
    private val title: String = "Confirm it's you",
    private val subtitle: String? = "Your credential's key signs what you share.",
) : HolderAuthenticator {
    override suspend fun authenticate(signature: Signature): Unit = withContext(Dispatchers.Main) {
        val host = activity() ?: throw StoreException("no activity to ask the holder in")
        suspendCancellableCoroutine { cont ->
            val cancel = CancellationSignal()
            cont.invokeOnCancellation { cancel.cancel() }
            val prompt = BiometricPrompt.Builder(host)
                .setTitle(title)
                .apply { subtitle?.let(::setSubtitle) }
                .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
                .build()
            prompt.authenticate(
                BiometricPrompt.CryptoObject(signature), cancel, host.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        cont.resume(Unit)
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        cont.resumeWithException(StoreException("the holder wasn't authenticated: $errString"))
                    }
                },
            )
        }
    }
}

/**
 * The wallet's keys, in Android Keystore: P-256 keys whose private
 * halves never leave its secure hardware — StrongBox where the device
 * has it ([Options.strongBox]), else the TEE. Each key's ID is its
 * Keystore alias after [Options.aliasPrefix]. Keys are usable only while
 * the device is unlocked, and holder keys, if
 * [Options.holderUserAuthentication], each time they sign only after
 * [authenticator] has authenticated the holder: the store refuses to be
 * made without one then.
 */
public class AndroidKeystoreKeyStore(
    /** How the store makes keys. */
    public val options: Options = Options(),
    private val authenticator: HolderAuthenticator? = null,
) : KeyStore {
    init {
        // Per-use authentication by biometrics or the screen lock is API
        // 30's: below it, fail now rather than make weaker keys.
        check(!options.holderUserAuthentication || Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            "holderUserAuthentication needs API 30; set it false and authenticate the holder in the app"
        }
        // Without one, holder keys could never sign: say so now, not at
        // the first presentation.
        require(!options.holderUserAuthentication || authenticator != null) {
            "holderUserAuthentication needs an authenticator (BiometricPromptAuthenticator, say)"
        }
        // deleteKeys deletes every key under the prefix: an empty one, or
        // one over the credential store's key, would delete that too.
        require(options.aliasPrefix.isNotEmpty() && !FileCredentialStore.DEFAULT_KEY_ALIAS.startsWith(options.aliasPrefix)) {
            "aliasPrefix must be non-empty and not cover the credential store's key"
        }
    }

    /** Where keys are made. */
    public enum class StrongBox {
        /** In StrongBox when the device has it, else the TEE. */
        PREFERRED,

        /** Only in StrongBox: creating a key fails on a device without it. */
        REQUIRED,

        /** Always the TEE: faster, where StrongBox's speed matters more. */
        OFF,
    }

    /**
     * How an [AndroidKeystoreKeyStore] makes keys: by default in StrongBox where the device has
     * it, holder keys asking for the holder each time.
     */
    public data class Options(
        /** Where keys are made. */
        val strongBox: StrongBox = StrongBox.PREFERRED,
        /**
         * Require the holder's biometrics or screen lock for each
         * signature by a holder key — that is, to present a credential.
         * It needs a secure lock screen; without one, creating a holder
         * key fails. It needs API 30: below it the key store refuses it
         * at construction; set it false there, and authenticate the
         * holder in the app before presenting.
         */
        val holderUserAuthentication: Boolean = true,
        /**
         * Prefixes every key's alias. Keys under another prefix are never
         * touched, by a sweep or anything else. It must be non-empty, and
         * must not cover [FileCredentialStore]'s default key alias, which a
         * sweep would then delete.
         */
        val aliasPrefix: String = "org.idfoundry.oid4vcgo.key.",
    )

    private val keystore: JavaKeyStore = JavaKeyStore.getInstance(PROVIDER).apply { load(null) }

    /** Keystore keys survive the app quitting. */
    override val isDurable: Boolean get() = true

    override fun createKey(purpose: KeyPurpose): String {
        val id = UUID.randomUUID().toString()
        val spec = KeyGenParameterSpec.Builder(alias(id), KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // Go hands over a SHA-256 digest: NONEwithECDSA signs it as is.
            .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
        // API 28's: below it, a key works while the device is locked,
        // once unlocked since boot.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setUnlockedDeviceRequired(true)
        // Only holder keys can require the holder: instance and DPoP keys
        // sign protocol messages silently (a Client Attestation PoP at PAR
        // and the token endpoint, a DPoP proof on every protocol request),
        // so prompting for them would interrupt each issuance several
        // times.
        // The constructor refused holderUserAuthentication below API 30.
        if (purpose == KeyPurpose.HOLDER && options.holderUserAuthentication && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            spec.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                // As iOS's user presence: a new fingerprint doesn't void the key.
                .setInvalidatedByBiometricEnrollment(false)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        // StrongBox is API 28's: below it, PREFERRED is the TEE and
        // REQUIRED fails, as on a device without it.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            if (options.strongBox == StrongBox.REQUIRED) throw StoreException("StrongBox needs API 28")
            generator.initialize(spec.build())
            generator.generateKeyPair()
            return id
        }
        when (options.strongBox) {
            StrongBox.OFF -> generator.initialize(spec.build())
            StrongBox.REQUIRED -> generator.initialize(spec.setIsStrongBoxBacked(true).build())
            StrongBox.PREFERRED -> try {
                generator.initialize(spec.setIsStrongBoxBacked(true).build())
                generator.generateKeyPair()
                return id
            } catch (e: StrongBoxUnavailableException) {
                generator.initialize(spec.setIsStrongBoxBacked(false).build())
            }
        }
        generator.generateKeyPair()
        return id
    }

    override fun publicKey(id: String): ByteArray? {
        val pub = keystore.getCertificate(alias(id))?.publicKey as? ECPublicKey ?: return null
        return byteArrayOf(4) + fixed(pub.w.affineX) + fixed(pub.w.affineY)
    }

    override fun sign(id: String, digest: ByteArray): ByteArray {
        val key = keystore.getKey(alias(id), null) as? PrivateKey ?: throw StoreException("no key $id")
        val signature = Signature.getInstance("NONEwithECDSA").apply { initSign(key) }
        if (requiresHolder(key)) {
            val auth = authenticator ?: throw StoreException("holder key $id needs a HolderAuthenticator to sign")
            // On Go's thread, never the main one: it waits for the holder.
            runBlocking { auth.authenticate(signature) }
        }
        signature.update(digest)
        return signature.sign()
    }

    override fun deleteKey(id: String) {
        keystore.deleteEntry(alias(id))
    }

    /** The IDs of every key this store holds (under its alias prefix). */
    public fun keyIDs(): List<String> =
        keystore.aliases().toList().filter { it.startsWith(options.aliasPrefix) }.map { it.removePrefix(options.aliasPrefix) }

    /**
     * Deletes every key this store holds except [except], and returns how
     * many it deleted. `Wallet.sweepOrphanedKeys` calls it with the keys
     * the wallet's credentials are bound to.
     */
    public fun deleteKeys(except: Set<String>): Int {
        var deleted = 0
        for (id in keyIDs()) {
            if (id !in except) {
                deleteKey(id)
                deleted++
            }
        }
        return deleted
    }

    /**
     * Where key [id] lives, as a KeyProperties.SECURITY_LEVEL_ value:
     * StrongBox, the TEE, or software. Android 11 can't tell StrongBox from
     * the TEE: there, a key in secure hardware is the TEE's. (The
     * constants are API 31's, but compile-time ints: they work on 30.)
     */
    @SuppressLint("InlinedApi")
    public fun securityLevel(id: String): Int? {
        val key = keystore.getKey(alias(id), null) as? PrivateKey ?: return null
        val info = info(key)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) return info.securityLevel
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT else KeyProperties.SECURITY_LEVEL_SOFTWARE
    }

    private fun requiresHolder(key: PrivateKey): Boolean = info(key).isUserAuthenticationRequired

    private fun info(key: PrivateKey): KeyInfo =
        KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)

    private fun alias(id: String): String {
        if (id.isEmpty() || !id.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }) throw StoreException("malformed key ID")
        return options.aliasPrefix + id
    }

    private fun fixed(n: BigInteger): ByteArray {
        val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - b.size) + b
    }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
