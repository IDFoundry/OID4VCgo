package dev.idfoundry.oid4vcwallet

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
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
 * that needs the holder's biometrics or screen lock for each use. It
 * returns once [signature] is authorized — after BiometricPrompt
 * succeeds with it as the CryptoObject — and throws if the holder
 * cancels. The key store calls it on Go's thread, which waits.
 * [BiometricPromptAuthenticator] is the standard one.
 */
public fun interface HolderAuthenticator {
    public suspend fun authenticate(signature: Signature)
}

/**
 * The system's biometric prompt over the app's current activity
 * ([activity], null when none is showing), allowing a strong biometric
 * or the screen lock, as Face ID or the passcode on iOS.
 */
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
 * [authenticator] has authenticated the holder.
 */
public class AndroidKeystoreKeyStore(
    public val options: Options = Options(),
    private val authenticator: HolderAuthenticator? = null,
) : KeyStore {
    /** Where keys are made. */
    public enum class StrongBox {
        /** In StrongBox when the device has it, else the TEE. */
        PREFERRED,

        /** Only in StrongBox: creating a key fails on a device without it. */
        REQUIRED,

        /** Always the TEE: faster, where StrongBox's speed matters more. */
        OFF,
    }

    public data class Options(
        val strongBox: StrongBox = StrongBox.PREFERRED,
        /**
         * Require the holder's biometrics or screen lock for each
         * signature by a holder key — that is, to present a credential.
         * It needs a secure lock screen; without one, creating a holder
         * key fails.
         */
        val holderUserAuthentication: Boolean = true,
        /** Prefixes every key's alias. Keys under another prefix are never touched, by a sweep or anything else. */
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
            .setUnlockedDeviceRequired(true)
        // Only holder keys can require the holder: instance and DPoP keys
        // sign protocol messages silently (a Client Attestation PoP at PAR
        // and the token endpoint, a DPoP proof on every protocol request),
        // so prompting for them would interrupt each issuance several
        // times.
        if (purpose == KeyPurpose.HOLDER && options.holderUserAuthentication) {
            spec.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                // As iOS's user presence: a new fingerprint doesn't void the key.
                .setInvalidatedByBiometricEnrollment(false)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
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
     * Deletes every key this store holds except [keep], and returns how
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

    /** Where key [id] lives: StrongBox, the TEE, or software. */
    public fun securityLevel(id: String): Int? {
        val key = keystore.getKey(alias(id), null) as? PrivateKey ?: return null
        return info(key).securityLevel
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
