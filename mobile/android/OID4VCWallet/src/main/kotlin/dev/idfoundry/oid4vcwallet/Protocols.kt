package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.runBlocking
import java.io.IOException
import dev.idfoundry.oid4vcwallet.gomobile.mobile.CredentialStore as MobileCredentialStore
import dev.idfoundry.oid4vcwallet.gomobile.mobile.KeyAgreement as MobileKeyAgreement
import dev.idfoundry.oid4vcwallet.gomobile.mobile.KeyStore as MobileKeyStore
import dev.idfoundry.oid4vcwallet.gomobile.mobile.WalletProvider as MobileWalletProvider

/**
 * What a key is for.
 *
 * @property rawValue The purpose as the Go side names it.
 */
public enum class KeyPurpose(public val rawValue: String) {
    /**
     * The wallet instance key a Wallet Attestation binds; it signs
     * silently, at each issuance's authorization.
     */
    INSTANCE("instance"),

    /** The key access tokens are bound to; it signs silently, on every request to the issuer. */
    DPOP("dpop"),

    /**
     * The key a credential is bound to; it signs only when presenting,
     * and may require user authentication.
     */
    HOLDER("holder");

    internal companion object {
        fun fromRawValue(raw: String): KeyPurpose? = entries.firstOrNull { it.rawValue == raw }
    }
}

/**
 * The wallet's keys: P-256 keys whose private halves never leave the
 * store (Android Keystore). An exception it throws reaches Go and comes
 * back as a [WalletException.Code.platform] error. Go calls it on its own
 * thread, never the main one.
 */
public interface KeyStore {
    /** Creates a P-256 key for [purpose] and returns its ID. */
    public fun createKey(purpose: KeyPurpose): String

    /**
     * The key's public key as an uncompressed X9.63 point
     * (0x04 || X || Y), or null when there's no such key.
     */
    public fun publicKey(id: String): ByteArray?

    /**
     * Signs a SHA-256 digest with the key, returning an ASN.1 DER ECDSA
     * signature. A holder key may ask the holder to authenticate here.
     */
    public fun sign(id: String, digest: ByteArray): ByteArray

    /** Deletes the key; deleting one that doesn't exist isn't an error. */
    public fun deleteKey(id: String)

    /**
     * Whether keys survive the app quitting. Receiving credentials needs
     * a durable store unless the configuration is for development.
     */
    public val isDurable: Boolean get() = false
}

/**
 * ECDH with the wallet's holder keys inside the key store, for deviceMac
 * in person (ISO/IEC 18013-5 §9.1.3.5). A [KeyStore] that is also one is
 * used for it when [WalletConfiguration.proximityDeviceAuth] is
 * [WalletConfiguration.ProximityDeviceAuth.MAC_PREFERRED].
 */
public fun interface KeyAgreement {
    /**
     * Runs ECDH between key [id] and [peerPublicKey], an uncompressed
     * X9.63 P-256 point, and returns the 32-byte shared secret. Throws
     * [KeyAgreementUnsupportedException] for a key that can't agree keys
     * (made for signing only): the wallet then signs instead.
     */
    public fun agree(id: String, peerPublicKey: ByteArray): ByteArray
}

/** A key that can't agree keys: the wallet signs instead of using a MAC. */
public class KeyAgreementUnsupportedException(message: String) : Exception(message)

/**
 * The wallet's credentials, as opaque records kept by ID under the
 * platform's data protection. An exception it throws reaches Go and
 * comes back as a [WalletException.Code.platform] error.
 */
public interface CredentialStore {
    /** Stores [record] under [id], replacing any record with that ID. */
    public fun put(id: String, record: ByteArray)

    /** The record stored under [id], or null. */
    public fun record(id: String): ByteArray?

    /** Every record. */
    public fun records(): List<ByteArray>

    /** Deletes the record; deleting one that doesn't exist isn't an error. */
    public fun delete(id: String)

    /**
     * Replaces the record under [id] with [record] — or deletes it, when
     * [record] is null — only if what's stored there is, byte for byte,
     * [expected] (null: no record), and returns what was stored before,
     * whether or not it replaced it.
     *
     * It must be atomic across every process sharing the store: nothing
     * may write the record between its read and its write, so [put] and
     * [delete] take the same lock, one every process sees (a file lock,
     * not only a JVM lock). The wallet changes records only this way, so
     * two processes never both present one copy as unused, complete one
     * authorization, or redeem one refresh token. [FileCredentialStore]
     * locks a file in its directory. Compare the record as [record]
     * returns it: decrypted, if the store encrypts.
     */
    public fun compareAndSwap(id: String, expected: ByteArray?, record: ByteArray?): ByteArray?

    /**
     * Whether records survive the app quitting. Receiving credentials
     * needs a durable store unless the configuration is for development:
     * it also keeps an authorization in progress while the holder is at
     * the issuer's pages.
     */
    public val isDurable: Boolean get() = false
}

/**
 * The Wallet Provider's backend, which attests the wallet and its keys
 * (HAIP 1.0 §4.4.1, §4.5.1). Keys are public JWKs, as JSON; the results
 * are compact JWTs. A real one attests only after checking platform
 * evidence (Key Attestation) that it's talking to the genuine app.
 */
public interface WalletProvider {
    /** A Wallet Attestation binding [instanceKey] to [clientID]. */
    public suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String

    /** A Key Attestation over [keys], carrying the issuer's [nonce]. */
    public suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String
}

// Adapters to gomobile's interfaces.

/** A KeyStore as gomobile's KeyStore. */
internal class KeyStoreAdapter(private val store: KeyStore) : MobileKeyStore {
    override fun createKey(purpose: String): String {
        val p = KeyPurpose.fromRawValue(purpose) ?: throw StoreException("unknown key purpose $purpose")
        return store.createKey(p)
    }

    override fun publicKey(id: String): ByteArray = store.publicKey(id) ?: ByteArray(0)

    override fun sign(id: String, digest: ByteArray): ByteArray = store.sign(id, digest)

    override fun deleteKey(id: String) = store.deleteKey(id)

    override fun durable(): Boolean = store.isDurable
}

/**
 * A KeyAgreement as gomobile's: a key that can't agree keys is marked
 * so Go signs instead.
 */
internal class KeyAgreementAdapter(private val agreement: KeyAgreement) : MobileKeyAgreement {
    override fun agree(id: String, peerPublicKey: ByteArray): ByteArray =
        try {
            agreement.agree(id, peerPublicKey)
        } catch (e: KeyAgreementUnsupportedException) {
            throw StoreException("[no_key_agreement] " + (e.message ?: "unsupported"))
        }
}

/** A CredentialStore as gomobile's CredentialStore. */
internal class CredentialStoreAdapter(private val store: CredentialStore) : MobileCredentialStore {
    override fun put(id: String, record: ByteArray) = store.put(id, record)

    override fun get(id: String): ByteArray = store.record(id) ?: ByteArray(0)

    override fun list(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write('['.code)
        store.records().forEachIndexed { i, r ->
            if (i > 0) out.write(','.code)
            out.write(r)
        }
        out.write(']'.code)
        return out.toByteArray()
    }

    override fun delete(id: String) = store.delete(id)

    // Go's empty record is no record, either way.
    override fun compareAndSwap(id: String, expected: ByteArray?, record: ByteArray?): ByteArray =
        store.compareAndSwap(id, expected?.takeIf { it.isNotEmpty() }, record?.takeIf { it.isNotEmpty() }) ?: ByteArray(0)

    override fun durable(): Boolean = store.isDurable
}

/**
 * A WalletProvider as gomobile's WalletProvider. Go calls it on its own
 * thread — never the main thread, since every Go call is made off it —
 * and waits; this bridges that wait to the suspending provider. An
 * IOException is marked as a network failure, which Go reports as
 * [WalletException.Code.network] (retryable) rather than
 * [WalletException.Code.platform].
 */
internal class WalletProviderAdapter(private val provider: WalletProvider) : MobileWalletProvider {
    override fun walletAttestation(clientID: String, instanceKeyJWK: ByteArray): ByteArray =
        wait { provider.walletAttestation(clientID, instanceKeyJWK) }.toByteArray()

    override fun keyAttestation(keysJWK: ByteArray, nonce: String): ByteArray {
        val keys = try {
            json.parseToJsonElement(keysJWK.decodeToString()) as kotlinx.serialization.json.JsonArray
        } catch (e: Exception) {
            throw StoreException("the keys to attest aren't a JSON array")
        }
        val each = keys.map { it.toString().toByteArray() }
        return wait { provider.keyAttestation(each, nonce) }.toByteArray()
    }

    private fun <T> wait(body: suspend () -> T): T =
        try {
            runBlocking { body() }
        } catch (e: IOException) {
            throw StoreException("[network] " + (e.message ?: e.javaClass.simpleName))
        }
}

/** A store's or provider's own failure. */
public class StoreException(message: String) : Exception(message)
