package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.IOException
import java.util.Base64
import dev.idfoundry.oid4vcwallet.gomobile.mobile.CallbackCanceller as MobileCallbackCanceller
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
     * The key a credential copy is bound to; it signs when presenting,
     * and the Credential Request's jwt proof when receiving or
     * refreshing, and may require user authentication.
     */
    HOLDER("holder");

    internal companion object {
        fun fromRawValue(raw: String): KeyPurpose? = entries.firstOrNull { it.rawValue == raw }
    }
}

/**
 * The wallet's keys: P-256 keys whose private halves never leave the
 * store (Android Keystore). An exception it throws reaches Go and comes
 * back as a [WalletException.Code.platform] error — a
 * [HolderCancelledException] from [sign], the holder dismissing its
 * prompt, as [WalletException.Code.cancelled]. Go calls it on its own
 * thread, never the main one.
 */
public interface KeyStore {
    /** Creates a P-256 key for [purpose] and returns its ID. */
    public fun createKey(purpose: KeyPurpose): String

    /**
     * Creates a P-256 key for [purpose], as [createKey] does, and returns
     * its ID. When [attestationChallenge] isn't null, a store that can
     * attest its keys makes the platform attest this one over it, so
     * [attestationChain] returns its chain. The wallet calls this one,
     * with the challenge its [WalletProvider.attestationChallenge] gave
     * for [purpose], and only when it gave one: without a challenge it
     * calls [createKey]. The default ignores the challenge and calls
     * [createKey]: a store that can't attest keys needn't implement it.
     * A store delegating to another (`KeyStore by …`) that overrides
     * [createKey] should override this one too, since delegation forwards it.
     */
    public fun createKey(purpose: KeyPurpose, attestationChallenge: ByteArray?): String = createKey(purpose)

    /**
     * Key [id]'s platform attestation: its certificate chain, each
     * certificate DER-encoded, the key's own first. Null when the store
     * has none for it — the key wasn't made with a challenge, or the
     * store can't attest keys, as the default can't. The wallet hands it
     * to the [WalletProvider] with the key ([KeyEvidence]).
     */
    public fun attestationChain(id: String): List<ByteArray>? = null

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

    /**
     * Ends a [sign] (or [KeyAgreement.agree]) with key [id] that's
     * waiting for the holder, because the call it's for was cancelled —
     * the coroutine that started the presentation, issuance or refresh:
     * dismiss the prompt, so [sign] throws, and the call ends at once.
     * The wallet calls it on another thread while [sign] runs, possibly
     * more than once, and possibly when nothing for [id] is waiting:
     * ignore it then. [AndroidKeystoreKeyStore] cancels its
     * [HolderAuthenticator]'s coroutine. The default does nothing: a
     * cancelled call then ends when the holder answers. A store
     * delegating to another (`KeyStore by …`) forwards it.
     */
    public fun cancelKeyUse(id: String) {
        // No-op by default: the call ends when the holder answers.
    }
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

    /**
     * The records whose IDs [idFilter] accepts. The wallet lists one kind
     * of record at a time this way — its credentials, or the pending
     * deferred credentials, authorizations or refresh grants it keeps
     * beside them — so a store that decrypts each record, as
     * [FileCredentialStore] does, opens only those. It may return others
     * too: the wallet tells records apart. By default it returns
     * [records].
     */
    public fun records(idFilter: (String) -> Boolean): List<ByteArray> = records()

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
 * A key the wallet asks its Wallet Provider to attest, with the platform's
 * evidence for it.
 *
 * @property jwk The public key, as a JWK (JSON).
 * @property keyID The key's ID in the wallet's [KeyStore]; null when the
 *   wallet can't tell which of its keys it is.
 * @property certificateChain The key's Android Key Attestation
 *   certificate chain ([KeyStore.attestationChain]), each certificate
 *   DER-encoded, the key's own first; empty when the key store gave none.
 *   A Wallet Provider verifies it before attesting the key: see the
 *   Going to production guide.
 */
public class KeyEvidence(
    public val jwk: ByteArray,
    public val keyID: String?,
    public val certificateChain: List<ByteArray>,
)

/**
 * What the wallet asks its Wallet Provider for a Wallet Attestation.
 *
 * @property clientID The wallet's client ID the attestation binds.
 * @property instanceKey The wallet instance key, with its evidence.
 */
public class WalletAttestationRequest(
    public val clientID: String,
    public val instanceKey: KeyEvidence,
)

/**
 * What the wallet asks its Wallet Provider for a Key Attestation.
 *
 * @property instanceKey The instance key of the issuance the keys are
 *   for, which a [WalletAttestationRequest] already sent with its
 *   evidence: the wallet always asks for a Wallet Attestation of it
 *   first. A provider that records its instance keys gives the Key
 *   Attestation that key's status (the Wallet Provider protocol's
 *   `instance_key`), so suspending or revoking the installation
 *   withdraws it too.
 * @property keys The holder keys to attest together, each with its
 *   evidence.
 * @property nonce The Credential Issuer's nonce the attestation carries.
 */
public class KeyAttestationRequest(
    public val instanceKey: KeyEvidence,
    public val keys: List<KeyEvidence>,
    public val nonce: String,
)

/**
 * The Wallet Provider's backend, which attests the wallet and its keys
 * (HAIP 1.0 §4.4.1, §4.5.1). Keys are public JWKs, as JSON; the results
 * are compact JWTs. A real one attests only after checking platform
 * evidence that it's talking to the genuine app and that the keys are in
 * secure hardware: it gives a challenge for each key the wallet makes
 * ([attestationChallenge]), and checks each key's Android Key Attestation
 * chain against it ([KeyEvidence.certificateChain]) before attesting.
 *
 * Implement [walletAttestation] and [keyAttestation] either with the
 * evidence ([WalletAttestationRequest], [KeyAttestationRequest]) — which
 * the wallet calls — or with the keys alone, which the evidence versions
 * call by default.
 */
public interface WalletProvider {
    /**
     * A Wallet Attestation binding [instanceKey] to [clientID]. The
     * default throws: implement this or the [WalletAttestationRequest]
     * version.
     */
    public suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
        throw StoreException("the WalletProvider implements no walletAttestation")

    /**
     * A Key Attestation over [keys], carrying the issuer's [nonce], for
     * the issuance whose instance key is [instanceKey]
     * ([KeyAttestationRequest.instanceKey]). The default throws:
     * implement this or the [KeyAttestationRequest] version.
     */
    public suspend fun keyAttestation(instanceKey: ByteArray, keys: List<ByteArray>, nonce: String): String =
        throw StoreException("the WalletProvider implements no keyAttestation")

    /**
     * A challenge for the key attestation of the next key the wallet
     * makes for [purpose] — fresh, from the Wallet Provider's backend,
     * which remembers it — or null for none. The wallet gives it to
     * [KeyStore.createKey], so [AndroidKeystoreKeyStore] has Android
     * Keystore attest the key over it (`setAttestationChallenge`), and
     * the key's chain then reaches [walletAttestation] or
     * [keyAttestation] in its [KeyEvidence]. Return one for
     * [KeyPurpose.HOLDER] (Key Attestation) and [KeyPurpose.INSTANCE]
     * (Wallet Attestation); [KeyPurpose.DPOP] keys aren't attested to
     * anyone. At most 128 bytes. Called on Go's thread, which waits, once
     * per key: a batch asks once per copy. An IOException is reported as
     * a network failure, as the attestations' are. The default gives
     * none, and keys carry no attestation chain.
     */
    public suspend fun attestationChallenge(purpose: KeyPurpose): ByteArray? = null

    /**
     * A Wallet Attestation for [request]. The default calls
     * [walletAttestation] with the instance key's JWK alone.
     */
    public suspend fun walletAttestation(request: WalletAttestationRequest): String =
        walletAttestation(request.clientID, request.instanceKey.jwk)

    /**
     * A Key Attestation for [request]. The default calls
     * [keyAttestation] with the instance key's and the keys' JWKs alone.
     */
    public suspend fun keyAttestation(request: KeyAttestationRequest): String =
        keyAttestation(request.instanceKey.jwk, request.keys.map { it.jwk }, request.nonce)
}

// Adapters to gomobile's interfaces.

/** The longest attestation challenge Android Keystore takes. */
internal const val MAX_ATTESTATION_CHALLENGE = 128

/**
 * The keys a wallet made, by public key (uncompressed X9.63), so the
 * Wallet Provider adapter can tell which key a JWK Go hands it is. It
 * keeps the most recent [limit].
 */
internal class CreatedKeys(private val limit: Int = 256) {
    private val ids = LinkedHashMap<String, String>()

    @Synchronized
    fun add(point: ByteArray, id: String) {
        ids[hex(point)] = id
        while (ids.size > limit) ids.remove(ids.keys.first())
    }

    @Synchronized
    fun id(point: ByteArray): String? = ids[hex(point)]

    @Synchronized
    fun remove(id: String) {
        ids.values.remove(id)
    }

    private fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
}

/**
 * A KeyStore as gomobile's KeyStore. With [provider], each key is made
 * over the attestation challenge the provider gives for its purpose;
 * with [created], each key made is recorded for [WalletProviderAdapter].
 */
internal class KeyStoreAdapter(
    private val store: KeyStore,
    private val provider: WalletProvider? = null,
    private val created: CreatedKeys? = null,
) : MobileKeyStore {
    override fun createKey(purpose: String): String {
        val p = KeyPurpose.fromRawValue(purpose) ?: throw StoreException("unknown key purpose $purpose")
        val challenge = provider?.let { pr -> waitForProvider { pr.attestationChallenge(p) } }
        if (challenge != null && (challenge.isEmpty() || challenge.size > MAX_ATTESTATION_CHALLENGE)) {
            throw StoreException("the Wallet Provider's attestation challenge must be 1 to $MAX_ATTESTATION_CHALLENGE bytes, not ${challenge.size}")
        }
        // Without a challenge, the one-argument createKey, as before: a
        // store delegating to another (`KeyStore by …`) that overrides only
        // it would otherwise be bypassed, since delegation forwards this
        // overload too.
        val id = if (challenge == null) store.createKey(p) else store.createKey(p, challenge)
        if (created != null) store.publicKey(id)?.let { created.add(it, id) }
        return id
    }

    override fun publicKey(id: String): ByteArray = store.publicKey(id) ?: ByteArray(0)

    override fun sign(id: String, digest: ByteArray): ByteArray = markingHolderCancellation { store.sign(id, digest) }

    override fun deleteKey(id: String) {
        store.deleteKey(id)
        created?.remove(id)
    }

    override fun durable(): Boolean = store.isDurable
}

/**
 * A KeyAgreement as gomobile's: a key that can't agree keys is marked
 * so Go signs instead.
 */
internal class KeyAgreementAdapter(private val agreement: KeyAgreement) : MobileKeyAgreement {
    override fun agree(id: String, peerPublicKey: ByteArray): ByteArray =
        try {
            markingHolderCancellation { agreement.agree(id, peerPublicKey) }
        } catch (e: KeyAgreementUnsupportedException) {
            throw StoreException("[no_key_agreement] " + (e.message ?: "unsupported"))
        }
}

/** A CredentialStore as gomobile's CredentialStore. */
internal class CredentialStoreAdapter(private val store: CredentialStore) : MobileCredentialStore {
    override fun put(id: String, record: ByteArray) = store.put(id, record)

    override fun get(id: String): ByteArray = store.record(id) ?: ByteArray(0)

    override fun list(): ByteArray = jsonArray(store.records())

    // prefixes is a comma-separated list; empty selects every ID.
    override fun listPrefixed(prefixes: String, excluding: Boolean): ByteArray {
        val ps = prefixes.split(',').filter { it.isNotEmpty() }
        return jsonArray(store.records { id -> ps.any { id.startsWith(it) } != excluding })
    }

    private fun jsonArray(records: List<ByteArray>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write('['.code)
        records.forEachIndexed { i, r ->
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
 *
 * Each key reaches the provider as [KeyEvidence]: its ID, found among
 * the keys [created] recorded (or, for an [AndroidKeystoreKeyStore],
 * among its keys), and its attestation chain from [store].
 */
internal class WalletProviderAdapter(
    private val provider: WalletProvider,
    private val store: KeyStore? = null,
    private val created: CreatedKeys? = null,
) : MobileWalletProvider {
    // The calls in progress, by the issuance's instance key, for cancel.
    internal val calls = CancellableWaits()

    override fun walletAttestation(clientID: String, instanceKeyJWK: ByteArray): ByteArray {
        val request = WalletAttestationRequest(clientID, evidence(instanceKeyJWK))
        return waitForProvider(calls, instanceKeyJWK) { provider.walletAttestation(request) }.toByteArray()
    }

    /**
     * Cancels the calls in progress for the issuance whose instance key
     * is [instanceKeyJWK], which Go no longer waits for: a provider
     * suspended cancellably stops there; one blocked in a request (as
     * [HttpWalletProvider]'s `HttpURLConnection` is) ends when it does.
     */
    fun cancel(instanceKeyJWK: ByteArray) {
        calls.cancel(instanceKeyJWK.decodeToString())
    }

    override fun keyAttestation(instanceKeyJWK: ByteArray, keysJWK: ByteArray, nonce: String): ByteArray {
        val keys = try {
            json.parseToJsonElement(keysJWK.decodeToString()) as JsonArray
        } catch (e: Exception) {
            throw StoreException("the keys to attest aren't a JSON array")
        }
        val request = KeyAttestationRequest(evidence(instanceKeyJWK), keys.map { evidence(it.toString().toByteArray()) }, nonce)
        return waitForProvider(calls, instanceKeyJWK) { provider.keyAttestation(request) }.toByteArray()
    }

    private fun evidence(jwk: ByteArray): KeyEvidence {
        val id = jwkPoint(jwk)?.let { point ->
            created?.id(point) ?: (store as? AndroidKeystoreKeyStore)?.keyID(point)
        }
        val chain = id?.let { store?.attestationChain(it) }.orEmpty()
        return KeyEvidence(jwk, id, chain)
    }
}

/**
 * A P-256 JWK's public key as an uncompressed X9.63 point, or null for
 * anything else.
 */
internal fun jwkPoint(jwk: ByteArray): ByteArray? {
    val o = runCatching { json.parseToJsonElement(jwk.decodeToString()) as? JsonObject }.getOrNull() ?: return null
    fun field(name: String): String? = (o[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (field("kty") != "EC" || field("crv") != "P-256") return null
    val decoder = Base64.getUrlDecoder()
    val x = runCatching { decoder.decode(field("x") ?: return null) }.getOrNull() ?: return null
    val y = runCatching { decoder.decode(field("y") ?: return null) }.getOrNull() ?: return null
    if (x.size != 32 || y.size != 32) return null
    return byteArrayOf(4) + x + y
}

/**
 * Runs a Wallet Provider call on Go's thread, which waits for it; an
 * IOException is marked as a network failure, which Go reports as
 * [WalletException.Code.network] (retryable), and a
 * [WalletProviderRefusedException] with an error code as a refusal,
 * which Go reports as [WalletException.Code.platform] with that code as
 * [WalletException.protocolError]. With [calls], it runs as
 * the wait for [instanceKeyJWK] there, so cancelling that ends it.
 */
internal fun <T> waitForProvider(calls: CancellableWaits? = null, instanceKeyJWK: ByteArray? = null, body: suspend () -> T): T =
    try {
        if (calls != null && instanceKeyJWK != null) calls.await(instanceKeyJWK.decodeToString(), body) else runBlocking { body() }
    } catch (e: IOException) {
        throw StoreException("[network] " + (e.message ?: e.javaClass.simpleName))
    } catch (e: WalletProviderRefusedException) {
        // The protocol's error code, for Go to carry as the error's
        // detail (protocolError).
        throw StoreException(e.error?.let { "[refused:$it] " + e.message } ?: (e.message ?: "the Wallet Provider refused"))
    } catch (e: CancellationException) {
        throw StoreException("the Wallet Provider call was cancelled", e)
    }

/**
 * Gomobile's CallbackCanceller over a wallet's key store and Wallet
 * Provider: Go calls it when a call waiting on one of them is cancelled,
 * so the holder's prompt is dismissed ([KeyStore.cancelKeyUse]) or the
 * provider's request stopped.
 */
internal class CallbackCancellerAdapter(
    private val store: KeyStore,
    private val provider: WalletProviderAdapter?,
) : MobileCallbackCanceller {
    override fun cancelKeyUse(id: String) = store.cancelKeyUse(id)

    override fun cancelProvider(instanceKeyJWK: ByteArray) {
        provider?.cancel(instanceKeyJWK)
    }
}

/** A store's or provider's own failure. */
public open class StoreException(message: String, cause: Throwable?) : Exception(message, cause) {
    public constructor(message: String) : this(message, null)
}

/**
 * The holder dismissed the prompt a holder key's use showed:
 * [BiometricPromptAuthenticator] throws it when the holder cancels, and
 * an app's own [HolderAuthenticator] or [KeyStore] may too. The call
 * ends with [WalletException.Code.cancelled] rather than
 * [WalletException.Code.platform].
 */
public class HolderCancelledException(message: String, cause: Throwable? = null) : StoreException(message, cause)

/**
 * Runs a key's use, marking a [HolderCancelledException] — anywhere in
 * the failure's causes — so Go reports it as
 * [WalletException.Code.cancelled].
 */
internal fun <T> markingHolderCancellation(use: () -> T): T =
    try {
        use()
    } catch (e: Exception) {
        val cancelled = generateSequence<Throwable>(e) { it.cause }.take(8).firstOrNull { it is HolderCancelledException }
        if (cancelled != null) throw StoreException("[cancelled] " + (cancelled.message ?: "the holder cancelled"), e)
        throw e
    }
