package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URISyntaxException
import java.security.MessageDigest
import java.util.Base64

/**
 * A [WalletProvider] over the Wallet Provider HTTP protocol, version 1,
 * that OID4VCgo's `walletprovider.Provider.Handler` serves
 * ([WALLET_PROVIDER.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/WALLET_PROVIDER.md)),
 * with Android Key Attestation (`android-key`) as its evidence:
 *
 * - The installation registers once, at its first Wallet Attestation:
 *   it makes a *registration key* in a key store of its own
 *   ([registrationKeyStore]) over a `registration` challenge, registers
 *   it with its attestation chain (`POST /v1/instances`), and keeps the
 *   instance ID and the key's ID in its [InstanceRegistry]. The
 *   registration key signs every later request (`Wallet-Provider-Request`);
 *   no attestation names it. If the registration or its key is lost,
 *   the next Wallet Attestation registers again, with a new key.
 * - [attestationChallenge] gets an `instance` challenge for each
 *   instance key — the wallet makes one per issuance, in its own key
 *   store — and a `holder` challenge the holder keys of one Key
 *   Attestation share, so [AndroidKeystoreKeyStore] makes each key over
 *   it.
 * - [walletAttestation] asks for a Wallet Attestation for the instance
 *   key (`instance_key`). While it remembers the `instance` challenge
 *   the key's attestation certificate carries, it sends that challenge
 *   and the key's chain: the provider needs them the first time it's
 *   asked for the key, and ignores them once it has recorded it. Later —
 *   at a refresh, once the challenge has expired — it sends the key
 *   alone.
 * - [keyAttestation] asks for a Key Attestation over the holder keys,
 *   with their chains, for the issuance of its instance key
 *   ([KeyAttestationRequest.instanceKey]), which a Wallet Attestation
 *   recorded.
 *
 * It sends nothing but to its base URL, over https, following no
 * redirect, with its timeout for connecting and for reading, and reads at most
 * 256 KiB of an answer. It checks a Wallet Attestation is for the client
 * and the instance key, and a Key Attestation is over the nonce sent and
 * attests only keys sent; their signatures are the issuer's to verify.
 *
 * Failures reach the wallet as [WalletException]s: one the network or the
 * provider's availability caused (no connection, a timeout, HTTP 5xx or
 * 429, a challenge that expired before it was used) as
 * [WalletException.Code.network], which may be retried; a refusal
 * ([WalletProviderRefusedException]) as [WalletException.Code.platform],
 * its message naming the protocol's error code. The codes below that
 * discard something count only at the status the provider answers them
 * with (403; 409 for `instance_key_registered`, 400 for
 * `evidence_required`): the same code in a redirect, or in a page from a
 * proxy in front of the provider, is a refusal without a code, which
 * discards nothing. On `instance_revoked`, it
 * forgets the registration and deletes its registration key: the next
 * Wallet Attestation registers the installation again. On
 * `registration_expired` — the provider no longer accepts the evidence
 * the installation registered with, as when a certificate of its
 * Android Key Attestation chain expired, which Remote Key
 * Provisioning's short-lived ones soon do — it forgets the registration
 * likewise, and a Wallet Attestation registers again, with a new
 * registration key and fresh evidence, and asks once more; refused
 * again, it fails. A Key Attestation refused so isn't asked again: its
 * instance key is the old registration's, which a new one doesn't know
 * (`unknown_instance_key`); the next issuance's Wallet Attestation
 * registers again. The old instance's instance keys stay its own
 * (`instance_key_registered`), so a credential whose refresh needs one
 * must be received again: the wallet reports that refresh as
 * [WalletException.Code.reissueRequired], and forgets its refresh grant,
 * as it does on `instance_key_expired` (the instance key's own evidence
 * expired: a new issuance makes a new instance key). On
 * `instance_not_active` (suspended) it keeps the registration: tell the
 * holder, as the provider may resume it. A signed request refused as
 * `invalid_signed_request` isn't retried: check the device's clock, and
 * that the provider still knows the instance.
 *
 * Keys are matched to the challenges they were made over by the
 * challenge's bytes in their attestation certificate. Holder keys made
 * while no Key Attestation has used the current holder challenge share
 * it, so of two issuances making holder keys at once only the first
 * Key Attestation can use it: the other fails as
 * [WalletException.Code.network], and succeeds when tried again with
 * new keys. A challenge the provider answers `invalid_challenge` for —
 * used up by an earlier request it refused after taking it, or expired —
 * is never sent again: asked again for holder keys made over it, the
 * provider fails as [WalletException.Code.platform] without a request,
 * and an instance key made over it is sent alone, attested if the
 * provider has recorded it and refused (`evidence_required`) if not.
 *
 * A Wallet Attestation for an instance key whose record the provider
 * deleted after its retention, sent alone once the challenge the key was
 * made over has expired, is refused (`evidence_required`): Android Key
 * Attestation can't vouch for an existing key over a new challenge, so
 * the wallet reports a refresh needing that key as
 * [WalletException.Code.reissueRequired] and forgets its refresh grant.
 *
 * Its requests are made with [HttpURLConnection], which the wallet's
 * `network.tlsPins` doesn't reach (those pin the Go SDK's own requests):
 * to pin the provider's certificates, give its domain a `<pin-set>` in
 * the app's network security configuration, which [HttpURLConnection]
 * follows.
 *
 * The installation registers once, and the challenges handed out are
 * remembered, for every `HttpWalletProvider` over the same
 * [FileInstanceRegistry] file (or the same [InMemoryInstanceRegistry])
 * in the process, so a wallet rebuilt mid-issuance with a new provider
 * carries on with the old one's. Over a registry of its own type, a
 * provider shares them with no other: keep one provider for it.
 */
public class HttpWalletProvider internal constructor(
    baseURL: String,
    private val instances: InstanceRegistry,
    private val registrationKeys: KeyStore,
    private val transport: WalletProviderTransport,
    private val clock: () -> Long,
    allowHttp: Boolean,
) : WalletProvider {
    /**
     * A client of the provider at [baseURL].
     *
     * @param baseURL Where the provider's protocol is mounted: an absolute
     *   `https` URL without user info, query or fragment. Its path is the
     *   prefix of every protocol path (`https://wp.example/wp` gives
     *   `https://wp.example/wp/v1/challenge`).
     * @param instances Where the registration is kept:
     *   [FileInstanceRegistry.standard] in an app.
     * @param registrationKeys Where the registration key is made
     *   ([KeyStore.createKey] for [KeyPurpose.INSTANCE], over the
     *   registration challenge) and kept, and signs requests
     *   ([KeyStore.sign]): a store that attests its keys, and that nothing
     *   else deletes from. By default [registrationKeyStore], Android
     *   Keystore under an alias prefix of its own. Not the wallet's key
     *   store: [Wallet.sweepOrphanedKeys] deletes every key there that no
     *   credential is bound to (and refuses a store under
     *   [REGISTRATION_KEY_ALIAS_PREFIX]).
     * @param timeoutMillis The connect and the read timeout of each request.
     * @throws IllegalArgumentException when [baseURL] isn't an absolute
     *   https URL without user info, query or fragment, or
     *   [timeoutMillis] isn't positive.
     */
    public constructor(
        baseURL: String,
        instances: InstanceRegistry,
        registrationKeys: KeyStore = registrationKeyStore(),
        timeoutMillis: Int = DEFAULT_TIMEOUT_MILLIS,
    ) : this(baseURL, instances, registrationKeys, UrlConnectionTransport(checkTimeout(timeoutMillis)), { System.currentTimeMillis() / 1000 }, false)

    private val base: URI = parseBaseURL(baseURL, allowHttp)

    /** The locks and challenges this provider shares with every other over the same registry. */
    private val state: WalletProviderState = when (instances) {
        is FileInstanceRegistry -> instances.walletProviderState
        is InMemoryInstanceRegistry -> instances.walletProviderState
        else -> WalletProviderState()
    }

    /** Guards the challenges below. */
    private val lock: Mutex get() = state.lock

    /** Held while the installation registers or forgets its registration, so it registers once. */
    private val registering: Mutex get() = state.registering

    /** `instance` challenges handed out, most recent last, until they expire. */
    private val instanceChallenges: ArrayDeque<IssuedChallenge> get() = state.instanceChallenges

    /** `holder` challenges handed out, most recent last, until they expire. */
    private val holderChallenges: ArrayDeque<IssuedChallenge> get() = state.holderChallenges

    /** The holder challenge each new holder key is made over, until it's used or near its expiry. */
    private var holderChallenge: IssuedChallenge?
        get() = state.holderChallenge
        set(value) {
            state.holderChallenge = value
        }

    /**
     * An `instance` challenge for each [KeyPurpose.INSTANCE] key; for
     * [KeyPurpose.HOLDER] keys, one `holder` challenge each key shares
     * until a [keyAttestation] uses it or it's within a minute of its
     * expiry; none for [KeyPurpose.DPOP] keys. The challenge's 32 bytes,
     * decoded, as Android Keystore's attestation challenge.
     */
    override suspend fun attestationChallenge(purpose: KeyPurpose): ByteArray? = when (purpose) {
        KeyPurpose.DPOP -> null
        // Fetched outside the lock, which every attestation takes: a
        // provider slow to answer holds up only the key waiting for it.
        KeyPurpose.INSTANCE -> challenge(PURPOSE_INSTANCE).also { c -> lock.withLock { remember(instanceChallenges, c) } }.bytes
        KeyPurpose.HOLDER -> (lock.withLock { currentHolderChallenge() } ?: newHolderChallenge()).bytes
    }

    /** The holder challenge new holder keys are made over, unless none is or it's near its expiry; under [lock]. */
    private fun currentHolderChallenge(): IssuedChallenge? =
        holderChallenge?.takeIf { it.expiresAt - clock() > CHALLENGE_REUSE_MARGIN_SECONDS }

    /**
     * A new holder challenge, fetched outside [lock], which becomes the
     * current one: unless another call made one current meanwhile, which
     * is taken instead, so keys made at once share it, as before.
     */
    private suspend fun newHolderChallenge(): IssuedChallenge {
        val fetched = challenge(PURPOSE_HOLDER)
        return lock.withLock {
            currentHolderChallenge() ?: fetched.also {
                remember(holderChallenges, it)
                holderChallenge = it
            }
        }
    }

    /**
     * A Wallet Attestation for [request]'s client and instance key,
     * registering the installation first if it isn't yet. The key's
     * chain goes with it while the `instance` challenge it was made over
     * is remembered and unexpired.
     */
    override suspend fun walletAttestation(request: WalletAttestationRequest): String {
        val key = request.instanceKey
        val point = jwkPoint(key.jwk) ?: throw StoreException(INSTANCE_KEY_NOT_P256)
        val body = linkedMapOf<String, JsonElement>("client_id" to JsonPrimitive(request.clientID), "instance_key" to jwkOf(point))
        val challenge = instanceChallengeOf(key)
        challenge?.let {
            body["challenge"] = JsonPrimitive(it.value)
            body["evidence"] = androidKeyEvidence(key.certificateChain)
        }
        val jwt = signedRegistered(WALLET_ATTESTATION_PATH, JsonObject(body), challenge).string("wallet_attestation")
        val claims = unverifiedClaims(jwt) ?: throw StoreException("the Wallet Attestation isn't a JWT")
        val cnf = ((claims["cnf"] as? JsonObject)?.get("jwk") as? JsonObject)?.let { jwkPoint(it.toString().toByteArray()) }
        if (claims.stringOrNull("sub") != request.clientID || cnf == null || !cnf.contentEquals(point)) {
            throw StoreException("the Wallet Attestation isn't for client ${request.clientID} and the instance key")
        }
        return jwt
    }

    /**
     * A Key Attestation over [request]'s holder keys, for the issuance
     * of its instance key, over the holder challenge they were made over,
     * signed with the registration key.
     */
    override suspend fun keyAttestation(request: KeyAttestationRequest): String {
        if (request.keys.isEmpty()) throw StoreException("no holder keys to attest")
        val instanceKey = jwkPoint(request.instanceKey.jwk) ?: throw StoreException(INSTANCE_KEY_NOT_P256)
        val points = request.keys.map { jwkPoint(it.jwk) ?: throw StoreException("a holder key isn't a P-256 JWK") }
        val evidence = request.keys.filter { it.certificateChain.isNotEmpty() }
        if (evidence.isEmpty()) throw StoreException("no holder key has an attestation chain: make the keys with AndroidKeystoreKeyStore")
        val instance = withContext(Dispatchers.IO) { kept() }
            ?: throw StoreException("the wallet isn't registered with the Wallet Provider: a Key Attestation follows a Wallet Attestation")
        val challenge = holderChallengeOf(evidence)
        val body = JsonObject(
            mapOf(
                "instance_key" to jwkOf(instanceKey),
                "challenge" to JsonPrimitive(challenge.value),
                "keys" to JsonArray(points.map(::jwkOf)),
                "evidence" to JsonArray(evidence.map { androidKeyEvidence(it.certificateChain) }),
                "nonce" to JsonPrimitive(request.nonce),
            ),
        )
        val jwt = signed(instance, KEY_ATTESTATION_PATH, body, challenge).string("key_attestation")
        checkKeyAttestation(jwt, points, request.nonce)
        return jwt
    }

    /** The unexpired `instance` challenge [key]'s attestation certificate carries, or null. */
    private suspend fun instanceChallengeOf(key: KeyEvidence): IssuedChallenge? {
        val leaf = key.certificateChain.firstOrNull() ?: return null
        return lock.withLock { instanceChallenges.lastOrNull { it.expiresAt > clock() && contains(leaf, it.bytes) } }
    }

    /**
     * The holder challenge the keys with [evidence] were made over, which
     * no new key is made over after. Keys made over none this provider
     * remembers unexpired fail here, without a request: sent with another
     * challenge, which the keys weren't made over, the provider would
     * refuse them and use that challenge up, failing a concurrent
     * issuance whose keys were made over it.
     */
    private suspend fun holderChallengeOf(evidence: List<KeyEvidence>): IssuedChallenge = lock.withLock {
        val leaves = evidence.map { it.certificateChain.first() }
        val chosen = holderChallenges.filter { it.expiresAt > clock() }
            .maxByOrNull { c -> leaves.count { contains(it, c.bytes) } }
            ?.takeIf { c -> leaves.any { contains(it, c.bytes) } }
            ?: throw StoreException("the holder keys weren't made over a holder challenge this Wallet Provider gave, or it has expired: make new keys")
        if (chosen.usedUp) throw StoreException("the holder keys were made over a challenge the Wallet Provider has used up: make new keys")
        // A challenge is used by the request naming it, accepted or
        // not: no new key is made over it. It's still remembered, so
        // keys made over it that another request used are sent with
        // it, and refused as invalid_challenge, a network failure,
        // which marks it used up (signed).
        if (holderChallenge === chosen) holderChallenge = null
        chosen
    }

    /** The registration kept, after registering the installation if it has none. */
    private suspend fun registered(): RegisteredInstance = registering.withLock {
        withContext(Dispatchers.IO) { kept() } ?: register()
    }

    /**
     * The registration kept, if the registration key store still holds
     * its key; one whose key is gone, or another, is forgotten, and that
     * other key deleted.
     */
    private fun kept(): RegisteredInstance? {
        val kept = instances.instance() ?: return null
        val point = registrationKeys.publicKey(kept.keyID)
        if (point != null && jwkThumbprint(point) == kept.keyThumbprint) return kept
        if (point != null) registrationKeys.deleteKey(kept.keyID)
        instances.remove(kept)
        return null
    }

    /**
     * Deletes every key in the registration key store but the kept
     * registration's, and returns how many it deleted: the keys of
     * registrations that never finished, as when the app's process ended
     * in the middle of one, which nothing else deletes. Call it at
     * launch. It takes its turn with registrations over the same
     * registry, so it never deletes the key of one in progress.
     *
     * Only an [AndroidKeystoreKeyStore] lists its keys: over another
     * store it deletes nothing, and returns 0. Call it only where this
     * provider's registration keys are the only ones in that store:
     * every provider made with the default [registrationKeyStore] shares
     * it, so an app with more than one Wallet Provider gives each an
     * [AndroidKeystoreKeyStore] of its own alias prefix (under
     * [REGISTRATION_KEY_ALIAS_PREFIX], which the wallet's mustn't cover)
     * before sweeping either.
     */
    public suspend fun sweepOrphanedRegistrationKeys(): Int {
        val store = registrationKeys as? AndroidKeystoreKeyStore ?: return 0
        return sweepRegistrationKeys(store::deleteKeys)
    }

    /** [sweepOrphanedRegistrationKeys] over a store that deletes its keys but those given with [deleteKeysExcept]. */
    internal suspend fun sweepRegistrationKeys(deleteKeysExcept: (Set<String>) -> Int): Int = registering.withLock {
        withContext(Dispatchers.IO) { deleteKeysExcept(kept()?.let { setOf(it.keyID) }.orEmpty()) }
    }

    /**
     * Registers the installation with a new registration key — and with
     * another if the provider has seen that one (`instance_key_registered`).
     */
    private suspend fun register(): RegisteredInstance =
        try {
            registerKey()
        } catch (e: WalletProviderRefusedException) {
            if (e.error != INSTANCE_KEY_REGISTERED) throw e
            registerKey()
        }

    /**
     * Makes a registration key over a fresh `registration` challenge,
     * registers it and keeps the registration; the key is deleted if it
     * isn't registered.
     */
    private suspend fun registerKey(): RegisteredInstance {
        val challenge = challenge(PURPOSE_REGISTRATION)
        val id = withContext(Dispatchers.IO) { registrationKeys.createKey(KeyPurpose.INSTANCE, challenge.bytes) }
        var registered: RegisteredInstance? = null
        try {
            val point = registrationKeys.publicKey(id) ?: throw StoreException("the registration key store lost the key it made")
            val chain = registrationKeys.attestationChain(id).orEmpty()
            if (chain.isEmpty()) throw StoreException("the registration key store didn't attest the registration key: use HttpWalletProvider.registrationKeyStore")
            val body = JsonObject(
                mapOf(
                    "challenge" to JsonPrimitive(challenge.value),
                    "registration_key" to jwkOf(point),
                    "evidence" to androidKeyEvidence(chain),
                ),
            )
            val instanceID = post(INSTANCES_PATH, body, null, HttpURLConnection.HTTP_CREATED).string("instance_id")
            val instance = RegisteredInstance(jwkThumbprint(point), id, instanceID)
            withContext(Dispatchers.IO) { instances.put(instance) }
            registered = instance
            return instance
        } finally {
            // A failure deleting it doesn't hide the registration's.
            if (registered == null) runCatching { registrationKeys.deleteKey(id) }
        }
    }

    /**
     * Deletes the revoked or expired [instance]'s registration key and forgets it —
     * in that order, so a failure leaves no key behind: a registration
     * whose key is gone is forgotten when next read ([kept]).
     */
    private suspend fun forget(instance: RegisteredInstance): Unit = registering.withLock {
        withContext(Dispatchers.IO) {
            registrationKeys.deleteKey(instance.keyID)
            instances.remove(instance)
        }
    }

    /**
     * Posts [body] to [path] as [signed] does, registering the
     * installation first if it isn't yet. On `registration_expired`,
     * which [signed] forgets the registration on, it registers again and
     * posts once more, and no more: a second refusal is thrown.
     */
    private suspend fun signedRegistered(path: String, body: JsonObject, bodyChallenge: IssuedChallenge?): JsonObject =
        try {
            signed(registered(), path, body, bodyChallenge)
        } catch (e: WalletProviderRefusedException) {
            if (e.error != REGISTRATION_EXPIRED) throw e
            signed(registered(), path, body, bodyChallenge)
        }

    /**
     * Posts [body] to [path], signed with [instance]'s registration key
     * over a fresh `request` challenge. On `instance_revoked` or
     * `registration_expired`, forgets the instance. On
     * `invalid_challenge`, marks [bodyChallenge], the challenge [body]
     * names, if any, used up ([forgetChallenge]): the request's own
     * challenge is fresh, so it's the body's the provider has used up —
     * as when it refused an earlier request naming it after taking it —
     * or found expired. It's then never sent again, rather than fail as a
     * network failure at every try.
     */
    private suspend fun signed(instance: RegisteredInstance, path: String, body: JsonObject, bodyChallenge: IssuedChallenge?): JsonObject {
        val challenge = challenge(PURPOSE_REQUEST)
        return try {
            post(path, body, { target, bytes -> signRequest(instance, challenge.value, target, bytes) }, HttpURLConnection.HTTP_OK)
        } catch (e: WalletProviderRefusedException) {
            if (e.error in FORGETS_REGISTRATION) forget(instance)
            throw e
        } catch (e: WalletProviderUnavailableException) {
            if (bodyChallenge != null && e.error == INVALID_CHALLENGE) forgetChallenge(bodyChallenge)
            throw e
        }
    }

    /**
     * Marks [c] used up: no key is made over it, and no request names it,
     * again. An instance key made over it is then sent alone, which the
     * provider attests if a concurrent request recorded it, and refuses
     * (`evidence_required`) otherwise; holder keys made over it are
     * refused here, rather than sent with another challenge, which the
     * provider would use up too.
     */
    private suspend fun forgetChallenge(c: IssuedChallenge): Unit = lock.withLock {
        c.usedUp = true
        instanceChallenges.remove(c)
        if (holderChallenge === c) holderChallenge = null
    }

    /** The `Wallet-Provider-Request` JWT for a POST of [body] to [path]. */
    private fun signRequest(instance: RegisteredInstance, challenge: String, path: String, body: ByteArray): String {
        val claims = requestClaims(instance.instanceID, "POST", path, body, challenge, clock())
        return signES256(REQUEST_JWT_HEADER, claims) { digest -> registrationKeys.sign(instance.keyID, digest) }
    }

    /** A fresh challenge for [purpose]. */
    private suspend fun challenge(purpose: String): IssuedChallenge {
        val answer = post(CHALLENGE_PATH, JsonObject(mapOf("purpose" to JsonPrimitive(purpose))), null, HttpURLConnection.HTTP_OK)
        val value = answer.string("challenge")
        if (answer.stringOrNull("purpose") != purpose) throw StoreException("the Wallet Provider answered with a challenge for another purpose")
        val bytes = decodeBase64URL(value)?.takeIf { it.size in MIN_CHALLENGE_BYTES..MAX_ATTESTATION_CHALLENGE }
            ?: throw StoreException("the Wallet Provider's challenge isn't 16 to $MAX_ATTESTATION_CHALLENGE bytes of base64url")
        val expiresAt = (answer["expires_at"] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
            ?: throw StoreException("the Wallet Provider's challenge has no expires_at")
        return IssuedChallenge(value, bytes, expiresAt)
    }

    private fun remember(list: ArrayDeque<IssuedChallenge>, c: IssuedChallenge) {
        val now = clock()
        list.removeAll { it.expiresAt <= now }
        list.addLast(c)
        while (list.size > MAX_REMEMBERED_CHALLENGES) list.removeFirst()
    }

    /**
     * Posts [body] to [path] — signed with [sign], given the escaped path
     * and the body bytes, if set — and returns the answer, which must have
     * status [want].
     */
    private suspend fun post(path: String, body: JsonObject, sign: ((String, ByteArray) -> String)?, want: Int): JsonObject =
        withContext(Dispatchers.IO) {
            val targetPath = (base.rawPath ?: "") + path
            val bytes = body.toString().toByteArray()
            val headers = linkedMapOf("Content-Type" to JSON_TYPE, "Accept" to JSON_TYPE)
            if (sign != null) headers[REQUEST_HEADER] = sign(targetPath, bytes)
            val answer = transport.post(URI(base.toString() + path), headers, bytes)
            val isJSON = answer.contentType?.substringBefore(';')?.trim()?.lowercase() == JSON_TYPE
            if (answer.status != want) throw failure(path, answer, isJSON)
            if (!isJSON) throw StoreException("the Wallet Provider answered $path with content type ${answer.contentType}")
            parseObject(answer.body) ?: throw StoreException("the Wallet Provider's answer to $path is malformed")
        }

    /**
     * The exception for an answer other than the one documented. A code
     * that discards the registration, an instance key or a refresh grant
     * ([CODE_STATUS]) at a status the provider doesn't answer it with — a
     * redirect, or a page from a proxy in front of the provider — isn't
     * the provider's refusal: it's dropped, and the answer refused as one
     * without a code, which discards nothing.
     */
    private fun failure(path: String, answer: WalletProviderAnswer, isJSON: Boolean): Exception {
        val o = if (isJSON) parseObject(answer.body) else null
        val sent = o?.stringOrNull("error")?.takeIf { it.isNotEmpty() }
        val atItsStatus = sent == null || CODE_STATUS[sent].let { it == null || it == answer.status }
        val code = sent.takeIf { atItsStatus }
        val description = o?.stringOrNull("error_description")?.takeIf { atItsStatus }
        return when {
            answer.status >= 500 || answer.status == 429 || code == INVALID_CHALLENGE ->
                WalletProviderUnavailableException(answer.status, code, "the Wallet Provider couldn't answer $path: HTTP ${answer.status}" + (code?.let { " $it" } ?: ""))
            else -> WalletProviderRefusedException(answer.status, code, description, path)
        }
    }

    /** The registration key's store, and the protocol's constants. */
    public companion object {
        /**
         * The alias prefix of [registrationKeyStore]'s keys. The wallet's
         * own [AndroidKeystoreKeyStore] mustn't cover it, as its default
         * prefix doesn't: [Wallet.sweepOrphanedKeys] refuses a store whose
         * prefix covers or falls under it, rather than delete the
         * registration key.
         */
        public const val REGISTRATION_KEY_ALIAS_PREFIX: String = "org.idfoundry.oid4vcgo.walletprovider."

        /**
         * The registration key's store: Android Keystore under
         * [REGISTRATION_KEY_ALIAS_PREFIX], apart from the wallet's keys;
         * in StrongBox as [strongBox] says; signing without the holder,
         * as instance keys do.
         */
        public fun registrationKeyStore(
            strongBox: AndroidKeystoreKeyStore.StrongBox = AndroidKeystoreKeyStore.StrongBox.PREFERRED,
        ): AndroidKeystoreKeyStore = AndroidKeystoreKeyStore(
            AndroidKeystoreKeyStore.Options(strongBox = strongBox, holderUserAuthentication = false, aliasPrefix = REGISTRATION_KEY_ALIAS_PREFIX),
        )

        /** The default connect and read timeout, as the Go client's. */
        internal const val DEFAULT_TIMEOUT_MILLIS = 30_000

        internal const val CHALLENGE_PATH = "/v1/challenge"
        internal const val INSTANCES_PATH = "/v1/instances"
        internal const val WALLET_ATTESTATION_PATH = "/v1/wallet-attestation"
        internal const val KEY_ATTESTATION_PATH = "/v1/key-attestation"
        internal const val REQUEST_HEADER = "Wallet-Provider-Request"
        internal const val REQUEST_JWT_HEADER = """{"alg":"ES256","typ":"wallet-provider-request+jwt"}"""

        internal const val PURPOSE_REGISTRATION = "registration"
        internal const val PURPOSE_INSTANCE = "instance"
        internal const val PURPOSE_HOLDER = "holder"
        internal const val PURPOSE_REQUEST = "request"

        internal const val INSTANCE_REVOKED = "instance_revoked"
        internal const val REGISTRATION_EXPIRED = "registration_expired"
        internal const val INVALID_CHALLENGE = "invalid_challenge"

        /** The refusals of a signed request that end the registration: it's forgotten, and the next one registers again. */
        internal val FORGETS_REGISTRATION = setOf(INSTANCE_REVOKED, REGISTRATION_EXPIRED)
        internal const val INSTANCE_KEY_REGISTERED = "instance_key_registered"
        internal const val INSTANCE_KEY_EXPIRED = "instance_key_expired"
        internal const val EVIDENCE_REQUIRED = "evidence_required"

        /**
         * The status the provider answers each code that discards
         * something with (`walletprovider.CodeStatus`): the registration
         * ([INSTANCE_REVOKED], [REGISTRATION_EXPIRED]), or, in Go, a
         * refresh grant bound to an instance key ([INSTANCE_KEY_EXPIRED],
         * [REGISTRATION_EXPIRED], [INSTANCE_KEY_REGISTERED],
         * [EVIDENCE_REQUIRED]). Acted on only at that status.
         */
        internal val CODE_STATUS: Map<String, Int> = mapOf(
            INSTANCE_REVOKED to 403, REGISTRATION_EXPIRED to 403, INSTANCE_KEY_EXPIRED to 403,
            INSTANCE_KEY_REGISTERED to 409, EVIDENCE_REQUIRED to 400,
        )

        /** The largest answer read, as the protocol's request limit. */
        internal const val MAX_RESPONSE_BYTES = 256 * 1024

        /** A holder challenge this close to its expiry isn't handed out again. */
        internal const val CHALLENGE_REUSE_MARGIN_SECONDS = 60L
        internal const val MIN_CHALLENGE_BYTES = 16
        internal const val MAX_REMEMBERED_CHALLENGES = 8

        private const val INSTANCE_KEY_NOT_P256 = "the instance key isn't a P-256 JWK"

        internal fun checkTimeout(millis: Int): Int {
            require(millis > 0) { "the timeout must be positive" }
            return millis
        }

        internal fun parseBaseURL(url: String, allowHttp: Boolean): URI {
            val u = try {
                URI(url)
            } catch (e: URISyntaxException) {
                throw IllegalArgumentException("the Wallet Provider URL isn't a URL")
            }
            val schemeOK = u.scheme == "https" || (allowHttp && u.scheme == "http")
            require(schemeOK && !u.host.isNullOrEmpty() && u.rawUserInfo == null && u.rawQuery == null && u.rawFragment == null) {
                "the Wallet Provider URL must be an absolute https URL without user info, query or fragment"
            }
            return URI(u.scheme + "://" + u.rawAuthority + (u.rawPath ?: "").trimEnd('/'))
        }
    }
}

/**
 * Fails unless [jwt] is a Key Attestation over [nonce] attesting at least
 * one of [points], and nothing else. An empty [nonce] (an issuer without
 * a Nonce Endpoint) is one the provider omits.
 */
private fun checkKeyAttestation(jwt: String, points: List<ByteArray>, nonce: String) {
    val claims = unverifiedClaims(jwt) ?: throw StoreException("the Key Attestation isn't a JWT")
    val attested = claims["attested_keys"] as? JsonArray
    val overNonce = if (claims["nonce"] == null) nonce.isEmpty() else claims.stringOrNull("nonce") == nonce
    if (!overNonce || attested.isNullOrEmpty()) {
        throw StoreException("the Key Attestation isn't over the nonce sent, or attests no key")
    }
    for (k in attested) {
        val p = (k as? JsonObject)?.let { jwkPoint(it.toString().toByteArray()) }
        if (p == null || points.none { it.contentEquals(p) }) throw StoreException("the Key Attestation attests a key that wasn't sent")
    }
}

/**
 * The Wallet Provider refused a request with one of the protocol's
 * errors, or answered other than the protocol documents (a redirect, a
 * path it doesn't serve). It reaches the wallet as
 * [WalletException.Code.platform], its [WalletException.protocolError]
 * [error] when there is one. An app's own [WalletProvider] may throw it
 * too, for the same.
 */
public class WalletProviderRefusedException(
    /** The HTTP status code. */
    public val status: Int,
    /**
     * The protocol's error code (`evidence_rejected`, `instance_revoked`,
     * `unknown_instance_key`, …), or null when the answer had none.
     */
    public val error: String?,
    /** The provider's fixed text for [error], for logs; never decide on it. */
    public val description: String?,
    path: String,
) : StoreException("the Wallet Provider refused $path: HTTP $status" + (error?.let { " $it" } ?: ""))

/**
 * The Wallet Provider couldn't answer — HTTP 5xx or 429 — or the
 * challenge a request named expired or was used before it arrived
 * (`invalid_challenge`). An [IOException], so it reaches the wallet as
 * [WalletException.Code.network]: try again. A request challenge is
 * fresh at each try; a challenge keys were made over isn't, and isn't
 * sent again (see [HttpWalletProvider]), so new keys succeed where the
 * old ones are refused.
 */
public class WalletProviderUnavailableException(
    /** The HTTP status code. */
    public val status: Int,
    /** The protocol's error code, or null when the answer had none. */
    public val error: String?,
    message: String,
) : IOException(message)

/**
 * What every [HttpWalletProvider] over one registry shares in the
 * process: its locks, and the challenges it handed out, so a wallet
 * rebuilt mid-issuance with a new provider registers once and still
 * finds the challenge its keys were made over.
 */
internal class WalletProviderState {
    val lock = Mutex()
    val registering = Mutex()
    val instanceChallenges = ArrayDeque<IssuedChallenge>()
    val holderChallenges = ArrayDeque<IssuedChallenge>()
    var holderChallenge: IssuedChallenge? = null
}

/** A challenge the provider issued. */
internal class IssuedChallenge(val value: String, val bytes: ByteArray, val expiresAt: Long) {
    /** Whether the provider has used it up (`invalid_challenge`); guarded by the provider's lock. */
    var usedUp: Boolean = false
}

/** An HTTP answer: status, content type and body, read to at most [HttpWalletProvider.MAX_RESPONSE_BYTES]. */
internal class WalletProviderAnswer(val status: Int, val contentType: String?, val body: ByteArray)

/** Posts a request to the Wallet Provider; an [IOException] for no answer. */
internal fun interface WalletProviderTransport {
    fun post(url: URI, headers: Map<String, String>, body: ByteArray): WalletProviderAnswer
}

/** The transport over [HttpURLConnection]: no redirects, no caching, bounded answers. */
internal class UrlConnectionTransport(private val timeoutMillis: Int) : WalletProviderTransport {
    override fun post(url: URI, headers: Map<String, String>, body: ByteArray): WalletProviderAnswer {
        val connection = url.toURL().openConnection() as HttpURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = timeoutMillis
            connection.readTimeout = timeoutMillis
            connection.requestMethod = "POST"
            connection.doOutput = true
            // Buffered, not streamed: the JDK's connection keeps no error
            // body for a streamed request answered 401 with WWW-Authenticate,
            // as invalid_signed_request is.
            headers.forEach { (k, v) -> connection.setRequestProperty(k, v) }
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val data = stream?.use { readBounded(it) } ?: ByteArray(0)
            return WalletProviderAnswer(status, connection.contentType, data)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBounded(input: java.io.InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > HttpWalletProvider.MAX_RESPONSE_BYTES) {
                throw IOException("the Wallet Provider's answer is larger than ${HttpWalletProvider.MAX_RESPONSE_BYTES} bytes")
            }
        }
        return out.toByteArray()
    }
}

private val base64URL: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()

internal fun encodeBase64URL(b: ByteArray): String = base64URL.encodeToString(b)

/** Unpadded base64url, as the protocol writes binary values; null for anything else. */
internal fun decodeBase64URL(s: String): ByteArray? =
    if (s.isEmpty() || s.contains('=')) null else runCatching { Base64.getUrlDecoder().decode(s) }.getOrNull()

internal fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

/** An uncompressed P-256 point as a public JWK, with only its required members. */
internal fun jwkOf(point: ByteArray): JsonObject = JsonObject(
    mapOf(
        "kty" to JsonPrimitive("EC"),
        "crv" to JsonPrimitive("P-256"),
        "x" to JsonPrimitive(encodeBase64URL(point.copyOfRange(1, 33))),
        "y" to JsonPrimitive(encodeBase64URL(point.copyOfRange(33, 65))),
    ),
)

/** An uncompressed P-256 point's JWK SHA-256 thumbprint (RFC 7638), base64url. */
internal fun jwkThumbprint(point: ByteArray): String {
    val x = encodeBase64URL(point.copyOfRange(1, 33))
    val y = encodeBase64URL(point.copyOfRange(33, 65))
    return encodeBase64URL(sha256("""{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}""".toByteArray()))
}

/** A key's `android-key` evidence: its attestation [chain]'s DER certificates concatenated, leaf first. */
internal fun androidKeyEvidence(chain: List<ByteArray>): JsonObject {
    val out = ByteArrayOutputStream()
    chain.forEach(out::write)
    return JsonObject(mapOf("kind" to JsonPrimitive("android-key"), "data" to JsonPrimitive(encodeBase64URL(out.toByteArray()))))
}

/** Whether [needle] occurs in [haystack]: a challenge's bytes in the certificate attesting a key over it. */
internal fun contains(haystack: ByteArray, needle: ByteArray): Boolean {
    if (needle.isEmpty() || needle.size > haystack.size) return false
    outer@ for (i in 0..haystack.size - needle.size) {
        for (j in needle.indices) if (haystack[i + j] != needle[j]) continue@outer
        return true
    }
    return false
}

/** A signed request's claims (WALLET_PROVIDER.md, Signed requests), in the Go client's order. */
internal fun requestClaims(instanceID: String, method: String, path: String, body: ByteArray, challenge: String, iat: Long): JsonObject =
    JsonObject(
        mapOf(
            "sub" to JsonPrimitive(instanceID),
            "method" to JsonPrimitive(method),
            "path" to JsonPrimitive(path),
            "body_sha256" to JsonPrimitive(encodeBase64URL(sha256(body))),
            "challenge" to JsonPrimitive(challenge),
            "iat" to JsonPrimitive(iat),
        ),
    )

/**
 * A compact JWS of [claims] under [header], ES256: [sign] signs the
 * signing input's SHA-256 digest, answering a DER ECDSA signature, which
 * becomes JWS's r || s.
 */
internal fun signES256(header: String, claims: JsonObject, sign: (ByteArray) -> ByteArray): String {
    val input = encodeBase64URL(header.toByteArray()) + "." + encodeBase64URL(claims.toString().toByteArray())
    val signature = derToRawECDSA(sign(sha256(input.toByteArray())), 32)
    return input + "." + encodeBase64URL(signature)
}

/**
 * An ASN.1 DER ECDSA signature, SEQUENCE { INTEGER r, INTEGER s }, as
 * JWS's fixed-width r || s, each [size] bytes.
 */
internal fun derToRawECDSA(der: ByteArray, size: Int): ByteArray {
    val reader = DerReader(der)
    reader.expect(reader.byte() == 0x30)
    reader.expect(reader.length() == der.size - reader.at)
    val r = reader.integer(size)
    val s = reader.integer(size)
    reader.expect(reader.at == der.size)
    return r + s
}

/** Reads a DER ECDSA signature, failing with [NOT_DER_ECDSA]. */
private class DerReader(private val der: ByteArray) {
    var at = 0

    fun expect(ok: Boolean) {
        if (!ok) throw StoreException(NOT_DER_ECDSA)
    }

    fun byte(): Int {
        expect(at < der.size)
        return der[at++].toInt() and 0xff
    }

    fun length(): Int {
        val first = byte()
        if (first < 0x80) return first
        expect(first == 0x81)
        return byte().also { expect(it >= 0x80) }
    }

    /** An INTEGER, unsigned and left-padded to [size] bytes. */
    fun integer(size: Int): ByteArray {
        expect(byte() == 0x02)
        val n = length()
        expect(n != 0 && at + n <= der.size)
        val v = der.copyOfRange(at, at + n)
        at += n
        val stripped = v.dropWhile { it == 0.toByte() }.toByteArray()
        expect(stripped.size <= size)
        return ByteArray(size - stripped.size) + stripped
    }
}

private const val NOT_DER_ECDSA = "the key store's signature isn't DER ECDSA"

private const val JSON_TYPE = "application/json"

/** A compact JWS's payload, decoded but not verified: a check the provider answered what was asked. */
internal fun unverifiedClaims(jwt: String): JsonObject? {
    val parts = jwt.split('.')
    if (parts.size != 3) return null
    return decodeBase64URL(parts[1])?.let(::parseObject)
}

private fun parseObject(b: ByteArray): JsonObject? =
    runCatching { json.parseToJsonElement(b.decodeToString(throwOnInvalidSequence = true)) as? JsonObject }.getOrNull()

private fun JsonObject.stringOrNull(name: String): String? = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content

private fun JsonObject.string(name: String): String =
    stringOrNull(name)?.takeIf { it.isNotEmpty() } ?: throw StoreException("the Wallet Provider's answer has no $name")
