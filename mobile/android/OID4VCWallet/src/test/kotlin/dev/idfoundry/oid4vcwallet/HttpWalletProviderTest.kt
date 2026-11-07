package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URI
import java.nio.file.Files
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import kotlin.concurrent.thread

private const val JSON = "application/json"
private const val CHALLENGE = "/v1/challenge"
private const val INSTANCES = "/v1/instances"
private const val WALLET_ATTESTATION = "/v1/wallet-attestation"
private const val KEY_ATTESTATION = "/v1/key-attestation"
private const val CLIENT_ID = "client-1"
private const val NONCE = "nonce-1"
private const val OK = "200 OK"
private const val INSTANCE_KEY = "instance_key"
private const val EVIDENCE = "evidence"
private const val KEY_REGISTERED = "instance_key_registered"
private const val NETWORK = "[network]"

/**
 * HttpWalletProvider against a fake provider speaking the protocol
 * (WALLET_PROVIDER.md), in process, and its HTTP transport against a
 * socket server.
 */
class HttpWalletProviderTest {
    // A key store of JVM keys signing as Android Keystore does (NONEwithECDSA
    // over a digest, DER), whose "attestation chain" is a leaf carrying the
    // challenge the key was made over, as an Android Key Attestation leaf does.
    private class FakeKeyStore(private val attests: Boolean = true) : KeyStore {
        val pairs = mutableMapOf<String, KeyPair>()
        val challenges = mutableMapOf<String, ByteArray?>()
        val purposes = mutableMapOf<String, KeyPurpose>()
        private var n = 0

        override fun createKey(purpose: KeyPurpose): String = createKey(purpose, null)

        override fun createKey(purpose: KeyPurpose, attestationChallenge: ByteArray?): String {
            val id = "k${n++}"
            pairs[id] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            challenges[id] = attestationChallenge
            purposes[id] = purpose
            return id
        }

        override fun publicKey(id: String): ByteArray? = pairs[id]?.let { point(it.public as ECPublicKey) }

        override fun sign(id: String, digest: ByteArray): ByteArray =
            Signature.getInstance("NONEwithECDSA").run {
                initSign(pairs[id]?.private ?: throw StoreException("no key $id"))
                update(digest)
                sign()
            }

        override fun deleteKey(id: String) {
            pairs.remove(id)
        }

        override fun attestationChain(id: String): List<ByteArray>? =
            challenges[id]?.takeIf { attests }?.let { listOf("LEAF".toByteArray() + it + "END".toByteArray(), "ROOT".toByteArray()) }

        fun evidence(id: String): KeyEvidence = KeyEvidence(jwkOf(publicKey(id)!!).toString().toByteArray(), id, attestationChain(id).orEmpty())
    }

    /** A Wallet Provider speaking protocol version 1 in process, checking what it's sent as the Go handler does. */
    private class FakeProvider(val prefix: String = "/wp") : WalletProviderTransport {
        var now = 1_000_000L
        val challenges = mutableMapOf<String, Pair<String, Long>>()

        /** Each instance's registration key, by instance ID. */
        val instances = mutableMapOf<String, ByteArray>()

        /** Each recorded instance key's instance, by its point in hex. */
        val instanceKeys = mutableMapOf<String, String>()
        val requests = mutableListOf<Pair<String, JsonObject>>()
        val signedClaims = mutableListOf<JsonObject>()

        /** An error to answer the next request to a path with: status, error. */
        val refuse = mutableMapOf<String, Pair<Int, String>>()

        /** Changes the claims of the attestations issued. */
        var tamper: (MutableMap<String, JsonElement>) -> Unit = {}

        /** How long a registration takes. */
        var registrationDelayMillis = 0L

        private val random = SecureRandom()

        // One request at a time, as providers may post from several threads.
        @Synchronized
        override fun post(url: URI, headers: Map<String, String>, body: ByteArray): WalletProviderAnswer {
            assertEquals(JSON, headers["Content-Type"])
            val path = url.rawPath.removePrefix(prefix)
            assertTrue(url.rawPath.startsWith(prefix))
            val o = json.parseToJsonElement(body.decodeToString()).jsonObject
            requests += path to o
            refuse.remove(path)?.let { (status, error) -> return error(status, error) }
            return when (path) {
                CHALLENGE -> challenge(o)
                INSTANCES -> register(o)
                WALLET_ATTESTATION -> walletAttestation(url.rawPath, headers, body, o)
                KEY_ATTESTATION -> keyAttestation(url.rawPath, headers, body, o)
                else -> answer(404, "not found", "text/plain")
            }
        }

        private fun challenge(o: JsonObject): WalletProviderAnswer {
            assertEquals(setOf("purpose"), o.keys)
            val purpose = o.getValue("purpose").jsonPrimitive.content
            assertTrue(purpose, purpose in setOf("registration", "instance", "holder", "request"))
            val b = ByteArray(32).also(random::nextBytes)
            val c = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
            challenges[c] = purpose to now + 300
            return answer(200, """{"challenge":"$c","purpose":"$purpose","expires_at":${now + 300}}""")
        }

        private fun register(o: JsonObject): WalletProviderAnswer {
            if (registrationDelayMillis > 0) Thread.sleep(registrationDelayMillis)
            assertEquals(setOf("challenge", "registration_key", EVIDENCE), o.keys)
            val challenge = o.getValue("challenge").jsonPrimitive.content
            val point = jwkPoint(o.getValue("registration_key").toString().toByteArray())!!
            if (!consume(challenge, "registration")) return error(400, "invalid_challenge")
            if (!vouches(o.getValue(EVIDENCE).jsonObject, challenge)) return error(403, "evidence_rejected")
            if (instances.values.any { it.contentEquals(point) } || hex(point) in instanceKeys) return error(409, KEY_REGISTERED)
            val id = "inst${instances.size}"
            instances[id] = point
            return answer(201, """{"instance_id":"$id"}""")
        }

        private fun walletAttestation(path: String, headers: Map<String, String>, body: ByteArray, o: JsonObject): WalletProviderAnswer {
            val instance = verify(path, headers, body) ?: return error(401, "invalid_signed_request")
            assertTrue(o.keys.toString(), o.keys.containsAll(setOf("client_id", INSTANCE_KEY)) && (o.keys - setOf("client_id", INSTANCE_KEY, "challenge", EVIDENCE)).isEmpty())
            val point = jwkPoint(o.getValue(INSTANCE_KEY).toString().toByteArray())!!
            val owner = instanceKeys[hex(point)]
            if (instances.getValue(instance).contentEquals(point) || (owner != null && owner != instance)) return error(409, KEY_REGISTERED)
            if (owner == null) {
                // A new instance key: its evidence over an instance challenge.
                val ev = o[EVIDENCE]?.jsonObject ?: return error(400, "evidence_required")
                val challenge = o.getValue("challenge").jsonPrimitive.content
                if (!consume(challenge, "instance")) return error(400, "invalid_challenge")
                if (!vouches(ev, challenge)) return error(403, "evidence_rejected")
                instanceKeys[hex(point)] = instance
            }
            return jwt(mutableMapOf("sub" to o.getValue("client_id"), "cnf" to JsonObject(mapOf("jwk" to jwkOf(point)))), "wallet_attestation")
        }

        private fun keyAttestation(path: String, headers: Map<String, String>, body: ByteArray, o: JsonObject): WalletProviderAnswer {
            val instance = verify(path, headers, body) ?: return error(401, "invalid_signed_request")
            assertTrue(o.keys.toString(), (o.keys - setOf("nonce")) == setOf(INSTANCE_KEY, "challenge", "keys", EVIDENCE))
            val point = jwkPoint(o.getValue(INSTANCE_KEY).toString().toByteArray())!!
            if (instanceKeys[hex(point)] != instance) return error(400, "unknown_instance_key")
            if (!consume(o.getValue("challenge").jsonPrimitive.content, "holder")) return error(400, "invalid_challenge")
            val claims = mutableMapOf<String, JsonElement>("attested_keys" to o.getValue("keys"))
            // An empty nonce is omitted, as the Go provider's omitempty does.
            o["nonce"]?.takeIf { it.jsonPrimitive.content.isNotEmpty() }?.let { claims["nonce"] = it }
            return jwt(claims, "key_attestation")
        }

        private fun vouches(ev: JsonObject, challenge: String): Boolean {
            assertEquals("android-key", ev.getValue("kind").jsonPrimitive.content)
            val data = Base64.getUrlDecoder().decode(ev.getValue("data").jsonPrimitive.content)
            return contains(data, Base64.getUrlDecoder().decode(challenge))
        }

        private fun consume(c: String, purpose: String): Boolean {
            val (p, exp) = challenges.remove(c) ?: return false
            return p == purpose && exp > now
        }

        // The instance the signed request is from, or null when it doesn't verify.
        private fun verify(path: String, headers: Map<String, String>, body: ByteArray): String? {
            val jwt = headers["Wallet-Provider-Request"] ?: return null
            val (h, p, s) = jwt.split('.')
            val header = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(h))).jsonObject
            assertEquals("ES256", header.getValue("alg").jsonPrimitive.content)
            assertEquals("wallet-provider-request+jwt", header.getValue("typ").jsonPrimitive.content)
            val claims = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(p))).jsonObject
            signedClaims += claims
            assertEquals(setOf("sub", "method", "path", "body_sha256", "challenge", "iat"), claims.keys)
            val instance = claims.getValue("sub").jsonPrimitive.content
            val point = instances[instance] ?: return null
            val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initVerify(publicKey(point))
                update("$h.$p".toByteArray())
                verify(Base64.getUrlDecoder().decode(s))
            }
            if (!ok) return null
            assertEquals("POST", claims.getValue("method").jsonPrimitive.content)
            assertEquals(path, claims.getValue("path").jsonPrimitive.content)
            assertEquals(encodeBase64URL(sha256(body)), claims.getValue("body_sha256").jsonPrimitive.content)
            assertEquals(now, claims.getValue("iat").jsonPrimitive.long)
            if (!consume(claims.getValue("challenge").jsonPrimitive.content, "request")) return null
            return instance
        }

        private fun jwt(claims: MutableMap<String, JsonElement>, member: String): WalletProviderAnswer {
            tamper(claims)
            val enc = Base64.getUrlEncoder().withoutPadding()
            val token = enc.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
                enc.encodeToString(JsonObject(claims).toString().toByteArray()) + ".c2ln"
            return answer(200, """{"$member":"$token","expires_at":${now + 7200}}""")
        }

        fun count(path: String): Int = requests.count { it.first == path }

        fun last(path: String): JsonObject = requests.last { it.first == path }.second

        fun challengePurposes(): List<String> = requests.filter { it.first == CHALLENGE }.map { it.second.getValue("purpose").jsonPrimitive.content }

        private fun error(status: Int, error: String) = answer(status, """{"error":"$error","error_description":"no"}""")

        private fun answer(status: Int, body: String, type: String = JSON) =
            WalletProviderAnswer(status, type, body.toByteArray())

        private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }

    /** A wallet: its key store, and a client of [provider] with a registration key store of its own. */
    private class Setup(
        val provider: FakeProvider = FakeProvider(),
        val registry: InstanceRegistry = InMemoryInstanceRegistry(),
        val registrationKeys: FakeKeyStore = FakeKeyStore(),
    ) {
        val keys = FakeKeyStore()
        val wp = client()

        fun client(registry: InstanceRegistry = this.registry) =
            HttpWalletProvider("https://wp.example${provider.prefix}/", registry, registrationKeys, provider, { provider.now }, false)

        fun newInstanceKey(): String = keys.createKey(KeyPurpose.INSTANCE, runBlocking { wp.attestationChallenge(KeyPurpose.INSTANCE) })

        fun newHolderKey(): String = keys.createKey(KeyPurpose.HOLDER, runBlocking { wp.attestationChallenge(KeyPurpose.HOLDER) })

        suspend fun walletAttestation(instanceKey: String, client: HttpWalletProvider = wp): String =
            client.walletAttestation(WalletAttestationRequest(CLIENT_ID, keys.evidence(instanceKey)))

        suspend fun keyAttestation(instanceKey: String, holders: List<String>, nonce: String = NONCE): String =
            wp.keyAttestation(KeyAttestationRequest(keys.evidence(instanceKey), holders.map(keys::evidence), nonce))
    }

    @Test
    fun registersOnceAndSignsWithTheRegistrationKey() = runBlocking {
        val provider = FakeProvider()
        val file = File(Files.createTempDirectory("instances").toFile(), "sub/instance.json")
        val s = Setup(provider, FileInstanceRegistry(file))
        val first = s.newInstanceKey()
        assertEquals(32, s.keys.challenges.getValue(first)!!.size)
        val wa = s.walletAttestation(first)
        assertEquals(CLIENT_ID, unverifiedClaims(wa)!!["sub"]!!.jsonPrimitive.content)

        // One registration key, made over the registration challenge, apart from the wallet's keys.
        val registered = s.registry.instance()!!
        assertEquals("inst0", registered.instanceID)
        val regKey = s.registrationKeys.pairs.keys.single()
        assertEquals(regKey, registered.keyID)
        assertEquals(KeyPurpose.INSTANCE, s.registrationKeys.purposes.getValue(regKey))
        assertEquals(jwkThumbprint(s.registrationKeys.publicKey(regKey)!!), registered.keyThumbprint)
        assertEquals(encodeBase64URL(s.registrationKeys.challenges.getValue(regKey)!!), provider.last(INSTANCES)["challenge"]!!.jsonPrimitive.content)

        // The instance key's first Wallet Attestation carries its chain and challenge.
        val sent = provider.last(WALLET_ATTESTATION)
        assertEquals(jwkOf(s.keys.publicKey(first)!!), sent[INSTANCE_KEY])
        assertEquals(encodeBase64URL(s.keys.challenges.getValue(first)!!), sent["challenge"]!!.jsonPrimitive.content)

        // A second issuance's instance key: no new registration.
        s.walletAttestation(s.newInstanceKey())
        // Another launch: the registry remembers the registration.
        val again = s.client(FileInstanceRegistry(file))
        s.walletAttestation(s.keys.createKey(KeyPurpose.INSTANCE, again.attestationChallenge(KeyPurpose.INSTANCE)), again)
        assertEquals(1, provider.count(INSTANCES))
        assertEquals(3, provider.instanceKeys.size)
        assertEquals(
            listOf("instance", "registration", "request", "instance", "request", "instance", "request"),
            provider.challengePurposes(),
        )
        // Every request is the registration's; the signed path is the escaped path as sent, with the base URL's prefix.
        assertTrue(provider.signedClaims.all { it["sub"]!!.jsonPrimitive.content == "inst0" })
        assertEquals("/wp/v1/wallet-attestation", provider.signedClaims.last()["path"]!!.jsonPrimitive.content)
    }

    @Test
    fun eachInstanceKeyGoesWithTheChallengeItWasMadeOver() = runBlocking {
        val s = Setup()
        val first = s.newInstanceKey()
        val second = s.newInstanceKey()
        // The first key goes with its own challenge, not the latest.
        s.walletAttestation(first)
        assertEquals(encodeBase64URL(s.keys.challenges.getValue(first)!!), s.provider.last(WALLET_ATTESTATION)["challenge"]!!.jsonPrimitive.content)
        s.walletAttestation(second)
        assertEquals(2, s.provider.instanceKeys.size)
    }

    @Test
    fun aRecordedInstanceKeyGoesAloneOnceItsChallengeExpired() = runBlocking {
        val s = Setup()
        val key = s.newInstanceKey()
        s.walletAttestation(key)
        // Again soon: the chain goes again, and the provider ignores it.
        s.walletAttestation(key)
        assertTrue(EVIDENCE in s.provider.last(WALLET_ATTESTATION))
        // At a refresh, once the challenge expired: the key alone.
        s.provider.now += 3600
        s.walletAttestation(key)
        assertEquals(setOf("client_id", INSTANCE_KEY), s.provider.last(WALLET_ATTESTATION).keys)
        // After a restart too.
        s.walletAttestation(key, s.client())
        assertEquals(1, s.provider.instanceKeys.size)
    }

    @Test
    fun anUnrecordedInstanceKeyWithoutEvidenceIsRefused() = runBlocking {
        val s = Setup()
        val bare = s.keys.createKey(KeyPurpose.INSTANCE)
        val e = runCatching { s.walletAttestation(bare) }.exceptionOrNull()
        assertTrue("$e", e is WalletProviderRefusedException && e.error == "evidence_required")
        // Its challenge expired: the same.
        val key = s.newInstanceKey()
        s.provider.now += 600
        val expired = runCatching { s.walletAttestation(key) }.exceptionOrNull()
        assertTrue("$expired", expired is WalletProviderRefusedException && expired.error == "evidence_required")
        // The registration stands.
        assertEquals(1, s.provider.count(INSTANCES))
    }

    @Test
    fun holderKeysShareAChallengeUntilUsed() = runBlocking {
        val s = Setup()
        val instance = s.newInstanceKey()
        s.walletAttestation(instance)

        val batch = (1..3).map { s.newHolderKey() }
        assertEquals(1, s.provider.challengePurposes().count { it == "holder" })
        assertEquals(1, batch.map { s.keys.challenges.getValue(it)!!.toList() }.toSet().size)
        assertNull(s.wp.attestationChallenge(KeyPurpose.DPOP))

        val ka = s.keyAttestation(instance, batch)
        val sent = s.provider.last(KEY_ATTESTATION)
        assertEquals(jwkOf(s.keys.publicKey(instance)!!), sent[INSTANCE_KEY])
        assertEquals(encodeBase64URL(s.keys.challenges.getValue(batch[0])!!), sent["challenge"]!!.jsonPrimitive.content)
        assertEquals(3, (sent["keys"] as JsonArray).size)
        assertEquals(3, (sent[EVIDENCE] as JsonArray).size)
        assertEquals(NONCE, sent["nonce"]!!.jsonPrimitive.content)
        assertEquals(NONCE, unverifiedClaims(ka)!!["nonce"]!!.jsonPrimitive.content)
        assertEquals("inst0", s.provider.signedClaims.last()["sub"]!!.jsonPrimitive.content)

        // Used: the next batch gets a new one.
        val next = s.newHolderKey()
        assertEquals(2, s.provider.challengePurposes().count { it == "holder" })
        assertFalse(s.keys.challenges.getValue(next)!!.contentEquals(s.keys.challenges.getValue(batch[0])!!))
    }

    @Test
    fun keyAttestationForAnUnknownInstanceKeyIsRefused() = runBlocking {
        val s = Setup()
        s.walletAttestation(s.newInstanceKey())
        // An instance key no Wallet Attestation recorded.
        val other = s.newInstanceKey()
        val e = runCatching { s.keyAttestation(other, listOf(s.newHolderKey())) }.exceptionOrNull()
        assertTrue("$e", e is WalletProviderRefusedException && e.status == 400 && e.error == "unknown_instance_key")
        assertTrue(e!!.message!!.contains("unknown_instance_key"))
        val marked = runCatching { waitForProvider<Unit> { throw e } }.exceptionOrNull()!!
        assertFalse(marked.message!!.startsWith(NETWORK))
    }

    @Test
    fun parallelBatchesSharingAChallengeFailAsNetwork() = runBlocking {
        val s = Setup()
        val instance = s.newInstanceKey()
        s.walletAttestation(instance)
        val a = s.newHolderKey()
        val b = s.newHolderKey()
        s.keyAttestation(instance, listOf(a), "n")
        val e = runCatching { s.keyAttestation(instance, listOf(b), "n") }.exceptionOrNull()
        assertTrue("$e", e is WalletProviderUnavailableException && e.error == "invalid_challenge")
        // Its challenge was the one b was made over.
        assertEquals(encodeBase64URL(s.keys.challenges.getValue(b)!!), s.provider.last(KEY_ATTESTATION)["challenge"]!!.jsonPrimitive.content)
    }

    @Test
    fun holderChallengeIsRenewedNearItsExpiry() = runBlocking {
        val s = Setup()
        val a = s.wp.attestationChallenge(KeyPurpose.HOLDER)!!
        s.provider.now += 200
        assertArrayEquals(a, s.wp.attestationChallenge(KeyPurpose.HOLDER))
        s.provider.now += 50 // 50 seconds left: within the margin
        val b = s.wp.attestationChallenge(KeyPurpose.HOLDER)!!
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun keyAttestationSkipsKeysWithoutAChain() = runBlocking {
        val s = Setup()
        val instance = s.newInstanceKey()
        s.walletAttestation(instance)
        val attested = s.newHolderKey()
        val bare = s.keys.createKey(KeyPurpose.HOLDER)
        s.keyAttestation(instance, listOf(attested, bare), "n")
        val sent = s.provider.last(KEY_ATTESTATION)
        assertEquals(2, (sent["keys"] as JsonArray).size)
        assertEquals(1, (sent[EVIDENCE] as JsonArray).size)
    }

    @Test
    fun keyAttestationNeedsARegistration() = runBlocking {
        val s = Setup()
        val instance = s.newInstanceKey()
        val e = runCatching { s.keyAttestation(instance, listOf(s.newHolderKey()), "n") }.exceptionOrNull()
        assertTrue("$e", e is StoreException && e.message!!.contains("isn't registered"))
        assertEquals(0, s.provider.count(KEY_ATTESTATION))
        assertEquals(0, s.provider.count(INSTANCES))
    }

    @Test
    fun keyAttestationAfterARestart() = runBlocking {
        val s = Setup()
        val instance = s.newInstanceKey()
        s.walletAttestation(instance)
        val again = s.client()
        val holder = s.keys.createKey(KeyPurpose.HOLDER, again.attestationChallenge(KeyPurpose.HOLDER))
        again.keyAttestation(KeyAttestationRequest(s.keys.evidence(instance), listOf(s.keys.evidence(holder)), "n"))
        assertEquals("inst0", s.provider.signedClaims.last()["sub"]!!.jsonPrimitive.content)
    }

    @Test
    fun aLostRegistrationKeyRegistersAgain() = runBlocking {
        val s = Setup()
        s.walletAttestation(s.newInstanceKey())
        val lost = s.registry.instance()!!
        s.registrationKeys.deleteKey(lost.keyID)
        s.walletAttestation(s.newInstanceKey())
        assertEquals(2, s.provider.count(INSTANCES))
        val now = s.registry.instance()!!
        assertEquals("inst1", now.instanceID)
        assertNotEquals(lost.keyID, now.keyID)
        assertEquals("inst1", s.provider.signedClaims.last()["sub"]!!.jsonPrimitive.content)
    }

    @Test
    fun aLostRegistryRegistersAgainWithANewKey() = runBlocking {
        val s = Setup()
        val old = s.newInstanceKey()
        s.walletAttestation(old)
        s.registry.remove(s.registry.instance()!!)
        // A new issuance works: a new registration key registers.
        s.walletAttestation(s.newInstanceKey())
        assertEquals(2, s.provider.instances.size)
        assertEquals("inst1", s.registry.instance()!!.instanceID)
        // An instance key the lost instance recorded is that instance's.
        val e = runCatching { s.walletAttestation(old) }.exceptionOrNull()
        assertTrue("$e", e is WalletProviderRefusedException && e.status == 409 && e.error == KEY_REGISTERED)
    }

    @Test
    fun aRegistrationKeyTheProviderHasSeenIsReplaced() = runBlocking {
        val s = Setup()
        s.provider.refuse[INSTANCES] = 409 to KEY_REGISTERED
        s.walletAttestation(s.newInstanceKey())
        assertEquals(2, s.provider.count(INSTANCES))
        // The refused key is deleted; the second is kept.
        assertEquals(setOf(s.registry.instance()!!.keyID), s.registrationKeys.pairs.keys)
        assertEquals(listOf("instance", "registration", "registration", "request"), s.provider.challengePurposes())
    }

    @Test
    fun aRefusedRegistrationDeletesItsKey() = runBlocking {
        val s = Setup()
        s.provider.refuse[INSTANCES] = 403 to "policy_refused"
        val e = runCatching { s.walletAttestation(s.newInstanceKey()) }.exceptionOrNull()
        assertTrue("$e", e is WalletProviderRefusedException && e.error == "policy_refused")
        assertTrue(s.registrationKeys.pairs.isEmpty())
        assertNull(s.registry.instance())
        assertEquals(0, s.provider.count(WALLET_ATTESTATION))
        // Tried again, it registers.
        s.walletAttestation(s.newInstanceKey())
        assertEquals("inst0", s.registry.instance()!!.instanceID)
    }

    @Test
    fun aRegistrationWhoseKeyIDNamesAnotherKeyIsForgotten() = runBlocking {
        val s = Setup()
        val stray = s.registrationKeys.createKey(KeyPurpose.INSTANCE, ByteArray(32))
        s.registry.put(RegisteredInstance("another key's", stray, "inst-old"))
        s.walletAttestation(s.newInstanceKey())
        // The stray key is deleted; the new registration's is kept.
        assertEquals(setOf(s.registry.instance()!!.keyID), s.registrationKeys.pairs.keys)
        assertEquals("inst0", s.registry.instance()!!.instanceID)
    }

    @Test
    fun theSweepKeepsOnlyTheRegistrationsKey() = runBlocking {
        val s = Setup()
        val deleteExcept = { keep: Set<String> ->
            val gone = s.registrationKeys.pairs.keys - keep
            gone.forEach(s.registrationKeys::deleteKey)
            gone.size
        }
        // Left by a registration that never finished; nothing registered.
        val left = s.registrationKeys.createKey(KeyPurpose.INSTANCE, ByteArray(32))
        assertEquals(1, s.wp.sweepRegistrationKeys(deleteExcept))
        assertNull(s.registrationKeys.publicKey(left))

        s.walletAttestation(s.newInstanceKey())
        val kept = s.registry.instance()!!
        repeat(2) { s.registrationKeys.createKey(KeyPurpose.INSTANCE, ByteArray(32)) }
        assertEquals(2, s.wp.sweepRegistrationKeys(deleteExcept))
        assertEquals(setOf(kept.keyID), s.registrationKeys.pairs.keys)
        // The registration still signs: no new one.
        s.walletAttestation(s.newInstanceKey())
        assertEquals(1, s.provider.count(INSTANCES))

        // A store that can't list its keys: nothing is deleted.
        s.registrationKeys.createKey(KeyPurpose.INSTANCE, ByteArray(32))
        assertEquals(0, s.wp.sweepOrphanedRegistrationKeys())
        assertEquals(2, s.registrationKeys.pairs.size)
    }

    @Test
    fun aRegistrationKeyStoreThatDoesntAttestIsRefused() = runBlocking {
        val s = Setup(registrationKeys = FakeKeyStore(attests = false))
        expectStoreException("didn't attest the registration key") { s.walletAttestation(s.newInstanceKey()) }
        assertTrue(s.registrationKeys.pairs.isEmpty())
        assertEquals(0, s.provider.count(INSTANCES))
    }

    @Test
    fun instanceRevokedForgetsTheRegistration() = runBlocking {
        val s = Setup()
        val key = s.newInstanceKey()
        s.walletAttestation(key)
        val revoked = s.registry.instance()!!
        s.provider.refuse[WALLET_ATTESTATION] = 403 to "instance_revoked"
        val e = runCatching { s.walletAttestation(key) }.exceptionOrNull()
        assertTrue(e is WalletProviderRefusedException)
        assertEquals("instance_revoked", (e as WalletProviderRefusedException).error)
        assertEquals(403, e.status)
        assertTrue(e.message!!.contains("instance_revoked"))
        assertNull(s.registry.instance())
        assertNull(s.registrationKeys.publicKey(revoked.keyID))
        // The next issuance registers afresh.
        s.walletAttestation(s.newInstanceKey())
        assertEquals("inst1", s.registry.instance()!!.instanceID)
    }

    @Test
    fun errorsMapToNetworkOrPlatform() = runBlocking {
        val s = Setup()
        val id = s.newInstanceKey()
        s.walletAttestation(id)
        val cases = listOf(
            Triple(500, "server_error", true),
            Triple(429, "slow_down", true),
            Triple(400, "invalid_challenge", true),
            Triple(403, "evidence_rejected", false),
            Triple(403, "policy_refused", false),
            Triple(403, "instance_not_active", false),
            Triple(401, "invalid_signed_request", false),
            Triple(409, KEY_REGISTERED, false),
            Triple(400, "unknown_client", false),
        )
        for ((status, error, retryable) in cases) {
            s.provider.refuse[WALLET_ATTESTATION] = status to error
            val before = s.provider.count(WALLET_ATTESTATION)
            val e = runCatching { s.walletAttestation(id) }.exceptionOrNull()!!
            // Not retried.
            assertEquals(before + 1, s.provider.count(WALLET_ATTESTATION))
            val marked = runCatching { waitForProvider<Unit> { throw e } }.exceptionOrNull()!!
            if (retryable) {
                assertTrue(error, e is WalletProviderUnavailableException)
                assertEquals(error, (e as WalletProviderUnavailableException).error)
                // The adapter reports it as network.
                assertTrue(marked.message!!.startsWith(NETWORK))
            } else {
                assertTrue(error, e is WalletProviderRefusedException)
                assertEquals(error, (e as WalletProviderRefusedException).error)
                assertFalse(marked.message!!.startsWith(NETWORK))
            }
        }
        // None of them forgets the registration.
        s.walletAttestation(id)
        assertEquals(1, s.provider.count(INSTANCES))
        assertEquals("inst0", s.registry.instance()!!.instanceID)
    }

    @Test
    fun attestationsAreChecked() = runBlocking {
        val s = Setup()
        val id = s.newInstanceKey()
        val other = jwkOf(s.keys.publicKey(s.keys.createKey(KeyPurpose.DPOP))!!)

        s.provider.tamper = { it["sub"] = JsonPrimitive("someone-else") }
        expectStoreException("isn't for client") { s.walletAttestation(id) }
        s.provider.tamper = { it["cnf"] = JsonObject(mapOf("jwk" to other)) }
        expectStoreException("isn't for client") { s.walletAttestation(id) }
        s.provider.tamper = {}
        s.walletAttestation(id)

        s.provider.tamper = { it["nonce"] = JsonPrimitive("another") }
        expectStoreException("nonce") { s.keyAttestation(id, listOf(s.newHolderKey()), "n") }
        s.provider.tamper = { it["attested_keys"] = JsonArray((it["attested_keys"] as JsonArray) + other) }
        expectStoreException("wasn't sent") { s.keyAttestation(id, listOf(s.newHolderKey()), "n") }
        s.provider.tamper = { it["attested_keys"] = JsonArray(emptyList()) }
        expectStoreException("attests no key") { s.keyAttestation(id, listOf(s.newHolderKey()), "n") }
    }

    @Test
    fun keyAttestationWithoutANonce() = runBlocking {
        // An issuer without a Nonce Endpoint gives an empty nonce, which
        // the provider omits from the Key Attestation.
        val s = Setup()
        val id = s.newInstanceKey()
        s.walletAttestation(id)
        val ka = s.keyAttestation(id, listOf(s.newHolderKey()), "")
        assertNull(unverifiedClaims(ka)!!["nonce"])
        // A nonce where none was sent, or none where one was, is refused.
        s.provider.tamper = { it["nonce"] = JsonPrimitive("n") }
        expectStoreException("nonce") { s.keyAttestation(id, listOf(s.newHolderKey()), "") }
        s.provider.tamper = { it.remove("nonce") }
        expectStoreException("nonce") { s.keyAttestation(id, listOf(s.newHolderKey()), "n") }
    }

    @Test
    fun anEscapedBasePathIsSignedAsSent() = runBlocking {
        val s = Setup(FakeProvider("/w%20p"))
        s.walletAttestation(s.newInstanceKey())
        assertEquals("/w%20p/v1/wallet-attestation", s.provider.signedClaims.last()["path"]!!.jsonPrimitive.content)
    }

    @Test
    fun providersOverOneRegistryFileRegisterOnce() = runBlocking {
        // An app rebuilding its wallet mid-issuance: a second provider over the same file.
        val dir = Files.createTempDirectory("instances").toFile()
        val s = Setup(registry = FileInstanceRegistry(File(dir, "wp/instance.json")))
        val other = s.client(FileInstanceRegistry(File(dir, "wp/./instance.json")))
        val a = s.newInstanceKey()
        val b = s.keys.createKey(KeyPurpose.INSTANCE, other.attestationChallenge(KeyPurpose.INSTANCE))
        s.provider.registrationDelayMillis = 50
        coroutineScope {
            val first = async(Dispatchers.IO) { s.walletAttestation(a) }
            val second = async(Dispatchers.IO) { s.walletAttestation(b, other) }
            first.await()
            second.await()
        }
        assertEquals(1, s.provider.count(INSTANCES))
        assertEquals(1, s.registrationKeys.pairs.size)
        // The second provider knows the challenge the first handed out.
        val c = s.newInstanceKey()
        s.walletAttestation(c, other)
        assertEquals(3, s.provider.instanceKeys.size)
    }

    private suspend fun expectStoreException(text: String, body: suspend () -> Unit) {
        try {
            body()
            fail("expected a refusal containing \"$text\"")
        } catch (e: StoreException) {
            assertTrue(e.message, e.message!!.contains(text))
        }
    }

    @Test
    fun keysMustBeP256JWKs() = runBlocking {
        val s = Setup()
        val id = s.newInstanceKey()
        val notAKey = """{"kty":"OKP","crv":"Ed25519","x":"AA"}""".toByteArray()
        expectStoreException("instance key isn't a P-256 JWK") { s.wp.walletAttestation(WalletAttestationRequest("c", KeyEvidence(notAKey, null, emptyList()))) }
        assertEquals(0, s.provider.count(INSTANCES))
        s.walletAttestation(id)
        val holder = s.keys.evidence(s.newHolderKey())
        expectStoreException("instance key isn't a P-256 JWK") { s.wp.keyAttestation(KeyAttestationRequest(KeyEvidence(notAKey, null, emptyList()), listOf(holder), "n")) }
        expectStoreException("holder key isn't a P-256 JWK") {
            s.wp.keyAttestation(KeyAttestationRequest(s.keys.evidence(id), listOf(holder, KeyEvidence(notAKey, null, emptyList())), "n"))
        }
        expectStoreException("no holder keys") { s.wp.keyAttestation(KeyAttestationRequest(s.keys.evidence(id), emptyList(), "n")) }
        assertEquals(0, s.provider.count(KEY_ATTESTATION))
    }

    @Test
    fun challengeAnswersAreChecked() = runBlocking {
        val bad = listOf(
            """{"challenge":"abc","purpose":"holder","expires_at":1}""",
            """{"challenge":"${"A".repeat(43)}","purpose":"request","expires_at":1}""",
            """{"challenge":"${"A".repeat(43)}","purpose":"holder"}""",
            """{"challenge":"${"A".repeat(42)}=","purpose":"holder","expires_at":1}""",
        )
        for (body in bad) {
            val wp = HttpWalletProvider("https://wp.example", InMemoryInstanceRegistry(), FakeKeyStore(), { _, _, _ ->
                WalletProviderAnswer(200, JSON, body.toByteArray())
            }, { 0L }, false)
            expectStoreException("challenge") { wp.attestationChallenge(KeyPurpose.HOLDER) }
        }
        val wp = HttpWalletProvider("https://wp.example", InMemoryInstanceRegistry(), FakeKeyStore(), { _, _, _ ->
            WalletProviderAnswer(200, "text/html", """{"challenge":"x"}""".toByteArray())
        }, { 0L }, false)
        expectStoreException("content type") { wp.attestationChallenge(KeyPurpose.HOLDER) }
    }

    @Test
    fun onlyHttpsBaseURLs() {
        for (url in listOf("http://wp.example", "https://user@wp.example", "https://wp.example?x=1", "https://wp.example#f", "wp.example", "https:///v1")) {
            try {
                HttpWalletProvider(url, InMemoryInstanceRegistry(), FakeKeyStore())
                fail("accepted $url")
            } catch (e: IllegalArgumentException) {
                // refused
            }
        }
        HttpWalletProvider("https://wp.example/wp/", InMemoryInstanceRegistry(), FakeKeyStore())
    }

    @Test
    fun requestJWT() {
        val keys = FakeKeyStore()
        val id = keys.createKey(KeyPurpose.INSTANCE)
        val body = """{"client_id":"c"}""".toByteArray()
        val claims = requestClaims("inst", "POST", "/wp/v1/wallet-attestation", body, "chal", 1234)
        assertEquals(
            """{"sub":"inst","method":"POST","path":"/wp/v1/wallet-attestation","body_sha256":"${encodeBase64URL(sha256(body))}","challenge":"chal","iat":1234}""",
            claims.toString(),
        )
        val jwt = signES256(HttpWalletProvider.REQUEST_JWT_HEADER, claims) { keys.sign(id, it) }
        val (h, p, s) = jwt.split('.')
        assertEquals("""{"alg":"ES256","typ":"wallet-provider-request+jwt"}""", String(Base64.getUrlDecoder().decode(h)))
        assertEquals(claims, unverifiedClaims(jwt))
        val sig = Base64.getUrlDecoder().decode(s)
        assertEquals(64, sig.size)
        val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run {
            initVerify(keys.pairs.getValue(id).public)
            update("$h.$p".toByteArray())
            verify(sig)
        }
        assertTrue(ok)
    }

    @Test
    fun derSignatures() {
        fun der(r: ByteArray, s: ByteArray): ByteArray {
            val body = byteArrayOf(2, r.size.toByte()) + r + byteArrayOf(2, s.size.toByte()) + s
            return byteArrayOf(0x30, body.size.toByte()) + body
        }
        val r = ByteArray(32) { (0x80 + it).toByte() }
        val s = ByteArray(32) { (it + 1).toByte() }
        // A leading zero for a high bit, and a short s.
        assertArrayEquals(r + s, derToRawECDSA(der(byteArrayOf(0) + r, s), 32))
        assertArrayEquals(r + ByteArray(2) + s.copyOfRange(2, 32), derToRawECDSA(der(r, s.copyOfRange(2, 32)), 32))
        for (bad in listOf(byteArrayOf(), der(r, s).copyOf(40), der(r, s) + 0, der(ByteArray(33) { 1 }, s), byteArrayOf(0x31, 0))) {
            try {
                derToRawECDSA(bad, 32)
                fail("accepted ${bad.size} bytes")
            } catch (e: StoreException) {
                // refused
            }
        }
        // Real signatures, over many keys: some r or s are short or have a high bit.
        val keys = FakeKeyStore()
        repeat(32) {
            val id = keys.createKey(KeyPurpose.DPOP)
            val raw = derToRawECDSA(keys.sign(id, sha256(byteArrayOf(it.toByte()))), 32)
            val ok = Signature.getInstance("SHA256withECDSAinP1363Format").run {
                initVerify(keys.pairs.getValue(id).public)
                update(byteArrayOf(it.toByte()))
                verify(raw)
            }
            assertTrue(ok)
        }
    }

    @Test
    fun thumbprintIsRFC7638() {
        // The canonical {"crv","kty","x","y"} JSON's SHA-256, computed apart.
        val point = byteArrayOf(4) + ByteArray(32) { 1 } + ByteArray(32) { 2 }
        assertEquals("kOFKxjJdOqJD5G4Yuw-cxHe64VGyxKEO_hoV83QfGj0", jwkThumbprint(point))
    }

    @Test
    fun registries() {
        val file = File(Files.createTempDirectory("reg").toFile(), "instance.json")
        for (reg in listOf(FileInstanceRegistry(file), InMemoryInstanceRegistry())) {
            assertNull(reg.instance())
            val a = RegisteredInstance("t1", "k1", "i1")
            val b = RegisteredInstance("t2", "k2", "i2")
            reg.put(a)
            reg.put(b)
            assertEquals(b, reg.instance())
            // Forgetting another leaves the one kept.
            reg.remove(a)
            assertEquals(b, reg.instance())
            reg.remove(b)
            assertNull(reg.instance())
            reg.remove(b)
        }
        FileInstanceRegistry(file).put(RegisteredInstance("t3", "k3", "i3"))
        assertEquals("i3", FileInstanceRegistry(file).instance()!!.instanceID)
        assertEquals(1, file.parentFile!!.listFiles()!!.size)
        file.writeText("not json")
        try {
            FileInstanceRegistry(file).instance()
            fail("read a malformed registry")
        } catch (e: StoreException) {
            // refused
        }
    }

    // The HTTP transport, against a socket server answering one request
    // per connection with [answer], recording what it was sent.
    private class SocketServer(
        val socket: ServerSocket = ServerSocket(0, 8, InetAddress.getLoopbackAddress()),
        private val answer: (String) -> ByteArray,
    ) : AutoCloseable by socket {
        val requests = mutableListOf<String>()

        init {
            thread(isDaemon = true) {
                while (!socket.isClosed) {
                    val conn = runCatching { socket.accept() }.getOrNull() ?: break
                    conn.use { c ->
                        val input = c.getInputStream().bufferedReader(Charsets.ISO_8859_1)
                        val head = generateSequence { input.readLine() }.takeWhile { it.isNotEmpty() }.toList()
                        val length = head.firstOrNull { it.lowercase().startsWith("content-length:") }?.substringAfter(':')?.trim()?.toInt() ?: 0
                        val body = CharArray(length).also { var n = 0; while (n < length) n += input.read(it, n, length - n) }
                        synchronized(requests) { requests += head.joinToString("\n") + "\n\n" + String(body) }
                        c.getOutputStream().write(answer(head.first()))
                        c.getOutputStream().flush()
                    }
                }
            }
        }

        val base: String get() = "http://127.0.0.1:${socket.localPort}/wp"
    }

    private fun http(status: String, type: String, body: ByteArray, extra: String = ""): ByteArray =
        ("HTTP/1.1 $status\r\nContent-Type: $type\r\nContent-Length: ${body.size}\r\nConnection: close\r\n$extra\r\n").toByteArray() + body

    private fun overHTTP(server: SocketServer) =
        HttpWalletProvider(server.base, InMemoryInstanceRegistry(), FakeKeyStore(), UrlConnectionTransport(5_000), { 0L }, true)

    @Test
    fun transportPostsJSON() = runBlocking {
        val c = encodeBase64URL(ByteArray(32) { 7 })
        SocketServer { http(OK, "application/json; charset=utf-8", """{"challenge":"$c","purpose":"instance","expires_at":10}""".toByteArray()) }.use { server ->
            assertArrayEquals(ByteArray(32) { 7 }, overHTTP(server).attestationChallenge(KeyPurpose.INSTANCE))
            val req = server.requests.single()
            assertTrue(req, req.startsWith("POST /wp/v1/challenge HTTP/1.1"))
            assertTrue(req, req.lowercase().contains("content-type: application/json"))
            assertTrue(req, req.endsWith("""{"purpose":"instance"}"""))
        }
    }

    @Test
    fun transportFollowsNoRedirect() = runBlocking {
        SocketServer { line ->
            if (line.contains("/elsewhere")) {
                http(OK, JSON, """{"challenge":"${encodeBase64URL(ByteArray(32))}","purpose":"holder","expires_at":10}""".toByteArray())
            } else {
                http("307 Temporary Redirect", "text/plain", ByteArray(0), "Location: /elsewhere\r\n")
            }
        }.use { server ->
            val e = runCatching { overHTTP(server).attestationChallenge(KeyPurpose.HOLDER) }.exceptionOrNull()
            assertTrue("$e", e is WalletProviderRefusedException && e.status == 307)
            assertEquals(1, server.requests.size)
        }
    }

    @Test
    fun transportReadsA401sError() = runBlocking {
        val body = """{"error":"invalid_signed_request","error_description":"The signed request didn't verify."}""".toByteArray()
        SocketServer { http("401 Unauthorized", JSON, body, "WWW-Authenticate: Wallet-Provider-Request\r\n") }.use { server ->
            val e = runCatching { overHTTP(server).attestationChallenge(KeyPurpose.HOLDER) }.exceptionOrNull()
            assertTrue("$e", e is WalletProviderRefusedException && e.status == 401 && e.error == "invalid_signed_request")
            assertEquals(1, server.requests.size)
        }
    }

    @Test
    fun transportBoundsAnswers() = runBlocking {
        val huge = ByteArray(HttpWalletProvider.MAX_RESPONSE_BYTES + 10) { ' '.code.toByte() }
        SocketServer { http(OK, JSON, huge) }.use { server ->
            val e = runCatching { overHTTP(server).attestationChallenge(KeyPurpose.HOLDER) }.exceptionOrNull()
            assertTrue("$e", e is IOException && e.message!!.contains("larger"))
        }
        SocketServer { http("503 Service Unavailable", "text/html", "<p>busy</p>".toByteArray()) }.use { server ->
            val e = runCatching { overHTTP(server).attestationChallenge(KeyPurpose.HOLDER) }.exceptionOrNull()
            assertTrue("$e", e is WalletProviderUnavailableException && e.status == 503 && e.error == null)
        }
    }

    private companion object {
        fun point(pub: ECPublicKey): ByteArray = byteArrayOf(4) + fixed(pub.w.affineX) + fixed(pub.w.affineY)

        fun fixed(n: BigInteger): ByteArray {
            val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(32 - b.size) + b
        }

        val params = (KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public as ECPublicKey).params

        fun publicKey(point: ByteArray) = KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(ECPoint(BigInteger(1, point.copyOfRange(1, 33)), BigInteger(1, point.copyOfRange(33, 65))), params),
        )
    }
}
