package dev.idfoundry.oid4vcwallet

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
private const val INSTANCES = "/v1/instances"
private const val WALLET_ATTESTATION = "/v1/wallet-attestation"
private const val KEY_ATTESTATION = "/v1/key-attestation"
private const val CLIENT_ID = "client-1"
private const val NONCE = "nonce-1"
private const val OK = "200 OK"

/**
 * HttpWalletProvider against a fake provider speaking the protocol
 * (WALLET_PROVIDER.md), in process, and its HTTP transport against a
 * socket server.
 */
class HttpWalletProviderTest {
    // A key store of JVM keys signing as Android Keystore does (NONEwithECDSA
    // over a digest, DER), whose "attestation chain" is a leaf carrying the
    // challenge the key was made over, as an Android Key Attestation leaf does.
    private class FakeKeyStore : KeyStore {
        val pairs = mutableMapOf<String, KeyPair>()
        val challenges = mutableMapOf<String, ByteArray?>()
        private var n = 0

        override fun createKey(purpose: KeyPurpose): String = createKey(purpose, null)

        override fun createKey(purpose: KeyPurpose, attestationChallenge: ByteArray?): String {
            val id = "k${n++}"
            pairs[id] = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            challenges[id] = attestationChallenge
            return id
        }

        override fun publicKey(id: String): ByteArray? = pairs[id]?.let { point(it.public as ECPublicKey) }

        override fun sign(id: String, digest: ByteArray): ByteArray =
            Signature.getInstance("NONEwithECDSA").run {
                initSign(pairs.getValue(id).private)
                update(digest)
                sign()
            }

        override fun deleteKey(id: String) {
            pairs.remove(id)
        }

        override fun attestationChain(id: String): List<ByteArray>? =
            challenges[id]?.let { listOf("LEAF".toByteArray() + it + "END".toByteArray(), "ROOT".toByteArray()) }

        fun evidence(id: String): KeyEvidence = KeyEvidence(jwkOf(publicKey(id)!!).toString().toByteArray(), id, attestationChain(id).orEmpty())
    }

    /** A Wallet Provider speaking protocol version 1 in process, checking what it's sent as the Go handler does. */
    private class FakeProvider(val prefix: String = "/wp") : WalletProviderTransport {
        var now = 1_000_000L
        val challenges = mutableMapOf<String, Pair<String, Long>>()
        val instances = mutableMapOf<String, ByteArray>()
        val requests = mutableListOf<Pair<String, JsonObject>>()
        val signedClaims = mutableListOf<JsonObject>()

        /** An error to answer the next request to a path with: status, error. */
        val refuse = mutableMapOf<String, Pair<Int, String>>()

        /** Changes the claims of the attestations issued. */
        var tamper: (MutableMap<String, JsonElement>) -> Unit = {}

        private val random = SecureRandom()

        override fun post(url: URI, headers: Map<String, String>, body: ByteArray): WalletProviderAnswer {
            assertEquals(JSON, headers["Content-Type"])
            val path = url.rawPath.removePrefix(prefix)
            assertTrue(url.rawPath.startsWith(prefix))
            val o = json.parseToJsonElement(body.decodeToString()).jsonObject
            requests += path to o
            refuse.remove(path)?.let { (status, error) -> return answer(status, """{"error":"$error","error_description":"no"}""") }
            return when (path) {
                "/v1/challenge" -> {
                    val purpose = o.getValue("purpose").jsonPrimitive.content
                    val b = ByteArray(32).also(random::nextBytes)
                    val c = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
                    challenges[c] = purpose to now + 300
                    answer(200, """{"challenge":"$c","purpose":"$purpose","expires_at":${now + 300}}""")
                }
                INSTANCES -> {
                    val challenge = o.getValue("challenge").jsonPrimitive.content
                    val point = jwkPoint(o.getValue("instance_key").toString().toByteArray())!!
                    val ev = o.getValue("evidence").jsonObject
                    assertEquals("android-key", ev.getValue("kind").jsonPrimitive.content)
                    val data = Base64.getUrlDecoder().decode(ev.getValue("data").jsonPrimitive.content)
                    if (!consume(challenge, "instance") || !contains(data, Base64.getUrlDecoder().decode(challenge))) {
                        return answer(403, """{"error":"evidence_rejected"}""")
                    }
                    if (instances.values.any { it.contentEquals(point) }) return answer(409, """{"error":"instance_key_registered"}""")
                    val id = "inst${instances.size}"
                    instances[id] = point
                    answer(201, """{"instance_id":"$id"}""")
                }
                WALLET_ATTESTATION -> {
                    val point = verify(url.rawPath, headers, body) ?: return answer(401, """{"error":"invalid_signed_request"}""")
                    jwt(mutableMapOf("sub" to o.getValue("client_id"), "cnf" to JsonObject(mapOf("jwk" to jwkOf(point)))), "wallet_attestation")
                }
                KEY_ATTESTATION -> {
                    verify(url.rawPath, headers, body) ?: return answer(401, """{"error":"invalid_signed_request"}""")
                    if (!consume(o.getValue("challenge").jsonPrimitive.content, "holder")) return answer(400, """{"error":"invalid_challenge"}""")
                    val claims = mutableMapOf<String, JsonElement>("attested_keys" to o.getValue("keys"))
                    o["nonce"]?.let { claims["nonce"] = it }
                    jwt(claims, "key_attestation")
                }
                else -> answer(404, "not found", "text/plain")
            }
        }

        private fun consume(c: String, purpose: String): Boolean {
            val (p, exp) = challenges.remove(c) ?: return false
            return p == purpose && exp > now
        }

        // The point of the instance the signed request is from, or null when it doesn't verify.
        private fun verify(path: String, headers: Map<String, String>, body: ByteArray): ByteArray? {
            val jwt = headers["Wallet-Provider-Request"] ?: return null
            val (h, p, s) = jwt.split('.')
            val header = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(h))).jsonObject
            assertEquals("ES256", header.getValue("alg").jsonPrimitive.content)
            assertEquals("wallet-provider-request+jwt", header.getValue("typ").jsonPrimitive.content)
            val claims = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(p))).jsonObject
            signedClaims += claims
            assertEquals(setOf("sub", "method", "path", "body_sha256", "challenge", "iat"), claims.keys)
            val point = instances[claims.getValue("sub").jsonPrimitive.content] ?: return null
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
            return point
        }

        private fun jwt(claims: MutableMap<String, JsonElement>, member: String): WalletProviderAnswer {
            tamper(claims)
            val enc = Base64.getUrlEncoder().withoutPadding()
            val token = enc.encodeToString("""{"alg":"ES256"}""".toByteArray()) + "." +
                enc.encodeToString(JsonObject(claims).toString().toByteArray()) + ".c2ln"
            return answer(200, """{"$member":"$token","expires_at":${now + 7200}}""")
        }

        fun count(path: String): Int = requests.count { it.first == path }

        fun challengePurposes(): List<String> = requests.filter { it.first == "/v1/challenge" }.map { it.second.getValue("purpose").jsonPrimitive.content }

        private fun answer(status: Int, body: String, type: String = JSON) =
            WalletProviderAnswer(status, type, body.toByteArray())
    }

    private fun client(provider: FakeProvider, keys: FakeKeyStore, registry: InstanceRegistry = InMemoryInstanceRegistry()) =
        HttpWalletProvider("https://wp.example${provider.prefix}/", keys, registry, provider, { provider.now }, false)

    private fun newInstanceKey(wp: HttpWalletProvider, keys: FakeKeyStore): String =
        keys.createKey(KeyPurpose.INSTANCE, runBlocking { wp.attestationChallenge(KeyPurpose.INSTANCE) })

    @Test
    fun registersOnceAndSignsRequests() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val dir = Files.createTempDirectory("instances").toFile()
        val registry = FileInstanceRegistry(File(dir, "sub/instances.json"))
        val wp = client(provider, keys, registry)
        val id = newInstanceKey(wp, keys)
        assertEquals(32, keys.challenges.getValue(id)!!.size)

        val wa = wp.walletAttestation(WalletAttestationRequest(CLIENT_ID, keys.evidence(id)))
        assertEquals(CLIENT_ID, unverifiedClaims(wa)!!["sub"]!!.jsonPrimitive.content)
        wp.walletAttestation(WalletAttestationRequest("client-2", keys.evidence(id)))
        assertEquals(1, provider.count(INSTANCES))
        assertEquals(2, provider.count(WALLET_ATTESTATION))
        val registered = registry.instances().single()
        assertEquals("inst0", registered.instanceID)
        assertEquals(id, registered.keyID)
        assertEquals(jwkThumbprint(keys.publicKey(id)!!), registered.keyThumbprint)

        // Another launch: the registry remembers the instance.
        val again = client(provider, keys, FileInstanceRegistry(File(dir, "sub/instances.json")))
        again.walletAttestation(WalletAttestationRequest(CLIENT_ID, keys.evidence(id)))
        assertEquals(1, provider.count(INSTANCES))
        assertEquals(listOf("instance", "request", "request", "request"), provider.challengePurposes())
        // The signed path is the escaped path as sent, with the base URL's prefix.
        assertEquals("/wp/v1/wallet-attestation", provider.signedClaims.last()["path"]!!.jsonPrimitive.content)
    }

    @Test
    fun registrationUsesTheChallengeTheKeyWasMadeOver() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        val first = newInstanceKey(wp, keys)
        val second = newInstanceKey(wp, keys)
        // The first key registers over its own challenge, not the latest.
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(first)))
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(second)))
        assertEquals(2, provider.instances.size)
    }

    @Test
    fun holderKeysShareAChallengeUntilUsed() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        val instance = newInstanceKey(wp, keys)
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(instance)))

        val batch = (1..3).map { keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER)) }
        assertEquals(1, provider.challengePurposes().count { it == "holder" })
        assertEquals(1, batch.map { keys.challenges.getValue(it)!!.toList() }.toSet().size)
        assertNull(wp.attestationChallenge(KeyPurpose.DPOP))

        val ka = wp.keyAttestation(KeyAttestationRequest(batch.map(keys::evidence), NONCE))
        val sent = provider.requests.last { it.first == KEY_ATTESTATION }.second
        assertEquals(encodeBase64URL(keys.challenges.getValue(batch[0])!!), sent["challenge"]!!.jsonPrimitive.content)
        assertEquals(3, (sent["keys"] as JsonArray).size)
        assertEquals(3, (sent["evidence"] as JsonArray).size)
        assertEquals(NONCE, sent["nonce"]!!.jsonPrimitive.content)
        assertEquals(NONCE, unverifiedClaims(ka)!!["nonce"]!!.jsonPrimitive.content)

        // Used: the next batch gets a new one.
        val next = keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER))
        assertEquals(2, provider.challengePurposes().count { it == "holder" })
        assertFalse(keys.challenges.getValue(next)!!.contentEquals(keys.challenges.getValue(batch[0])!!))
    }

    @Test
    fun parallelBatchesSharingAChallengeFailAsNetwork() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(newInstanceKey(wp, keys))))
        val a = keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER))
        val b = keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER))
        wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(a)), "n"))
        val e = runCatching { wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(b)), "n")) }.exceptionOrNull()
        assertTrue("$e", e is WalletProviderUnavailableException && e.error == "invalid_challenge")
        // Its challenge was the one b was made over.
        val sent = provider.requests.last { it.first == KEY_ATTESTATION }.second
        assertEquals(encodeBase64URL(keys.challenges.getValue(b)!!), sent["challenge"]!!.jsonPrimitive.content)
    }

    @Test
    fun holderChallengeIsRenewedNearItsExpiry() = runBlocking {
        val provider = FakeProvider()
        val wp = client(provider, FakeKeyStore())
        val a = wp.attestationChallenge(KeyPurpose.HOLDER)!!
        provider.now += 200
        assertArrayEquals(a, wp.attestationChallenge(KeyPurpose.HOLDER))
        provider.now += 50 // 50 seconds left: within the margin
        val b = wp.attestationChallenge(KeyPurpose.HOLDER)!!
        assertFalse(a.contentEquals(b))
    }

    @Test
    fun keyAttestationSkipsKeysWithoutAChain() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(newInstanceKey(wp, keys))))
        val attested = keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER))
        val bare = keys.createKey(KeyPurpose.HOLDER)
        wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(attested), keys.evidence(bare)), "n"))
        val sent = provider.requests.last().second
        assertEquals(2, (sent["keys"] as JsonArray).size)
        assertEquals(1, (sent["evidence"] as JsonArray).size)
    }

    @Test
    fun keyAttestationNeedsARegisteredInstance() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        val holder = keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER))
        val e = runCatching { wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(holder)), "n")) }.exceptionOrNull()
        assertTrue(e is StoreException && e.message!!.contains("no Wallet Provider instance"))
        assertEquals(0, provider.count(KEY_ATTESTATION))
    }

    @Test
    fun keyAttestationSignsWithARegisteredInstanceAfterARestart() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val registry = InMemoryInstanceRegistry()
        val first = client(provider, keys, registry)
        first.walletAttestation(WalletAttestationRequest("c", keys.evidence(newInstanceKey(first, keys))))
        val wp = client(provider, keys, registry)
        val holder = keys.createKey(KeyPurpose.HOLDER, wp.attestationChallenge(KeyPurpose.HOLDER))
        wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(holder)), "n"))
        assertEquals("inst0", provider.signedClaims.last()["sub"]!!.jsonPrimitive.content)
    }

    @Test
    fun instanceRevokedForgetsTheInstance() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val registry = InMemoryInstanceRegistry()
        val wp = client(provider, keys, registry)
        val id = newInstanceKey(wp, keys)
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id)))
        provider.refuse[WALLET_ATTESTATION] = 403 to "instance_revoked"
        val e = runCatching { wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id))) }.exceptionOrNull()
        assertTrue(e is WalletProviderRefusedException)
        assertEquals("instance_revoked", (e as WalletProviderRefusedException).error)
        assertEquals(403, e.status)
        assertTrue(e.message!!.contains("instance_revoked"))
        assertTrue(registry.instances().isEmpty())
        // A new instance key registers afresh.
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(newInstanceKey(wp, keys))))
        assertEquals(1, registry.instances().size)
    }

    @Test
    fun errorsMapToNetworkOrPlatform() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        val id = newInstanceKey(wp, keys)
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id)))
        val cases = listOf(
            Triple(500, "server_error", true),
            Triple(429, "slow_down", true),
            Triple(400, "invalid_challenge", true),
            Triple(403, "evidence_rejected", false),
            Triple(403, "instance_not_active", false),
            Triple(401, "invalid_signed_request", false),
        )
        for ((status, error, retryable) in cases) {
            provider.refuse[WALLET_ATTESTATION] = status to error
            val before = provider.count(WALLET_ATTESTATION)
            val e = runCatching { wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id))) }.exceptionOrNull()!!
            // Not retried.
            assertEquals(before + 1, provider.count(WALLET_ATTESTATION))
            if (retryable) {
                assertTrue("$error", e is WalletProviderUnavailableException)
                assertEquals(error, (e as WalletProviderUnavailableException).error)
                // The adapter reports it as network.
                val marked = runCatching { waitForProvider<Unit> { throw e } }.exceptionOrNull()!!
                assertTrue(marked.message!!.startsWith("[network]"))
            } else {
                assertTrue("$error", e is WalletProviderRefusedException)
                assertEquals(error, (e as WalletProviderRefusedException).error)
                val marked = runCatching { waitForProvider<Unit> { throw e } }.exceptionOrNull()!!
                assertFalse(marked.message!!.startsWith("[network]"))
            }
        }
        // instance_not_active keeps the instance.
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id)))
        assertEquals(1, provider.count(INSTANCES))
    }

    @Test
    fun attestationsAreChecked() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        val id = newInstanceKey(wp, keys)
        val other = jwkOf(keys.publicKey(keys.createKey(KeyPurpose.DPOP))!!)

        provider.tamper = { it["sub"] = JsonPrimitive("someone-else") }
        expectStoreException("isn't for client") { wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id))) }
        provider.tamper = { it["cnf"] = JsonObject(mapOf("jwk" to other)) }
        expectStoreException("isn't for client") { wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id))) }
        provider.tamper = {}
        wp.walletAttestation(WalletAttestationRequest("c", keys.evidence(id)))

        val holder = { keys.createKey(KeyPurpose.HOLDER, runBlocking { wp.attestationChallenge(KeyPurpose.HOLDER) }) }
        provider.tamper = { it["nonce"] = JsonPrimitive("another") }
        expectStoreException("nonce") { wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(holder())), "n")) }
        provider.tamper = { it["attested_keys"] = JsonArray((it["attested_keys"] as JsonArray) + other) }
        expectStoreException("wasn't sent") { wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(holder())), "n")) }
        provider.tamper = { it["attested_keys"] = JsonArray(emptyList()) }
        expectStoreException("attests no key") { wp.keyAttestation(KeyAttestationRequest(listOf(keys.evidence(holder())), "n")) }
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
    fun instanceKeyNeedsAnIDAndAChain() = runBlocking {
        val provider = FakeProvider()
        val keys = FakeKeyStore()
        val wp = client(provider, keys)
        val id = newInstanceKey(wp, keys)
        val e = keys.evidence(id)
        expectStoreException("which key store key") { wp.walletAttestation(WalletAttestationRequest("c", KeyEvidence(e.jwk, null, e.certificateChain))) }
        expectStoreException("no attestation chain") { wp.walletAttestation(WalletAttestationRequest("c", KeyEvidence(e.jwk, id, emptyList()))) }
        assertEquals(0, provider.count(INSTANCES))
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
            val wp = HttpWalletProvider("https://wp.example", FakeKeyStore(), InMemoryInstanceRegistry(), { _, _, _ ->
                WalletProviderAnswer(200, JSON, body.toByteArray())
            }, { 0L }, false)
            expectStoreException("challenge") { wp.attestationChallenge(KeyPurpose.HOLDER) }
        }
        val wp = HttpWalletProvider("https://wp.example", FakeKeyStore(), InMemoryInstanceRegistry(), { _, _, _ ->
            WalletProviderAnswer(200, "text/html", """{"challenge":"x"}""".toByteArray())
        }, { 0L }, false)
        expectStoreException("content type") { wp.attestationChallenge(KeyPurpose.HOLDER) }
    }

    @Test
    fun onlyHttpsBaseURLs() {
        for (url in listOf("http://wp.example", "https://user@wp.example", "https://wp.example?x=1", "https://wp.example#f", "wp.example", "https:///v1")) {
            try {
                HttpWalletProvider(url, FakeKeyStore(), InMemoryInstanceRegistry())
                fail("accepted $url")
            } catch (e: IllegalArgumentException) {
                // refused
            }
        }
        HttpWalletProvider("https://wp.example/wp/", FakeKeyStore(), InMemoryInstanceRegistry())
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
    fun fileRegistry() {
        val file = File(Files.createTempDirectory("reg").toFile(), "instances.json")
        val reg = FileInstanceRegistry(file)
        assertTrue(reg.instances().isEmpty())
        reg.put(RegisteredInstance("t1", "k1", "i1"))
        reg.put(RegisteredInstance("t2", "k2", "i2"))
        reg.put(RegisteredInstance("t1", "k1", "i3"))
        assertEquals(listOf("i2", "i3"), FileInstanceRegistry(file).instances().map { it.instanceID })
        reg.remove("t2")
        reg.remove("nothing")
        assertEquals(listOf("i3"), reg.instances().map { it.instanceID })
        repeat(FileInstanceRegistry.MAX_INSTANCES + 5) { reg.put(RegisteredInstance("x$it", "k", "i")) }
        assertEquals(FileInstanceRegistry.MAX_INSTANCES, reg.instances().size)
        assertEquals(1, file.parentFile!!.listFiles()!!.size)
        file.writeText("not json")
        try {
            reg.instances()
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
        HttpWalletProvider(server.base, FakeKeyStore(), InMemoryInstanceRegistry(), UrlConnectionTransport(5_000), { 0L }, true)

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
