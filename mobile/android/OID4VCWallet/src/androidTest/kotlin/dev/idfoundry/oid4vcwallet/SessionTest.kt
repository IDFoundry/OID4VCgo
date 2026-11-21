package dev.idfoundry.oid4vcwallet

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.net.ServerSocket
import java.net.Socket
import java.net.URLEncoder
import javax.crypto.KeyGenerator
import kotlin.concurrent.thread
import kotlin.time.Duration.Companion.seconds
import dev.idfoundry.oid4vcwallet.gomobile.mobile.TestEnv as MobileTestEnv

/** The in-process test issuer, Wallet Provider and Verifier (Go's TestEnv, in the mobiletest build). */
class TestEnv(deferIssuance: Boolean = false, batchSize: Int = 0) : AutoCloseable {
    val env: MobileTestEnv = Mobile.startBatchTestEnv(deferIssuance, batchSize.toLong())

    override fun close() = env.close()

    val configuration: WalletConfiguration get() = json.decodeFromString(WalletConfiguration.serializer(), env.configJSON())

    fun approve(url: String): String = env.approve(url)

    fun request(format: String = ""): Pair<String, String> = pair(env.request(format))

    /** A request from a Verifier registered for family_name only, asking for family_name and [extra], if set. */
    fun registeredRequest(format: String = SD_JWT, extra: String = ""): Pair<String, String> = pair(env.registeredRequest(format, extra))

    /** The link to a request the wallet refuses, whose error response the Verifier answers with [redirect]. */
    fun refusedRequest(redirect: String): String = env.refusedRequest(redirect)

    fun result(id: String): JsonObject = json.parseToJsonElement(env.requestResult(id)).jsonObject

    private fun pair(text: String): Pair<String, String> {
        val o = json.parseToJsonElement(text).jsonObject
        return o["id"]!!.jsonPrimitive.content to o["link"]!!.jsonPrimitive.content
    }
}

/**
 * Issuance and presentation end to end through the Kotlin API: Go
 * drives the protocols against the test issuer and Verifier, calling
 * back into Android Keystore keys, the credential store and the Wallet
 * Provider.
 */
@RunWith(AndroidJUnit4::class)
class SessionTest {
    private val prefix = "org.idfoundry.oid4vcgo.session.${System.nanoTime()}."
    private val envs = mutableListOf<TestEnv>()

    private fun env(deferIssuance: Boolean = false, batchSize: Int = 0) = TestEnv(deferIssuance, batchSize).also { envs += it }

    /** Keystore keys, holder keys without the holder: there's no one to ask in a test. */
    private fun keyStore() = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix))

    private fun wallet(
        env: TestEnv,
        keys: KeyStore = keyStore(),
        store: CredentialStore = InMemoryCredentialStore(),
        configuration: WalletConfiguration = env.configuration,
    ) = Wallet(configuration, keys, store, ProviderOf(env))

    @After
    fun cleanUp() {
        envs.forEach { it.close() }
        keyStore().deleteKeys(emptySet())
    }

    private suspend fun receive(env: TestEnv, w: Wallet): Issuance.Result {
        val s = w.startIssuance(env.env.authorizationCodeOffer())
        assertEquals(Offer.Grant.AUTHORIZATION_CODE, s.offer.grant)
        assertEquals(listOf(SD_JWT, "mso_mdoc"), s.offer.credentials.map { it.format }.sorted())
        s.completeAuthorization(env.approve(s.beginAuthorization()))
        val result = s.requestCredentials()
        s.close()
        return result
    }

    private suspend fun expectCode(code: WalletException.Code, body: suspend () -> Unit) {
        try {
            body()
            fail("expected $code")
        } catch (e: WalletException) {
            assertEquals(e.toString(), code, e.code)
        }
    }

    /**
     * A Wallet Provider giving attestation challenges receives each key
     * it attests with its ID and an Android Key Attestation chain over its
     * challenge: the instance key's for the Wallet Attestation, the holder
     * keys' for the Key Attestation, which names the instance key.
     */
    @Test
    fun providerReceivesKeyEvidence(): Unit = runBlocking {
        val env = env()
        val keys = keyStore()
        val provider = EvidenceRecorder(ProviderOf(env))
        val w = Wallet(env.configuration, keys, InMemoryCredentialStore(), provider)
        receive(env, w)

        val instance = provider.walletRequests.first().instanceKey
        assertNotNull(instance.keyID)
        assertEquals(keys.attestationChain(instance.keyID!!)!!.map { it.toList() }, instance.certificateChain.map { it.toList() })
        assertTrue(provider.keyRequests.isNotEmpty())
        // Each Key Attestation is for an instance key a Wallet Attestation
        // was asked for.
        val attested = provider.walletRequests.map { it.instanceKey.jwk.decodeToString() }
        for (r in provider.keyRequests) {
            assertTrue("a Key Attestation for an unattested instance key", r.instanceKey.jwk.decodeToString() in attested)
        }
        for (k in provider.keyRequests.flatMap { it.keys }) {
            assertNotNull(k.keyID)
            assertTrue("holder key ${k.keyID} has no attestation chain", k.certificateChain.size > 1)
        }
        assertTrue(provider.asked.toString(), provider.asked.containsAll(listOf(KeyPurpose.INSTANCE, KeyPurpose.HOLDER)))
    }

    @Test
    fun issueThenPresent(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val received = receive(env, w)
        assertEquals(2, received.credentials.size)
        assertTrue(received.deferred.isEmpty())
        val held = w.credentials()
        assertEquals(received.credentials.map { it.id }.toSet(), held.map { it.id }.toSet())

        val (id, link) = env.request()
        val p = w.startPresentation(link)
        assertTrue(p.verifier.name.isNotEmpty())
        assertEquals(listOf("mdl", "pid"), p.queries.map { it.queryID })
        assertTrue(p.queries.none { it.multiple })
        assertEquals(listOf(listOf(listOf("mdl"), listOf("pid"))), p.credentialSets.map { it.options })
        val sdjwt = held.first { it.format == SD_JWT }.id
        expectCode(WalletException.Code.invalidSelection) { p.preview(mapOf("pid" to listOf(sdjwt, sdjwt))) }
        val selection = mapOf("pid" to listOf(sdjwt))
        assertEquals(listOf(listOf(PathElement.Key("family_name"))), p.preview(selection).first().claims)
        assertEquals(listOf("pid"), p.respond(selection).queryIDs)
        val result = env.result(id)
        assertEquals("done", result["status"]?.jsonPrimitive?.content)
        assertEquals("Doe", result["claims"]?.jsonObject?.get("family_name")?.jsonPrimitive?.content)
        expectCode(WalletException.Code.wrongStep) { p.respond(selection) }

        // Claims for display, and whether the holder key is still there.
        val detail = w.credential(sdjwt)
        assertEquals(sdjwt, detail.summary.id)
        assertEquals(true, detail.summary.holderKeyPresent)
        assertEquals(JsonPrimitive("Doe"), detail.claims.jsonObject["family_name"])
        val mdoc = held.first { it.format == "mso_mdoc" }.id
        assertEquals(JsonPrimitive("Jane"), w.credential(mdoc).claims.jsonObject["org.example.test.1"]?.jsonObject?.get("given_name"))

        w.deleteCredential(sdjwt)
        assertEquals(1, w.credentials().size)
        expectCode(WalletException.Code.notFound) { w.credential(sdjwt) }
    }

    @Test
    fun preAuthorizedCodeWithPIN(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val s = w.startIssuance(env.env.preAuthorizedOffer("493536"))
        assertEquals(Offer.Grant.PRE_AUTHORIZED_CODE, s.offer.grant)
        assertEquals(6, s.offer.txCode?.length)
        try {
            s.redeemPreAuthorizedCode("000000")
            fail("a wrong PIN was accepted")
        } catch (e: WalletException) {
            assertEquals(WalletException.Code.protocol, e.code)
            assertTrue("a wrong PIN can be retried", e.isRetryable)
        }
        s.redeemPreAuthorizedCode("493536")
        assertEquals(1, s.requestCredentials().credentials.size)
        s.close()
    }

    /**
     * `issuers.credentialIssuers` refuses another issuer's offer with
     * `untrustedIssuer` before the holder is asked for its PIN; a
     * configuration with issuer roots and no decision about which
     * issuers' offers it takes, or two, is refused.
     */
    @Test
    fun credentialIssuers(): Unit = runBlocking {
        val env = env()
        val listed = env.configuration.let { it.copy(issuers = it.issuers.copy(credentialIssuers = listOf("https://issuer.other.example"))) }
        val w = wallet(env, configuration = listed)
        expectCode(WalletException.Code.untrustedIssuer) { w.startIssuance(env.env.preAuthorizedOffer("493536")) }

        val undecided = listed.copy(issuers = listed.issuers.copy(credentialIssuers = emptyList()))
        expectCode(WalletException.Code.invalidInput) { wallet(env, configuration = undecided) }
        val both = listed.copy(issuers = listed.issuers.copy(allowAnyCredentialIssuer = true))
        expectCode(WalletException.Code.invalidInput) { wallet(env, configuration = both) }
    }

    /** Deferred credentials survive the issuance closing and a relaunch: a new Wallet over the same stores polls them. */
    @Test
    fun deferredSurvivesARelaunch(): Unit = runBlocking {
        val env = env(deferIssuance = true)
        val keys = keyStore()
        val store = InMemoryCredentialStore()
        val w = wallet(env, keys, store)
        val s = w.startIssuance(env.env.authorizationCodeOffer())
        s.completeAuthorization(env.approve(s.beginAuthorization()))
        val result = s.requestCredentials()
        assertEquals(2, result.deferred.size)
        s.close()

        val relaunched = wallet(env, keys, store)
        val pending = relaunched.deferredCredentials()
        assertEquals(result.deferred.map { it.id }, pending.map { it.id })
        assertTrue("pending ones listed as credentials", relaunched.credentials().isEmpty())
        assertEquals("the sweep deleted a pending credential's key", 0, relaunched.sweepOrphanedKeys(keys))

        assertTrue(relaunched.pollDeferred(pending[0].id) is DeferredStatus.Pending)
        env.env.decide(true)
        val issued = relaunched.pollDeferred(pending[0].id)
        assertTrue("still pending", issued is DeferredStatus.Issued)
        env.env.decide(false)
        expectCode(WalletException.Code.credentialDenied) { relaunched.pollDeferred(pending[1].id) }
        assertTrue(relaunched.deferredCredentials().isEmpty())
        assertEquals("only the issued credential's key, and its refresh grant's instance key, are left", 2, keys.keyIDs().size)
    }

    /** A relaunched wallet over the same stores completes an authorization begun before the app was killed. */
    @Test
    fun resumeIssuanceAfterARelaunch(): Unit = runBlocking {
        val env = env()
        val keys = keyStore()
        val store = InMemoryCredentialStore()
        val w = wallet(env, keys, store)
        val quit = w.startIssuance(env.env.authorizationCodeOffer())
        val redirect = env.approve(quit.beginAuthorization())
        // The app is killed: no close().
        val relaunched = wallet(env, keys, store)
        assertEquals("the sweep deleted the authorization's keys", 0, relaunched.sweepOrphanedKeys(keys))
        val s = relaunched.resumeIssuance(redirect)
        assertEquals(2, s.requestCredentials().credentials.size)
        s.close()
        expectCode(WalletException.Code.notFound) { relaunched.resumeIssuance(redirect) }
    }

    @Test
    fun displayAndStatus(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val received = receive(env, w)
        val held = w.credentials()
        assertEquals(received.credentials.size, held.size)
        for (c in held) {
            assertEquals("Test Issuer", c.display?.issuerName)
            assertNotNull(c.display?.name)
            assertNotNull(c.display?.logo?.uri)
            assertEquals("#12107c", c.display?.backgroundColor)
            assertFalse(c.isExpired())
            assertNull("status before any check", c.status)
        }
        assertEquals(CredentialStatus.Value.Valid, w.checkStatus(held[0].id).status?.value)
        env.env.revoke()
        assertEquals(CredentialStatus.Value.Revoked, w.checkStatus(held[0].id).status?.value)
        assertEquals("the status isn't kept", CredentialStatus.Value.Revoked, w.credentials().first { it.id == held[0].id }.status?.value)
    }

    @Test
    fun batch(): Unit = runBlocking {
        val env = env(batchSize = 3)
        val w = wallet(env)
        receive(env, w)
        assertTrue(w.credentials().all { it.copies == 3 && it.copiesLeft == 3 })
        val p = w.startPresentation(env.request(SD_JWT).second)
        p.respond(p.defaultSelection())
        assertEquals(listOf(2, 3), w.credentials().map { it.copiesLeft }.sorted())
    }

    @Test
    fun registration(): Unit = runBlocking {
        val env = env(batchSize = 3)
        assertTrue(env.configuration.verifiers.registrarRoots.isNotEmpty())
        val w = wallet(env)
        receive(env, w)

        val within = w.startPresentation(env.registeredRequest().second)
        assertEquals(Presentation.Registration.Status.VERIFIED, within.verifier.registration.status)
        assertEquals("Testing", within.verifier.registration.purpose)
        assertNotNull(within.verifier.registration.privacyPolicy)
        assertEquals(2, within.verifier.registration.claims.size)
        assertTrue(within.queries.all { it.unregistered.isEmpty() && !it.unregisteredAll })
        within.decline()

        val over = w.startPresentation(env.registeredRequest(extra = "given_name").second)
        assertEquals(listOf(listOf(PathElement.Key("given_name"))), over.queries.first().unregistered)
        over.decline()

        val plain = w.startPresentation(env.request(SD_JWT).second)
        assertEquals(Presentation.Registration.Status.NONE, plain.verifier.registration.status)
        plain.decline()
    }

    /**
     * A request the wallet refuses throws requestRefused carrying the redirect_uri the
     * Verifier answered with: this call's own, taken from its operation, and still the
     * wallet's latest.
     */
    @Test
    fun refusedRequestCarriesItsRedirect(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val errors = listOf("https://verifier.example/first", "https://verifier.example/second").map { redirect ->
            try {
                w.startPresentation(env.refusedRequest(redirect))
                fail("a request carrying transaction_data was answered")
                error("unreachable")
            } catch (e: WalletException) {
                e
            }
        }
        assertEquals(listOf(WalletException.Code.requestRefused, WalletException.Code.requestRefused), errors.map { it.code })
        assertEquals(listOf("invalid_transaction_data", "invalid_transaction_data"), errors.map { it.protocolError })
        assertEquals(listOf("https://verifier.example/first", "https://verifier.example/second"), errors.map { it.refusalRedirect })
        assertFalse("the redirect stays out of logs", errors.any { it.message!!.contains("verifier.example") })
        assertEquals("https://verifier.example/second", w.takeRefusalRedirect())
        assertNull(w.takeRefusalRedirect())
    }

    @Test
    fun refresh(): Unit = runBlocking {
        val env = env(batchSize = 3)
        assertTrue(env.configuration.issuance.requestRefresh)
        val w = wallet(env)
        receive(env, w)
        assertTrue(w.credentials().all { it.refreshable })
        val p = w.startPresentation(env.request(SD_JWT).second)
        p.respond(p.defaultSelection())
        val used = w.credentials().first { it.copiesLeft == 2 }

        val refreshed = w.refreshCredential(used.id)
        assertNull(refreshed.deferred)
        assertEquals(used.id, refreshed.credential.id)
        assertEquals(3, refreshed.credential.copiesLeft)

        env.env.revokeGrants()
        expectCode(WalletException.Code.reissueRequired) { w.refreshCredential(used.id) }
    }

    @Test
    fun copyPolicyPerVerifier(): Unit = runBlocking {
        val env = env(batchSize = 3)
        val w = wallet(env, configuration = env.configuration.let { it.copy(presentation = it.presentation.copy(copyPolicy = WalletConfiguration.CopyPolicy.PER_VERIFIER)) })
        receive(env, w)
        val candidates = (0 until 2).map {
            val p = w.startPresentation(env.request(SD_JWT).second)
            p.queries[0].credentials[0].also { p.respond(p.defaultSelection()) }
        }
        assertEquals(listOf(false, true), candidates.map { it.shownToVerifier })
        assertEquals(listOf(false, false), candidates.map { it.linkableHere })
        val used = w.credentials().first { it.format == SD_JWT }
        assertEquals(2, used.copiesLeft)
        assertFalse(used.linkable)
    }

    /**
     * tlsPins reach Go: a malformed one (an IP address, which a handshake
     * doesn't name) is refused, and a pin for another host leaves the
     * services' requests as they were.
     */
    @Test
    fun tlsPins(): Unit = runBlocking {
        val env = env()
        val pin = java.util.Base64.getEncoder().encodeToString(ByteArray(32))
        expectCode(WalletException.Code.invalidInput) { wallet(env, configuration = env.configuration.let { it.copy(network = it.network.copy(tlsPins = mapOf("127.0.0.1" to listOf(pin)))) }) }
        receive(env, wallet(env, configuration = env.configuration.let { it.copy(network = it.network.copy(tlsPins = mapOf("issuer.example" to listOf(pin)))) }))
    }

    /**
     * With revocation [ISSUER], nothing is received until setCRLs supplies
     * a current CRL from the issuer's CA, and text that isn't a CRL is
     * refused.
     */
    @Test
    fun issuerRevocation(): Unit = runBlocking {
        val env = env()
        val w = wallet(env, configuration = env.configuration.let { it.copy(revocation = it.revocation.copy(roles = listOf(WalletConfiguration.RevocationRole.ISSUER))) })
        val refused = runCatching { receive(env, w) }.exceptionOrNull()
        assertTrue("received a credential with no CRL for its issuer's CA: $refused", refused is WalletException)
        expectCode(WalletException.Code.invalidInput) { w.setCRLs("not a CRL") }
        w.setCRLs(env.env.issuerCRL(false))
        assertEquals(2, receive(env, w).credentials.size)
    }

    @Test
    fun abandonDeferred(): Unit = runBlocking {
        val env = env(deferIssuance = true)
        val keys = keyStore()
        val w = wallet(env, keys)
        val s = w.startIssuance(env.env.authorizationCodeOffer())
        s.completeAuthorization(env.approve(s.beginAuthorization()))
        val result = s.requestCredentials()
        s.close()
        result.deferred.forEach { w.abandonDeferred(it.id) }
        assertTrue(w.deferredCredentials().isEmpty())
        assertEquals(emptyList<String>(), keys.keyIDs())
    }

    @Test
    fun declineWithNothingToPresent(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val (id, link) = env.request("mso_mdoc")
        val p = w.startPresentation(link)
        assertFalse(p.isAnswerable)
        expectCode(WalletException.Code.noMatchingCredential) { p.defaultSelection() }
        p.decline()
        assertTrue(env.result(id)["last_error"]?.jsonPrimitive?.content.orEmpty().contains("access_denied"))
    }

    /** Cancelling the coroutine cancels the Go call waiting on the network. */
    @Test
    fun cancellation(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val silent = ServerSocket(0)
        val held = mutableListOf<Socket>()
        thread(isDaemon = true) { runCatching { while (true) held += silent.accept() } }
        val offer = "openid-credential-offer://?credential_offer_uri=" + URLEncoder.encode("https://127.0.0.1:${silent.localPort}/offer", "UTF-8")
        val call = async { w.startIssuance(offer) }
        delay(300)
        call.cancel()
        withTimeout(5.seconds) { call.join() }
        assertTrue("a cancelled startIssuance returned", call.isCancelled)
        silent.close()
    }

    /** Several issuances at once, each calling back into Kotlin. */
    @Test
    fun concurrentIssuances(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        val total = (0 until 4).map { async { receive(env, w).credentials.size } }.awaitAll().sum()
        assertEquals(8, total)
        assertEquals(8, w.credentials().size)
    }

    /**
     * An OpenID4VP request over the Digital Credentials API, signed or
     * not, is answered with the response's data for the platform, which
     * the page verifies; declining hands back {"error": "access_denied"}.
     */
    @Test
    fun dcapiPresentation(): Unit = runBlocking {
        val env = env()
        val w = wallet(env)
        receive(env, w)
        val origin = "https://verifier.android.example"
        for ((format, signed) in listOf(SD_JWT to true, "mso_mdoc" to true, SD_JWT to false)) {
            val r = json.parseToJsonElement(env.env.dcapiRequest(format, origin, signed)).jsonObject
            val p = w.startDCAPIPresentation(
                r["protocol"]!!.jsonPrimitive.content, r["data"]!!.jsonPrimitive.content.toByteArray(), origin,
            )
            assertEquals(origin, p.verifier.origin)
            assertEquals("unsigned requests name no Verifier", signed, p.verifier.name.isNotEmpty())
            val presented = p.respond(p.defaultSelection())
            val response = presented.dcapiResponse
            assertNotNull("$format: no DC API response", response)
            val result = json.parseToJsonElement(env.env.dcapiResult(r["id"]!!.jsonPrimitive.content, response!!)).jsonObject
            assertEquals("$format signed=$signed: $result", "done", result["status"]?.jsonPrimitive?.content)
        }
        val r = json.parseToJsonElement(env.env.dcapiRequest(SD_JWT, origin, true)).jsonObject
        val p = w.startDCAPIPresentation(r["protocol"]!!.jsonPrimitive.content, r["data"]!!.jsonPrimitive.content.toByteArray(), origin)
        assertEquals("the origin has been shown it before", true, p.queries[0].credentials[0].shownToVerifier)
        val refusal = json.parseToJsonElement(env.env.dcapiResult(r["id"]!!.jsonPrimitive.content, p.decline().dcapiResponse!!)).jsonObject
        assertEquals("access_denied", refusal["error"]?.jsonPrimitive?.content)
    }

    /** The sweep keeps the keys the wallet's credentials are bound to and deletes the rest. */
    @Test
    fun sweepOrphanedKeys(): Unit = runBlocking {
        val env = env()
        val keys = keyStore()
        val w = wallet(env, keys)
        assertEquals(2, receive(env, w).credentials.size)
        val stray = keys.createKey(KeyPurpose.DPOP)
        // A secret key under the prefix, as a credential store's key
        // under a custom alias would be: not a key pair, so kept.
        val secretAlias = prefix + "secret"
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(secretAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
        val android = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            assertEquals(1, w.sweepOrphanedKeys(keys))
            assertNull(keys.publicKey(stray))
            assertTrue("a credential's key was swept", w.credentials().all { it.holderKeyPresent == true })
            assertTrue("the sweep deleted a secret key", android.containsAlias(secretAlias))
        } finally {
            android.deleteEntry(secretAlias)
        }

        // Not the Wallet Provider registration key's store.
        val registration = AndroidKeystoreKeyStore(
            AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = HttpWalletProvider.REGISTRATION_KEY_ALIAS_PREFIX + "session${System.nanoTime()}."),
        )
        val registrationKey = registration.createKey(KeyPurpose.INSTANCE)
        try {
            val refused = runCatching { w.sweepOrphanedKeys(registration) }.exceptionOrNull()
            assertTrue("swept the registration key's store: $refused", refused is IllegalArgumentException)
            assertNotNull(registration.publicKey(registrationKey))
        } finally {
            registration.deleteKey(registrationKey)
        }
    }

    /**
     * A Wallet Provider's registration key sweep refuses a store whose
     * prefix is, covers or falls under the key store's of a wallet built
     * with it, deleting nothing: it would delete the wallet's keys.
     */
    @Test
    fun registrationSweepRefusesTheWalletsKeys(): Unit = runBlocking {
        val env = env()
        val keys = keyStore()
        val walletKey = keys.createKey(KeyPurpose.HOLDER)
        for (registrationPrefix in listOf(prefix, prefix + "wp.", prefix.dropLast(1))) {
            val registration = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = registrationPrefix))
            val provider = HttpWalletProvider("https://wp.example", InMemoryInstanceRegistry(), registration)
            Wallet(env.configuration, keys, InMemoryCredentialStore(), provider)
            val refused = runCatching { provider.sweepOrphanedRegistrationKeys() }.exceptionOrNull()
            assertTrue("swept $registrationPrefix: $refused", refused is IllegalArgumentException)
            assertNotNull("the sweep deleted the wallet's key", keys.publicKey(walletKey))
        }
    }
}

/** The SD-JWT VC format. */
const val SD_JWT = "dc+sd-jwt"

/**
 * A Wallet Provider that gives an attestation challenge for instance and
 * holder keys and records the evidence it's asked to attest, then asks
 * [provider].
 */
internal class EvidenceRecorder(private val provider: WalletProvider) : WalletProvider {
    val asked: MutableList<KeyPurpose> = java.util.Collections.synchronizedList(mutableListOf())
    val walletRequests: MutableList<WalletAttestationRequest> = java.util.Collections.synchronizedList(mutableListOf())
    val keyRequests: MutableList<KeyAttestationRequest> = java.util.Collections.synchronizedList(mutableListOf())

    override suspend fun attestationChallenge(purpose: KeyPurpose): ByteArray? {
        asked += purpose
        return if (purpose == KeyPurpose.DPOP) null else "challenge-${purpose.rawValue}".toByteArray()
    }

    override suspend fun walletAttestation(request: WalletAttestationRequest): String {
        walletRequests += request
        return provider.walletAttestation(request)
    }

    override suspend fun keyAttestation(request: KeyAttestationRequest): String {
        keyRequests += request
        return provider.keyAttestation(request)
    }
}

/** The TestEnv's Wallet Provider, as the app's WalletProvider. */
internal class ProviderOf(env: TestEnv) : WalletProvider {
    private val provider = env.env.provider()

    override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
        provider.walletAttestation(clientID, instanceKey).decodeToString()

    override suspend fun keyAttestation(instanceKey: ByteArray, keys: List<ByteArray>, nonce: String): String =
        provider.keyAttestation(instanceKey, ("[" + keys.joinToString(",") { it.decodeToString() } + "]").toByteArray(), nonce).decodeToString()
}
