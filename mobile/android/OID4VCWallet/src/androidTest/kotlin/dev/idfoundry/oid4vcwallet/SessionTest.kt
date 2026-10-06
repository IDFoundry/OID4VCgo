package dev.idfoundry.oid4vcwallet

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
        assertTrue(env.configuration.registrarRoots.isNotEmpty())
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

    @Test
    fun refresh(): Unit = runBlocking {
        val env = env(batchSize = 3)
        assertTrue(env.configuration.requestRefresh)
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
        val w = wallet(env, configuration = env.configuration.copy(copyPolicy = WalletConfiguration.CopyPolicy.PER_VERIFIER))
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

    /** The sweep keeps the keys the wallet's credentials are bound to and deletes the rest. */
    @Test
    fun sweepOrphanedKeys(): Unit = runBlocking {
        val env = env()
        val keys = keyStore()
        val w = wallet(env, keys)
        assertEquals(2, receive(env, w).credentials.size)
        val stray = keys.createKey(KeyPurpose.DPOP)
        assertEquals(1, w.sweepOrphanedKeys(keys))
        assertNull(keys.publicKey(stray))
        assertTrue("a credential's key was swept", w.credentials().all { it.holderKeyPresent == true })
    }
}

/** The SD-JWT VC format. */
const val SD_JWT = "dc+sd-jwt"

/** The TestEnv's Wallet Provider, as the app's WalletProvider. */
private class ProviderOf(env: TestEnv) : WalletProvider {
    private val provider = env.env.provider()

    override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
        provider.walletAttestation(clientID, instanceKey).decodeToString()

    override suspend fun keyAttestation(keys: List<ByteArray>, nonce: String): String =
        provider.keyAttestation(("[" + keys.joinToString(",") { it.decodeToString() } + "]").toByteArray(), nonce).decodeToString()
}
