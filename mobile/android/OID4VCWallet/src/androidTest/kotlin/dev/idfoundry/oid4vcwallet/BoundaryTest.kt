package dev.idfoundry.oid4vcwallet

import androidx.test.ext.junit.runners.AndroidJUnit4
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.net.ServerSocket
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The gomobile boundary on Android: Kotlin calling Go, Go calling back
 * into Kotlin, errors both ways, cancellation and threads. Needs the test
 * build (-Poid4vc.testFramework=true).
 */
@RunWith(AndroidJUnit4::class)
class BoundaryTest {
    @Test
    fun abiAndTestBuild() {
        assertEquals(OID4VC.expectedABIVersion, OID4VC.abiVersion)
        assertTrue("the instrumented tests need the test build", OID4VC.isTestBuild)
    }

    /**
     * Go, loaded as a library, starts with an empty environment: the Go
     * side itself points it at the one CA store Android trusts, Android
     * 14's updatable one where it exists, else the system one
     * (golang/go#71258). Not both: Go trusts every directory listed.
     */
    @Test
    fun goReadsAndroidsCAStore() {
        val apex = "/apex/com.android.conscrypt/cacerts"
        val want = if (java.io.File(apex).isDirectory) apex else "/system/etc/security/cacerts"
        assertEquals(want, Mobile.certDirectories())
    }

    @Test
    fun parseRequestLink(): Unit = runBlocking {
        val link = "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fr%2F1&request_uri_method=post"
        assertEquals(RequestLink("x509_hash:abc", "https://verifier.example/r/1", "post"), OID4VC.parseRequestLink(link))
        try {
            OID4VC.parseRequestLink("https://not-a-request")
            fail("parsed a link that isn't one")
        } catch (e: WalletException) {
            assertEquals(WalletException.Code.invalidInput, e.code)
        }
    }

    /** Go creates, signs with (checking the signatures) and deletes keys held in Kotlin. */
    @Test
    fun checkKeyStoreCallsBack(): Unit = runBlocking {
        val store = SoftwareKeyStore()
        assertEquals(KeyPurpose.entries.toList(), OID4VC.checkKeyStore(store))
        assertTrue("every key was deleted", store.keys.isEmpty())
    }

    /** A callback's exception reaches Go and comes back as a platform error carrying its message. */
    @Test
    fun callbackErrorIsPlatform(): Unit = runBlocking {
        val failing = object : KeyStore by SoftwareKeyStore() {
            override fun createKey(purpose: KeyPurpose): String = throw StoreException("no keys today")
        }
        try {
            OID4VC.checkKeyStore(failing)
            fail("a failing key store passed")
        } catch (e: WalletException) {
            assertEquals(WalletException.Code.platform, e.code)
            assertTrue(e.message, e.message.contains("no keys today"))
        }
    }

    /** Cancelling the coroutine cancels a Go call waiting on the network. */
    @Test
    fun cancellationReachesGo(): Unit = runBlocking {
        // Accepts connections and never answers: the TLS handshake hangs.
        val silent = ServerSocket(0)
        val held = mutableListOf<java.net.Socket>()
        thread(isDaemon = true) { runCatching { while (true) held += silent.accept() } }
        val offerURI = "https://127.0.0.1:${silent.localPort}/offer"
        val offer = "openid-credential-offer://?credential_offer_uri=" + URLEncoder.encode(offerURI, "UTF-8")
        // The test issuer's configuration (development, its roots), with an
        // offer that names the silent server instead.
        val env = Mobile.startTestEnv(false)
        val wallet = Mobile.newWallet(
            env.configJSON(), KeyStoreAdapter(SoftwareKeyStore()), CredentialStoreAdapter(MemoryCredentialStore()), env.provider(),
        )
        val start = TimeSource.Monotonic.markNow()
        val call = launch { OID4VC.cancellable { op -> wallet.startIssuance(op, offer) } }
        delay(500)
        assertTrue("the call is still waiting", call.isActive)
        call.cancel()
        withTimeout(5.seconds) { call.join() }
        assertTrue(call.isCancelled)
        assertTrue("returned at once, not after a timeout", start.elapsedNow() < 5.seconds)
        silent.close()
        env.close()
    }

    /** Many Go calls at once, each calling back into Kotlin on its own thread. */
    @Test
    fun concurrentCalls(): Unit = runBlocking {
        val results = (1..32).map { async { OID4VC.checkKeyStore(SoftwareKeyStore()) } }.awaitAll()
        assertTrue(results.all { it == KeyPurpose.entries.toList() })
    }
}

/** P-256 software keys, for tests: Go's crypto.Signer contract over java.security. */
class SoftwareKeyStore : KeyStore {
    val keys = ConcurrentHashMap<String, KeyPair>()

    override fun createKey(purpose: KeyPurpose): String {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val id = UUID.randomUUID().toString()
        keys[id] = generator.generateKeyPair()
        return id
    }

    override fun publicKey(id: String): ByteArray? {
        val pub = keys[id]?.public as? ECPublicKey ?: return null
        return byteArrayOf(4) + fixed(pub.w.affineX) + fixed(pub.w.affineY)
    }

    override fun sign(id: String, digest: ByteArray): ByteArray {
        val key = keys[id] ?: throw StoreException("no key $id")
        return Signature.getInstance("NONEwithECDSA").run {
            initSign(key.private)
            update(digest)
            sign()
        }
    }

    override fun deleteKey(id: String) {
        keys.remove(id)
    }

    private fun fixed(n: BigInteger): ByteArray {
        val b = n.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
        return ByteArray(32 - b.size) + b
    }
}

/** Records in memory, for tests. */
class MemoryCredentialStore : CredentialStore {
    private val records = ConcurrentHashMap<String, ByteArray>()
    override fun put(id: String, record: ByteArray) { records[id] = record }
    override fun record(id: String): ByteArray? = records[id]
    override fun records(): List<ByteArray> = records.values.toList()
    override fun delete(id: String) { records.remove(id) }
}
