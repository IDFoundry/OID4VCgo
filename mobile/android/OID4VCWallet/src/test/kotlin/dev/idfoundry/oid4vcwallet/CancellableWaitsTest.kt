package dev.idfoundry.oid4vcwallet

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.suspendCancellableCoroutine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * A wait on Go's thread — a holder's prompt, a Wallet Provider call —
 * ends when the wallet's CallbackCanceller cancels it, dismissing the
 * prompt, and the callback returns at once.
 */
class CancellableWaitsTest {
    /** A prompt, as BiometricPromptAuthenticator's: shown until answered, or dismissed on cancellation. */
    private class FakePrompt {
        val shown = CountDownLatch(1)
        val dismissed = AtomicBoolean(false)

        suspend fun show(): Unit = suspendCancellableCoroutine { cont ->
            cont.invokeOnCancellation { dismissed.set(true) }
            shown.countDown()
        }
    }

    @Test
    fun returnsTheResult() {
        val waits = CancellableWaits()
        assertEquals("signed", waits.await("key") { "signed" })
        assertEquals(0, waits.size)
    }

    @Test
    fun cancelDismissesThePrompt() {
        val waits = CancellableWaits()
        val prompt = FakePrompt()
        thread {
            assertTrue(prompt.shown.await(5, TimeUnit.SECONDS))
            // Another key's cancel leaves it be.
            waits.cancel("other")
            assertFalse(prompt.dismissed.get())
            waits.cancel("key")
        }
        val start = System.nanoTime()
        try {
            waits.await("key") { prompt.show() }
            fail("the cancelled wait returned")
        } catch (e: CancellationException) {
            // The cancellation, as expected.
        }
        assertTrue("dismissed", prompt.dismissed.get())
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(5))
        assertEquals(0, waits.size)
    }

    @Test
    fun cancelWithNothingWaiting() {
        val waits = CancellableWaits()
        waits.cancel("key")
        assertEquals("signed", waits.await("key") { "signed" })
    }

    @Test
    fun callbackCancellerReachesTheKeyStore() {
        val cancelled = mutableListOf<String>()
        val store = object : KeyStore {
            override fun createKey(purpose: KeyPurpose): String = "id"
            override fun publicKey(id: String): ByteArray? = null
            override fun sign(id: String, digest: ByteArray): ByteArray = ByteArray(0)
            override fun deleteKey(id: String) {
                // Nothing to delete: the store holds no keys.
            }
            override fun cancelKeyUse(id: String) {
                cancelled += id
            }
        }
        CallbackCancellerAdapter(store, null).apply {
            cancelKeyUse("holder-1")
            // No provider: nothing to cancel.
            cancelProvider("{}".toByteArray())
        }
        assertEquals(listOf("holder-1"), cancelled)
    }

    @Test
    fun keyStoreDefaultIgnoresCancel() {
        val store = object : KeyStore {
            override fun createKey(purpose: KeyPurpose): String = "id"
            override fun publicKey(id: String): ByteArray? = null
            override fun sign(id: String, digest: ByteArray): ByteArray = ByteArray(0)
            override fun deleteKey(id: String) {
                // Nothing to delete: the store holds no keys.
            }
        }
        store.cancelKeyUse("id")
    }

    @Test
    fun callbackCancellerStopsTheProvider() {
        val jwk = """{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}""".toByteArray()
        val stopped = AtomicBoolean(false)
        val wp = WalletProviderAdapter(object : WalletProvider {
            override suspend fun walletAttestation(clientID: String, instanceKey: ByteArray): String =
                try {
                    awaitCancellation()
                } finally {
                    stopped.set(true)
                }
        })
        val canceller = CallbackCancellerAdapter(object : KeyStore {
            override fun createKey(purpose: KeyPurpose): String = "id"
            override fun publicKey(id: String): ByteArray? = null
            override fun sign(id: String, digest: ByteArray): ByteArray = ByteArray(0)
            override fun deleteKey(id: String) {
                // Nothing to delete: the store holds no keys.
            }
        }, wp)
        thread {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (wp.calls.size == 0 && System.nanoTime() < deadline) Thread.sleep(5)
            canceller.cancelProvider(jwk)
        }
        try {
            wp.walletAttestation("client", jwk)
            fail("the cancelled provider call returned")
        } catch (e: StoreException) {
            assertTrue(e.message.orEmpty(), e.message.orEmpty().contains("cancelled"))
        }
        assertTrue("stopped", stopped.get())
    }
}
