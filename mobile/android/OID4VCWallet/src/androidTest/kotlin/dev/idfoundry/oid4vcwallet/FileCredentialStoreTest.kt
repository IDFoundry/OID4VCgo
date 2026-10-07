package dev.idfoundry.oid4vcwallet

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class FileCredentialStoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dirs = mutableListOf<File>()
    private val alias = "org.idfoundry.oid4vcgo.test.store.${System.nanoTime()}"

    private fun store(dir: File = File(context.cacheDir, "store-${UUID.randomUUID()}").also { dirs += it }) =
        FileCredentialStore(dir, FileCredentialStore.Options(keyAlias = alias))

    @After
    fun cleanUp() {
        dirs.forEach { it.deleteRecursively() }
        java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    @Test
    fun records() {
        val s = store()
        assertTrue(s.records().isEmpty())
        assertNull(s.record("a"))
        s.put("a", """{"id":"a"}""".toByteArray())
        s.put("b-2_c", """{"id":"b"}""".toByteArray())
        s.put("a", """{"id":"a","v":2}""".toByteArray())
        assertArrayEquals("""{"id":"a","v":2}""".toByteArray(), s.record("a"))
        assertEquals(2, s.records().size)
        s.delete("a")
        s.delete("a")
        assertNull(s.record("a"))
    }

    /** IDs name files: anything that could leave the directory is refused. */
    @Test
    fun refusesMalformedIDs() {
        val s = store()
        for (id in listOf("", "../x", "a/b", "a.json", "é")) {
            try {
                s.put(id, "{}".toByteArray())
                fail("accepted $id")
            } catch (e: StoreException) {
                // As expected.
            }
        }
    }

    /** On disk a record is ciphertext, bound to its ID: altered or moved, it doesn't decrypt. */
    @Test
    fun encryptedAtRest() {
        val s = store()
        val secret = """{"family_name":"Doe"}"""
        s.put("a", secret.toByteArray())
        val file = File(s.directory, "a.rec")
        assertFalse("the claims are in the clear", file.readBytes().decodeToString().contains("Doe"))

        file.copyTo(File(s.directory, "b.rec"))
        expectStoreFailure { s.record("b") }

        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)
        expectStoreFailure { s.record("a") }
    }

    /** Credentials survive a new Wallet over the same directory; another key store's wallet sees their keys gone. */
    @Test
    fun acrossWallets(): Unit = runBlocking {
        TestEnv().use { env ->
            val dir = File(context.cacheDir, "store-${UUID.randomUUID()}").also { dirs += it }
            val prefix = "org.idfoundry.oid4vcgo.filestore.${System.nanoTime()}."
            val keys = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix))
            try {
                val first = Wallet(env.configuration, keys, store(dir), ProviderOf(env))
                val s = first.startIssuance(env.env.authorizationCodeOffer())
                s.completeAuthorization(env.approve(s.beginAuthorization()))
                val received = s.requestCredentials()
                s.close()

                val second = Wallet(env.configuration, keys, store(dir), null)
                val held = second.credentials()
                assertEquals(received.credentials.map { it.id }.toSet(), held.map { it.id }.toSet())
                assertTrue(held.all { it.holderKeyPresent == true })

                val otherKeys = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = "$prefix.none."))
                val other = Wallet(env.configuration, otherKeys, store(dir), null)
                assertTrue("another key store holds none of the keys", other.credentials().all { it.holderKeyPresent == false })
            } finally {
                keys.deleteKeys(emptySet())
            }
        }
    }

    private fun expectStoreFailure(body: () -> Unit) {
        try {
            body()
            fail("read a record that isn't intact")
        } catch (e: StoreException) {
            // As expected.
        }
    }
}
