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
        FileCredentialStore.keystoreFault = null
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

    @Test
    fun compareAndSwap() {
        val s = store()
        val a = """{"id":"a"}""".toByteArray()
        val b = """{"id":"a","v":2}""".toByteArray()
        assertNull("swapped into nothing", s.compareAndSwap("a", a, b))
        assertNull(s.record("a"))
        assertNull(s.compareAndSwap("a", null, a))
        assertArrayEquals(a, s.record("a"))
        assertArrayEquals("swapped over another record", a, s.compareAndSwap("a", b, "{}".toByteArray()))
        assertArrayEquals(a, s.record("a"))
        assertArrayEquals(a, s.compareAndSwap("a", a, b))
        assertArrayEquals(b, s.record("a"))
        assertArrayEquals(b, s.compareAndSwap("a", b, null))
        assertNull(s.record("a"))
        assertTrue(s.records().isEmpty())
    }

    /**
     * Stores open on one directory swap atomically between them: of
     * concurrent read-and-swap loops, none loses another's write.
     */
    @Test
    fun compareAndSwapAcrossStores() {
        val dir = File(context.cacheDir, "store-${UUID.randomUUID()}").also { dirs += it }
        val stores = List(4) { store(dir) }
        stores[0].put("counter", "0".toByteArray())
        val rounds = 25
        val threads = List(stores.size * 2) { i ->
            Thread {
                val s = stores[i % stores.size]
                repeat(rounds) {
                    while (true) {
                        val current = s.record("counter")!!
                        val next = (current.decodeToString().toInt() + 1).toString().toByteArray()
                        if (s.compareAndSwap("counter", current, next).contentEquals(current)) break
                    }
                }
            }.apply { start() }
        }
        threads.forEach { it.join() }
        assertEquals((threads.size * rounds).toString(), stores[1].record("counter")!!.decodeToString())
        assertEquals("only the record is listed, not the lock file", 1, stores[1].records().size)
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

        // One record that doesn't decrypt doesn't hide the others.
        s.put("c", """{"id":"c"}""".toByteArray())
        assertEquals(listOf("""{"id":"c"}"""), s.records().map { it.decodeToString() })
    }

    /**
     * Records past 64 KB, as an mdoc with a portrait is, round-trip:
     * API 28's Keymaster 3 (the LG G6's) gets a single AES-GCM operation
     * of 80 KB wrong. Run on such a device as well as a recent one.
     */
    @Test
    fun largeRecords() {
        val s = store()
        val sizes = listOf(1024, 65536, 65537, 81919, 81920, 81921, 204800)
        for (size in sizes) {
            val record = ByteArray(size) { (it * 31 + size).toByte() }
            val id = "r$size"
            s.put(id, record)
            val file = File(s.directory, "$id.rec")
            // Version, the wrapped key (IV, key, tag), the record's IV, the ciphertext and its tag: 89 + n.
            assertEquals("record $size's file", 1 + 12 + 32 + 16 + 12 + size + 16, file.length().toInt())
            assertEquals("record $size's version", 2, file.readBytes()[0].toInt())
            assertArrayEquals("record $size", record, s.record(id))
        }
        assertEquals(sizes.size, s.records().size)
        assertTrue(s.unreadableRecordIDs().isEmpty())
    }

    /** A record that doesn't decrypt is reported by its ID, so the app can have its credential received again. */
    @Test
    fun reportsUnreadableRecords() {
        val s = store()
        s.put("a", """{"id":"a"}""".toByteArray())
        s.put("b", """{"id":"b"}""".toByteArray())
        val file = File(s.directory, "a.rec")
        val bytes = file.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 1).toByte()
        file.writeBytes(bytes)

        try {
            s.record("a")
            fail("read a record that isn't intact")
        } catch (e: UnreadableRecordException) {
            assertEquals("a", e.id)
        }
        assertEquals(listOf("a"), s.unreadableRecordIDs())
        assertEquals(listOf("""{"id":"b"}"""), s.records().map { it.decodeToString() })
        s.delete("a")
        assertTrue(s.unreadableRecordIDs().isEmpty())
    }

    /**
     * A record written as 0.19.0 wrote it, in a single doFinal, either
     * reads back intact or is reported unreadable: never as other bytes.
     */
    @Test
    fun recordsWrittenInOneOperation() {
        val s = store()
        s.put("k", "{}".toByteArray()) // makes the store's key
        val key = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null) as javax.crypto.SecretKey
        for (size in listOf(1024, 65536, 65537, 81920, 81921, 204800)) {
            val record = ByteArray(size) { (it * 7 + size).toByte() }
            val id = "old$size"
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
            cipher.updateAAD(id.toByteArray())
            File(s.directory, "$id.rec").writeBytes(byteArrayOf(1) + cipher.iv + cipher.doFinal(record))
            val read = try {
                s.record(id)
            } catch (e: UnreadableRecordException) {
                null
            }
            android.util.Log.i("FileCredentialStoreTest", "a $size-byte record written in one operation: ${if (read == null) "unreadable" else "readable"}")
            if (read != null) assertArrayEquals("record $size", record, read)
            assertEquals(read == null, id in s.unreadableRecordIDs())
        }
    }

    /**
     * A record the Keystore key encrypted itself, in pieces as the Keymaster
     * gets right, reads back; replaced, it's written in the current form.
     */
    @Test
    fun readsRecordsTheKeystoreKeyEncrypted() {
        val s = store()
        val record = ByteArray(204800) { (it * 13).toByte() }
        val file = writeVersion1(s, "old", record)

        assertArrayEquals(record, s.record("old"))
        s.put("old", s.record("old")!!)
        assertEquals(2, file.readBytes()[0].toInt())
        assertArrayEquals(record, s.record("old"))
    }

    /**
     * A record in a format newer than this library reads isn't damaged:
     * it's kept and listed apart, never as one to delete. A malformed one
     * of a known format is damaged.
     */
    @Test
    fun keepsRecordsInNewerFormats() {
        val s = store()
        s.put("a", """{"id":"a"}""".toByteArray())
        val newer = File(s.directory, "newer.rec").apply { writeBytes(byteArrayOf(3) + ByteArray(120) { it.toByte() }) }
        val newerBytes = newer.readBytes()
        File(s.directory, "short.rec").writeBytes(byteArrayOf(2, 1, 2, 3))

        try {
            s.record("newer")
            fail("read a record in a newer format")
        } catch (e: UnsupportedRecordFormatException) {
            assertEquals("newer", e.id)
            assertEquals(3, e.version)
        }
        assertEquals(listOf("""{"id":"a"}"""), s.records().map { it.decodeToString() })
        assertEquals(listOf("newer"), s.unsupportedRecordIDs())
        assertEquals(listOf("short"), s.unreadableRecordIDs())
        assertArrayEquals("the newer record was changed", newerBytes, newer.readBytes())
    }

    /**
     * A Keystore decryption that comes back too short — as the LG G6's
     * returns 64 KB of an 80 KB record, its tag verified — is refused, not
     * returned, and the record isn't reported as damaged: it may be intact.
     */
    @Test
    fun refusesKeystoreReadsCutShort() {
        val s = store()
        val old = ByteArray(1024) { it.toByte() }
        writeVersion1(s, "old", old)
        s.put("new", """{"id":"new"}""".toByteArray())
        val files = listOf("old", "new").associateWith { File(s.directory, "$it.rec").readBytes() }

        FileCredentialStore.keystoreFault = { it.copyOf(it.size - 1) }
        for (id in listOf("old", "new")) {
            try {
                s.record(id)
                fail("returned a record $id cut short")
            } catch (e: UnreadableRecordException) {
                fail("reported record $id as damaged")
            } catch (e: StoreException) {
                // As expected.
            }
        }
        assertTrue(s.records().isEmpty())
        assertTrue(s.unreadableRecordIDs().isEmpty())

        FileCredentialStore.keystoreFault = null
        for ((id, bytes) in files) assertArrayEquals("record $id was changed", bytes, File(s.directory, "$id.rec").readBytes())
        assertArrayEquals(old, s.record("old"))
    }

    /** A record the device can't read just now — its Keystore key refused, as while locked — isn't reported as damaged. */
    @Test
    fun aLockedKeystoreIsntDamage() {
        val s = store()
        s.put("a", """{"id":"a"}""".toByteArray())
        FileCredentialStore.keystoreFault = { throw android.security.keystore.UserNotAuthenticatedException("locked") }
        for (read in listOf<() -> Any?>({ s.record("a") }, { s.records() }, { s.unreadableRecordIDs() })) {
            try {
                read()
                fail("read while the Keystore refused its key")
            } catch (e: android.security.keystore.UserNotAuthenticatedException) {
                // As expected: not a StoreException, so not a damaged record.
            }
        }
        FileCredentialStore.keystoreFault = null
        assertArrayEquals("""{"id":"a"}""".toByteArray(), s.record("a"))
    }

    /** A replacement that doesn't read back fails, and the record it would replace stays. */
    @Test
    fun aFailedReplacementKeepsTheRecord() {
        val s = store()
        val old = """{"id":"a","v":1}""".toByteArray()
        val new = """{"id":"a","v":2}""".toByteArray()
        s.put("a", old)
        val file = File(s.directory, "a.rec")
        val bytes = file.readBytes()

        // The record's key, unwrapped wrong: the new record doesn't decrypt.
        FileCredentialStore.keystoreFault = { it.copyOf().also { k -> k[0] = (k[0].toInt() xor 1).toByte() } }
        for (replace in listOf({ s.put("a", new) }, { s.compareAndSwap("a", old, new) })) {
            try {
                replace()
                fail("replaced a record with one that doesn't read back")
            } catch (e: StoreException) {
                // As expected.
            }
        }
        FileCredentialStore.keystoreFault = null
        assertArrayEquals(bytes, file.readBytes())
        assertArrayEquals(old, s.record("a"))
    }

    /** A version 1 record: [record] encrypted by the store's Keystore key itself, in 4 KB pieces. */
    private fun writeVersion1(s: FileCredentialStore, id: String, record: ByteArray): File {
        s.put("k", "{}".toByteArray()) // makes the store's key
        val key = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null) as javax.crypto.SecretKey
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(id.toByteArray())
        val out = java.io.ByteArrayOutputStream()
        var at = 0
        while (record.size - at > 4096) {
            cipher.update(record, at, 4096)?.let(out::write)
            at += 4096
        }
        out.write(cipher.doFinal(record, at, record.size - at))
        s.delete("k")
        return File(s.directory, "$id.rec").apply { writeBytes(byteArrayOf(1) + cipher.iv + out.toByteArray()) }
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
