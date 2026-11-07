package dev.idfoundry.oid4vcwallet

import java.io.File
import java.util.Base64
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * A configuration keeping status lists in a directory carries the key that authenticates
 * them; with no directory set, the lists are kept in the default one when its key can be had.
 */
class StatusCacheKeyTest {
    private val originalSource = StatusCacheKey.source
    private val originalDefault = StatusCacheKey.defaultDir
    private val key = ByteArray(StatusCacheKey.KEY_BYTES) { 5 }

    @After
    fun restore() {
        StatusCacheKey.source = originalSource
        StatusCacheKey.defaultDir = originalDefault
    }

    @Test
    fun keyAddedWithADirectory() {
        StatusCacheKey.source = { key }
        val config = json.parseToJsonElement(StatusCacheKey.configuration("""{"status_cache_dir":"/tmp/x","batch_size":3}""", "/tmp/x")).jsonObject
        assertEquals(Base64.getEncoder().encodeToString(key), config["status_cache_key"]!!.jsonPrimitive.content)
        assertEquals("/tmp/x", config["status_cache_dir"]!!.jsonPrimitive.content)
        assertEquals(3, config["batch_size"]!!.jsonPrimitive.int)
    }

    @Test
    fun nothingAddedInMemory() {
        StatusCacheKey.source = { error("not asked") }
        StatusCacheKey.defaultDir = { error("not asked") }
        val encoded = """{"batch_size":3,"status_cache_dir":""}"""
        assertSame(encoded, StatusCacheKey.configuration(encoded, ""))
    }

    @Test
    fun defaultDirectoryWhenUnset() {
        var asked: File? = null
        StatusCacheKey.source = { asked = it; key }
        StatusCacheKey.defaultDir = { File("/data/cache", StatusCacheKey.DEFAULT_DIR) }
        val config = json.parseToJsonElement(StatusCacheKey.configuration("""{"batch_size":3}""", null)).jsonObject
        assertEquals("/data/cache/oid4vcwallet-status-lists", config["status_cache_dir"]!!.jsonPrimitive.content)
        assertEquals(File("/data/cache/oid4vcwallet-status-lists"), asked)
        assertEquals(Base64.getEncoder().encodeToString(key), config["status_cache_key"]!!.jsonPrimitive.content)
    }

    @Test
    fun defaultInMemoryWithoutItsKey() {
        StatusCacheKey.source = { throw StoreException("locked") }
        StatusCacheKey.defaultDir = { File("/data/cache", StatusCacheKey.DEFAULT_DIR) }
        val encoded = """{"batch_size":3}"""
        assertSame(encoded, StatusCacheKey.configuration(encoded, null))
        StatusCacheKey.defaultDir = { null }
        assertSame(encoded, StatusCacheKey.configuration(encoded, null))
    }

    @Test
    fun chosenDirectoryFailsWithoutItsKey() {
        StatusCacheKey.source = { throw StoreException("locked") }
        assertThrows(StoreException::class.java) { StatusCacheKey.configuration("{}", "/tmp/x") }
    }

    /** The default directory is `java.io.tmpdir` only while that's this app's own cache directory. */
    @Test
    fun defaultOnlyInTheAppsCacheDirectory() {
        val mine = { _: File -> 10123 }
        for (path in listOf("/data/data/com.example/cache", "/data/user/10/com.example/cache", "/data/user_de/0/com.example/cache", "/mnt/expand/1234-abcd/user/0/com.example/cache")) {
            assertEquals(path, File(path), StatusCacheKey.appCacheDir(path, mine, 10123))
        }
        for (path in listOf(null, "", "/sdcard/Download", "/data/local/tmp", "/data/data/com.example/files", "/data/data/com.example/cache/sub", "/tmp")) {
            assertEquals(path, null, StatusCacheKey.appCacheDir(path, mine, 10123))
        }
        // Another uid's (an isolated process's, say), or one whose owner can't be told.
        assertEquals(null, StatusCacheKey.appCacheDir("/data/data/com.example/cache", mine, 99000))
        assertEquals(null, StatusCacheKey.appCacheDir("/data/data/com.example/cache", { null }, 10123))
        assertEquals(null, StatusCacheKey.appCacheDir("/data/data/com.example/cache", { throw RuntimeException("Stub!") }, 10123))
    }

    /** Made canonical first: a path naming the cache directory through `..` is judged as what it is. */
    @Test
    fun defaultJudgedCanonical() {
        assertEquals(File("/data/data/com.example/cache"), StatusCacheKey.appCacheDir("/data/data/com.example/files/../cache", { 1 }, 1))
        assertEquals(null, StatusCacheKey.appCacheDir("/data/data/com.example/cache/../files", { 1 }, 1))
    }

    @Test
    fun configurationsLeaveItUnset() {
        val encoded = json.encodeToString(WalletConfiguration.serializer(), WalletConfiguration(clientID = "c", locales = listOf("en")))
        assertFalse(json.parseToJsonElement(encoded).jsonObject.containsKey("status_cache_dir"))
        assertEquals(null, ProximityReaderConfiguration(issuerRoots = "").statusCacheDir)
    }
}
