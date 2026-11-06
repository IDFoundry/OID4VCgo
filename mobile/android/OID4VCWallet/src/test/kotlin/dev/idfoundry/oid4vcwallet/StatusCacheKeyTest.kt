package dev.idfoundry.oid4vcwallet

import java.util.Base64
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

/** A configuration keeping status lists in a directory carries the key that authenticates them. */
class StatusCacheKeyTest {
    private val original = StatusCacheKey.source

    @After
    fun restore() {
        StatusCacheKey.source = original
    }

    @Test
    fun keyAddedWithADirectory() {
        val key = ByteArray(StatusCacheKey.KEY_BYTES) { 5 }
        StatusCacheKey.source = { key }
        val config = json.parseToJsonElement(StatusCacheKey.configuration("""{"status_cache_dir":"/tmp/x","batch_size":3}""", "/tmp/x")).jsonObject
        assertEquals(Base64.getEncoder().encodeToString(key), config["status_cache_key"]!!.jsonPrimitive.content)
        assertEquals("/tmp/x", config["status_cache_dir"]!!.jsonPrimitive.content)
        assertEquals(3, config["batch_size"]!!.jsonPrimitive.int)
    }

    @Test
    fun nothingAddedInMemory() {
        StatusCacheKey.source = { error("not asked") }
        val encoded = """{"batch_size":3}"""
        assertSame(encoded, StatusCacheKey.configuration(encoded, ""))
    }
}
