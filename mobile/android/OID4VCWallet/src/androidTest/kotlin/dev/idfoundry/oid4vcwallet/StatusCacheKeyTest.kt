package dev.idfoundry.oid4vcwallet

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The status cache key is made once per directory and kept there,
 * wrapped by a Keystore key: the same key comes back, and a wrapped key
 * someone else replaced makes a new one rather than fail.
 */
@RunWith(AndroidJUnit4::class)
class StatusCacheKeyTest {
    private val dir = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "status-${UUID.randomUUID()}")

    @After
    fun cleanUp() {
        dir.deleteRecursively()
    }

    @Test
    fun keptAcrossCalls() {
        val first = StatusCacheKey.source(dir)
        assertEquals(StatusCacheKey.KEY_BYTES, first.size)
        assertArrayEquals(first, StatusCacheKey.source(dir))
        assertFalse("the key is kept wrapped", File(dir, ".status-cache-key").readBytes().contentEquals(first))
    }

    @Test
    fun defaultInTheAppsCacheDirectory() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals(File(context.cacheDir, StatusCacheKey.DEFAULT_DIR).canonicalFile, StatusCacheKey.defaultDir()?.canonicalFile)
    }

    @Test
    fun replacedKeyMadeAnew() {
        val first = StatusCacheKey.source(dir)
        File(dir, ".status-cache-key").writeBytes(ByteArray(60) { 1 })
        val second = StatusCacheKey.source(dir)
        assertFalse(first.contentEquals(second))
        assertArrayEquals(second, StatusCacheKey.source(dir))
    }
}
