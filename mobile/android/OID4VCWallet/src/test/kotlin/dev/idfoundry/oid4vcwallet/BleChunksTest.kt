package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import kotlin.random.Random

/** ISO/IEC 18013-5 §8.3.3.1.1.6's chunking, on the host JVM. */
class BleChunksTest {
    @Test
    fun characteristicSize() {
        assertEquals(20, BleChunks.characteristicSize(23))
        assertEquals(20, BleChunks.characteristicSize(0)) // never below the default MTU's
        assertEquals(182, BleChunks.characteristicSize(185))
        assertEquals(512, BleChunks.characteristicSize(517))
    }

    @Test
    fun splitAndReassemble() {
        for (size in listOf(0, 1, 18, 19, 20, 512, 10_000)) {
            val message = Random(size).nextBytes(size)
            val chunks = BleChunks.split(message, 20)
            for ((i, chunk) in chunks.withIndex()) {
                assert(chunk.size <= 20) { "chunk $i is ${chunk.size} bytes" }
                assertEquals(if (i == chunks.lastIndex) 0x00.toByte() else 0x01.toByte(), chunk[0])
            }
            val r = BleChunks.Reassembler()
            for (chunk in chunks.dropLast(1)) assertNull(r.add(chunk))
            assertArrayEquals("size $size", message, r.add(chunks.last()))
        }
        // 19 payload bytes a chunk: 38 bytes are exactly two.
        assertEquals(2, BleChunks.split(ByteArray(38), 20).size)
        assertEquals(3, BleChunks.split(ByteArray(39), 20).size)
    }

    @Test
    fun reassemblerRefuses() {
        val r = BleChunks.Reassembler()
        expectIOException { r.add(byteArrayOf()) }
        expectIOException { r.add(byteArrayOf(0x02, 0x41)) }
        // After an error, a new message starts clean.
        assertArrayEquals(byteArrayOf(0x42), r.add(byteArrayOf(0x00, 0x42)))
        val big = ByteArray(BleChunks.MAX_CHARACTERISTIC_SIZE).also { it[0] = 0x01 }
        expectIOException { repeat(BleChunks.MAX_MESSAGE_BYTES / (big.size - 1) + 1) { r.add(big) } }
    }

    private fun expectIOException(body: () -> Unit) {
        try {
            body()
            fail("no IOException")
        } catch (_: IOException) {
        }
    }
}
