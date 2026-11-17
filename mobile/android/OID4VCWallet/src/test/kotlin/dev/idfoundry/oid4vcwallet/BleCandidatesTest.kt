package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * The GATT server's candidate list ([BleCandidates]): devices that never
 * saw the QR code, writing State and chunks, can't push the reader out.
 */
class BleCandidatesTest {
    private val reader = 100

    /** Eight State-only devices, re-adding themselves between the reader's chunks, don't displace it partway through its message. */
    @Test fun readerPartwayThroughItsMessageIsNotDisplaced() {
        val list = BleCandidates<Int>()
        val others = 0 until BleCandidates.MAX_CANDIDATES
        others.forEach { list.start(it) }
        assertTrue("a silent candidate makes way for the reader", list.start(reader))
        assertNull(list.chunk(reader, byteArrayOf(0x01, 0xa2.toByte())))
        repeat(100) { others.filter { it !in list }.forEach { list.start(it) } }
        assertTrue(reader in list)
        assertNull(list.chunk(reader, byteArrayOf(0x01, 0x01)))
        assertArrayEquals(byteArrayOf(0xa2.toByte(), 0x01, 0x02), list.chunk(reader, byteArrayOf(0x00, 0x02)))
    }

    /** Re-adds are limited per device. */
    @Test fun startsAreLimitedPerDevice() {
        val list = BleCandidates<Int>()
        repeat(BleCandidates.MAX_STARTS) {
            assertTrue(list.start(1))
            list.end(1)
        }
        assertFalse(list.start(1))
        assertTrue(list.start(2))
    }

    /** A candidate past its deadline without a whole message may be displaced, even partway through one; within it, it may not. */
    @Test fun deadline() {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        for (o in 0 until BleCandidates.MAX_CANDIDATES) {
            list.start(o)
            assertNull(list.chunk(o, byteArrayOf(0x01, 0x00)))
        }
        assertFalse("every candidate is partway through, within its deadline", list.start(reader))
        clock += BleCandidates.DEADLINE_MS + 1
        assertTrue(list.start(reader))
        assertFalse("the oldest past its deadline made way", 0 in list)
    }

    /**
     * A candidate whose message was handed on is never displaced, and a
     * device whose message is queued or being judged can't start again
     * after leaving, so one device can't queue several.
     */
    @Test fun deviceIsNotListedAgainWhileItsMessageIsJudged() {
        val list = BleCandidates<Int>()
        list.start(1)
        assertArrayEquals(byteArrayOf(0x01), list.chunk(1, byteArrayOf(0x00, 0x01)))
        list.end(1) // State 0x02
        assertFalse(list.start(1))
        assertNull(list.chunk(1, byteArrayOf(0x00, 0x01)))

        list.start(2)
        assertNotNull(list.chunk(2, byteArrayOf(0x00, 0x02)))
        for (o in 10 until 10 + 3 * BleCandidates.MAX_CANDIDATES) list.start(o)
        assertTrue("a candidate whose message was handed on was displaced", 2 in list)

        list.refuse(1) // Go rejected it
        assertTrue(list.isRefused(1))
        assertFalse(list.start(1))
    }

    @Test fun chosen() {
        val list = BleCandidates<Int>()
        assertNull(list.chosen(null))
        list.start(1)
        list.start(2)
        assertEquals(1, list.chosen(null))
        list.chunk(2, byteArrayOf(0x00, 0x01))
        assertEquals(2, list.chosen(2))
        list.end(2)
        assertNull("the accepted device left", list.chosen(2))
    }

    /** A malformed chunk throws, for the transport to refuse the device. */
    @Test fun malformedChunk() {
        val list = BleCandidates<Int>()
        list.start(1)
        assertThrows(IOException::class.java) { list.chunk(1, byteArrayOf(0x07, 0x00)) }
    }
}
