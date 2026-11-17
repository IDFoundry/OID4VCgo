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
 * saw the QR code, writing State and chunks, can't push the reader out
 * or keep it out.
 */
class BleCandidatesTest {
    private val reader = -1
    /** A first chunk, more to come. */
    private val partial = byteArrayOf(0x01, 0xa2.toByte())

    /**
     * A full list of devices that only wrote State, displacing each other
     * between the reader's chunks, doesn't displace it partway through its
     * message.
     */
    @Test fun readerPartwayThroughItsMessageIsNotDisplaced() {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        (0 until BleCandidates.MAX_CANDIDATES).forEach { list.start(it) }
        clock = 1_000
        assertTrue("a full list makes way for the reader", list.start(reader))
        assertFalse("the one heard from least recently made way", 0 in list)
        clock = 2_000
        assertNull(list.chunk(reader, byteArrayOf(0x01, 0xa2.toByte())))
        clock = 3_000
        for (o in 1000 until 1000 + BleCandidates.MAX_CANDIDATES - 1) assertTrue(list.start(o))
        assertTrue(reader in list)
        clock = 3_500
        assertNull(list.chunk(reader, byteArrayOf(0x01, 0x01)))
        clock = 4_000
        for (o in 2000 until 2000 + BleCandidates.MAX_CANDIDATES - 1) assertTrue(list.start(o))
        assertArrayEquals(byteArrayOf(0xa2.toByte(), 0x01, 0x02), list.chunk(reader, byteArrayOf(0x00, 0x02)))
    }

    /** Displacing the reader takes a write from every other listed device, and one more, between two of its own. */
    @Test fun displacingTheReaderTakesAFullListOfNewerWrites() {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        for (o in 0 until BleCandidates.MAX_CANDIDATES - 1) list.start(o)
        clock = 1_000
        list.start(reader)
        assertNull(list.chunk(reader, partial))
        clock = 2_000
        for (o in 0 until BleCandidates.MAX_CANDIDATES - 2) assertNull(list.chunk(o, partial))
        assertTrue("the one other heard before the reader made way", list.start(100))
        assertTrue(reader in list)
        assertTrue(list.start(101))
        assertFalse("every other was heard after the reader", reader in list)
        assertNull("its last chunk is dropped", list.chunk(reader, byteArrayOf(0x00, 0x02)))
    }

    /** A newcomer displaces the candidate heard from least recently, even partway through its message. */
    @Test fun newcomerDisplacesTheLeastRecentlyHeard() {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        for (o in 0 until BleCandidates.MAX_CANDIDATES) {
            clock = o.toLong()
            list.start(o)
            assertNull(list.chunk(o, partial))
        }
        clock++
        assertNull(list.chunk(0, byteArrayOf(0x01, 0x00)))
        assertTrue(list.start(reader))
        assertTrue("it wrote last but one", 0 in list)
        assertFalse("the one heard from least recently made way", 1 in list)
    }

    /** The partial messages' bytes are bounded: a chunk past the bound displaces the one heard from least recently. */
    @Test fun bufferedBytesAreBounded() {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        val big = ByteArray(BleChunks.MAX_MESSAGE_BYTES).also { it[0] = 0x01 }
        for (o in 1..2) {
            clock = o.toLong()
            list.start(o)
            assertNull(list.chunk(o, big))
        }
        clock = 3
        list.start(3)
        assertNull(list.chunk(3, byteArrayOf(0x01, 0x00, 0x00, 0x00)))
        assertEquals(listOf(2, 3), list.ids)
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

    /**
     * Devices that never saw the QR code, using a new identity for each
     * State 0x01 (no limit on identities), list one more each millisecond,
     * each with the first chunk of a message it never finishes. The reader
     * writes State 0x01 once at [readerAt], then a three-chunk message
     * 10 ms apart. Returns when its message was handed on, or null if it
     * wasn't within the 30 s request timeout, which the devices' first
     * State write started.
     */
    private fun readerDelivered(readerAt: Long, firstInTick: Boolean): Long? {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        var next = 0
        var started = false
        var chunks = 0
        fun attacker() {
            if (list.start(next)) assertNull(list.chunk(next, partial))
            next++
        }
        fun readerStep(): Boolean {
            if (!started) {
                if (clock < readerAt) return false
                started = true
                list.start(reader)
                return false
            }
            if (chunks >= 3 || clock < readerAt + (chunks + 1) * 10L) return false
            chunks++
            return list.chunk(reader, if (chunks < 3) partial else byteArrayOf(0x00, 0x02)) != null
        }
        for (tick in 0L until 30_000L) {
            clock = tick
            if (firstInTick) {
                if (readerStep()) return clock
                attacker()
            } else {
                attacker()
                if (readerStep()) return clock
            }
        }
        return null
    }

    /** The reader gets its message to Go wherever it arrives in the request window, however the writes in a millisecond are ordered. */
    @Test fun devicesWithoutTheQrCodeCantKeepTheReaderOut() {
        for (readerAt in listOf(50L, 500L, 2_000L, 10_000L)) {
            for (firstInTick in listOf(false, true)) {
                assertEquals("reader at $readerAt ms (first in its tick: $firstInTick)", readerAt + 30, readerDelivered(readerAt, firstInTick))
            }
        }
    }

    /**
     * A reader whose message takes longer than 10 s (a small MTU, a
     * congested radio) keeps its place while it sends, as devices that
     * never saw the QR code list a new identity each millisecond.
     */
    @Test fun aSlowReaderKeepsItsPlaceWhileItSends() {
        var clock = 0L
        val list = BleCandidates<Int> { clock }
        assertTrue(list.start(reader))
        var next = 0
        for (tick in 1L..12_000L) {
            clock = tick
            if (list.start(next)) assertNull(list.chunk(next, partial))
            next++
            if (tick % 20 == 0L && tick < 12_000L) assertNull("at $tick ms", list.chunk(reader, partial))
            assertTrue("displaced at $tick ms", reader in list)
        }
        assertNotNull(list.chunk(reader, byteArrayOf(0x00, 0x02)))
    }
}
