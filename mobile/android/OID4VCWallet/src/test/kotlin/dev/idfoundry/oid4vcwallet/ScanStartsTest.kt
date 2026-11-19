package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertEquals
import org.junit.Test

/** Android starts no scan for an app that started five in the last 30 seconds. */
class ScanStartsTest {
    private var clock = 1_000_000L
    private val starts = ScanStarts { clock }

    @Test
    fun fourStartsLeaveTheNextFree() {
        repeat(4) {
            starts.record()
            clock += 1_000
        }
        assertEquals(0, starts.blockedFor())
    }

    @Test
    fun fiveStartsBlockUntilTheOldestIsThirtySecondsOld() {
        val first = clock
        repeat(5) {
            starts.record()
            clock += 2_000
        }
        assertEquals(first + ScanStarts.WINDOW_MS - clock, starts.blockedFor())
        clock = first + ScanStarts.WINDOW_MS
        assertEquals(0, starts.blockedFor())
    }

    @Test
    fun onlyTheLastFiveCount() {
        repeat(5) {
            starts.record()
            clock += 10_000
        }
        // The first is 50 s old, the second 40 s: the last five began
        // 40 s ago.
        starts.record()
        assertEquals(0, starts.blockedFor())
        clock += 1_000
        starts.record()
        starts.record()
        starts.record()
        // Now the last five began 11 s ago, with the fifth start.
        assertEquals(ScanStarts.WINDOW_MS - 11_000, starts.blockedFor())
    }
}
