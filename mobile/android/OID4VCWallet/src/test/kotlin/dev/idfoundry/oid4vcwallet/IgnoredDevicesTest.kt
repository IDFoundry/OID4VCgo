package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The devices a GATT client in central client mode passes over
 * ([IgnoredDevices], [checkReaderIdent]): only one that showed another
 * Ident, and only for a while, since another device can claim its
 * address.
 */
class IgnoredDevicesTest {
    @Test fun aDeviceIsPassedOverForAWhileOnly() {
        var clock = 0L
        val ignored = IgnoredDevices<String> { clock }
        ignored.ignore("reader")
        assertTrue("reader" in ignored)
        assertFalse("other" in ignored)
        clock = IgnoredDevices.IGNORE_MS - 1
        assertTrue("reader" in ignored)
        clock = IgnoredDevices.IGNORE_MS
        assertFalse("a device claiming the reader's address kept it passed over past the limit", "reader" in ignored)
    }

    @Test fun ignoringAgainRestartsTheLimit() {
        var clock = 0L
        val ignored = IgnoredDevices<String> { clock }
        ignored.ignore("a")
        clock = IgnoredDevices.IGNORE_MS - 1
        ignored.ignore("a")
        clock = IgnoredDevices.IGNORE_MS + 1
        assertTrue("a" in ignored)
    }

    /** Only an Ident that was read and differs is another session's reader: a failed or unanswered read is a failed attempt. */
    @Test fun onlyAnIdentReadAndDifferentIsAnotherReader() {
        val want = byteArrayOf(1, 2, 3)
        checkReaderIdent(want.copyOf(), want)
        val differs = assertThrows(ProximityTransportException::class.java) { checkReaderIdent(byteArrayOf(1, 2, 4), want) }
        assertTrue(differs.wrongReader)
        val unread = assertThrows(ProximityTransportException::class.java) { checkReaderIdent(null, want) }
        assertFalse("a failed read passed over the device", unread.wrongReader)
    }
}
