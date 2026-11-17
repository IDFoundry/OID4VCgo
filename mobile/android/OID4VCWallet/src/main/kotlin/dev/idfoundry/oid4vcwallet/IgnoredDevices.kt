package dev.idfoundry.oid4vcwallet

/**
 * The devices a GATT client in mdoc central client mode passes over
 * while it looks for this session's reader: one whose Ident was read and
 * differs (another session's reader), or that has no mdoc service,
 * characteristic or Ident to read. Each is passed over for [IGNORE_MS],
 * not for the session: devices are known by their address, which another
 * device can claim, so one that claims the reader's address and shows
 * another Ident keeps the reader passed over only that long. A failure
 * that says nothing about which device it is — a dropped link, a GATT
 * error, an Ident read that fails or isn't answered — ignores nothing:
 * it is one failed connection attempt. Thread-safe.
 */
internal class IgnoredDevices<K>(private val now: () -> Long = { System.nanoTime() / 1_000_000 }) {
    /** When each device is no longer ignored. */
    private val until = HashMap<K, Long>()

    /** Passes over [key] for [IGNORE_MS]. */
    @Synchronized fun ignore(key: K) {
        val t = now()
        until.values.removeAll { it <= t }
        until[key] = t + IGNORE_MS
    }

    /** Whether [key] is passed over now. */
    @Synchronized operator fun contains(key: K): Boolean {
        val u = until[key] ?: return false
        if (now() < u) return true
        until.remove(key)
        return false
    }

    companion object {
        /** How long a device is passed over. */
        const val IGNORE_MS: Long = 10_000
    }
}

/**
 * Checks the Ident a device showed, [read], against this session's
 * reader's, [want]. A read that failed or wasn't answered (null) is a
 * failed attempt; an Ident that differs is another session's reader
 * ([ProximityTransportException.wrongReader]).
 */
internal fun checkReaderIdent(read: ByteArray?, want: ByteArray) {
    read ?: throw ProximityTransportException("couldn't read the reader's Ident")
    if (!read.contentEquals(want)) {
        throw ProximityTransportException("the device found isn't this session's reader (its Ident differs)", wrongReader = true)
    }
}
