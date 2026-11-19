package dev.idfoundry.oid4vcwallet

/**
 * When a GATT client started its recent BLE scans, to tell when Android
 * will report a new one's results. Android starts no scan for an app
 * that has started [LIMIT] in the last [WINDOW_MS], and says nothing:
 * the scan just finds nothing. A reader passing over devices starts a
 * scan for each, so a device rotating its address could make the reader
 * scan that often and its time to find another device run out while
 * the holder still advertises; that time counts from [blockedFor]'s end.
 * Thread-safe.
 */
internal class ScanStarts(private val now: () -> Long = { System.nanoTime() / 1_000_000 }) {
    /** The last [LIMIT] starts, oldest first. */
    private val starts = ArrayDeque<Long>()

    /** A scan starts now. */
    @Synchronized fun record() {
        starts.addLast(now())
        while (starts.size > LIMIT) starts.removeFirst()
    }

    /**
     * How many milliseconds from now until a scan started will report
     * results: 0 unless the last [LIMIT] all started in the last
     * [WINDOW_MS].
     */
    @Synchronized fun blockedFor(): Long {
        if (starts.size < LIMIT) return 0
        return (starts.first() + WINDOW_MS - now()).coerceAtLeast(0)
    }

    companion object {
        /** Android's limit: scans an app may start in [WINDOW_MS]. */
        const val LIMIT = 5
        const val WINDOW_MS: Long = 30_000
    }
}
