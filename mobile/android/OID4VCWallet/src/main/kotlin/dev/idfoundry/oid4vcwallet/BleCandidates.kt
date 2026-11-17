package dev.idfoundry.oid4vcwallet

import java.io.IOException

/**
 * The devices that started a session (State 0x01) on a GATT server
 * before one was committed to, any of which may be the reader, and
 * their first messages' chunks. Not thread-safe: [GattServerTransport]
 * keeps it under its lock.
 *
 * A device that starts a session is listed, whenever it comes: with
 * [MAX_CANDIDATES] listed, it displaces the one heard from least
 * recently (its State 0x01 or its last chunk), never one whose message
 * was handed on. A chunk that takes the partial messages past
 * [MAX_BUFFERED_BYTES] displaces others the same way, so memory stays
 * bounded. However many identities devices that never saw the QR code
 * use, they can't keep the reader out: displacing it partway through
 * its message takes [MAX_CANDIDATES] writes from other devices, each
 * listed or listing itself, between two of its own. Each device can be
 * listed [MAX_STARTS] times at most, and one whose message was handed on
 * isn't listed again until Go has judged it, so Go sees one message per
 * device at a time.
 */
internal class BleCandidates<ID>(private val now: () -> Long = { System.nanoTime() / 1_000_000 }) {
    private class Candidate(var heard: Long) {
        val reassembler = BleChunks.Reassembler()
        /** Whether its first message was handed on: later chunks are dropped. */
        var delivered = false
    }

    /** Oldest first. */
    private val candidates = LinkedHashMap<ID, Candidate>()
    /** Devices dropped for good: Go rejected their message, or they sent a malformed chunk. */
    private val refused = HashSet<ID>()
    /** Devices whose first message was handed on and not yet judged. */
    private val judging = HashSet<ID>()
    private val starts = HashMap<ID, Int>()

    /** The listed devices, oldest first. */
    val ids: List<ID> get() = candidates.keys.toList()

    fun isRefused(id: ID): Boolean = id in refused

    operator fun contains(id: ID): Boolean = id in candidates

    /** [id] wrote State 0x01. True when it is listed. */
    fun start(id: ID): Boolean {
        if (id in candidates) return true
        if (id in refused || id in judging || (starts[id] ?: 0) >= MAX_STARTS) return false
        if (candidates.size >= MAX_CANDIDATES) {
            candidates.remove(leastRecentlyHeard(except = id) ?: return false)
        }
        starts[id] = (starts[id] ?: 0) + 1
        candidates[id] = Candidate(now())
        return true
    }

    /** The candidate to displace, other than [except]: the one heard from least recently whose message wasn't handed on. */
    private fun leastRecentlyHeard(except: ID): ID? =
        candidates.entries.filter { !it.value.delivered && it.key != except }.minByOrNull { it.value.heard }?.key

    /**
     * [id] wrote State 0x02 or disconnected: it is no longer listed. A
     * message of its already handed on stays judged.
     */
    fun end(id: ID) {
        candidates.remove(id)
    }

    /**
     * Adds a chunk from [id], returning its first whole message. It
     * throws for a malformed chunk: refuse the device.
     */
    @Throws(IOException::class)
    fun chunk(id: ID, value: ByteArray): ByteArray? {
        val c = candidates[id]?.takeIf { !it.delivered } ?: return null
        val message = c.reassembler.add(value)
        c.heard = now()
        if (message == null) {
            makeRoom(keeping = id)
            return null
        }
        c.delivered = true
        judging += id
        return message
    }

    /**
     * Displaces others, least recently heard first, until the partial
     * messages fit [MAX_BUFFERED_BYTES]. [keeping]'s own is at most
     * [BleChunks.MAX_MESSAGE_BYTES], so it always fits.
     */
    private fun makeRoom(keeping: ID) {
        var buffered = candidates.values.sumOf { it.reassembler.buffered }
        while (buffered > MAX_BUFFERED_BYTES) {
            val other = leastRecentlyHeard(except = keeping) ?: return
            buffered -= candidates.remove(other)?.reassembler?.buffered ?: 0
        }
    }

    /** Forgets [id] and ignores it from now on. */
    fun refuse(id: ID) {
        candidates.remove(id)
        judging -= id
        refused += id
    }

    /**
     * The device to commit to: [pending], the one whose message Go
     * accepted, if still listed; before any message, the first listed.
     */
    fun chosen(pending: ID?): ID? = if (pending == null) candidates.keys.firstOrNull() else pending.takeIf { it in candidates }

    /** Forgets every candidate, once one is committed to. */
    fun clear() {
        candidates.clear()
        judging.clear()
    }

    companion object {
        /** How many devices may be listed at once. */
        const val MAX_CANDIDATES: Int = 64
        /**
         * How many bytes the listed devices' partial messages may hold in
         * all: room for a whole message of [BleChunks.MAX_MESSAGE_BYTES]
         * and as much again.
         */
        const val MAX_BUFFERED_BYTES: Int = 2 * BleChunks.MAX_MESSAGE_BYTES
        /** How many times one device may be listed. */
        const val MAX_STARTS: Int = 3
        /** How many first messages may wait for Go: more is a refused device. */
        const val MAX_FIRST_MESSAGES: Int = 16
    }
}
