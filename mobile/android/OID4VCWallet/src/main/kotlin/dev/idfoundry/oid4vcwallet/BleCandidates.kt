package dev.idfoundry.oid4vcwallet

import java.io.IOException

/**
 * The devices that started a session (State 0x01) on a GATT server
 * before one was committed to, any of which may be the reader, and
 * their first messages' chunks. Not thread-safe: [GattServerTransport]
 * keeps it under its lock.
 *
 * At most [MAX_CANDIDATES] are listed. A device that starts a session
 * when the list is full displaces the oldest candidate past its
 * [DEADLINE_MS] without a whole message, else the oldest that hasn't
 * sent a chunk; never one partway through its message within its
 * deadline, nor one whose message was handed on. With none to displace,
 * it isn't listed. Each device can be listed [MAX_STARTS] times at most,
 * so devices that only write State can't keep displacing others; one
 * whose message was handed on isn't listed again until Go has judged it.
 */
internal class BleCandidates<ID>(private val now: () -> Long = { System.nanoTime() / 1_000_000 }) {
    private class Candidate(val started: Long) {
        val reassembler = BleChunks.Reassembler()
        /** Whether a chunk of its first message has arrived. */
        var receiving = false
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
            candidates.remove(displaceable() ?: return false)
        }
        starts[id] = (starts[id] ?: 0) + 1
        candidates[id] = Candidate(now())
        return true
    }

    /** The candidate a newcomer displaces, if any. */
    private fun displaceable(): ID? {
        val t = now()
        return candidates.entries.firstOrNull { !it.value.delivered && t - it.value.started > DEADLINE_MS }?.key
            ?: candidates.entries.firstOrNull { !it.value.delivered && !it.value.receiving }?.key
    }

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
        c.receiving = true
        val message = c.reassembler.add(value) ?: return null
        c.delivered = true
        judging += id
        return message
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
        /** How many devices may start a session at once. */
        const val MAX_CANDIDATES: Int = 8
        /**
         * How long, from its State 0x01, a candidate keeps its place while
         * its first message arrives. Past it, a newcomer may displace it.
         */
        const val DEADLINE_MS: Long = 10_000
        /** How many times one device may be listed. */
        const val MAX_STARTS: Int = 3
    }
}
