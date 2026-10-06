package dev.idfoundry.oid4vcwallet

import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * ISO/IEC 18013-5 §8.3.3.1.1.6's message chunking over GATT: each
 * characteristic value is one prefix byte — 0x01 when more chunks
 * follow, 0x00 for the last — and up to (size − 1) message bytes.
 */
internal object BleChunks {
    /** The most a GATT attribute value holds, and what Multipaz uses. */
    const val MAX_CHARACTERISTIC_SIZE: Int = 512

    /** The default ATT MTU, before any exchange. */
    const val DEFAULT_MTU: Int = 23

    /** The largest message accepted: the Go side's MaxMessageBytes. */
    const val MAX_MESSAGE_BYTES: Int = 2 shl 20

    private const val MORE: Byte = 0x01
    private const val LAST: Byte = 0x00

    /** The characteristic value size for [mtu]: MTU − 3, at most 512. */
    fun characteristicSize(mtu: Int): Int = minOf(MAX_CHARACTERISTIC_SIZE, maxOf(DEFAULT_MTU, mtu) - 3)

    /** Splits [message] into chunks of at most [characteristicSize] bytes, prefix included. */
    fun split(message: ByteArray, characteristicSize: Int): List<ByteArray> {
        require(characteristicSize >= 2) { "a chunk needs room for its prefix and a byte" }
        val payload = characteristicSize - 1
        if (message.isEmpty()) return listOf(byteArrayOf(LAST))
        val chunks = ArrayList<ByteArray>((message.size + payload - 1) / payload)
        var offset = 0
        while (offset < message.size) {
            val end = minOf(message.size, offset + payload)
            val chunk = ByteArray(1 + end - offset)
            chunk[0] = if (end < message.size) MORE else LAST
            message.copyInto(chunk, 1, offset, end)
            chunks += chunk
            offset = end
        }
        return chunks
    }

    /** Reassembles chunks into whole messages. Not thread-safe. */
    class Reassembler {
        private val buffer = ByteArrayOutputStream()

        /**
         * Adds [chunk] and returns the whole message when it was the last,
         * else null. A chunk with another prefix, or a message over
         * [MAX_MESSAGE_BYTES], is a protocol error.
         */
        @Throws(IOException::class)
        fun add(chunk: ByteArray): ByteArray? {
            if (chunk.isEmpty()) throw IOException("an empty chunk")
            if (buffer.size() + chunk.size - 1 > MAX_MESSAGE_BYTES) {
                buffer.reset()
                throw IOException("a message over $MAX_MESSAGE_BYTES bytes")
            }
            buffer.write(chunk, 1, chunk.size - 1)
            return when (chunk[0]) {
                MORE -> null
                LAST -> buffer.toByteArray().also { buffer.reset() }
                else -> {
                    buffer.reset()
                    throw IOException("a chunk with prefix ${chunk[0]}")
                }
            }
        }
    }
}
