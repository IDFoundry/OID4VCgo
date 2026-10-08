package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import java.util.UUID

/**
 * Carries one ISO/IEC 18013-5 session's whole messages between the
 * holder and the reader: over BLE GATT ([GattServerTransport],
 * [GattClientTransport]), or in memory in tests. Messages are whole:
 * chunking is the transport's.
 */
internal interface ProximityTransport {
    /**
     * Advertises or scans, connects, and returns once the session has
     * started: the GATT client has subscribed and written 0x01 to State.
     */
    suspend fun connect()

    /** Sends one whole message. */
    suspend fun send(message: ByteArray)

    /**
     * The next whole message from the other side. It throws
     * [ProximityTransportException] once the other side ends the
     * session (State 0x02) or disconnects.
     */
    suspend fun receive(): ByteArray

    /**
     * Ends the session: writes or notifies 0x02 to State if it started,
     * disconnects, and stops advertising or scanning. Calling it again
     * does nothing.
     */
    fun close()
}

/**
 * Several transports at once, for a holder offering both BLE modes: it
 * advertises and scans until a reader connects either way, keeps that
 * transport and closes the others. It fails only once every one has.
 */
internal class EitherTransport(private val transports: List<ProximityTransport>) : ProximityTransport {
    @Volatile private var chosen: ProximityTransport? = null

    /** The one that connected. */
    val connected: ProximityTransport? get() = chosen

    override suspend fun connect(): Unit = coroutineScope {
        val results = Channel<Result<ProximityTransport>>(transports.size)
        val jobs: List<Job> = transports.map { t -> launch { results.send(runCatching { t.connect(); t }) } }
        var failure: Throwable? = null
        repeat(transports.size) {
            val result = results.receive()
            val winner = result.getOrNull()
            if (winner != null) {
                chosen = winner
                jobs.forEach { it.cancel() }
                transports.filter { it !== winner }.forEach { it.close() }
                return@coroutineScope
            }
            failure = failure ?: result.exceptionOrNull()
        }
        throw failure ?: ProximityTransportException("couldn't connect")
    }

    override suspend fun send(message: ByteArray) {
        (chosen ?: throw ProximityTransportException("the session hasn't started")).send(message)
    }

    override suspend fun receive(): ByteArray =
        (chosen ?: throw ProximityTransportException("the session hasn't started")).receive()

    override fun close() {
        transports.forEach { it.close() }
    }
}

/** The transport failed, or the other side ended the session ([peerEnded]). */
internal class ProximityTransportException(
    message: String,
    val peerEnded: Boolean = false,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * The GATT characteristics of one BLE mode (§8.3.3.1.1.4 Table 11): the
 * GATT server's service has State, Client2Server, Server2Client and, in
 * mdoc central client mode, Ident.
 */
internal data class GattCharacteristics(
    val state: UUID,
    val client2Server: UUID,
    val server2Client: UUID,
    val ident: UUID?,
) {
    companion object {
        private fun uuid(n: Int): UUID = UUID.fromString("%08x-a123-48ce-896b-4c76973373e6".format(n))

        /** mdoc peripheral server mode: the mdoc is the GATT server. */
        val peripheralServer: GattCharacteristics = GattCharacteristics(uuid(1), uuid(2), uuid(3), null)

        /** mdoc central client mode: the reader is the GATT server, with Ident. */
        val centralClient: GattCharacteristics = GattCharacteristics(uuid(5), uuid(6), uuid(7), uuid(8))

        /** The Client Characteristic Configuration descriptor, for notifications. */
        val clientConfiguration: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

        /** State's values (§8.3.3.1.1.5 Table 13). */
        const val STATE_START: Byte = 0x01
        const val STATE_END: Byte = 0x02
    }
}
