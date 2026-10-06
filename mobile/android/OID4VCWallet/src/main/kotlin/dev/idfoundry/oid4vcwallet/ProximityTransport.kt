package dev.idfoundry.oid4vcwallet

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
