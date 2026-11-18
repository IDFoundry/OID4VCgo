package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import kotlin.time.Duration.Companion.seconds

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

    /**
     * The device whose message [receive] returned last isn't this
     * session's peer (Go rejected it): drop it, and have [receive]
     * return the next first message, from any other device. A GATT
     * client disconnects, passes over the device, and connects to the
     * next one advertising the service: at the next [connect], or
     * [receive]. A transport with one peer keeps it.
     */
    fun reject() {
        // One peer: nothing else to wait for.
    }

    /**
     * The device whose message [receive] returned last is this session's
     * reader (Go accepted it): stop looking for others, and from now on
     * send to it and receive only from it. Before [send], a GATT server
     * whose [receive] returned nothing yet commits to the first device
     * that started the session. Calling it again does nothing.
     */
    fun commit() {
        // One peer: already committed.
    }
}

/**
 * How many unread messages a BLE transport keeps. A session reads each
 * message before the next is due, so more is a misbehaving peer, and the
 * transport ends the session rather than buffer for it.
 */
internal const val INCOMING_MESSAGE_CAPACITY = 4

/** The failure when a peer overruns [INCOMING_MESSAGE_CAPACITY]. */
internal const val TOO_MANY_MESSAGES = "too many unread messages from the other device"

/**
 * Several transports at once, for a holder offering both BLE modes: it
 * advertises and scans until a reader connects either way, and keeps
 * every way open until Go accepts a first message ([commit]): that
 * transport is kept and the others closed. A device that only starts a
 * session, or sends a first message Go rejects, closes nothing. It fails
 * only once every transport has.
 */
internal class EitherTransport(private val transports: List<ProximityTransport>) : ProximityTransport {
    /** A transport's first message, before one is chosen. */
    private class Arrival(val index: Int, val message: ByteArray)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Any()
    @Volatile private var chosen: ProximityTransport? = null
    /** The transport whose message [receive] returned last; under [lock]. */
    private var pending: Int? = null
    /** Each transport's wait for Go's verdict on its message, true when chosen; under [lock]. */
    private val verdicts = HashMap<Int, CompletableDeferred<Boolean>>()
    /** Each transport's failure, by index; under [lock]. */
    private val failures = arrayOfNulls<Throwable>(transports.size)
    private var pumps: List<Job> = emptyList()
    private val started = CompletableDeferred<Unit>()
    /** At most one message per transport waits: each waits for its verdict. */
    private val arrivals = Channel<Arrival>(Channel.UNLIMITED)

    /** The one chosen. */
    val connected: ProximityTransport? get() = chosen

    /** Starts every transport and returns once one has connected. */
    override suspend fun connect() {
        synchronized(lock) {
            if (pumps.isEmpty()) pumps = transports.indices.map { i -> scope.launch { pump(i) } }
        }
        started.await()
    }

    /**
     * Connects transport [i], then hands each first message it receives
     * to [receive], waiting for Go's verdict before the next: until it is
     * chosen, when its messages go to [receive] directly.
     */
    private suspend fun pump(i: Int) {
        val t = transports[i]
        try {
            t.connect()
            started.complete(Unit)
            while (true) {
                val message = t.receive()
                val verdict = CompletableDeferred<Boolean>()
                synchronized(lock) { verdicts[i] = verdict }
                arrivals.send(Arrival(i, message))
                if (verdict.await()) return
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            failed(i, e)
        }
    }

    /** Transport [i] failed: the whole fails once every one has, unless one was chosen. */
    private fun failed(i: Int, e: Exception) {
        val all = synchronized(lock) {
            failures[i] = e
            if (chosen == null && failures.all { it != null }) failures.first() else null
        } ?: return
        started.completeExceptionally(all)
        arrivals.close(all)
    }

    override suspend fun send(message: ByteArray) {
        (chosen ?: throw ProximityTransportException("the session hasn't started")).send(message)
    }

    override suspend fun receive(): ByteArray {
        chosen?.let { return it.receive() }
        val arrival = try {
            arrivals.receive()
        } catch (e: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            throw ProximityTransportException("the session ended", peerEnded = true, cause = e)
        }
        synchronized(lock) { pending = arrival.index }
        return arrival.message
    }

    override fun reject() {
        val (i, verdict) = synchronized(lock) {
            val i = pending ?: return
            if (chosen != null) return
            pending = null
            i to verdicts.remove(i)
        }
        transports[i].reject()
        verdict?.complete(false)
    }

    override fun commit() {
        val (i, verdict) = synchronized(lock) {
            val i = pending ?: return
            if (chosen != null) return
            chosen = transports[i]
            pending = null
            i to verdicts.remove(i)
        }
        transports[i].commit()
        verdict?.complete(true)
        val losers = transports.indices.filter { it != i }
        losers.forEach { pumps[it].cancel() }
        // Wait for the others to stop before closing them: one still
        // connecting could otherwise open a GATT server or client after
        // its close(), which is then never closed.
        scope.launch {
            withContext(NonCancellable) {
                withTimeoutOrNull(LOSER_STOP_TIMEOUT) { losers.forEach { pumps[it].join() } }
                losers.forEach { transports[it].close() }
            }
        }
    }

    override fun close() {
        transports.forEach { it.close() }
        scope.cancel()
        val ended = ProximityTransportException("the session ended", peerEnded = true)
        started.completeExceptionally(ended)
        arrivals.close(ended)
    }

    private companion object {
        val LOSER_STOP_TIMEOUT = 2.seconds
    }
}

/** The failure's message when Bluetooth is off, or turns off. */
internal const val BLUETOOTH_OFF = "Bluetooth is off"

/**
 * The transport failed, or the other side ended the session
 * ([peerEnded]), or the device found isn't this session's reader
 * ([wrongReader]: its Ident differs), or Bluetooth is off
 * ([bluetoothUnavailable]).
 */
internal class ProximityTransportException(
    message: String,
    val peerEnded: Boolean = false,
    cause: Throwable? = null,
    val wrongReader: Boolean = false,
    val bluetoothUnavailable: Boolean = false,
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
