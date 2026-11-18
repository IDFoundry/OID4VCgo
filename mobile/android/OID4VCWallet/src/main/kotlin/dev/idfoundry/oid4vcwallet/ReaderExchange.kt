package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlin.time.Duration
import kotlin.time.TimeSource

/**
 * A reader's request and the holder's answer to it. In mdoc peripheral
 * server mode ([passesOver]) the reader connects to whichever device
 * advertises the holder's service UUID, which the holder's adverts carry
 * in the clear, so the device answering needn't be the holder: one whose
 * answer Go rejects ([handle]'s "rejected" event: it doesn't decrypt, or
 * is a bare status, which isn't encrypted), or whose link is lost before
 * it answers, is passed over ([ProximityTransport.reject]), and the same
 * request goes to the next device advertising the UUID, until
 * [deadline]. The holder takes it once.
 */
internal class ReaderExchange(
    private val transport: ProximityTransport,
    private val passesOver: Boolean,
    /** The end of the time to find the holder's device: the session's connect timeout. */
    private val deadline: TimeSource.Monotonic.ValueTimeMark,
    /** How long to wait for an answer. */
    private val idle: Duration,
    /** Go's event, as JSON, for an answer: TryHandleMessage when [passesOver], else HandleMessage. */
    private val handle: (ByteArray) -> ReaderEventJSON,
    /** Called each time the request is sent. */
    private val sent: () -> Unit = {},
) {
    /**
     * Sends [establishment] and returns Go's event for the answer. When
     * no other device is found before [deadline], the outcome is the last
     * rejected answer, a "rejected" event, whose reason the caller
     * reports as an "ended" one's, or, with none, the lost link, thrown.
     * An answer that isn't in time is a [ProximityException] TimedOut.
     */
    suspend fun run(establishment: ByteArray): ReaderEventJSON {
        var rejected: ReaderEventJSON? = null
        while (true) {
            val answer = try {
                transport.send(establishment)
                sent()
                withTimeout(idle) { transport.receive() }
            } catch (e: TimeoutCancellationException) {
                throw ProximityException(ProximityException.Reason.TimedOut, "the holder didn't respond in time", e)
            } catch (e: ProximityTransportException) {
                if (!passesOver || e.bluetoothUnavailable) throw e
                if (passOver()) continue
                return rejected ?: throw e
            }
            val event = handle(answer)
            if (event.event != "rejected") return event
            rejected = event
            if (!passOver()) return event
        }
    }

    /**
     * Passes over the device that answered, or lost its link, and
     * connects to the next one advertising the holder's service UUID
     * before [deadline]: true once connected, false when none is found
     * in time.
     */
    private suspend fun passOver(): Boolean {
        transport.reject()
        val left = -deadline.elapsedNow()
        if (!left.isPositive()) return false
        return try {
            withTimeout(left) { transport.connect() }
            true
        } catch (e: TimeoutCancellationException) {
            false
        } catch (e: ProximityTransportException) {
            if (e.bluetoothUnavailable) throw e
            false
        }
    }
}
