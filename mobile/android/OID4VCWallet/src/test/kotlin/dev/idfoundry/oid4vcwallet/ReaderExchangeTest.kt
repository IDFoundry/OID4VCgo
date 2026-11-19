package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A reader in mdoc peripheral server mode connects to whichever device
 * advertises the holder's service UUID: a device whose answer Go
 * rejects, or whose link is lost before it answers, is passed over and
 * the same request goes to the next, until the connect timeout, or until
 * no other device advertises the UUID.
 */
class ReaderExchangeTest {
    /** Each answer in turn, or a lost link. */
    private class Fake(answers: List<Any>, private val connectable: Int = Int.MAX_VALUE) : ProximityTransport {
        private val answers = ArrayDeque(answers)
        val sent = mutableListOf<ByteArray>()
        var rejects = 0
        var connects = 0
        /** Each bounded connect's time to find a device: passing over one. */
        val findWithins = mutableListOf<kotlin.time.Duration>()
        /** Connects without that bound. */
        var unbounded = 0

        override suspend fun connect() {
            unbounded++
            next()
        }

        override suspend fun connect(findWithin: kotlin.time.Duration) {
            findWithins += findWithin
            next()
        }

        /** Connects to the next device; past [connectable], none advertises. */
        private fun next() {
            if (connects == connectable) throw ProximityTransportException("no other device advertises the service")
            connects++
        }

        override suspend fun send(message: ByteArray) {
            sent += message
        }

        override suspend fun receive(): ByteArray = when (val next = answers.removeFirst()) {
            is ByteArray -> next
            is Exception -> throw next
            else -> error("not an answer: $next")
        }

        override fun reject() {
            rejects++
        }

        override fun close() = Unit
    }

    private val junk = byteArrayOf(1)
    private val status20 = byteArrayOf(20)
    private val holder = byteArrayOf(9)
    private val establishment = byteArrayOf(0x42)

    /** Go's events: TryHandleMessage's, or with [tried] false HandleMessage's. */
    private fun handle(tried: Boolean = true): (ByteArray) -> ReaderEventJSON = { answer ->
        when {
            answer.contentEquals(holder) -> ReaderEventJSON("verified")
            !tried -> ReaderEventJSON("ended", reason = if (answer.contentEquals(status20)) "declined" else "error", error = "[protocol] x")
            answer.contentEquals(status20) -> ReaderEventJSON("rejected", reason = "declined")
            else -> ReaderEventJSON("rejected", reason = "error", error = "[protocol] not this session's")
        }
    }

    private fun exchange(t: Fake, passesOver: Boolean = true, budget: kotlin.time.Duration = 1.minutes) =
        ReaderExchange(t, passesOver, TimeSource.Monotonic.markNow() + budget, 30.seconds, handle(passesOver))

    @Test
    fun impostorsArePassedOverAndTheRequestSentAgain() = runBlocking {
        val lost = ProximityTransportException("the other device disconnected", peerEnded = true)
        val t = Fake(listOf(junk, status20, lost, holder))
        val event = exchange(t).run(establishment)
        assertEquals("verified", event.event)
        assertEquals(3, t.rejects)
        assertEquals(3, t.connects)
        assertEquals(4, t.sent.size)
        assertTrue("the same request each time", t.sent.all { it.contentEquals(establishment) })
        assertEquals("each pass over waits only to find another device", List(3) { ReaderExchange.PASS_OVER_FIND }, t.findWithins)
        assertEquals(0, t.unbounded)
    }

    @Test
    fun aDeclineIsTheOutcomeOnceNoOtherDeviceAdvertises() = runBlocking {
        // The holder declined and stopped advertising: with a minute
        // left, the reader looks for another device for PASS_OVER_FIND,
        // not the minute.
        val t = Fake(listOf(status20), connectable = 0)
        val event = exchange(t, budget = 1.minutes).run(establishment)
        assertEquals("rejected", event.event)
        assertEquals("declined", event.reason)
        assertEquals(1, t.rejects)
        assertEquals(listOf(ReaderExchange.PASS_OVER_FIND), t.findWithins)
        assertEquals(0, t.unbounded)
    }

    @Test
    fun theLastRejectionIsTheOutcomeOnceTheTimeIsUp() = runBlocking {
        val t = Fake(listOf(status20))
        val event = exchange(t, budget = 0.seconds).run(establishment)
        assertEquals("rejected", event.event)
        assertEquals("declined", event.reason)
        assertEquals(1, t.rejects)
        assertEquals(0, t.connects)
    }

    @Test
    fun aDeclineStaysTheOutcomePastALostLink() = runBlocking {
        val lost = ProximityTransportException("the other device disconnected", peerEnded = true)
        val t = Fake(listOf(status20, lost), connectable = 1)
        val event = exchange(t).run(establishment)
        assertEquals("rejected", event.event)
        assertEquals("declined", event.reason)
        assertEquals(2, t.rejects)
    }

    @Test
    fun aLostLinkIsTheOutcomeOnceTheTimeIsUp() = runBlocking {
        val lost = ProximityTransportException("the other device disconnected", peerEnded = true)
        try {
            exchange(Fake(listOf(lost)), budget = 0.seconds).run(establishment)
            fail("no failure")
        } catch (e: ProximityTransportException) {
            assertSame(lost, e)
        }
    }

    @Test
    fun noOtherDeviceFoundEndsTheSearch() = runBlocking {
        val t = object : ProximityTransport {
            var rejects = 0
            override suspend fun connect() = throw ProximityTransportException("couldn't connect to the other device")
            override suspend fun connect(findWithin: kotlin.time.Duration) = connect()
            override suspend fun send(message: ByteArray) = Unit
            override suspend fun receive(): ByteArray = junk
            override fun reject() {
                rejects++
            }
            override fun close() = Unit
        }
        val event = ReaderExchange(t, true, TimeSource.Monotonic.markNow() + 1.minutes, 30.seconds, handle()).run(establishment)
        assertEquals("rejected", event.event)
        assertEquals("error", event.reason)
        assertEquals(1, t.rejects)
    }

    @Test
    fun bluetoothOffIsNeverPassedOver() = runBlocking {
        val off = ProximityTransportException(BLUETOOTH_OFF, bluetoothUnavailable = true)
        val t = Fake(listOf(off))
        try {
            exchange(t).run(establishment)
            fail("no failure")
        } catch (e: ProximityTransportException) {
            assertSame(off, e)
        }
        assertEquals(0, t.rejects)
    }

    @Test
    fun withoutPassingOverTheFirstAnswerEnds() = runBlocking {
        val t = Fake(listOf(status20))
        val event = exchange(t, passesOver = false).run(establishment)
        assertEquals("ended", event.event)
        assertEquals("declined", event.reason)
        assertEquals(0, t.rejects)

        val lost = ProximityTransportException("the other device disconnected", peerEnded = true)
        try {
            exchange(Fake(listOf(lost)), passesOver = false).run(establishment)
            fail("no failure")
        } catch (e: ProximityTransportException) {
            assertSame(lost, e)
        }
    }
}
