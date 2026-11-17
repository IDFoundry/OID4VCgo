package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * A holder offering both BLE modes: every transport stays open until Go
 * accepts a first message; that one is kept, the others closed.
 */
class EitherTransportTest {
    private class Fake(val message: Byte = 7, val connects: suspend () -> Unit) : ProximityTransport {
        @Volatile var closed = false
        @Volatile var cancelled = false
        @Volatile var rejects = 0
        val sent = mutableListOf<ByteArray>()

        override suspend fun connect() {
            try {
                connects()
            } catch (e: kotlinx.coroutines.CancellationException) {
                cancelled = true
                throw e
            }
        }

        override suspend fun send(message: ByteArray) {
            sent += message
        }

        override suspend fun receive(): ByteArray {
            if (closed) throw ProximityTransportException("closed")
            return byteArrayOf(message)
        }

        override fun reject() {
            rejects++
        }

        override fun close() {
            closed = true
        }
    }

    private suspend fun eventually(what: String, condition: () -> Boolean) {
        withTimeout(5_000) { while (!condition()) delay(10) }
        assertTrue(what, condition())
    }

    @Test
    fun firstAcceptedWins(): Unit = runBlocking {
        val go = CompletableDeferred<Unit>()
        val waiting = Fake { awaitCancellation() }
        val connecting = Fake { go.await() }
        val either = EitherTransport(listOf(waiting, connecting))
        go.complete(Unit)
        either.connect()
        assertNull("chosen before any message was accepted", either.connected)
        assertFalse("the other was stopped on a connection alone", waiting.closed)
        assertArrayEquals(byteArrayOf(7), either.receive())
        either.commit()
        assertSame(connecting, either.connected)
        eventually("the other wasn't stopped") { waiting.cancelled && waiting.closed }
        assertFalse(connecting.closed)
        either.send(byteArrayOf(1))
        assertArrayEquals(byteArrayOf(1), connecting.sent.single())
        assertArrayEquals(byteArrayOf(7), either.receive())
        either.close()
        assertTrue(connecting.closed)
    }

    /** A first message Go rejects leaves every transport open, and the next first message, from either, is handed on. */
    @Test
    fun rejectedMessageKeepsEveryWayOpen(): Unit = runBlocking {
        val blind = Fake(1) { }
        val reader = Fake(2) { delay(50) }
        val either = EitherTransport(listOf(blind, reader))
        either.connect()
        assertArrayEquals(byteArrayOf(1), either.receive())
        either.reject()
        assertEquals(1, blind.rejects)
        assertFalse(blind.closed || reader.closed)
        while (true) {
            val got = either.receive()
            if (got.contentEquals(byteArrayOf(2))) break
            either.reject()
        }
        either.commit()
        assertSame(reader, either.connected)
        eventually("the blind transport wasn't closed") { blind.closed }
        either.close()
    }

    /** One way failing (no advertising, say) leaves the other to connect. */
    @Test
    fun oneFailingLeavesTheOther(): Unit = runBlocking {
        val failing = Fake { throw ProximityTransportException("this device can't advertise over BLE") }
        val connecting = Fake { }
        val either = EitherTransport(listOf(failing, connecting))
        either.connect()
        either.receive()
        either.commit()
        assertSame(connecting, either.connected)
        either.close()
    }

    @Test
    fun failsOnceEveryOneHas(): Unit = runBlocking {
        val either = EitherTransport(
            listOf(
                Fake { throw ProximityTransportException("first") },
                Fake { throw ProximityTransportException("second") },
            ),
        )
        try {
            either.connect()
            fail("connected")
        } catch (e: ProximityTransportException) {
            assertEquals("first", e.message)
        }
        try {
            either.send(byteArrayOf(1))
            fail("sent without a connection")
        } catch (e: ProximityTransportException) {
            // As expected.
        }
    }
}
