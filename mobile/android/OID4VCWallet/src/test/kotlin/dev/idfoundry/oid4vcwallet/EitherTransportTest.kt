package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** A holder offering both BLE modes: the first transport to connect is kept, the others closed. */
class EitherTransportTest {
    private class Fake(val connects: suspend () -> Unit) : ProximityTransport {
        var closed = false
        var cancelled = false
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

        override suspend fun receive(): ByteArray = byteArrayOf(7)

        override fun close() {
            closed = true
        }
    }

    @Test
    fun firstToConnectWins(): Unit = runBlocking {
        val go = CompletableDeferred<Unit>()
        val waiting = Fake { awaitCancellation() }
        val connecting = Fake { go.await() }
        val either = EitherTransport(listOf(waiting, connecting))
        go.complete(Unit)
        either.connect()
        assertSame(connecting, either.connected)
        assertTrue("the other wasn't stopped", waiting.cancelled && waiting.closed)
        assertFalse(connecting.closed)
        either.send(byteArrayOf(1))
        assertArrayEquals(byteArrayOf(1), connecting.sent.single())
        assertArrayEquals(byteArrayOf(7), either.receive())
        either.close()
        assertTrue(connecting.closed)
    }

    /** One way failing (no advertising, say) leaves the other to connect. */
    @Test
    fun oneFailingLeavesTheOther(): Unit = runBlocking {
        val failing = Fake { throw ProximityTransportException("this device can't advertise over BLE") }
        val connecting = Fake { }
        val either = EitherTransport(listOf(failing, connecting))
        either.connect()
        assertSame(connecting, either.connected)
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
