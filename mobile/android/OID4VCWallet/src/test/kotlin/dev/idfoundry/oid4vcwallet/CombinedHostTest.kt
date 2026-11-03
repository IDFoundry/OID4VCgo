package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread

class CombinedHostTest {
    private val select = NfcCommandKind.SELECT_NDEF
    @Test fun type4SelectKeepsQrAvailableUntilHandover() {
        val arbiter = CombinedEngagementArbiter(false) {}
        assertTrue(arbiter.acceptNfc(select, false))
        assertNull("Type 4 discovery must not commit NFC", arbiter.state.value)
        assertTrue("QR cannot win after an incomplete tap", arbiter.select(false))
    }

    private class Fake(private val connecting: suspend () -> Unit) : ProximityTransport {
        var closed = false
        override suspend fun connect() = connecting()
        override suspend fun send(message: ByteArray) { check(!closed) }
        override suspend fun receive(): ByteArray = byteArrayOf(7)
        override fun close() { closed = true }
    }

    @Test fun qrConnectionRejectsNfcSelect(): Unit = runBlocking {
        val arbiter = CombinedEngagementArbiter(false) {}
        val qr = Fake {}
        val nfc = Fake { error("loser connected") }
        val combined = CombinedTransport(arbiter, qr, nfc)
        combined.connect()
        assertEquals(SelectedEngagement.QR, arbiter.state.value)
        assertArrayEquals(nfcResponse(0x6985), if (arbiter.acceptNfc(select, false)) byteArrayOf() else nfcResponse(0x6985))
        combined.close()
        assertTrue(qr.closed && nfc.closed)
        assertFalse(arbiter.select(false))
    }

    @Test fun nfcHandoverStopsQrBeforeNfcConnect(): Unit = runBlocking {
        val started = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()
        val arbiter = CombinedEngagementArbiter(false) {}
        val qr = Fake { started.complete(Unit); try { awaitCancellation() } finally { cancelled.complete(Unit) } }
        val nfc = Fake { assertTrue(cancelled.isCompleted); assertTrue(qr.closed) }
        val combined = CombinedTransport(arbiter, qr, nfc)
        val connecting = async { combined.connect() }
        started.await()
        assertTrue(arbiter.acceptNfc(select, false))
        assertNull(arbiter.state.value)
        assertTrue(arbiter.select(true)) // The complete Hs has now been read.
        withTimeout(1000) { connecting.await() }
        assertFalse(arbiter.select(false))
        assertEquals(SelectedEngagement.NFC_BLE, arbiter.state.value)
        assertArrayEquals(byteArrayOf(7), combined.receive())
        combined.close()
    }

    @Test fun simultaneousClaimsHaveOneWinner() {
        repeat(100) {
            var claims = 0
            val arbiter = CombinedEngagementArbiter(false) { claims++ }
            val start = CountDownLatch(1)
            var qr = false
            var nfc = false
            val a = thread { start.await(); qr = arbiter.select(false) }
            val b = thread { start.await(); nfc = arbiter.select(true) }
            start.countDown(); a.join(); b.join()
            assertTrue(qr.xor(nfc)); assertEquals(1, claims)
        }
    }

    @Test fun invalidSelectDoesNotWithdrawQr() {
        val arbiter = CombinedEngagementArbiter(true) {}
        assertTrue(arbiter.acceptNfc(NfcCommandKind.OTHER, false))
        assertTrue(arbiter.acceptNfc(NfcCommandKind.SELECT_OTHER, false))
        assertFalse("data before the handover was read", arbiter.acceptNfc(NfcCommandKind.SELECT_DATA, false))
        assertNull(arbiter.state.value)
        assertTrue(arbiter.select(false))
    }

    @Test fun cancelDuringEachStageAndTwentyReplacements(): Unit = runBlocking {
        repeat(20) { index ->
            val arbiter = CombinedEngagementArbiter(index % 2 == 0) {}
            val started = CompletableDeferred<Unit>()
            val qr = Fake { started.complete(Unit); awaitCancellation() }
            val nfc = Fake { awaitCancellation() }
            val combined = CombinedTransport(arbiter, qr, nfc)
            val job = launch { combined.connect() }
            started.await()
            if (index % 3 != 0) arbiter.acceptNfc(select, false)
            if (index % 3 == 2) arbiter.select(true)
            job.cancelAndJoin()
            combined.close()
            assertTrue(qr.closed && nfc.closed)
            assertFalse(arbiter.select(false)); assertFalse(arbiter.acceptNfc(select, true))
        }
    }

    @Test fun missingOrFailedQrLeavesNfcData(): Unit = runBlocking {
        for (qr in listOf(null, Fake { throw SecurityException("permission unavailable") })) {
            val arbiter = CombinedEngagementArbiter(true) {}
            val combined = CombinedTransport(arbiter, qr, Fake {})
            val job = async { combined.connect() }
            assertTrue(arbiter.acceptNfc(select, false))
            assertNull(arbiter.state.value)
            assertTrue(arbiter.acceptNfc(NfcCommandKind.SELECT_DATA, true))
            withTimeout(1000) { job.await() }
            assertEquals(SelectedEngagement.NFC_DATA, arbiter.state.value)
            combined.close()
        }
    }

    @Test fun appOwnerReplacementsAwaitCleanup(): Unit = runBlocking {
        class Owner { var closed = false }
        val owners = PresentationOwners<Owner> { it.closed = true }
        var previous: Owner? = null
        repeat(20) {
            val next = owners.replace {
                previous?.let { assertTrue(it.closed) }
                Owner()
            }
            previous?.let { owners.clear(it) }
            assertSame(next, owners.owner())
            previous = next
        }
        val stale = checkNotNull(previous)
        val closing = CompletableDeferred<Unit>()
        val finishClose = CompletableDeferred<Unit>()
        val serialized = PresentationOwners<Owner> { closing.complete(Unit); finishClose.await(); it.closed = true }
        val old = serialized.replace { Owner() }
        val replacement = async { serialized.replace { assertTrue(old.closed); Owner() } }
        closing.await()
        assertFalse(replacement.isCompleted)
        finishClose.complete(Unit)
        val next = replacement.await()
        serialized.clear(old)
        assertSame(next, serialized.owner())
        owners.clear(stale)
        assertNull(owners.owner())
    }

    @Test fun cancellationBeforeAndAfterHandoverAndQrConnection(): Unit = runBlocking {
        for (readHs in listOf(false, true)) {
            val arbiter = CombinedEngagementArbiter(false) {}
            val gate = NfcHandoverGate()
            var created = 0
            val started = CompletableDeferred<Unit>()
            val nfcStarted = CompletableDeferred<Unit>()
            val combined = CombinedTransport(arbiter, Fake { started.complete(Unit); awaitCancellation() }, gate.transport {
                created++
                Fake { nfcStarted.complete(Unit); awaitCancellation() }
            })
            val job = launch { combined.connect() }
            started.await()
            arbiter.acceptNfc(select, false)
            if (readHs) {
                assertTrue(arbiter.select(true))
                gate.complete()
                withTimeout(1000) { nfcStarted.await() }
                assertEquals(1, created)
            }
            job.cancelAndJoin()
            combined.close()
            val beforeLateRead = created
            gate.complete()
            assertEquals(beforeLateRead, created)
            if (!readHs) assertEquals(0, created)
            assertFalse(arbiter.acceptNfc(select, true))
        }
        val arbiter = CombinedEngagementArbiter(false) {}
        val qr = Fake {}
        val combined = CombinedTransport(arbiter, qr, Fake { error("unselected NFC connected") })
        combined.connect()
        combined.close()
        assertTrue(qr.closed)
        assertFalse(arbiter.select(false))
        assertFalse(arbiter.acceptNfc(select, true))
    }
}
