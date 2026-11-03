package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

/**
 * A scripted holder: commands are [kind, tag], classified by their first
 * byte. Go's NFCHolder does the APDU work; these tests cover what Kotlin
 * adds around it — arbitration, the handover gate and transports.
 */
internal class ScriptedHolder : NfcHolderCore {
    var onProcess: (ByteArray) -> NfcStep = { NfcStep(nfcResponse(0x9000)) }
    var onRespond: (ByteArray) -> NfcStep = { NfcStep(nfcResponse(0x9000), delivered = true) }
    var deactivation = NfcDeactivation(cancel = false, dataClosed = false)
    val deactivations = mutableListOf<Pair<Boolean, Boolean>>()
    var refused = 0
    var closed = false
    override fun classify(command: ByteArray): Int = command[0].toInt()
    override fun process(command: ByteArray): NfcStep = onProcess(command)
    override fun respond(message: ByteArray): NfcStep = onRespond(message)
    override fun refuseMessage(): ByteArray { refused++; return nfcResponse(0x6985) }
    override fun deactivate(handoverCommitted: Boolean, qrSelected: Boolean): NfcDeactivation {
        deactivations += handoverCommitted to qrSelected
        return deactivation
    }
    override fun close() { closed = true }

    companion object {
        fun command(kind: Int = NfcCommandKind.OTHER) = byteArrayOf(kind.toByte(), 0)
        val readHs = NfcStep(nfcResponse(0x9000), handoverRead = true)
    }
}

class CombinedNfcHandoverTest {
    private class Transport(private val start: suspend () -> Unit) : ProximityTransport {
        var closed = false
        var connections = 0
        override suspend fun connect() { connections++; start() }
        override suspend fun send(message: ByteArray) {
            // Messages sent are not inspected here.
        }
        override suspend fun receive(): ByteArray = byteArrayOf(1)
        override fun close() { closed = true }
    }

    private class Offers(data: Boolean = false) {
        val holder = ScriptedHolder()
        val qrStarted = CompletableDeferred<Unit>()
        val qrConnected = CompletableDeferred<Unit>()
        var claims = 0
        var cancelled = false
        val dataTransport = if (data) NfcDataHolderTransport() else null
        val arbiter = CombinedEngagementArbiter(data) { claims++ }
        val engagement = NfcEngagement(holder, dataTransport, arbiter) { cancelled = true; arbiter.close() }
        val qr = Transport { qrStarted.complete(Unit); qrConnected.await() }
        val nfc = Transport { assertTrue("NFC started before QR cleanup", qr.closed) }
        var nativeCreated = 0
        val combined = CombinedTransport(arbiter, qr, engagement.gate.transport { nativeCreated++; nfc })

        fun exchange(command: ByteArray = ScriptedHolder.command()): ByteArray? = engagement.process(command)
        fun readHs(): ByteArray? {
            holder.onProcess = { ScriptedHolder.readHs }
            return exchange().also { holder.onProcess = { NfcStep(nfcResponse(0x9000)) } }
        }
    }

    private suspend fun withOffers(block: suspend (Offers, suspend () -> Unit) -> Unit) = coroutineScope {
        val offers = Offers()
        val connecting = async { offers.combined.connect() }
        try {
            withTimeout(5000) { offers.qrStarted.await() }
            block(offers) { withTimeout(5000) { connecting.await() } }
        } finally {
            connecting.cancelAndJoin()
            offers.combined.close()
        }
    }

    @Test fun fieldLossBeforeTheHandoverIsReadLeavesQrConnectable(): Unit = runBlocking {
        withOffers { f, connected ->
            f.exchange(ScriptedHolder.command(NfcCommandKind.SELECT_NDEF))
            f.exchange()
            assertFalse(f.engagement.gate.isComplete)
            f.engagement.deactivate()
            assertEquals(listOf(false to false), f.holder.deactivations)
            assertFalse(f.cancelled)
            assertFalse(f.qr.closed)
            f.qrConnected.complete(Unit)
            connected()
            assertEquals(SelectedEngagement.QR, f.arbiter.state.value)
            assertEquals(0, f.nativeCreated)
            assertEquals(1, f.claims)
        }
    }

    @Test fun readHandoverCommitsAndStartsNfcExactlyOnce(): Unit = runBlocking {
        withOffers { f, connected ->
            f.exchange()
            assertNull("NFC committed before Hs was read", f.arbiter.state.value)
            assertFalse(f.qr.closed)
            assertArrayEquals(nfcResponse(0x9000), f.readHs())
            connected()
            assertEquals(SelectedEngagement.NFC_BLE, f.arbiter.state.value)
            assertTrue(f.qr.closed)
            f.readHs()
            assertEquals(1, f.nativeCreated)
            assertEquals(1, f.nfc.connections)
            assertEquals(1, f.claims)
        }
    }

    @Test fun uncommittedAttemptCanBeRetried(): Unit = runBlocking {
        withOffers { f, connected ->
            f.exchange()
            f.engagement.deactivate()
            assertNull(f.arbiter.state.value)
            f.readHs()
            connected()
            assertEquals(SelectedEngagement.NFC_BLE, f.arbiter.state.value)
            assertEquals(1, f.nativeCreated)
        }
    }

    @Test fun qrWinWhileACommandIsProcessedRefusesNfcAndSurvivesFieldLoss(): Unit = runBlocking {
        withOffers { f, connected ->
            f.holder.onProcess = {
                assertTrue(f.arbiter.select(false))
                f.qrConnected.complete(Unit)
                ScriptedHolder.readHs
            }
            assertArrayEquals(nfcResponse(0x6985), f.exchange())
            connected()
            assertArrayEquals(nfcResponse(0x6985), f.exchange())
            f.engagement.deactivate()
            assertEquals(true, f.holder.deactivations.single().second)
            assertFalse("losing NFC field loss cancelled QR", f.cancelled)
            assertFalse(f.qr.closed)
            assertEquals(SelectedEngagement.QR, f.arbiter.state.value)
            assertEquals(1, f.claims)
            assertEquals(0, f.nativeCreated)
        }
    }

    @Test fun frozenNegotiatedHandoverIsCancelled(): Unit = runBlocking {
        withOffers { f, _ ->
            f.exchange()
            f.holder.deactivation = NfcDeactivation(cancel = true, dataClosed = false)
            f.engagement.deactivate()
            assertTrue(f.cancelled)
            assertFalse(f.arbiter.select(false))
        }
    }

    @Test fun nfcDataCommitsOnDataSelectAfterHsNotOnHsRead(): Unit = runBlocking {
        val f = Offers(data = true)
        f.readHs()
        assertTrue(f.engagement.gate.isComplete)
        assertNull(f.arbiter.state.value)
        f.holder.onProcess = { NfcStep(nfcResponse(0x9000), dataSelected = true) }
        assertArrayEquals(nfcResponse(0x9000), f.exchange(ScriptedHolder.command(NfcCommandKind.SELECT_DATA)))
        assertEquals(SelectedEngagement.NFC_DATA, f.arbiter.state.value)
        assertFalse(f.arbiter.select(false))
        withTimeout(1000) { checkNotNull(f.dataTransport).connect() }
        f.combined.close()
    }

    @Test fun dataSelectBeforeHsIsReadIsRefused() {
        val f = Offers(data = true)
        assertArrayEquals(nfcResponse(0x6985), f.exchange(ScriptedHolder.command(NfcCommandKind.SELECT_DATA)))
        assertNull(f.arbiter.state.value)
        f.combined.close()
    }
}
