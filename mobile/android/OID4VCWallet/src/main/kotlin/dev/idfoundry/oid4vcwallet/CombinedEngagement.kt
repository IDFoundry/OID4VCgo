package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** NFC handover and retrieval offered alongside a QR engagement. */
public data class NfcEngagementOptions(
    /** Use TNEP negotiated handover instead of static handover. */
    val negotiated: Boolean = false,
    /** Transfer session messages over NFC instead of BLE after handover. */
    val nfcData: Boolean = false,
)

/** The engagement and data transport selected by the first reader. */
public enum class SelectedEngagement {
    /** QR engagement with BLE retrieval. */
    QR,
    /** NFC engagement with BLE retrieval. */
    NFC_BLE,
    /** NFC engagement with classic NFC retrieval. */
    NFC_DATA,
}

/** Serializes QR connection, completed NFC handover/data selection, and cancellation. */
internal class CombinedEngagementArbiter(
    val nfcData: Boolean,
    private val claim: (Boolean) -> Unit,
) {
    private val selected = MutableStateFlow<SelectedEngagement?>(null)
    val state: StateFlow<SelectedEngagement?> = selected.asStateFlow()
    private val ready = CompletableDeferred<SelectedEngagement>()
    private var closed = false

    @Synchronized fun select(nfc: Boolean): Boolean {
        val path = if (!nfc) SelectedEngagement.QR else if (nfcData) SelectedEngagement.NFC_DATA else SelectedEngagement.NFC_BLE
        if (closed) return false
        selected.value?.let { return it == path }
        claim(nfc)
        selected.value = path
        ready.complete(path)
        ProximityDiagnostics.event("Engagement committed: $path")
        return true
    }

    suspend fun await(): SelectedEngagement = ready.await()
    @Synchronized fun close() { closed = true; ready.cancel() }

    /** Whether NFC may answer a command of [kind] (an [NfcCommandKind]); selecting NFC data commits NFC. */
    @Synchronized fun acceptNfc(kind: Int, dataReady: Boolean): Boolean {
        if (closed || selected.value == SelectedEngagement.QR) return false
        return when (kind) {
            NfcCommandKind.SELECT_DATA -> nfcData && dataReady && select(true)
            else -> true // Type 4 discovery does not commit a handover.
        }
    }
}

/** QR advertises immediately; NFC creates its transport only after QR cleanup. */
internal class CombinedTransport(
    private val arbiter: CombinedEngagementArbiter,
    private val qr: ProximityTransport?,
    private val nfc: ProximityTransport,
) : ProximityTransport {
    @Volatile private var chosen: ProximityTransport? = null

    override suspend fun connect(): Unit = coroutineScope {
        val qrJob = qr?.let { transport -> launch {
            try {
                ProximityDiagnostics.event("QR offer starting")
                transport.connect()
                if (!arbiter.select(false)) transport.close()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                transport.close()
                // Bluetooth off: the QR code shown is dead, and an NFC
                // handover to BLE can't work either. Only NFC data
                // retrieval goes on without it.
                if (e is ProximityTransportException && e.bluetoothUnavailable && !arbiter.nfcData) {
                    ProximityDiagnostics.event("QR offer failed: Bluetooth is off; ending the session")
                    throw e
                }
                // A failed QR offer must not break NFC-only retrieval.
                ProximityDiagnostics.event("QR offer failed; NFC remains available")
            }
        } }
        try {
            if (arbiter.await() == SelectedEngagement.QR) {
                qrJob?.join()
                chosen = checkNotNull(qr)
            } else {
                ProximityDiagnostics.event("Withdrawing QR offer after NFC commitment")
                qrJob?.cancelAndJoin()
                qr?.close()
                ProximityDiagnostics.event("QR resources closed; NFC transport may start")
                chosen = nfc
                nfc.connect()
            }
        } finally {
            qrJob?.cancelAndJoin()
        }
    }

    override suspend fun send(message: ByteArray): Unit = connected().send(message)
    override suspend fun receive(): ByteArray = connected().receive()
    private fun connected(): ProximityTransport = chosen ?: throw ProximityTransportException("engagement not connected")
    override fun close() { arbiter.close(); qr?.close(); nfc.close() }
}
