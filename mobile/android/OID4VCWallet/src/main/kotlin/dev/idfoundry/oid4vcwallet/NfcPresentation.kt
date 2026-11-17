package dev.idfoundry.oid4vcwallet

import android.app.Activity
import android.content.ComponentName
import android.nfc.NfcAdapter
import android.nfc.cardemulation.CardEmulation
import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import dev.idfoundry.oid4vcwallet.gomobile.mobile.ProximityPresentation as MobileProximityPresentation

/**
 * One armed static NFC engagement and its subsequent BLE presentation.
 * The application retains this object across HCE service recreation. Repeated
 * reads reuse its key, service UUID and handover bytes. Consent and results
 * are exposed through [presentation].
 */
public class NfcPresentation internal constructor(
    handle: MobileProximityPresentation,
    timeouts: ProximityTimeouts,
    negotiated: Boolean = false,
    private val dataTransport: NfcDataHolderTransport? = null,
    transportFor: (HolderEngagement) -> ProximityTransport,
) {
    internal val combined: CombinedEngagementArbiter? = if (handle.isCombined())
        CombinedEngagementArbiter(dataTransport != null) { handle.selectEngagement(it) } else null
    private val engagement = NfcEngagement(
        GoNfcHolder(OID4VC.wrap { handle.nfcHolder(negotiated, dataTransport != null) }),
        dataTransport, combined,
    ) { cancelCombined() }

    /** The consent flow and final result of this presentation. */
    public val presentation: ProximityPresentation = ProximityPresentation(handle, { initial ->
        val nfc = engagement.gate.transport {
            dataTransport ?: currentEngagement().let { offer ->
                ProximityDiagnostics.event("NFC BLE transport starting: ${offer.modes.map { it.first }}")
                transportFor(offer)
            }
        }
        combined?.let { arbiter ->
            val qr = if (initial.modes.isEmpty()) null else NfcHandoverGate().apply { complete() }.transport { transportFor(initial) }
            CombinedTransport(arbiter, qr, nfc)
        } ?: nfc
    }, timeouts)

    private fun currentEngagement(): HolderEngagement = presentation.currentHolderEngagement()

    @Synchronized internal fun process(command: ByteArray, respond: (ByteArray) -> Unit = {}): ByteArray? {
        if (presentation.state.value.isFinal) return nfcResponse(0x6985)
        return engagement.process(command, respond)
    }

    @Synchronized internal fun deactivate() {
        engagement.deactivate()
    }

    /**
     * Makes the app's declared [service] preferred while [activity] is resumed.
     * Call on every resume while armed, and [releaseForeground] on pause.
     */
    public fun preferForeground(activity: Activity, service: Class<out NfcEngagementService>): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return false
        return CardEmulation.getInstance(adapter).setPreferredService(activity, ComponentName(activity, service))
    }

    /** Releases foreground preference when the activity pauses or the presentation ends. */
    public fun releaseForeground(activity: Activity): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(activity) ?: return false
        return CardEmulation.getInstance(adapter).unsetPreferredService(activity)
    }

    /** Cancels and waits for radio cleanup before a replacement can be armed. */
    public suspend fun close() {
        cancelCombined()
        presentation.awaitClosed()
        NfcPresentations.clear(this)
    }

    internal fun cancelCombined() { combined?.close(); presentation.cancel() }
}

/** App-level registry; service instances never own or manufacture presentations. */
internal object NfcPresentations {
    private val owners = PresentationOwners<NfcPresentation> { it.close() }
    suspend fun replace(create: () -> NfcPresentation): NfcPresentation = owners.replace(create)
    fun clear(owner: NfcPresentation) { owners.clear(owner) }
    fun owner(): NfcPresentation? = owners.owner()
    fun deactivate() { owners.owner()?.deactivate() }
}

/** Defers native resource creation until the reader has read the complete Hs. */
internal class NfcHandoverGate {
    private val ready = CompletableDeferred<Unit>()
    val isComplete: Boolean get() = ready.isCompleted && !ready.isCancelled
    fun complete() { ready.complete(Unit) }

    fun transport(create: () -> ProximityTransport): ProximityTransport = object : ProximityTransport {
        private var delegate: ProximityTransport? = null
        private var closed = false
        override suspend fun connect() {
            ready.await()
            val transport = synchronized(this) {
                if (closed) throw ProximityTransportException("NFC presentation closed")
                (delegate ?: create().also { delegate = it })
            }
            transport.connect()
        }
        override suspend fun send(message: ByteArray) = connected().send(message)
        override suspend fun receive(): ByteArray = connected().receive()
        override fun reject() = connected().reject()
        override fun commit() = connected().commit()
        private fun connected(): ProximityTransport = synchronized(this) {
            delegate ?: throw ProximityTransportException("NFC handover incomplete")
        }
        @Synchronized override fun close() {
            if (closed) return
            closed = true
            ready.cancel()
            delegate?.close()
        }
    }
}

/**
 * Subclass and declare in the app manifest with BIND_NFC_SERVICE, the
 * HOST_APDU_SERVICE action and @xml/oid4vc_nfc_aids metadata. The service
 * starts unarmed after process restart; arm using [Wallet.startNfcPresentation].
 */
public abstract class NfcEngagementService : HostApduService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val serial = Mutex()
    private val responseLock = Any()
    private var epoch = 0L

    /** Serializes one command off the APDU callback thread and returns its response asynchronously. */
    final override fun processCommandApdu(commandApdu: ByteArray, extras: Bundle?): ByteArray? {
        val owner = NfcPresentations.owner() ?: return nfcResponse(0x6985)
        val requestEpoch = synchronized(responseLock) { epoch }
        val command = commandApdu.copyOf()
        scope.launch {
            serial.withLock {
                if (synchronized(responseLock) { epoch != requestEpoch } || NfcPresentations.owner() !== owner) return@withLock
                fun respond(response: ByteArray) {
                    synchronized(responseLock) {
                        if (epoch != requestEpoch || NfcPresentations.owner() !== owner) throw ProximityTransportException("NFC link is no longer active")
                        sendResponseApdu(response)
                    }
                }
                val response = runCatching { owner.process(command, ::respond) }.getOrElse { nfcResponse(0x6f00) }
                response?.let { runCatching { respond(it) } }
            }
        }
        return null
    }

    /** Invalidates pending RF responses and resets file selection; a completed BLE handover continues. */
    final override fun onDeactivated(reason: Int) {
        synchronized(responseLock) { epoch++ }
        val owner = NfcPresentations.owner()
        scope.launch { serial.withLock { owner?.deactivate() } }
    }

    /** Stops this service instance's worker without replacing the application-owned presentation. */
    final override fun onDestroy() {
        synchronized(responseLock) { epoch++ }
        scope.cancel()
        super.onDestroy()
    }
}
