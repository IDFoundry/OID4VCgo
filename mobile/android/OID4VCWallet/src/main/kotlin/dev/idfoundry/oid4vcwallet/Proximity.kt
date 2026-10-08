package dev.idfoundry.oid4vcwallet

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonObject
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import java.util.UUID
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import dev.idfoundry.oid4vcwallet.gomobile.mobile.ProximityPresentation as MobileProximityPresentation
import dev.idfoundry.oid4vcwallet.gomobile.mobile.ProximityReader as MobileProximityReader
import dev.idfoundry.oid4vcwallet.gomobile.mobile.ProximityReaderSession as MobileProximityReaderSession

/**
 * How long an in-person session waits (ISO/IEC 18013-5 recommends at
 * least 30 seconds from engagement to the request, §8.2.3, and 300
 * seconds of inactivity before ending a session, §9.1.1.4).
 */
public data class ProximityTimeouts(
    /** For the other device to connect, after the QR code is shown or scanned. */
    val connect: Duration = 60.seconds,
    /** For the reader's request, once connected. */
    val request: Duration = 30.seconds,
    /** For the holder to decide, or the holder's answer to arrive. */
    val idle: Duration = 300.seconds,
)

/** An in-person session failed over Bluetooth, rather than in the protocol ([WalletException]). */
public class ProximityException internal constructor(
    public val reason: Reason,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    public enum class Reason {
        /** Bluetooth is off, or the device can't do BLE advertising or scanning. */
        BluetoothUnavailable,

        /** The app lacks a permission [ProximityPermissions] lists. */
        PermissionMissing,

        /** A [ProximityTimeouts] timeout passed. */
        TimedOut,

        /** The connection was lost, or the other device broke the transport's rules. */
        ConnectionLost,
    }

    override val message: String get() = super.message ?: ""

    /** A sentence fit to show the holder. */
    public val description: String
        get() = when (reason) {
            Reason.BluetoothUnavailable -> "Turn on Bluetooth and try again."
            Reason.PermissionMissing -> "Allow the app to find and connect to nearby devices."
            Reason.TimedOut -> "The other device didn't respond in time."
            Reason.ConnectionLost -> "The connection to the other device was lost."
        }
}

/** The runtime permissions an in-person session needs, for the app to request. */
public object ProximityPermissions {
    /** The holder's, in the default modes (both): [holder] of every [ProximityBLEMode]. */
    public val holder: List<String>
        get() = holder(ProximityBLEMode.entries.toSet())

    /**
     * The holder's in [modes]: advertising and accepting a connection in
     * peripheral server mode, scanning and connecting in central client
     * mode.
     */
    public fun holder(modes: Set<ProximityBLEMode>): List<String> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            buildList {
                if (ProximityBLEMode.CENTRAL_CLIENT in modes) add(Manifest.permission.BLUETOOTH_SCAN)
                add(Manifest.permission.BLUETOOTH_CONNECT)
                if (ProximityBLEMode.PERIPHERAL_SERVER in modes) add(Manifest.permission.BLUETOOTH_ADVERTISE)
            }
        } else if (ProximityBLEMode.CENTRAL_CLIENT in modes) {
            // Android 11 delivers BLE scan results only with location.
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        } else {
            emptyList()
        }

    /** The reader's: scanning and connecting, and advertising for a holder in central client mode. */
    public val reader: List<String>
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            listOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_ADVERTISE)
        } else {
            // Android 11 delivers BLE scan results only with location.
            listOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    /** Those of [permissions] the app hasn't been granted. */
    public fun missing(context: Context, permissions: List<String>): List<String> =
        permissions.filter { context.checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }

    internal fun require(context: Context, permissions: List<String>) {
        val missing = missing(context, permissions)
        if (missing.isNotEmpty()) {
            throw ProximityException(ProximityException.Reason.PermissionMissing, "missing ${missing.joinToString()}")
        }
    }
}

/**
 * The BLE roles a holder offers in its QR code (ISO/IEC 18013-5
 * §8.3.3.1.1); the reader picks one, central client mode when offered
 * both.
 */
public enum class ProximityBLEMode(internal val rawValue: String) {
    /** The holder advertises and is the GATT server; the reader connects. */
    PERIPHERAL_SERVER("peripheral_server"),

    /** The reader advertises and is the GATT server; the holder scans and connects. */
    CENTRAL_CLIENT("central_client"),
}

/** Who sent a request, as the holder sees it. */
public data class ProximityReaderIdentity(
    public val status: Status,
    /**
     * The reader certificate's subject common name: its verified name only
     * when [status] is [Status.Trusted]; "" when the request wasn't signed.
     */
    public val name: String,
    /** The certificate chain the request carried, leaf first. */
    public val chain: List<X509Certificate>,
    /** Why [status] isn't [Status.Trusted], for logs. */
    public val error: String?,
) {
    public enum class Status {
        /** Signed by a certificate that chains to [WalletConfiguration.mdocReaderRoots]. */
        Trusted,

        /** Signed, by a certificate that doesn't chain to them: its name is unproven. */
        Untrusted,

        /** Not signed: anyone who scanned the QR code could have asked. */
        Unauthenticated,

        /** A signature that doesn't verify for this session: possibly replayed. */
        Invalid,
    }
}

/**
 * The holder's side of an ISO/IEC 18013-5 in-person presentation over
 * BLE: show [qrCode], and the reader that scans it connects, or
 * advertises for the holder to connect, in one of the
 * [ProximityBLEMode]s the session offers. Follow [state]: on [State.RequestReceived],
 * ask the holder, then [respond] or [decline]. [cancel] ends it at any
 * point. One request per session.
 */
public class ProximityPresentation internal constructor(
    private val handle: MobileProximityPresentation,
    transportFor: (HolderEngagement) -> ProximityTransport,
    private val timeouts: ProximityTimeouts,
) {
    public sealed interface State {
        /** Showing the QR code, advertising or scanning, waiting for a reader. */
        public data object WaitingForReader : State

        /** A reader connected; its request is on its way. */
        public data object Connected : State

        /** The reader's request, for the holder's consent. */
        public data class RequestReceived(val request: Request) : State

        /** Answering: the holder key is signing, or the response is being sent. */
        public data object Responding : State

        /** The response was sent. [linkable]: the copy presented had been seen by another Verifier. */
        public data class Presented(val linkable: Boolean) : State

        /** The holder declined: nothing was disclosed. */
        public data object Declined : State

        /** The reader ended the session first. */
        public data object ReaderEnded : State

        /** [cancel] was called, or the app is gone. */
        public data object Cancelled : State

        /** The session failed: [error] is a [ProximityException] or [WalletException]. */
        public data class Failed(val error: Exception) : State

        /** Whether the session is over. */
        public val isFinal: Boolean
            get() = this is Presented || this is Declined || this is ReaderEnded || this is Cancelled || this is Failed
    }

    /** The reader's request. */
    public data class Request(
        val reader: ProximityReaderIdentity,
        /** The requested documents, in the request's order, each with the held mdocs of its doctype. */
        val documents: List<MdocPresentation.Document>,
    )

    private val engagement: EngagementJSON = decode(handle.engagement())

    /** The QR code to show: "mdoc:" and the device engagement. */
    public val qrCode: String = engagement.qrCode

    private val _state = MutableStateFlow<State>(State.WaitingForReader)
    public val state: StateFlow<State> = _state.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transport = transportFor(engagement.toHolderEngagement())

    init {
        scope.launch { run() }
    }

    private suspend fun run() {
        try {
            within(timeouts.connect, "no reader connected") { transport.connect() }
            advance(State.WaitingForReader, State.Connected)
            val first = within(timeouts.request, "the reader sent no request") { transport.receive() }
            if (handleMessage(first).event != "request") return
            val request = decode<RequestJSON>(handle.request()).toRequest()
            if (!advance(State.Connected, State.RequestReceived(request))) return
            // The holder decides; meanwhile the reader can only end the
            // session. Responding can take a while (a biometric prompt):
            // the idle timeout runs only while the request waits.
            while (!_state.value.isFinal) {
                val next = withTimeoutOrNull(timeouts.idle) { transport.receive() }
                if (next != null) {
                    handleMessage(next)
                } else if (_state.value is State.RequestReceived) {
                    sendTermination()
                    finish(State.Failed(ProximityException(ProximityException.Reason.TimedOut, "the holder didn't decide in time")))
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProximityTransportException) {
            if (_state.value is State.Responding) return // respond reports it
            finish(if (e.peerEnded) State.ReaderEnded else State.Failed(transportFailure(e)))
        } catch (e: ProximityException) {
            sendTermination()
            finish(State.Failed(e))
        } catch (e: WalletException) {
            finish(State.Failed(e))
        } catch (e: Exception) {
            finish(State.Failed(WalletException(WalletException.Code.internal, null, e.toString())))
        }
    }

    /** Hands [message] to Go, sends its reply, and ends the session on an "ended" event. */
    private suspend fun handleMessage(message: ByteArray): EventJSON {
        val event = decode<EventJSON>(OID4VC.cancellable { op -> handle.handleMessage(op, message) })
        event.send?.let { transport.send(it) }
        if (event.event == "ended") {
            finish(
                when (event.reason) {
                    "reader_ended" -> State.ReaderEnded
                    else -> State.Failed(WalletException.from(Exception(event.error ?: "[protocol] the session failed")))
                },
            )
        }
        return event
    }

    /**
     * Presents the held mdoc [credentialID] for document number
     * [document], disclosing exactly [elements], each one it requested,
     * and sends the response, which ends the session. The holder key
     * signs now, so a key store requiring the holder prompts. It returns
     * whether the copy presented had been seen by another Verifier. On a
     * [WalletException] nothing was sent and the request stands: try
     * again, or [decline].
     */
    public suspend fun respond(document: Int, credentialID: String, elements: List<MdocPresentation.Element>): Boolean {
        val request = _state.value as? State.RequestReceived
            ?: throw WalletException(WalletException.Code.wrongStep, null, "no request to answer")
        if (!_state.compareAndSet(request, State.Responding)) throw WalletException(WalletException.Code.wrongStep, null, "no request to answer")
        val pairs = json.encodeToString(ListSerializer(ListSerializer(String.serializer())), elements.map { listOf(it.namespace, it.identifier) })
        val answer = try {
            decode<RespondedJSON>(OID4VC.cancellable { op -> handle.respond(op, document.toLong(), credentialID, pairs) })
        } catch (e: WalletException) {
            _state.compareAndSet(State.Responding, request)
            throw e
        }
        try {
            transport.send(answer.send)
        } catch (e: ProximityTransportException) {
            val error = transportFailure(e)
            finish(State.Failed(error))
            throw error
        }
        finish(State.Presented(answer.linkable), letReaderEnd = true)
        return answer.linkable
    }

    /** Declines the request, or ends the session before one: the reader is told, and nothing is disclosed. */
    public suspend fun decline() {
        if (_state.value.isFinal || _state.value is State.Responding) return
        ending = State.Declined
        sendTermination()
        finish(State.Declined)
    }

    /** Ends the session now, from any state. */
    public fun cancel() {
        if (_state.value.isFinal) return
        ending = State.Cancelled
        scope.launch {
            withTimeoutOrNull(TERMINATION_TIMEOUT) { sendTermination() }
            finish(State.Cancelled)
        }
    }

    /** Sends status 20, if a reader is connected. */
    private suspend fun sendTermination() {
        val message = decode<SendJSON>(handle.terminate()).send
        if (_state.value !is State.WaitingForReader) runCatching { transport.send(message) }
    }

    private fun advance(from: State, to: State): Boolean = _state.compareAndSet(from, to)

    /**
     * How the holder chose to end the session, once they did: the reader
     * disconnecting on the termination sent then doesn't end it as
     * anything else.
     */
    @Volatile
    private var ending: State? = null

    /**
     * Moves to [final] unless the session is over already, then closes
     * the transport: at once, or with [letReaderEnd] after the reader
     * disconnects or a few seconds pass, so the last message reaches it.
     */
    private fun finish(final: State, letReaderEnd: Boolean = false) {
        if (ending.let { it != null && it != final }) return
        while (true) {
            val current = _state.value
            if (current.isFinal) return
            if (_state.compareAndSet(current, final)) break
        }
        scope.launch {
            if (letReaderEnd) {
                // Until the reader disconnects or ends: receive throws then.
                withTimeoutOrNull(LINGER) { runCatching { while (true) transport.receive() } }
            }
            transport.close()
            scope.cancel()
        }
    }

    private suspend fun <T> within(timeout: Duration, what: String, body: suspend () -> T): T =
        try {
            withTimeout(timeout) { body() }
        } catch (e: TimeoutCancellationException) {
            throw ProximityException(ProximityException.Reason.TimedOut, what, e)
        }

    @Serializable
    private data class EngagementJSON(
        @SerialName("qr_code") val qrCode: String,
        @SerialName("ble_modes") val bleModes: List<BLEModeJSON>,
        val ident: String = "",
    ) {
        fun toHolderEngagement(): HolderEngagement = HolderEngagement(
            bleModes.map { m ->
                (ProximityBLEMode.entries.firstOrNull { it.rawValue == m.mode } ?: throw WalletException(WalletException.Code.internal, null, "unknown BLE mode ${m.mode}")) to
                    UUID.fromString(m.serviceUUID)
            },
            if (ident.isEmpty()) null else Base64.getDecoder().decode(ident),
        )
    }

    @Serializable
    private data class BLEModeJSON(val mode: String, @SerialName("service_uuid") val serviceUUID: String)

    @Serializable
    private data class RequestJSON(val reader: ReaderJSON, val documents: List<MdocPresentation.Document> = emptyList()) {
        fun toRequest(): Request = Request(reader.toIdentity(), documents)
    }

    @Serializable
    private data class RespondedJSON(@Serializable(Base64Serializer::class) val send: ByteArray, val linkable: Boolean = false)

    private companion object {
        val LINGER = 5.seconds
        val TERMINATION_TIMEOUT = 2.seconds
    }
}

/** The modes a holder's session offers, each with its service UUID, and the Ident a central client checks. */
internal class HolderEngagement(val modes: List<Pair<ProximityBLEMode, UUID>>, val ident: ByteArray?) {
    /** The BLE transports for these modes: one, or [EitherTransport] over both. */
    fun transport(context: Context): ProximityTransport {
        val transports = modes.map { (mode, uuid) ->
            when (mode) {
                ProximityBLEMode.PERIPHERAL_SERVER -> GattServerTransport(context, uuid, GattCharacteristics.peripheralServer)
                ProximityBLEMode.CENTRAL_CLIENT -> GattClientTransport(context, uuid, GattCharacteristics.centralClient, ident)
            }
        }
        return transports.singleOrNull() ?: EitherTransport(transports)
    }
}

/** A transport failure as the app sees it. */
internal fun transportFailure(e: ProximityTransportException): ProximityException {
    val reason = when (e.message) {
        "Bluetooth is off", "this device has no Bluetooth", "this device can't advertise over BLE" -> ProximityException.Reason.BluetoothUnavailable
        else -> ProximityException.Reason.ConnectionLost
    }
    return ProximityException(reason, e.message ?: "", e)
}

@Serializable
internal data class ReaderJSON(
    val status: String,
    val name: String = "",
    val chain: List<String> = emptyList(),
    val error: String? = null,
) {
    fun toIdentity(): ProximityReaderIdentity {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = chain.mapNotNull { der ->
            runCatching { factory.generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(der))) as X509Certificate }.getOrNull()
        }
        val identityStatus = when (status) {
            "trusted" -> ProximityReaderIdentity.Status.Trusted
            "untrusted" -> ProximityReaderIdentity.Status.Untrusted
            "invalid" -> ProximityReaderIdentity.Status.Invalid
            else -> ProximityReaderIdentity.Status.Unauthenticated
        }
        return ProximityReaderIdentity(identityStatus, name, certs, error)
    }
}

@Serializable
internal data class EventJSON(
    val event: String,
    @Serializable(Base64Serializer::class) val send: ByteArray? = null,
    val reason: String? = null,
    val error: String? = null,
)

@Serializable
internal data class SendJSON(@Serializable(Base64Serializer::class) val send: ByteArray)

/** A [ProximityReader]'s configuration. */
@Serializable
public data class ProximityReaderConfiguration(
    /** PEM certificates: the IACAs whose mdocs the reader accepts. */
    @SerialName("issuer_roots") val issuerRoots: String,
    /**
     * The reader's key in the [KeyStore] and its PEM certificate chain,
     * leaf first: with both, requests are signed (reader authentication),
     * so holders see who is asking. The leaf should carry the mdoc reader
     * authentication extended key usage (1.0.18013.5.1.6).
     */
    @SerialName("reader_key_id") val readerKeyID: String? = null,
    @SerialName("reader_chain") val readerChain: String? = null,
    /** Tolerates an issuer's clock this far off the reader's, at most an hour. */
    @SerialName("max_clock_skew_seconds") val maxClockSkewSeconds: Long? = null,
    /** Accepts only document signers with the mDL document signer extended key usage. */
    @SerialName("require_mdl_signer_eku") val requireMDLSignerEKU: Boolean = false,
)

/**
 * An ISO/IEC 18013-5 mdoc reader: a verifier asking for an mdoc in
 * person over BLE. It needs no [Wallet]. [keyStore] holds the reader's
 * key, [ProximityReaderConfiguration.readerKeyID]; null for a reader
 * that doesn't sign.
 */
public class ProximityReader(configuration: ProximityReaderConfiguration, keyStore: KeyStore? = null) {
    private val adapter = keyStore?.let(::KeyStoreAdapter)
    private val handle: MobileProximityReader = OID4VC.wrap {
        Mobile.newProximityReader(json.encodeToString(ProximityReaderConfiguration.serializer(), configuration), adapter)
    }

    /**
     * Reads the holder's [qrCode] and starts a session asking for
     * [docType]'s [elements] (namespace → identifiers): it scans for the
     * holder, or advertises for it, as the holder's QR code offers. It
     * throws [ProximityException] for a missing permission, and
     * [WalletException] (`invalidInput`) for a QR code it can't use.
     */
    public fun start(
        context: Context,
        qrCode: String,
        docType: String,
        elements: Map<String, List<String>>,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
    ): ProximityReaderSession {
        ProximityPermissions.require(context, ProximityPermissions.reader)
        val session = OID4VC.wrap { handle.start(qrCode) }
        return ProximityReaderSession(session, docType, elements, timeouts) { e ->
            val uuid = UUID.fromString(e.serviceUUID)
            if (e.bleMode == "central_client") {
                GattServerTransport(context.applicationContext, uuid, GattCharacteristics.centralClient, Base64.getDecoder().decode(e.ident))
            } else {
                GattClientTransport(context.applicationContext, uuid, GattCharacteristics.peripheralServer)
            }
        }
    }

    internal fun startWith(qrCode: String, docType: String, elements: Map<String, List<String>>, timeouts: ProximityTimeouts, transport: ProximityTransport): ProximityReaderSession =
        ProximityReaderSession(OID4VC.wrap { handle.start(qrCode) }, docType, elements, timeouts) { transport }
}

/** One reader session: follow [state] to [State.Verified] or another final state. */
public class ProximityReaderSession internal constructor(
    private val handle: MobileProximityReaderSession,
    private val docType: String,
    private val elements: Map<String, List<String>>,
    private val timeouts: ProximityTimeouts,
    transportFor: (ReaderEngagementJSON) -> ProximityTransport,
) {
    public sealed interface State {
        /** Looking for the holder's device, or waiting for it to connect. */
        public data object Connecting : State

        /** Connected: the request is sent, and the holder is deciding. */
        public data object WaitingForResponse : State

        /** The mdoc verified. */
        public data class Verified(val result: VerifiedMdoc) : State

        /** The holder declined (not authenticated: anyone nearby could send that). */
        public data object Declined : State

        /** [cancel] was called. */
        public data object Cancelled : State

        /** The session failed: [error] is a [ProximityException] or [WalletException]. */
        public data class Failed(val error: Exception) : State

        public val isFinal: Boolean get() = this is Verified || this is Declined || this is Cancelled || this is Failed
    }

    private val engagement: ReaderEngagementJSON = decode(handle.engagement())

    /** Whether requests carry reader authentication. */
    public val signed: Boolean = engagement.signed

    /** The BLE mode this session uses, of those the holder offered: central client mode when it offered both. */
    public val mode: ProximityBLEMode = ProximityBLEMode.entries.first { it.rawValue == engagement.bleMode }

    private val _state = MutableStateFlow<State>(State.Connecting)
    public val state: StateFlow<State> = _state.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transport = transportFor(engagement)

    init {
        scope.launch { run() }
    }

    private suspend fun run() {
        try {
            try {
                withTimeout(timeouts.connect) { transport.connect() }
            } catch (e: TimeoutCancellationException) {
                throw ProximityException(ProximityException.Reason.TimedOut, "the holder's device wasn't found", e)
            }
            val elementsJSON = json.encodeToString(MapSerializer(String.serializer(), ListSerializer(String.serializer())), elements)
            val request = decode<SendJSON>(OID4VC.offMain { handle.request(docType, elementsJSON) })
            transport.send(request.send)
            _state.compareAndSet(State.Connecting, State.WaitingForResponse)
            val answer = try {
                withTimeout(timeouts.idle) { transport.receive() }
            } catch (e: TimeoutCancellationException) {
                throw ProximityException(ProximityException.Reason.TimedOut, "the holder didn't respond in time", e)
            }
            val event = decode<ReaderEventJSON>(handle.handleMessage(answer))
            event.send?.let { runCatching { transport.send(it) } }
            finish(
                when {
                    event.event == "verified" && event.verified != null -> State.Verified(event.verified.toVerified())
                    event.reason == "declined" -> State.Declined
                    else -> State.Failed(WalletException.from(Exception(event.error ?: "[protocol] the session failed")))
                },
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: ProximityTransportException) {
            finish(State.Failed(transportFailure(e)))
        } catch (e: ProximityException) {
            terminate()
            finish(State.Failed(e))
        } catch (e: WalletException) {
            terminate()
            finish(State.Failed(e))
        } catch (e: Exception) {
            finish(State.Failed(WalletException(WalletException.Code.internal, null, e.toString())))
        }
    }

    /** Ends the session now, from any state. */
    public fun cancel() {
        if (_state.value.isFinal) return
        cancelling = true
        scope.launch {
            withTimeoutOrNull(2.seconds) { terminate() }
            finish(State.Cancelled)
        }
    }

    /** Set by cancel: the holder disconnecting on its termination doesn't end the session as a failure. */
    @Volatile
    private var cancelling = false

    private suspend fun terminate() {
        val message = decode<SendJSON>(handle.terminate()).send
        if (_state.value is State.WaitingForResponse) runCatching { transport.send(message) }
    }

    private fun finish(final: State) {
        if (cancelling && final != State.Cancelled) return
        while (true) {
            val current = _state.value
            if (current.isFinal) return
            if (_state.compareAndSet(current, final)) break
        }
        transport.close()
        scope.cancel()
    }
}

/** A verified mdoc, as a [ProximityReaderSession] received it. */
public data class VerifiedMdoc(
    val doctype: String,
    /** The disclosed elements: namespace → identifier → value, byte strings as base64 and dates as their text. */
    val claims: JsonObject,
    /** Any device-signed elements. */
    val deviceSignedClaims: JsonObject?,
    /** The document signer certificate's subject common name. */
    val issuer: String,
    /** The common name of the IACA it chains to. */
    val trustAnchor: String,
    val validFrom: Instant,
    val validUntil: Instant,
    /** "signature" or "mac". */
    val deviceAuth: String,
    /**
     * The MSO's status list reference, unchecked: check it before relying
     * on the document.
     */
    val statusList: StatusListReference?,
) {
    public data class StatusListReference(val uri: String, val index: Long)
}

@Serializable
internal data class ReaderEngagementJSON(
    @SerialName("service_uuid") val serviceUUID: String,
    @SerialName("ble_mode") val bleMode: String,
    val ident: String = "",
    val signed: Boolean = false,
)

@Serializable
internal data class ReaderEventJSON(
    val event: String,
    val verified: VerifiedJSON? = null,
    @Serializable(Base64Serializer::class) val send: ByteArray? = null,
    val reason: String? = null,
    val error: String? = null,
)

@Serializable
internal data class VerifiedJSON(
    val doctype: String,
    val claims: JsonObject,
    @SerialName("device_signed_claims") val deviceSignedClaims: JsonObject? = null,
    val issuer: String = "",
    @SerialName("trust_anchor") val trustAnchor: String = "",
    @SerialName("valid_from") @Serializable(InstantSerializer::class) val validFrom: Instant,
    @SerialName("valid_until") @Serializable(InstantSerializer::class) val validUntil: Instant,
    @SerialName("device_auth") val deviceAuth: String,
    val status: StatusJSON? = null,
) {
    @Serializable
    data class StatusJSON(val uri: String, val idx: Long)

    fun toVerified(): VerifiedMdoc = VerifiedMdoc(
        doctype, claims, deviceSignedClaims, issuer, trustAnchor, validFrom, validUntil, deviceAuth,
        status?.let { VerifiedMdoc.StatusListReference(it.uri, it.idx) },
    )
}
