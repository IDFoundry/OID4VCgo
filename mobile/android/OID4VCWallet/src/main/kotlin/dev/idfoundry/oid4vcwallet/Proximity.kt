package dev.idfoundry.oid4vcwallet

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
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
    /** Why the session failed. */
    public val reason: Reason,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    /** Why a session failed. */
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

    /** Detail for logs. */
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
    /** Whether the request was signed, and by a reader the wallet recognizes. */
    public val status: Status,
    /**
     * The reader's name, from a certificate that chains to
     * [WalletConfiguration.mdocReaderRoots]: set only when [status] is
     * [Status.Trusted].
     */
    public val name: String,
    /** The certificate chain the request carried, leaf first. */
    public val chain: List<X509Certificate>,
    /** Why [status] isn't [Status.Trusted], for logs. */
    public val error: String?,
    /**
     * The name an untrusted or invalid request's certificate gives itself:
     * anyone can claim any name, so never show it as the reader's. "" when
     * the reader is trusted or didn't sign.
     */
    public val claimedName: String = "",
    /**
     * `certificate_revoked` or `no_current_crl` (`Mobile.DetailCertificateRevoked`,
     * `Mobile.DetailNoCurrentCRL`) when [error] is the reader certificate's revocation check,
     * null otherwise. From OID4VCWallet 0.27.0.
     */
    public val errorDetail: String? = null,
) {
    /** How far a request's reader authentication goes. */
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
    /** Where the session is: follow [state]. */
    public sealed interface State {
        /** Showing the QR code, advertising or scanning, waiting for a reader. */
        public data object WaitingForReader : State

        /** A reader connected; its request is on its way. */
        public data object Connected : State

        /**
         * The reader's request, for the holder's consent.
         *
         * @property request The reader's request.
         */
        public data class RequestReceived(val request: Request) : State

        /** Answering: the holder key is signing, or the response is being sent. */
        public data object Responding : State

        /**
         * The response was sent. [linkable]: the copy presented had been seen by another Verifier.
         *
         * @property linkable Whether the copy presented had been seen by another Verifier.
         */
        public data class Presented(val linkable: Boolean) : State

        /** The holder declined: nothing was disclosed. */
        public data object Declined : State

        /** The reader ended the session first. */
        public data object ReaderEnded : State

        /**
         * [cancel] was called, the app is gone, or the caller of [respond]
         * was cancelled while the response was being sent.
         */
        public data object Cancelled : State

        /**
         * The session failed: [error] is a [ProximityException] or [WalletException].
         *
         * @property error A [ProximityException] or a [WalletException].
         */
        public data class Failed(val error: Exception) : State

        /** Whether the session is over. */
        public val isFinal: Boolean
            get() = this is Presented || this is Declined || this is ReaderEnded || this is Cancelled || this is Failed
    }

    /** The reader's request. */
    public data class Request(
        /** Who sent the request. */
        val reader: ProximityReaderIdentity,
        /** The requested documents, in the request's order, each with the held mdocs of its doctype. */
        val documents: List<MdocPresentation.Document>,
    )

    private val engagement: EngagementJSON = decode(handle.engagement())

    /** The QR code to show: "mdoc:" and the device engagement. */
    public val qrCode: String = engagement.qrCode

    private val _state = MutableStateFlow<State>(State.WaitingForReader)
    /**
     * The session's state: [State.WaitingForReader] first, until one of the final states
     * ([State.isFinal]).
     */
    public val state: StateFlow<State> = _state.asStateFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val transport = transportFor(engagement.toHolderEngagement())
    private val closed = CompletableDeferred<Unit>()
    private val runner = scope.launch(start = CoroutineStart.LAZY) { run() }

    init {
        runner.start()
    }

    /** Waits until this presentation's tasks and radio resources have closed. */
    public suspend fun awaitClosed(): Unit = closed.await()

    internal fun currentHolderEngagement(): HolderEngagement = decode<EngagementJSON>(handle.engagement()).toHolderEngagement()

    private suspend fun run() {
        try {
            within(timeouts.connect, "no reader connected") { transport.connect() }
            advance(State.WaitingForReader, State.Connected)
            val first = within(timeouts.request, "the reader sent no request") { transport.receive() }
            // An "ended" event has finished the session; any other ("none")
            // carried no request, so nothing would ever end it.
            val event = handleMessage(first).event
            if (event != "request") {
                if (event != "ended") {
                    sendTermination()
                    finish(State.Failed(WalletException.from(Exception("[protocol] the reader's first message carried no request"))))
                }
                return
            }
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
     * again, or [decline]. It is [respond] with one answer.
     */
    public suspend fun respond(document: Int, credentialID: String, elements: List<MdocPresentation.Element>): Boolean =
        respond(listOf(MdocPresentation.Answer(document, credentialID, elements))).linkable

    /**
     * What [respond] presented.
     *
     * @property linkable Whether any copy presented had been seen by another Verifier.
     * @property linkableCredentials The credentials presented with such a copy, by ID.
     */
    public data class Responded(val linkable: Boolean, val linkableCredentials: List<String>)

    /**
     * Presents several of the request's documents in one response, each
     * of [answers] as the one-document [respond] presents one, and sends
     * it, which ends the session. A document left out isn't in the
     * response: the reader may ask for more than the holder shares. No
     * document may be answered twice, nor one credential answer two.
     *
     * Each holder key signs now, in the request's order, so each key
     * store requiring the holder prompts in turn: on Android one
     * prompt per key (see [AndroidKeystoreKeyStore.Options.holderAuthenticationTimeout]).
     * On a [WalletException] — one prompt cancelled, say — nothing was
     * sent, the keys after it weren't asked, and the request stands:
     * try again, or [decline].
     *
     * It never leaves the session in [State.Responding]:
     * - Returning: the response was sent, and the state is [State.Presented].
     * - A [WalletException], or the caller's cancellation, before
     *   anything was sent: the state is [State.RequestReceived] again.
     * - A [ProximityException]: the response couldn't be delivered, and
     *   the state is [State.Failed] with it.
     * - The caller's cancellation while the response was being sent: the
     *   reader may hold part of it, so the state is [State.Cancelled].
     * - A [WalletException] with [WalletException.Code.internal] from
     *   sending: the state is [State.Failed] with it.
     *
     * After [cancel], the state is [State.Cancelled] whatever it throws.
     */
    public suspend fun respond(answers: List<MdocPresentation.Answer>): Responded {
        val request = _state.value as? State.RequestReceived
            ?: throw WalletException(WalletException.Code.wrongStep, null, "no request to answer")
        if (!_state.compareAndSet(request, State.Responding)) throw WalletException(WalletException.Code.wrongStep, null, "no request to answer")
        val answersJSON = MdocPresentation.answersJSON(answers)
        val answer = try {
            decode<RespondedJSON>(OID4VC.cancellable { op -> handle.respondDocuments(op, answersJSON) })
        } catch (e: Exception) {
            // Nothing was sent, whatever went wrong: a refusal of Go's, or
            // the caller's own cancellation. The request stands.
            _state.compareAndSet(State.Responding, request)
            throw e
        }
        // Cancelled once Go's respond had returned (cancelled before, it
        // gives nothing to send): the response stays here.
        if (ending != null) throw WalletException(WalletException.Code.cancelled, null, "the session was cancelled")
        try {
            transport.send(answer.send)
        } catch (e: ProximityTransportException) {
            val error = transportFailure(e)
            finish(State.Failed(error))
            throw error
        } catch (e: CancellationException) {
            // The caller's own cancellation, mid-send: the reader may hold
            // part of the response, so it can't be sent again.
            finish(State.Cancelled)
            throw e
        } catch (e: Exception) {
            val error = WalletException(WalletException.Code.internal, null, e.toString())
            finish(State.Failed(error))
            throw error
        }
        finish(State.Presented(answer.linkable), letReaderEnd = true)
        return Responded(answer.linkable, answer.linkableCredentials)
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
        scope.launch { shutDown(letReaderEnd) }
    }

    /** Stops the session's work and closes the transport, as [finish] describes. */
    private suspend fun shutDown(letReaderEnd: Boolean) {
        if (letReaderEnd) {
            // Until the reader disconnects or ends: receive throws then.
            withTimeoutOrNull(LINGER) { runCatching { while (true) transport.receive() } }
        }
        try {
            withTimeout(5.seconds) { runner.cancelAndJoin() }
            transport.close()
            closed.complete(Unit)
        } catch (e: Exception) {
            runCatching { transport.close() }
            closed.completeExceptionally(e)
        } finally {
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
        fun toHolderEngagement(): HolderEngagement {
            val modes = bleModes.map { m ->
                (ProximityBLEMode.entries.firstOrNull { it.rawValue == m.mode } ?: throw WalletException(WalletException.Code.internal, null, "unknown BLE mode ${m.mode}")) to
                    UUID.fromString(m.serviceUUID)
            }
            val decoded = if (ident.isEmpty()) null else runCatching { Base64.getDecoder().decode(ident) }.getOrNull()
            // Central client mode checks the reader's Ident (§8.3.3.1.1.4):
            // without one, any device advertising the service would do.
            if (modes.any { it.first == ProximityBLEMode.CENTRAL_CLIENT } && decoded?.size != 16) {
                throw WalletException(WalletException.Code.internal, null, "central client mode without the reader's Ident")
            }
            return HolderEngagement(modes, decoded)
        }
    }

    @Serializable
    private data class BLEModeJSON(val mode: String, @SerialName("service_uuid") val serviceUUID: String)

    @Serializable
    private data class RequestJSON(val reader: ReaderJSON, val documents: List<MdocPresentation.Document> = emptyList()) {
        fun toRequest(): Request = Request(reader.toIdentity(), documents)
    }

    @Serializable
    private data class RespondedJSON(
        @Serializable(Base64Serializer::class) val send: ByteArray,
        val linkable: Boolean = false,
        @SerialName("linkable_credentials") val linkableCredentials: List<String> = emptyList(),
    )

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
    val reason = if (e.bluetoothUnavailable) ProximityException.Reason.BluetoothUnavailable else ProximityException.Reason.ConnectionLost
    return ProximityException(reason, e.message ?: "", e)
}

@Serializable
internal data class ReaderJSON(
    val status: String,
    val name: String = "",
    @SerialName("claimed_name") val claimedName: String = "",
    val chain: List<String> = emptyList(),
    val error: String? = null,
    @SerialName("error_detail") val errorDetail: String? = null,
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
        return ProximityReaderIdentity(identityStatus, name, certs, error, claimedName, errorDetail)
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
    /** The reader's PEM certificate chain, leaf first, for [readerKeyID]. */
    @SerialName("reader_chain") val readerChain: String? = null,
    /** Tolerates an issuer's clock this far off the reader's, at most an hour. */
    @SerialName("max_clock_skew_seconds") val maxClockSkewSeconds: Long? = null,
    /**
     * Deprecated, and does nothing: the default check already requires
     * the mDL document signer extended key usage, refusing a document
     * signer certificate without it (or an OCSP signer's), so setting
     * this changes nothing. It still can't be set with
     * [acceptMDLSignerWithoutEKU]. Its `require_mdl_signer_eku` key is
     * still accepted within ABI 15, and goes at the next ABI version,
     * with this property.
     */
    @Deprecated("the default check already requires the mDL document signer extended key usage; setting it changes nothing")
    @SerialName("require_mdl_signer_eku") val requireMDLSignerEKU: Boolean = false,
    /**
     * Each document type's own IACAs, as PEM certificates: a document of
     * a type named here must chain to them, not to [issuerRoots], so an
     * issuer trusted for one document type can't sign another. With it,
     * [issuerRoots] may be empty, and then only the types named here are
     * accepted.
     */
    @SerialName("issuer_roots_by_doctype") val issuerRootsByDocType: Map<String, String> = emptyMap(),
    /**
     * PEM `X509 CRL` blocks: the Certificate Revocation Lists the roles in
     * [revocation] are checked against. Replace them at runtime with
     * [ProximityReader.setCRLs] as they expire.
     */
    @SerialName("crls") val crls: String = "",
    /**
     * The roles whose certificate chains must pass a CRL check against
     * [crls]. A role listed fails closed for any CA it has no current CRL
     * from, until [ProximityReader.setCRLs] supplies one.
     */
    @SerialName("revocation") val revocation: List<RevocationRole> = emptyList(),
    /**
     * PEM certificates of the CAs that issued certificates pinned in the
     * roots, for a role in [revocation], as [WalletConfiguration.crlIssuers].
     */
    @SerialName("crl_issuers") val crlIssuers: String = "",
    /** Where [ProximityReader.refreshCRLs] fetches the lists from, as [WalletConfiguration.crlDistributionPoints]. */
    @SerialName("crl_distribution_points") val crlDistributionPoints: List<CRLDistributionPoint> = emptyList(),
    /**
     * Also fetches the distribution point each self-signed IACA in
     * [issuerRoots], [issuerRootsByDocType] (with [RevocationRole.ISSUER]
     * or [RevocationRole.STATUS] in [revocation]) and [crlIssuers] names
     * for its own list.
     */
    @SerialName("crl_distribution_points_from_roots") val crlDistributionPointsFromRoots: Boolean = false,
    /** Refuses plain `http` distribution points. */
    @SerialName("crl_require_https") val crlRequireHTTPS: Boolean = false,
    /**
     * Also accepts a document signer certificate with no extended key
     * usage, which is refused by default for lacking the mDL document
     * signer's, for issuers whose document signers have none. It can't be
     * set with [requireMDLSignerEKU].
     */
    @SerialName("accept_mdl_signer_without_eku") val acceptMDLSignerWithoutEKU: Boolean = false,
    /**
     * The roles that decline checking revocation, for where something
     * else stands in for it. Outside [development], each role must be in
     * [revocation] or here; a role can't be in both.
     */
    @SerialName("no_revocation_check") val noRevocationCheck: List<RevocationRole> = emptyList(),
    /**
     * Declares that every IACA in [issuerRoots] may issue every document
     * type the reader asks for. Outside [development], [issuerRoots] needs
     * it; otherwise name each type's IACAs in [issuerRootsByDocType].
     */
    @SerialName("any_issuer_for_any_type") val anyIssuerForAnyType: Boolean = false,
    /**
     * Whether a session checks a verified document's revocation status
     * before reporting it. Outside [development], it's required: null
     * throws `invalid_input`. With [StatusCheck.CHECK], a session reports
     * [ProximityReaderSession.State.Verified] only for a document whose
     * status is valid, or that has none ([VerifiedMdoc.status]), and fails
     * with `document_not_valid` otherwise; with [StatusCheck.DECLINE],
     * nothing checks it, for a reader where something else stands in. In
     * development, null is [StatusCheck.DECLINE].
     */
    @SerialName("status") val statusCheck: StatusCheck? = null,
    /**
     * Relaxes what production requires, for a reader trying out a
     * development issuer's documents. Never ship an app with it set.
     * Without it, [ProximityReader] requires a production reader's
     * decisions, throwing `invalid_input` otherwise: each role in
     * [revocation] or [noRevocationCheck], and [anyIssuerForAnyType] with
     * [issuerRoots]. With it, a role in neither checks no revocation, and
     * any IACA in [issuerRoots] may issue any document type. Refused
     * (`invalid_input`) unless the app called [OID4VC.allowDevelopment].
     */
    @SerialName("development") val development: Boolean = false,
    /**
     * PEM certificates [ProximityReader.refreshCRLs]'s `https` fetches trust besides the
     * system's, as [WalletConfiguration.developmentRoots]: a development CA's distribution
     * points served under its own TLS certificate, which Go on Android can't otherwise be
     * given. Only with [development] (`invalid_input` otherwise). From OID4VCWallet 0.27.0.
     */
    @SerialName("development_roots") val developmentRoots: String = "",
    /** The largest status list `checkStatus` reads, in bytes; 0 means 1 MiB. */
    @SerialName("status_max_bytes") val statusMaxBytes: Int = 0,
    /** The largest identifier list `checkStatus` reads, in bytes; 0 means 4 MiB. */
    @SerialName("identifier_list_max_bytes") val identifierListMaxBytes: Int = 0,
    /** How long `checkStatus` uses a list it fetched, in seconds, as [WalletConfiguration.statusCacheMaxAgeSeconds]. */
    @SerialName("status_cache_max_age_seconds") val statusCacheMaxAgeSeconds: Long = 0,
    /** Where `checkStatus` keeps lists across launches, as [WalletConfiguration.statusCacheDir]. */
    @SerialName("status_cache_dir") val statusCacheDir: String? = null,
) {
    /** A reader's trust role whose certificates can be checked for revocation. */
    @Serializable
    public enum class RevocationRole {
        /** The document signer's certificate chain, when a document is verified. */
        @SerialName("issuer") ISSUER,

        /** A status list signer's, in `checkStatus`. */
        @SerialName("status") STATUS,
    }

    /** Whether a reader session checks a verified document's revocation status before reporting it. */
    @Serializable
    public enum class StatusCheck {
        /** Checked: a session reports [ProximityReaderSession.State.Verified] only for a document whose status is valid, or that has none. */
        @SerialName("check") CHECK,

        /** Not checked, for a reader where something else stands in. */
        @SerialName("decline") DECLINE,
    }
}

/**
 * An ISO/IEC 18013-5 mdoc reader: a verifier asking for an mdoc in
 * person over BLE. It needs no [Wallet]. [keyStore] holds the reader's
 * key, [ProximityReaderConfiguration.readerKeyID]; null for a reader
 * that doesn't sign.
 */
public class ProximityReader(configuration: ProximityReaderConfiguration, keyStore: KeyStore? = null) {
    private val adapter = keyStore?.let(::KeyStoreAdapter)
    private val handle: MobileProximityReader = OID4VC.wrap {
        OID4VC.checkDevelopment(configuration.development)
        Mobile.newProximityReader(StatusCacheKey.configuration(json.encodeToString(ProximityReaderConfiguration.serializer(), configuration), configuration.statusCacheDir), adapter)
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
    ): ProximityReaderSession = start(context, qrCode, listOf(DocumentRequest(docType, elements)), timeouts)

    /**
     * One document a reader asks for.
     *
     * @property docType The requested document type.
     * @property elements The requested elements: namespace → identifiers.
     */
    public data class DocumentRequest(val docType: String, val elements: Map<String, List<String>>)

    /**
     * [start] asking for several [documents] at once, each of a
     * different type, at most eight. The holder may answer any of them:
     * [ProximityReaderSession.State.Verified.documents] has each one it
     * did, so check each one needed came back.
     */
    public fun start(
        context: Context,
        qrCode: String,
        documents: List<DocumentRequest>,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
    ): ProximityReaderSession {
        ProximityPermissions.require(context, ProximityPermissions.reader)
        val session = OID4VC.wrap { handle.start(qrCode) }
        return ProximityReaderSession(session, documents, timeouts) { e ->
            val uuid = UUID.fromString(e.serviceUUID)
            if (e.bleMode == "central_client") {
                GattServerTransport(context.applicationContext, uuid, GattCharacteristics.centralClient, Base64.getDecoder().decode(e.ident))
            } else {
                GattClientTransport(context.applicationContext, uuid, GattCharacteristics.peripheralServer)
            }
        }
    }

    /**
     * Replaces the Certificate Revocation Lists the configuration's
     * [ProximityReaderConfiguration.revocation] roles are checked against
     * with [pem]'s `X509 CRL` blocks, for sessions already started too.
     * CRLs expire at their nextUpdate: fetch fresh ones and call this
     * before then. Text holding anything else, or a CA's list older than
     * the one held, throws [WalletException] (`invalidInput`) and keeps
     * the lists as they were; empty text removes them all.
     */
    public fun setCRLs(pem: String) {
        OID4VC.wrap { handle.setCRLs(pem) }
    }

    /**
     * Fetches the configuration's CRL distribution points and keeps each
     * current list its CA signed that isn't older than the one held, for
     * sessions already started too, as [Wallet.refreshCRLs].
     */
    public suspend fun refreshCRLs(): CRLRefreshResult =
        CRLRefreshResult.of(OID4VC.cancellable { op -> handle.refreshCRLs(op) })

    internal fun startWith(qrCode: String, docType: String, elements: Map<String, List<String>>, timeouts: ProximityTimeouts, transport: ProximityTransport): ProximityReaderSession =
        startWith(qrCode, listOf(DocumentRequest(docType, elements)), timeouts, transport)

    internal fun startWith(qrCode: String, documents: List<DocumentRequest>, timeouts: ProximityTimeouts, transport: ProximityTransport): ProximityReaderSession =
        ProximityReaderSession(OID4VC.wrap { handle.start(qrCode) }, documents, timeouts) { transport }

    internal fun startNfcWith(hs: ByteArray, hr: ByteArray?, docType: String, elements: Map<String, List<String>>, timeouts: ProximityTimeouts, nfcData: Boolean, transport: ProximityTransport): ProximityReaderSession {
        val session = OID4VC.wrap {
            when {
                nfcData && hr != null -> handle.startFromNegotiatedNFCDataHandover(hs, hr)
                nfcData -> handle.startFromNFCDataHandover(hs)
                hr != null -> handle.startFromNegotiatedHandover(hs, hr)
                else -> handle.startFromHandover(hs)
            }
        }
        return ProximityReaderSession(session, listOf(DocumentRequest(docType, elements)), timeouts, usesNfcData = nfcData) { transport }
    }

    /**
     * Reads static or negotiated NFC handover from [tag], then starts BLE
     * or classic NFC-only retrieval according to the selected carrier.
     * Obtain the tag through Android reader mode with FLAG_READER_SKIP_NDEF_CHECK.
     * Call from a coroutine; cancellation closes the tag. NFC removal after the
     * handover does not end BLE. Bluetooth permissions must already be granted
     * for BLE retrieval; NFC-only retrieval does not require them.
     */
    public suspend fun startFromNfc(
        context: Context,
        tag: android.nfc.Tag,
        docType: String,
        elements: Map<String, List<String>>,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
    ): ProximityReaderSession = startFromNfc(context, tag, listOf(DocumentRequest(docType, elements)), timeouts)

    /**
     * [startFromNfc] asking for several [documents] at once, as
     * [start] with documents does.
     */
    public suspend fun startFromNfc(
        context: Context,
        tag: android.nfc.Tag,
        documents: List<DocumentRequest>,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
    ): ProximityReaderSession {
        val hr = OID4VC.wrap { Mobile.newNFCHandoverRequestWithNFCData("[\"peripheral_server\",\"central_client\"]", 255, 256) }
        val connection = NfcTagConnection(tag)
        var retained = false
        try {
            val handover = try { withTimeout(timeouts.connect) { connection.read(hr) } }
            catch (e: TimeoutCancellationException) { throw ProximityException(ProximityException.Reason.TimedOut, "NFC handover timed out", e) }
            val dataParameters = runCatching {
                decode<NfcDataParametersJSON>(Mobile.parseNfcDataParameters(handover.hs))
            }.getOrNull()
            if (dataParameters != null) {
                val session = OID4VC.wrap {
                    if (handover.hr == null) handle.startFromNFCDataHandover(handover.hs)
                    else handle.startFromNegotiatedNFCDataHandover(handover.hs, handover.hr)
                }
                connection.allowConsentDelay(timeouts.idle.inWholeMilliseconds.coerceIn(1, Int.MAX_VALUE.toLong()).toInt())
                val transport = NfcDataReaderTransport(connection::exchange, connection::close, connection.maxTransceive, dataParameters)
                return ProximityReaderSession(session, documents, timeouts, usesNfcData = true) { transport }.also { retained = true }
            }
            connection.close()
            ProximityPermissions.require(context, ProximityPermissions.reader)
            val session = OID4VC.wrap {
                if (handover.hr == null) handle.startFromHandover(handover.hs)
                else handle.startFromNegotiatedHandover(handover.hs, handover.hr)
            }
            return ProximityReaderSession(session, documents, timeouts) { e ->
            val app = context.applicationContext
            val uuid = UUID.fromString(e.serviceUUID)
            if (e.bleMode == "central_client") {
                GattServerTransport(app, uuid, GattCharacteristics.centralClient, Base64.getDecoder().decode(e.ident))
            } else {
                GattClientTransport(app, uuid, GattCharacteristics.peripheralServer)
            }
        }
        } finally { if (!retained) connection.close() }
    }
}

/** One reader session: follow [state] to [State.Verified] or another final state. */
public class ProximityReaderSession internal constructor(
    private val handle: MobileProximityReaderSession,
    private val documents: List<ProximityReader.DocumentRequest>,
    private val timeouts: ProximityTimeouts,
    /** Whether this session exchanges messages over NFC rather than BLE. */
    public val usesNfcData: Boolean = false,
    transportFor: (ReaderEngagementJSON) -> ProximityTransport,
) {
    /** Where the session is: follow [state]. */
    public sealed interface State {
        /** Looking for the holder's device, or waiting for it to connect. */
        public data object Connecting : State

        /** Connected: the request is sent, and the holder is deciding. */
        public data object WaitingForResponse : State

        /**
         * The mdoc verified.
         *
         * @property result The verified mdoc: the first, for several.
         * @property documents Every verified mdoc, in the response's order: for a request
         * of several documents, the ones the holder answered.
         */
        public data class Verified(val result: VerifiedMdoc, val documents: List<VerifiedMdoc> = listOf(result)) : State

        /** The holder declined (not authenticated: anyone nearby could send that). */
        public data object Declined : State

        /** [cancel] was called. */
        public data object Cancelled : State

        /**
         * The session failed: [error] is a [ProximityException] or [WalletException].
         *
         * @property error A [ProximityException] or a [WalletException].
         */
        public data class Failed(val error: Exception) : State

        /** Whether the session is over. */
        public val isFinal: Boolean get() = this is Verified || this is Declined || this is Cancelled || this is Failed
    }

    private val engagement: ReaderEngagementJSON = decode(handle.engagement())

    /** Whether requests carry reader authentication. */
    public val signed: Boolean = engagement.signed

    /**
     * Whether the session checks a verified document's revocation status before reporting it
     * [State.Verified] ([ProximityReaderConfiguration.statusCheck]).
     */
    public val checksStatus: Boolean = engagement.checkStatus

    /** The BLE mode selected; meaningful only when [usesNfcData] is false. */
    public val mode: ProximityBLEMode = ProximityBLEMode.entries.first { it.rawValue == engagement.bleMode }

    private val _state = MutableStateFlow<State>(State.Connecting)
    /**
     * The session's state: [State.Connecting] first, until one of the final states
     * ([State.isFinal]).
     */
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
            val elementsSerializer = MapSerializer(String.serializer(), ListSerializer(String.serializer()))
            val request = if (documents.size == 1) {
                val elementsJSON = json.encodeToString(elementsSerializer, documents[0].elements)
                decode<SendJSON>(OID4VC.offMain { handle.request(documents[0].docType, elementsJSON) })
            } else {
                val requestsJSON = json.encodeToString(ListSerializer(DocumentRequestJSON.serializer()), documents.map { DocumentRequestJSON(it.docType, it.elements) })
                decode<SendJSON>(OID4VC.offMain { handle.requestDocuments(requestsJSON) })
            }
            transport.send(request.send)
            _state.compareAndSet(State.Connecting, State.WaitingForResponse)
            val answer = try {
                withTimeout(timeouts.idle) { transport.receive() }
            } catch (e: TimeoutCancellationException) {
                throw ProximityException(ProximityException.Reason.TimedOut, "the holder didn't respond in time", e)
            }
            val event = decode<ReaderEventJSON>(handle.handleMessage(answer))
            sendLast(event)
            finish(
                when {
                    event.event == "verified" && event.verified != null ->
                        settled((event.documents ?: listOf(event.verified)).map { it.toVerified() })
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

    /**
     * The final state for [mdocs], which verified: [State.Verified], unless the configuration
     * checks status and it isn't [MdocStatus.Valid] or [MdocStatus.NoStatus] (a
     * [WalletException] `document_not_valid`, its [WalletException.protocolError] the status as
     * the list says it), or the check failed. The connection is closed first: the status list is
     * fetched over the network. Cancellation propagates.
     */
    private suspend fun settled(mdocs: List<VerifiedMdoc>): State {
        if (!checksStatus) return State.Verified(mdocs[0], mdocs)
        transport.close()
        return try {
            val checked = decode<MdocStatusJSON>(OID4VC.cancellable { op -> handle.checkStatus(op) })
            val text = checked.status
            when (val status = mdocStatusOf(text)) {
                MdocStatus.Valid, MdocStatus.NoStatus -> {
                    // Each document's own status; one alone has the combined one.
                    val each = mdocs.mapIndexed { i, m -> m.copy(status = checked.statuses.getOrNull(i)?.let(::mdocStatusOf) ?: status) }
                    State.Verified(each[0], each)
                }
                else -> State.Failed(
                    WalletException(WalletException.Code.documentNotValid, text, "the document's revocation status is $text"),
                )
            }
        } catch (e: WalletException) {
            State.Failed(e)
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

    /**
     * Sends the session's last message, if any. BLE ends with State 0x02 on
     * close. NFC has no such signal, so an NFC-only session that got an
     * answer ends with session termination (status 20), and waits briefly
     * for that exchange before the tag closes: a holder keeping the session
     * open for another request would otherwise see only a lost field.
     */
    private suspend fun sendLast(event: ReaderEventJSON) {
        if (!usesNfcData) {
            event.send?.let { runCatching { transport.send(it) } }
            return
        }
        val last = event.send ?: if (event.reason == "declined") return else decode<SendJSON>(handle.terminate()).send
        runCatching {
            transport.send(last)
            withTimeoutOrNull(LAST_NFC_MESSAGE_TIMEOUT) { transport.receive() }
        }
    }

    private companion object {
        val LAST_NFC_MESSAGE_TIMEOUT = 1.seconds
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

    /**
     * Checks the revocation status of the mdoc the session verified: fetches the Token Status List
     * its MSO names, over https from a public address, and verifies it's signed under the
     * certificate the MSO names or else under the CA that signed the document signer (ISO/IEC
     * 18013-5 §12.3.6). Rely on the document only when this is [MdocStatus.Valid] or
     * [MdocStatus.NoStatus]. Call it once the session is [State.Verified]; before, it throws a
     * [WalletException] with code `wrong_step`. A failed fetch is `network`, a list that doesn't
     * verify `protocol`; cancelling the coroutine cancels it. The list covers many documents, so
     * fetching it doesn't tell its publisher which one was presented.
     */
    public suspend fun checkStatus(): MdocStatus =
        mdocStatusOf(decode<MdocStatusJSON>(OID4VC.cancellable { op -> handle.checkStatus(op) }).status)
}

/** A verified mdoc, as a [ProximityReaderSession] received it. */
public data class VerifiedMdoc(
    /** The mdoc's document type. */
    val doctype: String,
    /** The disclosed elements: namespace → identifier → value, byte strings as base64 and dates as their text. */
    val claims: JsonObject,
    /** Any device-signed elements. */
    val deviceSignedClaims: JsonObject?,
    /**
     * The document signer certificate's subject common name, for display: any document signer
     * under a trusted IACA can choose it, so decide on [issuerChain].
     */
    val issuer: String,
    /** The common name of the IACA it chains to, for display. */
    val trustAnchor: String,
    /** When the mdoc's signed data (its MSO) became valid. */
    val validFrom: Instant,
    /** When it expires. */
    val validUntil: Instant,
    /** "signature" or "mac". */
    val deviceAuth: String,
    /**
     * The MSO's status list reference, unchecked: call
     * [ProximityReaderSession.checkStatus] before relying on the document.
     */
    val statusList: StatusListReference?,
    /**
     * The document signer's verified certificate path, leaf first, ending at the IACA in
     * [ProximityReaderConfiguration.issuerRoots] it chains to: decide which issuers to accept on
     * it.
     */
    val issuerChain: List<X509Certificate> = emptyList(),
    /**
     * The MSO's identifier list reference (ISO/IEC 18013-5 §12.3.6.4), unchecked, beside or
     * instead of [statusList]: either may revoke the document, and
     * [ProximityReaderSession.checkStatus] checks both.
     */
    val identifierList: IdentifierListReference? = null,
    /**
     * Its revocation status as the session checked it, [MdocStatus.Valid] or
     * [MdocStatus.NoStatus], when the configuration's
     * [ProximityReaderConfiguration.statusCheck] is [ProximityReaderConfiguration.StatusCheck.CHECK];
     * null when it's [ProximityReaderConfiguration.StatusCheck.DECLINE].
     */
    val status: MdocStatus? = null,
) {
    /**
     * Where the mdoc's status is published: a Token Status List at [uri], and the mdoc's [index]
     * in it.
     *
     * @property uri The status list's URL.
     * @property index The mdoc's index in the list.
     */
    public data class StatusListReference(val uri: String, val index: Long)

    /**
     * Where the mdoc's revocation is published: an identifier list at [uri], which names the
     * mdoc's [id] if it's revoked.
     *
     * @property uri The identifier list's URL.
     * @property id The mdoc's identifier, as base64.
     */
    public data class IdentifierListReference(val uri: String, val id: String)
}

@Serializable
internal data class ReaderEngagementJSON(
    @SerialName("service_uuid") val serviceUUID: String,
    @SerialName("ble_mode") val bleMode: String,
    val ident: String = "",
    val signed: Boolean = false,
    @SerialName("check_status") val checkStatus: Boolean = false,
)

@Serializable
internal data class ReaderEventJSON(
    val event: String,
    val verified: VerifiedJSON? = null,
    val documents: List<VerifiedJSON>? = null,
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
    @SerialName("issuer_chain") val issuerChain: List<String> = emptyList(),
) {
    /**
     * [idx] is left out when 0, and an identifier list has none; a status list's carries the
     * identifier list the MSO names too.
     */
    @Serializable
    data class StatusJSON(
        val type: String? = null,
        val uri: String,
        val idx: Long = 0,
        val id: String? = null,
        @SerialName("identifier_list") val identifierList: IdentifierListJSON? = null,
    )

    @Serializable
    data class IdentifierListJSON(val uri: String, val id: String)

    fun toVerified(): VerifiedMdoc {
        val factory = CertificateFactory.getInstance("X.509")
        val chain = issuerChain.mapNotNull { der ->
            runCatching { factory.generateCertificate(ByteArrayInputStream(Base64.getDecoder().decode(der))) as X509Certificate }.getOrNull()
        }
        return VerifiedMdoc(
            doctype, claims, deviceSignedClaims, issuer, trustAnchor, validFrom, validUntil, deviceAuth,
            status?.takeIf { it.type == null || it.type == "status_list" }?.let { VerifiedMdoc.StatusListReference(it.uri, it.idx) },
            chain,
            status?.let { s ->
                if (s.type == "identifier_list" && s.id != null) {
                    VerifiedMdoc.IdentifierListReference(s.uri, s.id)
                } else {
                    s.identifierList?.let { VerifiedMdoc.IdentifierListReference(it.uri, it.id) }
                }
            },
        )
    }
}

/** A verified mdoc's revocation status, as [ProximityReaderSession.checkStatus] found it. */
public sealed interface MdocStatus {
    /** Neither revoked nor suspended. */
    public data object Valid : MdocStatus

    /** Revoked for good (the list's `invalid`). */
    public data object Revoked : MdocStatus

    /** Suspended, for now. */
    public data object Suspended : MdocStatus

    /**
     * A status the issuer's list defines itself, as "0x" and its value.
     *
     * @property value The status, as "0x" and its value.
     */
    public data class Other(val value: String) : MdocStatus

    /** The MSO names no revocation list. */
    public data object NoStatus : MdocStatus

    /**
     * The MSO's status names no mechanism the reader knows, and no list says otherwise than
     * valid: the status isn't known. Before OID4VCWallet 0.22.0, also an MSO naming an
     * identifier list (ISO/IEC 18013-5 §12.3.6.4), which is now checked.
     */
    public data object Unknown : MdocStatus
}

/** [text], CheckStatus's status, as an [MdocStatus]. */
internal fun mdocStatusOf(text: String): MdocStatus = when (text) {
    "valid" -> MdocStatus.Valid
    "invalid" -> MdocStatus.Revoked
    "suspended" -> MdocStatus.Suspended
    "none" -> MdocStatus.NoStatus
    "unknown" -> MdocStatus.Unknown
    else -> MdocStatus.Other(text)
}

@Serializable
internal data class MdocStatusJSON(val status: String, val statuses: List<String> = emptyList())

/** One document of [ProximityReaderSession]'s request, as the gomobile layer takes it. */
@Serializable
internal data class DocumentRequestJSON(@SerialName("doctype") val docType: String, val elements: Map<String, List<String>>)
