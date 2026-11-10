package oid4vcgo.interop.multipaz

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.buildCborArray
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethod
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.devicesigned.DeviceAuth
import org.multipaz.mdoc.engagement.DeviceEngagement
import org.multipaz.mdoc.engagement.buildDeviceEngagement
import org.multipaz.mdoc.request.buildDeviceRequest
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.response.buildDeviceResponse
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.sessionencryption.SessionEncryption
import org.multipaz.mdoc.transport.MdocTransport
import org.multipaz.presentment.Iso18013Presentment
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.util.UUID
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import org.multipaz.verification.MdocApiDcResponse
import org.multipaz.verification.MdocVerifiedPresentation
import org.multipaz.verification.VerificationUtil
import org.multipaz.verification.VerifierIdentity
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

private const val DOC_TYPE = DrivingLicense.MDL_DOCTYPE
private const val NAMESPACE = DrivingLicense.MDL_NAMESPACE
private const val ORIGIN = "https://verifier.interop.example"

/** The Digital Credentials API protocol of ISO/IEC TS 18013-7 Annex C. */
private const val ANNEX_C = "org-iso-mdoc"

/** What each reader asks for, and whether it says it will keep it. */
private val REQUESTED = mapOf("family_name" to true, "given_name" to false, "age_over_18" to false)

/**
 * Every case: Multipaz and OID4VCgo in each role, in person (ISO/IEC
 * 18013-5, QR engagement, session encryption, reader authentication,
 * signature and deviceMac) and over the Digital Credentials API
 * (ISO/IEC TS 18013-7 Annex C), with controls.
 */
class Cases(
    private val peer: Peer,
    private val pki: Pki,
    private val holder: Holder,
    private val issuerTrust: TrustManager,
) : Checks() {
    /** Runs every case, returning how many failed. */
    suspend fun run(): Int {
        mpzReaderCases()
        goReaderCases()
        mpzVerifierCases()
        goVerifierCases()
        return failed
    }

    private suspend fun mpzReaderCases() {
        println("### Multipaz reader → OID4VCgo's holder (walletflow)")
        for (mac in listOf(false, true)) {
            val auth = if (mac) "mac" else "signature"
            check("mDL by $auth, the reader authenticated: Multipaz verified it") {
                val r = mpzReader(mac, pki.reader)
                r.problem ?: when {
                    r.holderSaw != "trusted" -> "the holder took the reader as ${r.holderSaw}"
                    r.deviceAuth != auth -> "device authentication was ${r.deviceAuth}"
                    r.disclosed != REQUESTED.keys -> "disclosed ${r.disclosed}"
                    !r.issuerTrusted -> "the issuer's chain doesn't reach OID4VCgo's IACA"
                    else -> null
                }
            }
        }
        check("control: a reader under a CA the holder doesn't trust is shown as untrusted") {
            val untrusted = mpzReader(false, pki.otherReader)
            if (untrusted.holderSaw == "untrusted") null else "the holder took it as ${untrusted.holderSaw} (${untrusted.problem})"
        }

    }

    private suspend fun goReaderCases() {
        println("### OID4VCgo's reader (proximity) → Multipaz holder")
        for (mac in listOf(false, true)) {
            val auth = if (mac) "mac" else "signature"
            check("mDL by $auth, the reader authenticated: OID4VCgo verified it") {
                val r = goReader(mac)
                r.error ?: when {
                    holder.lastReaderTrusted != true -> "Multipaz didn't trust OID4VCgo's reader"
                    r.string("device_auth") != auth -> "device authentication was ${r.string("device_auth")}"
                    r.claims.keys != REQUESTED.keys.map { "$NAMESPACE/$it" }.toSet() -> "disclosed ${r.claims.keys}"
                    else -> null
                }
            }
        }
        check("control: the reader refuses an mDL from an IACA it doesn't trust") {
            refusal(goReader(false, trust = "other"), "does not verify against a trusted root")
        }
        check("control: the reader refuses a DeviceResponse signed over another session transcript") {
            refusal(goReaderAnsweredOver(otherTranscript = true), "verify DeviceSignature")
        }

    }

    private suspend fun mpzVerifierCases() {
        println("### Annex C: Multipaz verifier → OID4VCgo's wallet (walletflow)")
        check("org-iso-mdoc request signed by the reader: Multipaz verified the answer") {
            val annexC = mpzVerifier(pki.reader)
            annexC.problem ?: when {
                annexC.holderSaw != "Multipaz interop reader" -> "the wallet saw the reader as '${annexC.holderSaw}'"
                annexC.disclosed != REQUESTED.keys -> "disclosed ${annexC.disclosed}"
                !annexC.issuerTrusted -> "the issuer's chain doesn't reach OID4VCgo's IACA"
                else -> null
            }
        }
        check("control: a request signed under a CA the wallet doesn't trust names no reader") {
            val annexCUntrusted = mpzVerifier(pki.otherReader)
            if (annexCUntrusted.holderSaw == "") null else "the wallet saw '${annexCUntrusted.holderSaw}' (${annexCUntrusted.problem})"
        }

    }

    private suspend fun goVerifierCases() {
        println("### Annex C: OID4VCgo's verifier (mdocdcapi) → Multipaz wallet")
        check("org-iso-mdoc request signed by OID4VCgo's reader: OID4VCgo verified the answer") {
            val toMpz = goVerifier()
            toMpz.error ?: when {
                toMpz.claims.keys != REQUESTED.keys.map { "$NAMESPACE/$it" }.toSet() -> "disclosed ${toMpz.claims.keys}"
                else -> null
            }
        }
        // Signed, the request's reader authentication covers the session
        // transcript, and so the origin: Multipaz's wallet refuses to
        // answer it from another. Unsigned, it answers, and the
        // verifier's HPKE open, whose info is the transcript, refuses.
        check("control: the verifier refuses an answer to its unsigned request bound to another origin") {
            refusal(goVerifier(answeredFrom = "https://other.interop.example", readerCA = ""), "decrypt the response")
        }
        check("control: the verifier refuses an mDL from an IACA it doesn't trust") {
            refusal(goVerifier(trust = "other"), "does not verify against a trusted root")
        }
    }

    /** What a Multipaz reader or verifier saw. */
    private data class MpzResult(
        val problem: String? = null,
        val holderSaw: String? = null,
        val deviceAuth: String? = null,
        val disclosed: Set<String> = emptySet(),
        val issuerTrusted: Boolean = false,
    )

    /**
     * A Multipaz reader, authenticating with [readerKey], asks
     * OID4VCgo's holder for [REQUESTED] by QR engagement, and verifies
     * the answer.
     */
    private suspend fun mpzReader(mac: Boolean, readerKey: AsymmetricKey.X509Certified): MpzResult {
        val start = peer.call("holder_start", "mac" to mac)
        start.error?.let { return MpzResult(problem = "holder_start: $it") }
        val engagement = start.string("qr")!!.removePrefix("mdoc:").fromBase64Url()
        val deviceEngagement = DeviceEngagement.fromDataItem(Cbor.decode(engagement))
        val eReaderKey = Crypto.createEcPrivateKey(deviceEngagement.eDeviceKey.curve)
        val transcript = transcript(engagement, eReaderKey.publicKey, Simple.NULL)
        val session = SessionEncryption(MdocRole.MDOC_READER, eReaderKey, deviceEngagement.eDeviceKey, Cbor.encode(transcript))
        val request = buildDeviceRequest(transcript) {
            addDocRequest(
                docType = DOC_TYPE,
                nameSpaces = mapOf(NAMESPACE to REQUESTED),
                docRequestInfo = null,
                readerKey = readerKey,
            )
        }
        val answer = peer.call("holder_message", "msg" to session.encryptMessage(Cbor.encode(request.toDataItem()), null).toBase64Url())
        val saw = answer.string("reader")
        answer.error?.let { return MpzResult(problem = "the holder: $it", holderSaw = saw) }
        val (plaintext, _) = session.decryptMessage(answer.string("send")!!.fromBase64Url())
        plaintext ?: return MpzResult(problem = "the holder sent no DeviceResponse", holderSaw = saw)
        val response = DeviceResponse.fromDataItem(Cbor.decode(plaintext))
        response.verify(sessionTranscript = transcript, eReaderKey = AsymmetricKey.anonymous(eReaderKey))
        val document = response.documents.single()
        return MpzResult(
            holderSaw = saw,
            deviceAuth = if (document.deviceAuth is DeviceAuth.Mac) "mac" else "signature",
            disclosed = disclosed(document),
            issuerTrusted = issuerTrust.verify(document.issuerCertChain.certificates).isTrusted,
        )
    }

    /**
     * OID4VCgo's reader, trusting [trust]'s IACA, asks Multipaz's holder
     * (Iso18013Presentment) by its QR engagement, and verifies the
     * answer.
     */
    private suspend fun goReader(mac: Boolean, trust: String = "mpz"): Reply {
        holder.lastReaderTrusted = null
        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val deviceEngagement = engagement(eDeviceKey.publicKey)
        val encoded = Cbor.encode(deviceEngagement.toDataItem())
        val start = peer.call("reader_start", "qr" to "mdoc:" + encoded.toBase64Url(), "trust" to trust)
        if (start.error != null) return start
        val transport = OneExchange(start.string("send")!!.fromBase64Url())
        coroutineScope {
            val presentment = launch {
                Iso18013Presentment(
                    transport = transport,
                    eDeviceKey = eDeviceKey,
                    deviceEngagement = deviceEngagement.toDataItem(),
                    handover = Simple.NULL,
                    source = holder.source(mac),
                    keyAgreementPossible = if (mac) listOf(EcCurve.P256) else emptyList(),
                )
            }
            withTimeout(30.seconds) { transport.answer.await() }
            presentment.cancel()
        }
        return peer.call("reader_response", "msg" to transport.answer.await().toBase64Url())
    }

    /**
     * OID4VCgo's reader asks Multipaz's mDL, answered by hand, with
     * Multipaz's DeviceResponse builder, signed over a session
     * transcript other than the session's when [otherTranscript].
     */
    private suspend fun goReaderAnsweredOver(otherTranscript: Boolean): Reply {
        val eDeviceKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val deviceEngagement = engagement(eDeviceKey.publicKey)
        val encoded = Cbor.encode(deviceEngagement.toDataItem())
        val start = peer.call("reader_start", "qr" to "mdoc:" + encoded.toBase64Url(), "trust" to "mpz")
        if (start.error != null) return start
        val establishment = start.string("send")!!.fromBase64Url()
        val eReaderKey = SessionEncryption.getEReaderKey(establishment)
        val transcript = transcript(encoded, eReaderKey.publicKey, Simple.NULL)
        val session = SessionEncryption(MdocRole.MDOC, eDeviceKey, eReaderKey.publicKey, Cbor.encode(transcript))
        session.decryptMessage(establishment)
        val signedOver = if (otherTranscript) transcript(encoded, eReaderKey.publicKey, Tstr("another session")) else transcript
        val response = buildDeviceResponse(sessionTranscript = signedOver, status = 0) {
            addDocument(
                credential = holder.credential(DOMAIN_SIGNATURE),
                requestedClaims = REQUESTED.map { (name, retain) ->
                    MdocRequestedClaim(docType = DOC_TYPE, namespaceName = NAMESPACE, dataElementName = name, intentToRetain = retain)
                },
            )
        }
        val message = session.encryptMessage(Cbor.encode(response.toDataItem()), null)
        return peer.call("reader_response", "msg" to message.toBase64Url())
    }

    /**
     * A Multipaz verifier, signing with [readerKey], asks OID4VCgo's
     * wallet for [REQUESTED] by org-iso-mdoc, and verifies the answer.
     */
    private suspend fun mpzVerifier(readerKey: AsymmetricKey.X509Certified): MpzResult {
        val nonce = ByteString(Crypto.secureRandom.nextBytes(16))
        val encryptionKey = Crypto.createEcPrivateKey(EcCurve.P256)
        val request = VerificationUtil.generateDcRequestMdoc(
            exchangeProtocols = listOf(ANNEX_C),
            docType = DOC_TYPE,
            claims = REQUESTED.map { (name, retain) ->
                MdocRequestedClaim(docType = DOC_TYPE, namespaceName = NAMESPACE, dataElementName = name, intentToRetain = retain)
            },
            nonce = nonce,
            origin = ORIGIN,
            responseEncryptionKey = encryptionKey.publicKey,
            verifierIdentities = listOf(VerifierIdentity(readerKey)),
            zkSystemSpecs = emptyList(),
        )
        val data = request["requests"]!!.jsonArray[0].jsonObject["data"]!!.jsonObject
        val answer = peer.call("dcapi_answer", "data" to data.toString(), "origin" to ORIGIN)
        val saw = answer.string("reader") ?: ""
        answer.error?.let { return MpzResult(problem = "the wallet: $it", holderSaw = saw) }
        val response = buildJsonObject {
            put("protocol", JsonPrimitive(ANNEX_C))
            put("data", Json.parseToJsonElement(answer.string("data")!!))
        }
        val decrypted = VerificationUtil.decryptDcResponse(
            response = response,
            nonce = nonce,
            origin = ORIGIN,
            responseEncryptionKey = AsymmetricKey.anonymous(encryptionKey),
        ) as MdocApiDcResponse
        val presentation = VerificationUtil.verifyMdocDeviceResponse(
            now = Clock.System.now(),
            deviceResponse = decrypted.deviceResponse,
            sessionTranscript = decrypted.sessionTranscript,
            eReaderKey = null,
            documentTypeRepository = null,
            zkSystemRepository = null,
            request = null,
        ).single() as MdocVerifiedPresentation
        return MpzResult(
            holderSaw = saw,
            disclosed = presentation.issuerSignedClaims.filter { it.namespaceName == NAMESPACE }.map { it.dataElementName }.toSet(),
            issuerTrusted = issuerTrust.verify(presentation.documentSignerCertChain.certificates).isTrusted,
        )
    }

    /**
     * OID4VCgo's verifier, trusting [trust]'s IACA, asks Multipaz's
     * wallet by org-iso-mdoc from [ORIGIN], signed by its reader from
     * [readerCA] ("go"; "" for unsigned); the wallet answers as if asked
     * from [answeredFrom].
     */
    private suspend fun goVerifier(answeredFrom: String = ORIGIN, trust: String = "mpz", readerCA: String = "go"): Reply {
        val request = peer.call("dcapi_request", "origin" to ORIGIN, "reader_ca" to readerCA)
        if (request.error != null) return request
        val answer = org.multipaz.presentment.digitalCredentialsPresentment(
            protocol = ANNEX_C,
            data = Json.parseToJsonElement(request.string("data")!!).jsonObject,
            appId = null,
            origin = answeredFrom,
            preselectedDocuments = emptyList(),
            source = holder.source(mac = false),
        )
        val response = answer["data"]!!.jsonObject["response"]!!.jsonPrimitive.content
        return peer.call("dcapi_verify", "response" to response, "trust" to trust)
    }

    private fun disclosed(document: MdocDocument): Set<String> =
        document.issuerNamespaces.data[NAMESPACE]?.keys ?: emptySet()

    /** An engagement offering BLE central client mode, as a phone's QR code does. */
    private fun engagement(eDeviceKey: EcPublicKey): DeviceEngagement = buildDeviceEngagement(eDeviceKey) {
        addConnectionMethod(
            MdocConnectionMethodBle(
                supportsPeripheralServerMode = false,
                supportsCentralClientMode = true,
                peripheralServerModeUuid = null,
                centralClientModeUuid = UUID.randomUUID(),
            )
        )
    }

    /** The SessionTranscript: DeviceEngagementBytes, EReaderKeyBytes, Handover (§9.1.5.1). */
    private fun transcript(engagement: ByteArray, eReaderKey: EcPublicKey, handover: DataItem): DataItem = buildCborArray {
        add(Tagged(Tagged.ENCODED_CBOR, Bstr(engagement)))
        add(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(eReaderKey.toCoseKey().toDataItem()))))
        add(handover)
    }
}

/**
 * The transport between OID4VCgo's reader and Multipaz's holder for one
 * exchange: it hands the holder [establishment], and keeps its answer.
 */
private class OneExchange(private val establishment: ByteArray) : MdocTransport() {
    val answer = CompletableDeferred<ByteArray>()
    private var delivered = false
    private val _state = MutableStateFlow(State.CONNECTED)
    override val state: StateFlow<State> = _state
    override val role = MdocRole.MDOC
    override val connectionMethod: MdocConnectionMethod = MdocConnectionMethodBle(
        supportsPeripheralServerMode = false,
        supportsCentralClientMode = true,
        peripheralServerModeUuid = null,
        centralClientModeUuid = UUID.randomUUID(),
    )
    override val scanningTime: Duration? = null

    override suspend fun advertise() {
        // Nothing to advertise: the messages pass in process.
    }
    override suspend fun open(eSenderKey: EcPublicKey) {
        // Already connected: there's no radio to open.
    }
    override suspend fun sendMessage(message: ByteArray) {
        answer.complete(message)
    }
    override suspend fun waitForMessage(): ByteArray {
        if (!delivered) {
            delivered = true
            return establishment
        }
        return CompletableDeferred<ByteArray>().await()
    }
    override suspend fun close() {
        _state.value = State.CLOSED
    }
}
