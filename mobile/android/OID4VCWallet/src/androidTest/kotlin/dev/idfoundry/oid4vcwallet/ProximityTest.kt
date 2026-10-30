package dev.idfoundry.oid4vcwallet

import android.os.Build
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.time.Duration.Companion.seconds

/** One end of an in-memory transport: what BLE carries, without the radio. */
internal class PipeTransport : ProximityTransport {
    lateinit var peer: PipeTransport
    private val inbox = Channel<ByteArray>(Channel.UNLIMITED)
    private val connected = CompletableDeferred<Unit>()

    /** Whether the other end connects at all: false for a reader that never comes. */
    var peerConnects = true
    @Volatile var closed = false
        private set

    override suspend fun connect() {
        connected.complete(Unit)
        if (!peerConnects) CompletableDeferred<Unit>().await()
        peer.connected.await()
    }

    override suspend fun send(message: ByteArray) {
        if (peer.inbox.trySend(message).isFailure) throw ProximityTransportException("the other end is closed", peerEnded = true)
    }

    override suspend fun receive(): ByteArray =
        try {
            inbox.receive()
        } catch (e: ClosedReceiveChannelException) {
            throw ProximityTransportException("the other end closed", peerEnded = true, cause = e)
        }

    override fun close() {
        closed = true
        inbox.close()
        peer.inbox.close()
    }

    companion object {
        fun pair(): Pair<PipeTransport, PipeTransport> {
            val a = PipeTransport()
            val b = PipeTransport()
            a.peer = b
            b.peer = a
            return a to b
        }
    }
}

/**
 * In-person presentation through the Kotlin API, holder and reader in
 * one process over an in-memory transport: the Go sessions, Android
 * Keystore signing and both state machines, without BLE.
 */
@RunWith(AndroidJUnit4::class)
class ProximityTest {
    private val prefix = "org.idfoundry.oid4vcgo.proximity.${System.nanoTime()}."
    private val envs = mutableListOf<TestEnv>()
    private val keys = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix))
    private val timeouts = ProximityTimeouts(connect = 10.seconds, request = 10.seconds, idle = 30.seconds)

    @After
    fun cleanUp() {
        envs.forEach { it.close() }
        keys.deleteKeys(emptySet())
    }

    private class Setup(val wallet: Wallet, val reader: ProximityReader, val mdocID: String, val env: TestEnv)

    /** A wallet holding the test mdoc and recognizing the test reader, and that reader. */
    private suspend fun setup(
        signed: Boolean = true,
        requireTrusted: Boolean = false,
        holderKeys: AndroidKeystoreKeyStore = keys,
        deviceAuth: WalletConfiguration.ProximityDeviceAuth = WalletConfiguration.ProximityDeviceAuth.SIGNATURE,
    ): Setup {
        val env = TestEnv().also { envs += it }
        val readerSetup = json.parseToJsonElement(env.env.proximityReader(KeyStoreAdapter(keys))).jsonObject
        val readerConfig = json.decodeFromString(ProximityReaderConfiguration.serializer(), readerSetup["reader_config"]!!.jsonPrimitive.content)
        val wallet = Wallet(
            env.configuration.copy(
                mdocReaderRoots = readerSetup["mdoc_reader_roots"]!!.jsonPrimitive.content,
                mdocReaderRequireEKU = true,
                requireTrustedMdocReader = requireTrusted,
                proximityDeviceAuth = deviceAuth,
            ),
            holderKeys, InMemoryCredentialStore(), ProviderOf(env),
        )
        val s = wallet.startIssuance(env.env.authorizationCodeOffer())
        s.completeAuthorization(env.approve(s.beginAuthorization()))
        val mdocID = s.requestCredentials().credentials.first { it.format == "mso_mdoc" }.id
        s.close()
        val reader = if (signed) {
            ProximityReader(readerConfig, keys)
        } else {
            ProximityReader(ProximityReaderConfiguration(issuerRoots = readerConfig.issuerRoots, development = true))
        }
        return Setup(wallet, reader, mdocID, env)
    }

    private fun start(s: Setup, modes: Set<ProximityBLEMode> = setOf(ProximityBLEMode.PERIPHERAL_SERVER)): Pair<ProximityPresentation, ProximityReaderSession> {
        val (holderEnd, readerEnd) = PipeTransport.pair()
        val holder = s.wallet.startProximityPresentation(timeouts, holderEnd, modes)
        val reader = s.reader.startWith(holder.qrCode, DOC_TYPE, mapOf(NAMESPACE to listOf("family_name", "given_name")), timeouts, readerEnd)
        return holder to reader
    }

    private suspend fun <S> awaitFinal(flow: kotlinx.coroutines.flow.StateFlow<S>, isFinal: (S) -> Boolean): S =
        withTimeout(30.seconds) { flow.first(isFinal) }

    private suspend fun awaitRequest(holder: ProximityPresentation): ProximityPresentation.Request =
        (
            withTimeout(30.seconds) {
                holder.state.first { it is ProximityPresentation.State.RequestReceived || it.isFinal }
            } as? ProximityPresentation.State.RequestReceived
            ?: throw AssertionError("no request: ${holder.state.value}")
            ).request

    /** A reader is a production one unless `development` is set: a configuration leaving its decisions open is `invalid_input`. */
    @Test
    fun readerIsProductionByDefault() {
        val issuerRoots = TestEnv().also { envs += it }.configuration.issuerRoots
        try {
            ProximityReader(ProximityReaderConfiguration(issuerRoots = issuerRoots))
            throw AssertionError("an undecided production reader was configured")
        } catch (e: WalletException) {
            assertEquals(WalletException.Code.invalidInput, e.code)
        }
        ProximityReader(ProximityReaderConfiguration(issuerRoots = issuerRoots, development = true))
        ProximityReader(
            ProximityReaderConfiguration(
                issuerRoots = issuerRoots,
                noRevocationCheck = listOf(ProximityReaderConfiguration.RevocationRole.ISSUER, ProximityReaderConfiguration.RevocationRole.STATUS),
                anyIssuerForAnyType = true,
            ),
        )
    }

    @Test
    fun presentAndVerify(): Unit = runBlocking {
        val s = setup()
        val (holder, reader) = start(s)
        assertTrue(holder.qrCode.startsWith("mdoc:"))
        assertTrue(reader.signed)

        val request = awaitRequest(holder)
        assertEquals(ProximityReaderIdentity.Status.Trusted, request.reader.status)
        assertEquals("Test Reader", request.reader.name)
        assertEquals(2, request.reader.chain.size)
        val document = request.documents.single()
        assertEquals(DOC_TYPE, document.doctype)
        // In the request's order: the reader encodes them sorted.
        assertEquals(listOf("given_name", "family_name"), document.elements.map { it.identifier })
        assertEquals(s.mdocID, document.credentials.single().id)

        val linkable = holder.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "family_name")))
        assertFalse(linkable)
        val result = awaitFinal(reader.state) { it.isFinal }
        val verified = (result as? ProximityReaderSession.State.Verified)?.result ?: throw AssertionError("reader: $result")
        assertEquals(DOC_TYPE, verified.doctype)
        val claims = verified.claims[NAMESPACE]!!.jsonObject
        assertEquals("Doe", claims["family_name"]!!.jsonPrimitive.content)
        assertEquals(setOf("family_name"), claims.keys)
        assertEquals("signature", verified.deviceAuth)
        assertTrue(verified.statusList != null)
        assertTrue(verified.issuerChain.size >= 2)
        assertEquals(ProximityPresentation.State.Presented(false), awaitFinal(holder.state) { it.isFinal })

        // The reader checks the status list the MSO names, and sees a revocation.
        assertEquals(MdocStatus.Valid, reader.checkStatus())
        s.env.env.revoke()
        assertEquals(MdocStatus.Revoked, reader.checkStatus())
    }

    /** Actual Kotlin/Go bindings and Keystore, simulated NFC APDUs and BLE messages. */
    @Test
    fun nfcHandoverAuthenticatesAndVerifies(): Unit = runBlocking {
        val s = setup()
        for (negotiated in listOf(false, true)) for (mode in ProximityBLEMode.entries) {
            val (holderEnd, readerEnd) = PipeTransport.pair()
            val created = java.util.concurrent.atomic.AtomicInteger()
            val owner = s.wallet.startNfcPresentation(timeouts, setOf(mode), negotiated) { created.incrementAndGet(); holderEnd }
            try {
                assertEquals(0, created.get())
                val hr = dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile.newNFCHandoverRequest("[\"${mode.rawValue}\"]")
                val nfc = NfcType4Reader({ checkNotNull(owner.process(it)) }, 128)
                val hs = nfc.read(hr)
                val reader = s.reader.startNfcWith(hs, if (negotiated) hr else null, DOC_TYPE,
                    mapOf(NAMESPACE to listOf("family_name")), timeouts, false, readerEnd)
                val request = awaitRequest(owner.presentation)
                assertEquals(ProximityReaderIdentity.Status.Trusted, request.reader.status)
                assertEquals(1, created.get())
                assertTrue(hs.contentEquals(nfc.read()))
                assertEquals(1, created.get())
                owner.presentation.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "family_name")))
                val verified = awaitFinal(reader.state) { it.isFinal } as ProximityReaderSession.State.Verified
                assertEquals("Doe", verified.result.claims[NAMESPACE]!!.jsonObject["family_name"]!!.jsonPrimitive.content)
            } finally { owner.close() }
        }
    }

    /** Combined offers authenticate through the selected transcript and one consent flow. */
    @Test
    fun combinedEngagementRoundTrips(): Unit = runBlocking {
        val s = setup()
        val mode = ProximityBLEMode.PERIPHERAL_SERVER
        for (negotiated in listOf(false, true)) for (carrier in listOf("peripheral", "central", "nfc")) for (nfcWins in listOf(false, true)) {
            val selectedMode = if (carrier == "central") ProximityBLEMode.CENTRAL_CLIENT else mode
            val nfcData = carrier == "nfc"
            val (qrHolder, qrReader) = PipeTransport.pair()
            val (nfcHolder, nfcReader) = PipeTransport.pair()
            if (nfcWins) qrHolder.peerConnects = false
            val qrCreated = CompletableDeferred<Unit>()
            val created = java.util.concurrent.atomic.AtomicInteger()
            val combined = s.wallet.startCombinedPresentation(timeouts, setOf(selectedMode), NfcEngagementOptions(negotiated, nfcData)) {
                if (created.incrementAndGet() == 1) { qrCreated.complete(Unit); qrHolder } else nfcHolder
            }
            try {
                withTimeout(10.seconds) { qrCreated.await() }
                assertTrue(combined.qrCode.startsWith("mdoc:"))
                val reader: ProximityReaderSession
                if (!nfcWins) {
                    // A static-only reader abandons TNEP, or drops out during a static Hs.
                    fun apdu(command: ByteArray): ByteArray {
                        val response = checkNotNull(combined.owner.process(command))
                        assertTrue(response.takeLast(2).toByteArray().contentEquals(nfcResponse(0x9000)))
                        return response.copyOf(response.size - 2)
                    }
                    apdu(byteArrayOf(0,0xa4.toByte(),4,0,7) + NDEF_AID + byteArrayOf(0))
                    apdu(byteArrayOf(0,0xa4.toByte(),0,0x0c,2,0xe1.toByte(),4))
                    val length = apdu(byteArrayOf(0,0xb0.toByte(),0,0,2))
                    val count = if (negotiated) ((length[0].toInt() and 255) shl 8) or (length[1].toInt() and 255) else 1
                    apdu(byteArrayOf(0,0xb0.toByte(),0,2,count.toByte()))
                    assertEquals(null, combined.selectedEngagement.value)
                    combined.owner.deactivate()
                    assertEquals(ProximityPresentation.State.WaitingForReader, combined.state.value)
                    reader = s.reader.startWith(combined.qrCode, DOC_TYPE, mapOf(NAMESPACE to listOf("family_name")), timeouts, qrReader)
                    awaitRequest(combined.owner.presentation)
                    val select = byteArrayOf(0, 0xa4.toByte(), 4, 0x0c, 7) + NDEF_AID
                    assertTrue(nfcResponse(0x6985).contentEquals(combined.owner.process(select)))
                    assertEquals(SelectedEngagement.QR, combined.selectedEngagement.value)
                    assertEquals(1, created.get())
                } else {
                    val modes = "[\"${selectedMode.rawValue}\"]"
                    val hr = if (nfcData) Mobile.newNFCHandoverRequestWithNFCData(modes,255,256) else Mobile.newNFCHandoverRequest(modes)
                    val hs = NfcType4Reader({ checkNotNull(combined.owner.process(it)) }, 128).read(hr)
                    assertEquals(if (nfcData) null else SelectedEngagement.NFC_BLE, combined.selectedEngagement.value)
                    val transport = if (nfcData) {
                        val parameters = decode<NfcDataParametersJSON>(Mobile.parseNfcDataParameters(hs))
                        NfcDataReaderTransport({ command ->
                            val response = java.util.concurrent.ArrayBlockingQueue<ByteArray>(1)
                            combined.owner.process(command) { response.offer(it) } ?: response.poll(30, java.util.concurrent.TimeUnit.SECONDS) ?: error(APDU_TIMED_OUT)
                        }, {}, 128, parameters)
                    } else nfcReader
                    reader = s.reader.startNfcWith(hs, if (negotiated) hr else null, DOC_TYPE, mapOf(NAMESPACE to listOf("family_name")), timeouts, nfcData, transport)
                    awaitRequest(combined.owner.presentation)
                    assertEquals(if (nfcData) SelectedEngagement.NFC_DATA else SelectedEngagement.NFC_BLE, combined.selectedEngagement.value)
                    assertEquals(if (nfcData) 1 else 2, created.get())
                    assertTrue("QR resources survived NFC selection", qrHolder.closed)
                }
                assertEquals(ProximityReaderIdentity.Status.Trusted, (combined.state.value as ProximityPresentation.State.RequestReceived).request.reader.status)
                combined.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "family_name")))
                val verified = awaitFinal(reader.state) { it.isFinal } as ProximityReaderSession.State.Verified
                assertEquals("Doe", verified.result.claims[NAMESPACE]!!.jsonObject["family_name"]!!.jsonPrimitive.content)
                assertTrue(combined.state.value is ProximityPresentation.State.Presented)
            } finally { combined.close() }
        }
    }

    @Test
    fun combinedNfcOnlyWithoutQrAndOwnerReplacement(): Unit = runBlocking {
        val s = setup()
        var previous: CombinedPresentation? = null
        var previousTransport: PipeTransport? = null
        repeat(20) { index ->
            val (holder, _) = PipeTransport.pair()
            holder.peerConnects = false
            val created = CompletableDeferred<Unit>()
            val next = s.wallet.startCombinedPresentation(timeouts, setOf(ProximityBLEMode.PERIPHERAL_SERVER), NfcEngagementOptions(index % 2 == 0, true)) { created.complete(Unit); holder }
            withTimeout(10.seconds) { created.await() }
            previous?.let {
                assertEquals(ProximityPresentation.State.Cancelled, it.state.value)
                assertTrue(checkNotNull(previousTransport).closed)
                assertTrue(nfcResponse(0x6985).contentEquals(it.owner.process(byteArrayOf(0,0xa4.toByte(),4,0x0c,7)+NDEF_AID)))
            }
            assertTrue(NfcPresentations.owner() === next.owner)
            if (index % 3 == 0) next.owner.process(byteArrayOf(0,0xa4.toByte(),4,0x0c,7)+NDEF_AID)
            previous = next
            previousTransport = holder
        }
        previous!!.close()
        assertEquals(null, NfcPresentations.owner())
        val combined = s.wallet.startCombinedPresentation(timeouts, setOf(ProximityBLEMode.PERIPHERAL_SERVER), NfcEngagementOptions(nfcData = true), true) { error("omitted QR started BLE") }
        try {
            assertEquals("", combined.qrCode)
            val hs = NfcType4Reader({ checkNotNull(combined.owner.process(it)) },128).read()
            val parameters = decode<NfcDataParametersJSON>(dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile.parseNfcDataParameters(hs))
            val transport = NfcDataReaderTransport({ command ->
                val response = java.util.concurrent.ArrayBlockingQueue<ByteArray>(1)
                combined.owner.process(command) { response.offer(it) } ?: response.poll(30, java.util.concurrent.TimeUnit.SECONDS) ?: error(APDU_TIMED_OUT)
            }, {}, 128, parameters)
            val reader = s.reader.startNfcWith(hs, null, DOC_TYPE, mapOf(NAMESPACE to listOf("family_name")), timeouts, true, transport)
            awaitRequest(combined.owner.presentation)
            combined.decline()
            assertEquals(ProximityReaderSession.State.Declined, awaitFinal(reader.state) { it.isFinal })
        } finally { combined.close() }
    }

    /** Kotlin's command kinds mirror Go's ClassifyNFCCommand. */
    @Test
    fun nfcCommandKindsMatchGo() {
        val mobile = dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile::class.java
        for ((name, kind) in listOf(
            "NFCCommandOther" to NfcCommandKind.OTHER,
            "NFCCommandSelectNDEF" to NfcCommandKind.SELECT_NDEF,
            "NFCCommandSelectData" to NfcCommandKind.SELECT_DATA,
            "NFCCommandSelectDataNoFCI" to NfcCommandKind.SELECT_DATA_NO_FCI,
            "NFCCommandSelectOther" to NfcCommandKind.SELECT_OTHER,
        )) assertEquals(name, mobile.getField(name).getLong(null), kind.toLong())
        assertEquals(NfcCommandKind.SELECT_NDEF.toLong(), dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile.classifyNFCCommand(byteArrayOf(0, 0xa4.toByte(), 4, 0, 7) + NDEF_AID))
    }

    /** APDUs carry the real encrypted messages end to end, without an RF field. */
    @Test
    fun nfcOnlyAuthenticatesAndVerifies(): Unit = runBlocking {
        val s = setup()
        for (negotiated in listOf(false, true)) {
        val owner = s.wallet.startNfcPresentation(timeouts, emptySet(), negotiated, true) { error("NFC-only started BLE") }
        try {
            val hr = dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile.newNFCHandoverRequestWithNFCData("[\"peripheral_server\",\"central_client\"]",255,256)
            val hs = NfcType4Reader({ checkNotNull(owner.process(it)) }, 128).read(hr)
            val parameters = decode<NfcDataParametersJSON>(dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile.parseNfcDataParameters(hs))
            val commands = java.util.Collections.synchronizedList(mutableListOf<ByteArray>())
            val exchange: (ByteArray) -> ByteArray = { command ->
                commands.add(command)
                val response = java.util.concurrent.ArrayBlockingQueue<ByteArray>(1)
                owner.process(command) { response.offer(it) } ?: response.poll(30, java.util.concurrent.TimeUnit.SECONDS) ?: error(APDU_TIMED_OUT)
            }
            val transport = NfcDataReaderTransport(exchange, {}, 128, parameters)
            val reader = s.reader.startNfcWith(hs, if (negotiated) hr else null, DOC_TYPE, mapOf(NAMESPACE to listOf("family_name")), timeouts, true, transport)
            val request = awaitRequest(owner.presentation)
            assertEquals(ProximityReaderIdentity.Status.Trusted, request.reader.status)
            owner.presentation.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "family_name")))
            val verified = awaitFinal(reader.state) { it.isFinal } as ProximityReaderSession.State.Verified
            assertEquals("Doe", verified.result.claims[NAMESPACE]!!.jsonObject["family_name"]!!.jsonPrimitive.content)
            // NFC has no State 0x02: the reader ends with session termination, so a holder
            // keeping the session open for another request doesn't see only a lost field.
            // The reader sends it after Verified, so wait for it: a short ENVELOPE (header, Lc,
            // DO53 (tag, length, message), Le) after the response's last GET RESPONSE.
            val last = withTimeout(10.seconds) {
                while ((commands.last()[1].toInt() and 255) != 0xc3) delay(20)
                commands.last()
            }
            val do53 = last.copyOfRange(5, 5 + (last[4].toInt() and 255))
            assertEquals(0x53, do53[0].toInt())
            assertEquals("a16673746174757314", do53.copyOfRange(2, do53.size).joinToString("") { "%02x".format(it) })
        } finally { owner.close() }
        }
    }

    @Test
    fun nfcReplacementAndStartupFailureCleanUp(): Unit = runBlocking {
        val s = setup()
        val created = java.util.concurrent.atomic.AtomicInteger()
        var previous: NfcPresentation? = null
        repeat(20) {
            val next = s.wallet.startNfcPresentation(timeouts, setOf(ProximityBLEMode.PERIPHERAL_SERVER), false) {
                created.incrementAndGet(); error("unread NFC started BLE")
            }
            previous?.let {
                assertEquals(ProximityPresentation.State.Cancelled, it.presentation.state.value)
                it.presentation.awaitClosed()
            }
            previous = next
        }
        previous!!.close()
        assertEquals(0, created.get())
        val closed = java.util.concurrent.atomic.AtomicInteger()
        val failed = s.wallet.startNfcPresentation(timeouts, setOf(ProximityBLEMode.PERIPHERAL_SERVER), false) {
            object : ProximityTransport {
                override suspend fun connect() { throw ProximityTransportException("advertising failed") }
                override suspend fun send(message: ByteArray) { error("not connected") }
                override suspend fun receive(): ByteArray = error("not connected")
                override fun close() { closed.incrementAndGet() }
            }
        }
        NfcType4Reader({ checkNotNull(failed.process(it)) }, 128).read()
        assertTrue(awaitFinal(failed.presentation.state) { it.isFinal } is ProximityPresentation.State.Failed)
        failed.close()
        assertEquals(1, closed.get())
        val recovered = s.wallet.startNfcPresentation(timeouts, setOf(ProximityBLEMode.PERIPHERAL_SERVER), false) { error("unread NFC started BLE") }
        recovered.close()
    }

    /**
     * With MAC preferred and holder keys that agree keys, the reader
     * verifies a deviceMac: from API 31, where Android Keystore agrees
     * keys; below it, the same wallet signs.
     */
    @Test
    fun deviceMacWhereKeystoreAgreesKeys(): Unit = runBlocking {
        val agreeing = AndroidKeystoreKeyStore(
            AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix, holderKeyAgreement = true),
        )
        val s = setup(holderKeys = agreeing, deviceAuth = WalletConfiguration.ProximityDeviceAuth.MAC_PREFERRED)
        val (holder, reader) = start(s)
        awaitRequest(holder)
        holder.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "family_name")))
        val result = awaitFinal(reader.state) { it.isFinal }
        val verified = (result as? ProximityReaderSession.State.Verified)?.result ?: throw AssertionError("reader: $result")
        val expected = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) "mac" else "signature"
        assertEquals(expected, verified.deviceAuth)
        assertEquals("Doe", verified.claims[NAMESPACE]!!.jsonObject["family_name"]!!.jsonPrimitive.content)
    }

    /** A wallet left at signatures signs, even with holder keys that agree keys. */
    @Test
    fun signatureByDefaultWithAgreeingKeys(): Unit = runBlocking {
        val agreeing = AndroidKeystoreKeyStore(
            AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix, holderKeyAgreement = true),
        )
        val s = setup(holderKeys = agreeing)
        val (holder, reader) = start(s)
        awaitRequest(holder)
        holder.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "family_name")))
        val verified = (awaitFinal(reader.state) { it.isFinal } as? ProximityReaderSession.State.Verified)?.result
            ?: throw AssertionError("reader: ${reader.state.value}")
        assertEquals("signature", verified.deviceAuth)
    }

    @Test
    fun declined(): Unit = runBlocking {
        val (holder, reader) = start(setup())
        awaitRequest(holder)
        holder.decline()
        assertEquals(ProximityPresentation.State.Declined, holder.state.value)
        assertEquals(ProximityReaderSession.State.Declined, awaitFinal(reader.state) { it.isFinal })
    }

    @Test
    fun anUnrequestedElementIsRefused(): Unit = runBlocking {
        val s = setup()
        val (holder, reader) = start(s)
        awaitRequest(holder)
        try {
            holder.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "portrait")))
            throw AssertionError("an unrequested element was presented")
        } catch (e: WalletException) {
            assertEquals(WalletException.Code.invalidSelection, e.code)
        }
        // The request still stands.
        assertTrue(holder.state.value is ProximityPresentation.State.RequestReceived)
        holder.respond(0, s.mdocID, listOf(MdocPresentation.Element(NAMESPACE, "given_name")))
        assertTrue(awaitFinal(reader.state) { it.isFinal } is ProximityReaderSession.State.Verified)
    }

    /** Offered both modes, a reader chooses central client mode; offered one, that one. */
    @Test
    fun bleModes(): Unit = runBlocking {
        val s = setup()
        for ((modes, chosen) in listOf(
            ProximityBLEMode.entries.toSet() to ProximityBLEMode.CENTRAL_CLIENT,
            setOf(ProximityBLEMode.CENTRAL_CLIENT) to ProximityBLEMode.CENTRAL_CLIENT,
            setOf(ProximityBLEMode.PERIPHERAL_SERVER) to ProximityBLEMode.PERIPHERAL_SERVER,
        )) {
            val (holder, reader) = start(s, modes)
            assertEquals("offered $modes", chosen, reader.mode)
            awaitRequest(holder)
            holder.cancel()
            assertEquals(ProximityPresentation.State.Cancelled, awaitFinal(holder.state) { it.isFinal })
        }
    }

    @Test
    fun readerCancels(): Unit = runBlocking {
        val (holder, reader) = start(setup())
        awaitRequest(holder)
        reader.cancel()
        assertEquals(ProximityReaderSession.State.Cancelled, awaitFinal(reader.state) { it.isFinal })
        assertEquals(ProximityPresentation.State.ReaderEnded, awaitFinal(holder.state) { it.isFinal })
    }

    @Test
    fun unsignedReaderShownAsUnauthenticated(): Unit = runBlocking {
        val (holder, reader) = start(setup(signed = false))
        assertFalse(reader.signed)
        val request = awaitRequest(holder)
        assertEquals(ProximityReaderIdentity.Status.Unauthenticated, request.reader.status)
        assertEquals("", request.reader.name)
        holder.cancel()
        assertEquals(ProximityPresentation.State.Cancelled, awaitFinal(holder.state) { it.isFinal })
    }

    @Test
    fun untrustedReaderRefusedWhenRequired(): Unit = runBlocking {
        val (holder, reader) = start(setup(signed = false, requireTrusted = true))
        val final = awaitFinal(holder.state) { it.isFinal }
        val error = (final as? ProximityPresentation.State.Failed)?.error as? WalletException ?: throw AssertionError("holder: $final")
        assertEquals(WalletException.Code.untrustedVerifier, error.code)
        assertEquals(ProximityReaderSession.State.Declined, awaitFinal(reader.state) { it.isFinal })
    }

    @Test
    fun noReaderTimesOut(): Unit = runBlocking {
        val s = setup()
        val (holderEnd, _) = PipeTransport.pair()
        holderEnd.peerConnects = false
        val holder = s.wallet.startProximityPresentation(ProximityTimeouts(connect = 1.seconds), holderEnd)
        val final = awaitFinal(holder.state) { it.isFinal }
        val error = (final as? ProximityPresentation.State.Failed)?.error as? ProximityException ?: throw AssertionError("holder: $final")
        assertEquals(ProximityException.Reason.TimedOut, error.reason)
    }

    private companion object {
        const val DOC_TYPE = "org.example.test.1"
        const val NAMESPACE = "org.example.test.1"
        const val APDU_TIMED_OUT = "APDU timed out"
        /** The Type 4 Tag NDEF application's AID. */
        val NDEF_AID = byteArrayOf(0xd2.toByte(), 0x76, 0, 0, 0x85.toByte(), 1, 1)
    }
}
