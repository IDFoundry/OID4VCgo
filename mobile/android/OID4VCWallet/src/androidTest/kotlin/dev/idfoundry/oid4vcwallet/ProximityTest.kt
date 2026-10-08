package dev.idfoundry.oid4vcwallet

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
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

    private class Setup(val wallet: Wallet, val reader: ProximityReader, val mdocID: String)

    /** A wallet holding the test mdoc and recognizing the test reader, and that reader. */
    private suspend fun setup(signed: Boolean = true, requireTrusted: Boolean = false): Setup {
        val env = TestEnv().also { envs += it }
        val readerSetup = json.parseToJsonElement(env.env.proximityReader(KeyStoreAdapter(keys))).jsonObject
        val readerConfig = json.decodeFromString(ProximityReaderConfiguration.serializer(), readerSetup["reader_config"]!!.jsonPrimitive.content)
        val wallet = Wallet(
            env.configuration.copy(
                mdocReaderRoots = readerSetup["mdoc_reader_roots"]!!.jsonPrimitive.content,
                mdocReaderRequireEKU = true,
                requireTrustedMdocReader = requireTrusted,
            ),
            keys, InMemoryCredentialStore(), ProviderOf(env),
        )
        val s = wallet.startIssuance(env.env.authorizationCodeOffer())
        s.completeAuthorization(env.approve(s.beginAuthorization()))
        val mdocID = s.requestCredentials().credentials.first { it.format == "mso_mdoc" }.id
        s.close()
        val reader = if (signed) {
            ProximityReader(readerConfig, keys)
        } else {
            ProximityReader(ProximityReaderConfiguration(issuerRoots = readerConfig.issuerRoots))
        }
        return Setup(wallet, reader, mdocID)
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
        assertEquals(ProximityPresentation.State.Presented(false), awaitFinal(holder.state) { it.isFinal })
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
    }
}
