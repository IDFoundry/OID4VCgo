package dev.idfoundry.oid4vcwallet

import androidx.test.ext.junit.runners.AndroidJUnit4
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

/** Answering a reader's request for several documents in one response. */
@RunWith(AndroidJUnit4::class)
class MultiDocumentTest {
    private val prefix = "org.idfoundry.oid4vcgo.multidoc.${System.nanoTime()}."
    private val envs = mutableListOf<TestEnv>()
    private val keys = AndroidKeystoreKeyStore(AndroidKeystoreKeyStore.Options(holderUserAuthentication = false, aliasPrefix = prefix))
    private val timeouts = ProximityTimeouts(connect = 10.seconds, request = 10.seconds, idle = 30.seconds)

    @After
    fun cleanUp() {
        envs.forEach { it.close() }
        keys.deleteKeys(emptySet())
    }

    private class Setup(val wallet: Wallet, val reader: ProximityReader, val ids: Map<String, String>)

    /** A wallet holding mdocs of two types, recognizing the test reader, and that reader. */
    private suspend fun setup(): Setup {
        val env = TestEnv().also { envs += it }
        val readerSetup = json.parseToJsonElement(env.env.proximityReader(KeyStoreAdapter(keys))).jsonObject
        val readerConfig = json.decodeFromString(ProximityReaderConfiguration.serializer(), readerSetup["reader_config"]!!.jsonPrimitive.content)
            .copy(statusCheck = ProximityReaderConfiguration.StatusCheck.CHECK)
        val wallet = Wallet(
            env.configuration.copy(mdocReaderRoots = readerSetup["mdoc_reader_roots"]!!.jsonPrimitive.content, mdocReaderRequireEKU = true),
            keys, InMemoryCredentialStore(), ProviderOf(env),
        )
        val s = wallet.startIssuance(env.env.multiDocumentOffer())
        s.completeAuthorization(env.approve(s.beginAuthorization()))
        val ids = s.requestCredentials().credentials.associate { it.doctype!! to it.id }
        s.close()
        return Setup(wallet, ProximityReader(readerConfig, keys), ids)
    }

    private fun start(s: Setup): Pair<ProximityPresentation, ProximityReaderSession> {
        val (holderEnd, readerEnd) = PipeTransport.pair()
        val holder = s.wallet.startProximityPresentation(timeouts, holderEnd)
        val reader = s.reader.startWith(
            holder.qrCode,
            listOf(
                ProximityReader.DocumentRequest(DOC_TYPE_1, mapOf(DOC_TYPE_1 to listOf("family_name"))),
                ProximityReader.DocumentRequest(DOC_TYPE_2, mapOf(DOC_TYPE_2 to listOf("family_name", "given_name"))),
            ),
            timeouts, readerEnd,
        )
        return holder to reader
    }

    private suspend fun awaitRequest(holder: ProximityPresentation): ProximityPresentation.Request =
        (
            withTimeout(30.seconds) {
                holder.state.first { it is ProximityPresentation.State.RequestReceived || it.isFinal }
            } as? ProximityPresentation.State.RequestReceived
            ?: throw AssertionError("no request: ${holder.state.value}")
            ).request

    /** Two answers in one response: the reader verifies both. */
    @Test
    fun respondWithTwoDocuments(): Unit = runBlocking {
        val s = setup()
        val (holder, reader) = start(s)
        val request = awaitRequest(holder)
        assertEquals(listOf(DOC_TYPE_1, DOC_TYPE_2), request.documents.map { it.doctype })

        val responded = holder.respond(
            listOf(
                MdocPresentation.Answer(1, s.ids.getValue(DOC_TYPE_2), listOf(MdocPresentation.Element(DOC_TYPE_2, "given_name"))),
                MdocPresentation.Answer(0, s.ids.getValue(DOC_TYPE_1), listOf(MdocPresentation.Element(DOC_TYPE_1, "family_name"))),
            ),
        )
        assertFalse(responded.linkable)
        assertTrue(responded.linkableCredentials.isEmpty())
        val result = withTimeout(30.seconds) { reader.state.first { it.isFinal } }
        val verified = result as? ProximityReaderSession.State.Verified ?: throw AssertionError("reader: $result")
        assertEquals(listOf(DOC_TYPE_1, DOC_TYPE_2), verified.documents.map { it.doctype })
        assertEquals(setOf("family_name"), verified.documents[0].claims[DOC_TYPE_1]!!.jsonObject.keys)
        assertEquals("Jane", verified.documents[1].claims[DOC_TYPE_2]!!.jsonObject["given_name"]!!.jsonPrimitive.content)
        assertTrue(verified.documents.all { it.status == MdocStatus.Valid })
        assertEquals(ProximityPresentation.State.Presented(false), withTimeout(30.seconds) { holder.state.first { it.isFinal } })
    }

    /** A refused answer sends nothing: the request stands, and a good answer then goes through. */
    @Test
    fun refusedAnswersLeaveTheRequest(): Unit = runBlocking {
        val s = setup()
        val (holder, reader) = start(s)
        awaitRequest(holder)
        val one = MdocPresentation.Answer(0, s.ids.getValue(DOC_TYPE_1), listOf(MdocPresentation.Element(DOC_TYPE_1, "family_name")))
        for (answers in listOf(emptyList(), listOf(one, one), listOf(one.copy(elements = listOf(MdocPresentation.Element(DOC_TYPE_1, "given_name")))))) {
            try {
                holder.respond(answers)
                throw AssertionError("respond($answers) succeeded")
            } catch (e: WalletException) {
                assertEquals(WalletException.Code.invalidSelection, e.code)
            }
            assertTrue(holder.state.value is ProximityPresentation.State.RequestReceived)
        }
        holder.respond(listOf(one))
        val result = withTimeout(30.seconds) { reader.state.first { it.isFinal } }
        val verified = result as? ProximityReaderSession.State.Verified ?: throw AssertionError("reader: $result")
        assertEquals(listOf(DOC_TYPE_1), verified.documents.map { it.doctype })
    }

    /** The one-document respond still answers a request for several, with that one. */
    @Test
    fun oneDocumentRespondStillWorks(): Unit = runBlocking {
        val s = setup()
        val (holder, reader) = start(s)
        awaitRequest(holder)
        assertFalse(holder.respond(1, s.ids.getValue(DOC_TYPE_2), listOf(MdocPresentation.Element(DOC_TYPE_2, "family_name"))))
        val result = withTimeout(30.seconds) { reader.state.first { it.isFinal } }
        val verified = result as? ProximityReaderSession.State.Verified ?: throw AssertionError("reader: $result")
        assertEquals(DOC_TYPE_2, verified.result.doctype)
    }

    private companion object {
        const val DOC_TYPE_1 = "org.example.test.1"
        const val DOC_TYPE_2 = "org.example.test.2"
    }
}
