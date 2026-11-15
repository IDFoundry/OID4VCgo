package oid4vcgo.interop.multipaz

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.Tstr
import org.multipaz.cbor.buildCborArray
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcPublicKey
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.mdoc.engagement.DeviceEngagement
import org.multipaz.mdoc.request.DeviceRequest
import org.multipaz.mdoc.request.DeviceRequestInfo
import org.multipaz.mdoc.request.DocumentSet
import org.multipaz.mdoc.request.UseCase
import org.multipaz.mdoc.request.buildDeviceRequest
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.sessionencryption.SessionEncryption
import org.multipaz.util.fromBase64Url
import org.multipaz.util.toBase64Url
import java.io.File
import java.util.Base64
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/** The mDL the second-edition requests ask for first, as the other cases do. */
private const val MDL_DOC_TYPE = DrivingLicense.MDL_DOCTYPE
private const val MDL_NAMESPACE = DrivingLicense.MDL_NAMESPACE
private val MDL_REQUESTED = mapOf("family_name" to true, "given_name" to false, "age_over_18" to false)

/** A second document, which the holder doesn't hold, so document sets have something to group. */
private const val OTHER_DOC_TYPE = "org.example.interop.membership"
private const val OTHER_NAMESPACE = "org.example.interop"
private val OTHER_REQUESTED = mapOf("member_id" to false)

/**
 * The information the second-edition cases send: two use cases, purpose
 * hints with a negative code, and an extension the holder doesn't
 * interpret but must keep signed.
 */
private fun sampleInfo(): DeviceRequestInfo = DeviceRequestInfo.fromValues(
    useCases = listOf(
        UseCase(
            mandatory = true,
            documentSets = listOf(DocumentSet(listOf(0)), DocumentSet(listOf(0, 1))),
            purposeHints = mapOf("org.example.controller" to 3, "org.example.other" to -2),
        ),
        UseCase(mandatory = false, documentSets = listOf(DocumentSet(listOf(1))), purposeHints = emptyMap()),
    ),
    otherInfo = mapOf("org.example.interopExtension" to Tstr("not interpreted")),
)

/**
 * One second-edition request: who signs each document request, who
 * signs it as a whole, in order, its information, and what OID4VCgo's
 * holder should make of it: the reader's status, whether a verified
 * whole-request signature covers the information, and, for a
 * trusted reader, whose certificate. [otherSession] signs the whole
 * request over another session's transcript: a control.
 */
private class SecondEditionCase(
    val name: String,
    val id: String,
    val docSigner: AsymmetricKey.X509Certified?,
    val allSigners: List<AsymmetricKey.X509Certified>,
    val info: DeviceRequestInfo?,
    val wantReader: String,
    val wantSigned: Boolean,
    val wantLeaf: AsymmetricKey.X509Certified? = null,
    val otherSession: Boolean = false,
) {
    val control: Boolean get() = wantReader != "trusted"
}

/** Every case, the fixture bundle's those without [SecondEditionCase.otherSession]. */
private fun secondEditionCases(pki: Pki): List<SecondEditionCase> = listOf(
    SecondEditionCase(
        "signed only as a whole, by the trusted reader, with use cases and purpose hints",
        "whole_request_only", null, listOf(pki.reader), sampleInfo(), "trusted", true, pki.reader,
    ),
    SecondEditionCase(
        "signed as a whole, present but empty information",
        "present_empty_information", null, listOf(pki.reader), DeviceRequestInfo.fromValues(), "trusted", true, pki.reader,
    ),
    SecondEditionCase(
        "signed as a whole, no information",
        "absent_information", null, listOf(pki.reader), null, "trusted", false, pki.reader,
    ),
    SecondEditionCase(
        "signed per document and as a whole, by the trusted reader",
        "mixed_signatures", pki.reader, listOf(pki.reader), sampleInfo(), "trusted", true, pki.reader,
    ),
    SecondEditionCase(
        "signed as a whole by an untrusted reader, then the trusted one: the trusted one is the reader",
        "multiple_signers_one_trusted", null, listOf(pki.otherReader, pki.reader), sampleInfo(), "trusted", true, pki.reader,
    ),
    SecondEditionCase(
        "control: trusted per-document signatures, the whole request by an untrusted reader, are untrusted, still signed",
        "untrusted_whole_request_trusted_documents", pki.reader, listOf(pki.otherReader), sampleInfo(), "untrusted", true,
    ),
    SecondEditionCase(
        "control: a whole-request signature over another session's transcript is invalid, its information unsigned",
        "other_session", null, listOf(pki.reader), sampleInfo(), "invalid", false, otherSession = true,
    ),
)

/** [c]'s DeviceRequest, built and signed by Multipaz over [transcript]. */
private suspend fun buildSecondEdition(c: SecondEditionCase, transcript: DataItem): DeviceRequest =
    buildDeviceRequest(transcript, deviceRequestInfo = c.info) {
        addDocRequest(MDL_DOC_TYPE, mapOf(MDL_NAMESPACE to MDL_REQUESTED), docRequestInfo = null, readerKey = c.docSigner)
        addDocRequest(OTHER_DOC_TYPE, mapOf(OTHER_NAMESPACE to OTHER_REQUESTED), docRequestInfo = null, readerKey = c.docSigner)
        for (signer in c.allSigners) addReaderAuthAll(signer)
    }

/**
 * What OID4VCgo's peer reports of a holder's request information
 * (scripts/peer's describeRequestInfo), for [info] covered or not.
 */
private fun describe(info: DeviceRequestInfo?, signed: Boolean): String {
    info ?: return "none"
    return "signed=$signed use_cases=" + info.useCases.joinToString("") { uc ->
        val sets = uc.documentSets.joinToString("") { set -> set.docRequestIds.joinToString(",", "[", "]") }
        val hints = uc.purposeHints.entries.map { "${it.key}:${it.value}" }.sorted().joinToString(",")
        "[mandatory=${uc.mandatory} sets=$sets hints=$hints]"
    }
}

/** The SessionTranscript: DeviceEngagementBytes, EReaderKeyBytes, Handover (§9.1.5.1). */
private fun sessionTranscript(engagement: ByteArray, eReaderKey: EcPublicKey): DataItem = buildCborArray {
    add(Tagged(Tagged.ENCODED_CBOR, Bstr(engagement)))
    add(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(eReaderKey.toCoseKey().toDataItem()))))
    add(Simple.NULL)
}

/**
 * The second-edition cases: a Multipaz reader sends OID4VCgo's holder
 * (walletflow) requests built and signed with Multipaz's request
 * builder — readerAuthAll, deviceRequestInfo — and checks the reader
 * status and request information the holder reports, then verifies its
 * answer. Whole messages, no radio.
 */
class ReaderAuthAllCases(private val peer: Peer, private val pki: Pki) : Checks() {
    /** Runs every case, returning how many failed. */
    suspend fun run(): Int {
        println("### Multipaz reader, second edition (readerAuthAll, deviceRequestInfo) → OID4VCgo's holder (walletflow)")
        for (c in secondEditionCases(pki)) {
            check(c.name) { holderSaw(c) }
        }
        return failed
    }

    /** null if the holder made of [c] what it should, or what went wrong. */
    private suspend fun holderSaw(c: SecondEditionCase): String? {
        val start = peer.call("holder_start", "mac" to false)
        start.error?.let { return "holder_start: $it" }
        val engagement = start.string("qr")!!.removePrefix("mdoc:").fromBase64Url()
        val deviceEngagement = DeviceEngagement.fromDataItem(Cbor.decode(engagement))
        val eReaderKey = Crypto.createEcPrivateKey(deviceEngagement.eDeviceKey.curve)
        val transcript = sessionTranscript(engagement, eReaderKey.publicKey)
        val session = SessionEncryption(MdocRole.MDOC_READER, eReaderKey, deviceEngagement.eDeviceKey, Cbor.encode(transcript))
        val signedOver = if (c.otherSession) buildCborArray { add(Simple.NULL); add(Simple.NULL); add(Tstr("another session")) } else transcript
        val request = buildSecondEdition(c, signedOver)
        val answer = peer.call("holder_message", "msg" to session.encryptMessage(Cbor.encode(request.toDataItem()), null).toBase64Url())
        answer.error?.let { return "the holder: $it" }
        val saw = answer.string("reader")
        val info = answer.string("request_info")
        val want = describe(c.info, c.wantSigned)
        when {
            saw != c.wantReader -> return "the holder took the reader as $saw, want ${c.wantReader}"
            info != want -> return "the holder's request information was '$info', want '$want'"
        }
        reason = "reader $saw, ${info!!.substringBefore(" use_cases")}"
        // The holder answered the mDL request: the session completes.
        val (plaintext, _) = session.decryptMessage(answer.string("send")!!.fromBase64Url())
        plaintext ?: return "the holder sent no DeviceResponse"
        DeviceResponse.fromDataItem(Cbor.decode(plaintext)).verify(sessionTranscript = transcript, eReaderKey = AsymmetricKey.anonymous(eReaderKey))
        return null
    }
}

/**
 * The offline fixture bundle for OID4VCgo's Go tests
 * (proximity/testdata/multipaz/reader_auth_all.json): the same requests,
 * built and signed by Multipaz over a fixed synthetic session transcript
 * by certificates valid at a fixed time, each signature verified by
 * Multipaz before it is written. Key material is fresh each time: a
 * regenerated bundle has equivalent cases, not the same bytes.
 */
object ReaderAuthAllFixtures {
    /** When the bundle's certificates are valid: the Go tests verify at this time. */
    val VERIFICATION_TIME: Instant = Instant.parse("2026-01-01T00:00:00Z")

    suspend fun write(file: File) {
        // Valid from an hour before VERIFICATION_TIME for 20 years: fixed dates, which Multipaz's
        // own verification, at the current time, also accepts.
        val pki = Pki.create(VERIFICATION_TIME, validFor = (20 * 365).days)
        // A QR-handover-shaped transcript of fixed, synthetic members.
        val transcript = buildCborArray {
            add(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(Tstr("synthetic DeviceEngagement")))))
            add(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(Tstr("synthetic EReaderKey")))))
            add(Simple.NULL)
        }
        val transcriptBytes = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(transcript))))
        val b64 = Base64.getEncoder()
        val requests = secondEditionCases(pki).filterNot { it.otherSession }.map { c ->
            val encoded = Cbor.encode(buildSecondEdition(c, transcript).toDataItem())
            // Multipaz verifies every signature it made before it is written.
            DeviceRequest.fromDataItem(Cbor.decode(encoded)).verifyReaderAuthentication(transcript)
            c to encoded
        }
        val bundle = buildJsonObject {
            put("description", "ISO/IEC 18013-5 second-edition DeviceRequests built and signed by Multipaz's request builder " +
                "(interop/multipaz/driver -fixtures), for proximity's Go tests. Test keys and certificates only.")
            put("generator_version", "multipaz ${multipazVersion()}")
            put("verification_time", VERIFICATION_TIME.toString())
            put("session_transcript_bytes", b64.encodeToString(transcriptBytes))
            put("trust_anchors", pki.readerRoot.toPem())
            putJsonArray("cases") {
                for ((c, encoded) in requests) {
                    add(buildJsonObject {
                        put("name", c.id)
                        put("description", c.name)
                        put("device_request", b64.encodeToString(encoded))
                        putJsonObject("expected") {
                            put("reader_status", c.wantReader)
                            put("request_info_signed", c.wantSigned)
                            put("reader_leaf", c.wantLeaf?.certChain?.certificates?.first()?.toPem()?.let(::JsonPrimitive) ?: JsonNull)
                            put("documents", documentsJson())
                            put("request_info", c.info?.let(::infoJson) ?: JsonNull)
                        }
                    })
                }
            }
        }
        file.parentFile?.mkdirs()
        file.writeText(Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), bundle) + "\n")
    }

    private fun documentsJson(): JsonArray = buildJsonArray {
        for ((docType, ns, elements) in listOf(
            Triple(MDL_DOC_TYPE, MDL_NAMESPACE, MDL_REQUESTED),
            Triple(OTHER_DOC_TYPE, OTHER_NAMESPACE, OTHER_REQUESTED),
        )) {
            add(buildJsonObject {
                put("doctype", docType)
                putJsonArray("elements") {
                    for ((element, retain) in elements) {
                        add(buildJsonObject {
                            put("namespace", ns)
                            put("identifier", element)
                            put("intent_to_retain", retain)
                        })
                    }
                }
            })
        }
    }

    private fun infoJson(info: DeviceRequestInfo): JsonElement = buildJsonObject {
        putJsonArray("use_cases") {
            for (uc in info.useCases) {
                add(buildJsonObject {
                    put("mandatory", uc.mandatory)
                    putJsonArray("document_sets") {
                        for (set in uc.documentSets) add(JsonArray(set.docRequestIds.map(::JsonPrimitive)))
                    }
                    putJsonObject("purpose_hints") {
                        for ((id, code) in uc.purposeHints) put(id, code)
                    }
                })
            }
        }
    }

    /** The Multipaz release on the class path, from its jar's name. */
    private fun multipazVersion(): String =
        System.getProperty("java.class.path").split(File.pathSeparator)
            .firstNotNullOfOrNull { Regex("""^multipaz-jvm-(.+)\.jar$""").find(File(it).name)?.groupValues?.get(1) }
            ?: "unknown"
}
