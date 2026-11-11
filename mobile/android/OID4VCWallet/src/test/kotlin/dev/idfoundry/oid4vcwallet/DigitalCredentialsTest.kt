package dev.idfoundry.oid4vcwallet

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64

/** DigitalCredentials' parts that run on the host JVM. */
class DigitalCredentialsTest {
    private val openid4vp = """{"protocol":"openid4vp-v1-signed","data":{"request":"eyJ"}}"""
    private val mdoc = """{"protocol":"org-iso-mdoc","data":{"deviceRequest":"o2","encryptionInfo":"gm"}}"""

    @Test
    fun prefersOpenID4VP() {
        // A page offering both is answered over OpenID4VP, whatever their order.
        val chosen = DigitalCredentials.firstSupported("""{"requests":[$mdoc,$openid4vp]}""")
        assertEquals("openid4vp-v1-signed", chosen?.first)
        assertEquals("eyJ", Json.parseToJsonElement(chosen!!.second).jsonObject["request"]?.jsonPrimitive?.content)
    }

    @Test
    fun mdocWhenAlone() {
        val chosen = DigitalCredentials.firstSupported("""{"requests":[{"protocol":"other","data":{}},$mdoc]}""")
        assertEquals(DigitalCredentials.MDOC_PROTOCOL, chosen?.first)
    }

    @Test
    fun refusesWhatItCantAnswer() {
        for (json in listOf(
            "",
            "[]",
            """{"requests":{}}""",
            """{"requests":[{"protocol":"other","data":{}}]}""",
            """{"requests":[{"protocol":"openid4vp-v1-signed","data":"a string"}]}""",
            """{"requests":[{"protocol":7,"data":{}}]}""",
        )) {
            assertNull(json, DigitalCredentials.firstSupported(json))
        }
    }

    @Test
    fun noCertificateNoAppOrigin() {
        // Not an origin every app without a certificate would share.
        assertNull(DigitalCredentials.appOrigin(null))
        assertNull(DigitalCredentials.appOrigin(ByteArray(0)))
    }

    @Test
    fun mdocResponseData() {
        val encrypted = byteArrayOf(0x82.toByte(), 0x65, 0xFF.toByte(), 0xFE.toByte())
        val data = Json.parseToJsonElement(MdocPresentation.Response(encrypted).responseData()).jsonObject
        assertEquals(setOf("response"), data.keys)
        val response = data["response"]!!.jsonPrimitive.content
        // base64url, unpadded (ISO/IEC TS 18013-7 Annex C).
        assertEquals(-1, response.indexOfAny(charArrayOf('=', '+', '/')))
        assertArrayEquals(encrypted, Base64.getUrlDecoder().decode(response))
    }

    @Test
    fun claimNamesOnlyByDefault() {
        // Values (a portrait among them) reach the system's registry before consent only when asked for.
        assertFalse(DigitalCredentials.RegistrationOptions().claimValues)
    }

    @Test
    fun claimValues() {
        assertEquals("Doe", DigitalCredentials.matchValue(JsonPrimitive("Doe")))
        assertEquals(42L, DigitalCredentials.matchValue(JsonPrimitive(42)))
        assertEquals(true, DigitalCredentials.matchValue(JsonPrimitive(true)))
        assertEquals("—", DigitalCredentials.matchValue(JsonNull))
        assertEquals("a, b", DigitalCredentials.text(JsonArray(listOf(JsonPrimitive("a"), JsonPrimitive("b")))))
        assertEquals("yes", DigitalCredentials.text(JsonPrimitive(true)))
    }

    @Test
    fun cardColours() {
        assertEquals(0xFF12107C.toInt(), DigitalCredentials.cssColor("#12107C"))
        assertEquals(0xFFFFAA00.toInt(), DigitalCredentials.cssColor(" #fa0 "))
        assertNull(DigitalCredentials.cssColor("red"))
        assertNull(DigitalCredentials.cssColor("#12345"))
        assertNull(DigitalCredentials.cssColor(null))
    }

    @Test
    fun credentialManagerFingerprint() {
        val sha256 = DigitalCredentials.GOOGLE_PLAY_SERVICES.certificateSHA256.single()
        assertEquals(32, sha256.size)
        assertEquals("f0fd6c5b", sha256.take(4).joinToString("") { "%02x".format(it) })
        assertEquals("db83", sha256.takeLast(2).joinToString("") { "%02x".format(it) })
    }
}
