package dev.idfoundry.oid4vcwallet

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class CRLRefreshResultTest {
    /** The Go side's RefreshCRLs JSON decodes, its time as an Instant. */
    @Test
    fun decodes() {
        val r = CRLRefreshResult.of(
            """{"abi": 14, "results": [{"url": "http://ca.example/a.crl", "outcome": "updated"},
               {"url": "http://ca.example/b.crl", "outcome": "failed", "error": "[network] network error: refused"}],
               "crls": "-----BEGIN X509 CRL-----\n", "next_refresh": "2026-11-04T10:00:00Z"}""",
        )
        assertEquals(listOf(CRLRefreshResult.Outcome.UPDATED, CRLRefreshResult.Outcome.FAILED), r.results.map { it.outcome })
        assertNull(r.results[0].error)
        assertEquals("[network] network error: refused", r.results[1].error)
        assertTrue(r.anyFailed)
        assertEquals("-----BEGIN X509 CRL-----\n", r.crls)
        assertEquals(Instant.parse("2026-11-04T10:00:00Z"), r.nextRefresh)
    }

    /** A result the Go side didn't write is the wrapper's internal error. */
    @Test
    fun refusesMalformed() {
        for (text in listOf(
            """{"results": [{"url": "x", "outcome": "maybe"}], "crls": "", "next_refresh": "2026-11-04T10:00:00Z"}""",
            """{"results": [], "crls": "", "next_refresh": "soon"}""",
        )) {
            val e = assertThrows(WalletException::class.java) { CRLRefreshResult.of(text) }
            assertEquals(WalletException.Code.internal, e.code)
        }
    }

    /** The distribution points reach the Go side under its keys. */
    @Test
    fun configurationKeys() {
        val config = WalletConfiguration(
            crlDistributionPoints = listOf(CRLDistributionPoint("http://ca.example/ca.crl", "PEM")),
            crlDistributionPointsFromRoots = true,
            crlRequireHTTPS = true,
            // The default reads the device's locales, an Android API.
            locales = listOf("en"),
        )
        val o = json.parseToJsonElement(json.encodeToString(WalletConfiguration.serializer(), config)).jsonObject
        val point = o["crl_distribution_points"]!!.jsonArray[0] as JsonObject
        assertEquals("http://ca.example/ca.crl", point["url"]!!.jsonPrimitive.content)
        assertEquals("PEM", point["issuer"]!!.jsonPrimitive.content)
        assertEquals("true", o["crl_distribution_points_from_roots"]!!.jsonPrimitive.content)
        assertEquals("true", o["crl_require_https"]!!.jsonPrimitive.content)
    }
}
