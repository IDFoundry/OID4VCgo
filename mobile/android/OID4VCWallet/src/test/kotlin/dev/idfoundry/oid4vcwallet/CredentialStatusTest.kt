package dev.idfoundry.oid4vcwallet

import org.junit.Assert.*
import org.junit.Test

class CredentialStatusTest {
    private fun status(text: String): CredentialStatus = json.decodeFromString<CredentialStatus>(text)

    /** A status's reason is read; one this version doesn't know is kept as it is. */
    @Test
    fun reasons() {
        for ((raw, want) in mapOf(
            "status_list" to CredentialStatus.Reason.StatusList,
            "identifier_list" to CredentialStatus.Reason.IdentifierList,
            "issuer_certificate_revoked" to CredentialStatus.Reason.IssuerCertificateRevoked,
            "issuer_untrusted" to CredentialStatus.Reason.IssuerUntrusted,
            "no_current_crl" to CredentialStatus.Reason.NoCurrentCRL,
            "unrecognized_status" to CredentialStatus.Reason.UnrecognizedStatus,
            "something_new" to CredentialStatus.Reason.Other("something_new"),
        )) {
            val s = status("""{"value": "invalid", "reason": "$raw", "checked_at": "2026-11-04T00:00:00Z"}""")
            assertEquals(raw, want, s.reason)
        }
    }

    /** A valid status, or one recorded before reasons were kept, has none. */
    @Test
    fun noReason() {
        val s = status("""{"value": "valid", "checked_at": "2026-11-04T00:00:00Z"}""")
        assertEquals(CredentialStatus.Value.Valid, s.value)
        assertNull(s.reason)
    }
}
