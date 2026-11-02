package dev.idfoundry.oid4vcwallet

import org.junit.Assert.*
import org.junit.Test

class VerifiedJsonTest {
    private fun verified(status: String): VerifiedMdoc = json.decodeFromString<VerifiedJSON>(
        """{"doctype": "org.iso.18013.5.1.mDL", "claims": {}, "valid_from": "2026-10-01T00:00:00Z",
           "valid_until": "2027-10-01T00:00:00Z", "device_auth": "signature", "status": $status}""",
    ).toVerified()

    /** An MSO naming both lists shows both: the identifier list may revoke it while the status list says valid. */
    @Test
    fun bothLists() {
        val v = verified(
            """{"type": "status_list", "uri": "https://status.example/1", "idx": 412,
               "identifier_list": {"type": "identifier_list", "uri": "https://status.example/ids", "id": "qw=="}}""",
        )
        assertEquals(VerifiedMdoc.StatusListReference("https://status.example/1", 412), v.statusList)
        assertEquals(VerifiedMdoc.IdentifierListReference("https://status.example/ids", "qw=="), v.identifierList)
    }

    @Test
    fun identifierListAlone() {
        val v = verified("""{"type": "identifier_list", "uri": "https://status.example/ids", "id": "qw=="}""")
        assertNull(v.statusList)
        assertEquals(VerifiedMdoc.IdentifierListReference("https://status.example/ids", "qw=="), v.identifierList)
    }

    @Test
    fun statusListAlone() {
        val v = verified("""{"type": "status_list", "uri": "https://status.example/1", "idx": 3}""")
        assertEquals(VerifiedMdoc.StatusListReference("https://status.example/1", 3), v.statusList)
        assertNull(v.identifierList)
    }
}
