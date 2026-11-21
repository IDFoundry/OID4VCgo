package dev.idfoundry.oid4vcwallet

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The grouped configurations keep the flat JSON they had before their
 * options were grouped: the keys Go reads (ABI.md), in the same order,
 * with defaults left out as before.
 */
class ConfigurationJSONTest {
    // Strict, as an app decoding its own configuration may be: an unknown key is refused.
    private val strict = Json

    private val walletJSON = """{"client_id":"wallet","redirect_uri":"com.example.wallet:/callback",""" +
        """"issuer_roots":"IR","verifier_roots":"VR","registrar_roots":"RR","mdoc_reader_roots":"MRR",""" +
        """"mdoc_reader_require_eku":true,"require_trusted_mdoc_reader":true,"require_signed_dcapi_requests":true,""" +
        """"accept_x509_san_dns":true,"development":true,"development_roots":"DR","locales":["de","en"],""" +
        """"batch_size":3,"request_refresh":true,"copy_policy":"per_verifier",""" +
        """"tls_pins":{"issuer.example":["pin1","pin2"]},"allowed_private_hosts":["internal.example"],""" +
        """"issuance_profile":"haip","proof_key_by_jwk":true,"proof_key_by_index":true,""" +
        """"proximity_device_auth":"mac_preferred","verifier_require_eku":"1.2.3","registrar_require_eku":"1.2.4",""" +
        """"status_issuers":{"https://issuer.example":["https://status.example"]},"require_issuer_name":true,""" +
        """"issuer_metadata_roots":"IMR","require_signed_issuer_metadata":true,"require_issuer_metadata_name":true,""" +
        """"max_issuer_metadata_age_seconds":3600,"issuer_require_eku":"1.2.5","issuer_metadata_require_eku":"1.2.6",""" +
        """"allow_foreign_iss":true,"credential_issuers":["https://issuer.example"],"allow_any_credential_issuer":true,""" +
        """"mdoc_issuer_roots":"MIR","mdoc_issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":"MDL"},""" +
        """"mdoc_issuer_require_eku":"1.0.18013.5.1.2","crls":"CRLS","revocation":["issuer","verifier"],""" +
        """"crl_issuers":"CI","no_revocation_check":["registrar","status"],"accept_mdl_signer_without_eku":true,""" +
        """"crl_distribution_points":[{"url":"https://ca.example/ca.crl","issuer":"CA"}],""" +
        """"crl_distribution_points_from_roots":true,"crl_require_https":true,"status_max_bytes":2048,""" +
        """"identifier_list_max_bytes":4096,"status_cache_max_age_seconds":600,"status_cache_dir":"/data/cache",""" +
        """"verifier_redirect_schemes":["com.example.verifier"]}"""

    private val readerJSON = """{"issuer_roots":"IR","reader_key_id":"reader","reader_chain":"CHAIN",""" +
        """"max_clock_skew_seconds":300,"issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":"MDL"},"crls":"CRLS",""" +
        """"revocation":["issuer"],"crl_issuers":"CI","crl_distribution_points":[{"url":"https://ca.example/ca.crl","issuer":"CA"}],""" +
        """"crl_distribution_points_from_roots":true,"crl_require_https":true,"accept_mdl_signer_without_eku":true,""" +
        """"no_revocation_check":["status"],"any_issuer_for_any_type":true,"status":"check","development":true,""" +
        """"development_roots":"DR","status_max_bytes":2048,"identifier_list_max_bytes":4096,""" +
        """"status_cache_max_age_seconds":600,"status_cache_dir":"/data/cache"}"""

    @Test
    fun walletRoundTrips() {
        val c = strict.decodeFromString(WalletConfiguration.serializer(), walletJSON)
        assertEquals(walletJSON, strict.encodeToString(WalletConfiguration.serializer(), c))
        assertEquals(
            WalletConfiguration(
                clientID = "wallet",
                redirectURI = "com.example.wallet:/callback",
                issuers = WalletConfiguration.IssuerTrust(
                    roots = "IR", requireEKU = "1.2.5", mdocRoots = "MIR",
                    mdocRootsByDocType = mapOf("org.iso.18013.5.1.mDL" to "MDL"), mdocRequireEKU = "1.0.18013.5.1.2",
                    acceptMDLSignerWithoutEKU = true, requireIssuerName = true, allowForeignIss = true,
                    statusIssuers = mapOf("https://issuer.example" to listOf("https://status.example")),
                    credentialIssuers = listOf("https://issuer.example"), allowAnyCredentialIssuer = true,
                ),
                issuerMetadata = WalletConfiguration.IssuerMetadataTrust(
                    roots = "IMR", requireEKU = "1.2.6", requireSigned = true, requireName = true, maxAgeSeconds = 3600,
                ),
                verifiers = WalletConfiguration.VerifierTrust(
                    roots = "VR", requireEKU = "1.2.3", acceptX509SANDNS = true, registrarRoots = "RR",
                    registrarRequireEKU = "1.2.4", mdocReaderRoots = "MRR", mdocReaderRequireEKU = true,
                    requireTrustedMdocReader = true, requireSignedDCAPIRequests = true,
                ),
                revocation = WalletConfiguration.Revocation(
                    roles = listOf(WalletConfiguration.RevocationRole.ISSUER, WalletConfiguration.RevocationRole.VERIFIER),
                    declined = listOf(WalletConfiguration.RevocationRole.REGISTRAR, WalletConfiguration.RevocationRole.STATUS),
                    crls = "CRLS", crlIssuers = "CI",
                    distributionPoints = listOf(CRLDistributionPoint("https://ca.example/ca.crl", "CA")),
                    distributionPointsFromRoots = true, requireHTTPS = true,
                ),
                status = StatusLists(maxBytes = 2048, identifierListMaxBytes = 4096, cacheMaxAgeSeconds = 600, cacheDir = "/data/cache"),
                network = WalletConfiguration.Network(
                    tlsPins = mapOf("issuer.example" to listOf("pin1", "pin2")), allowedPrivateHosts = listOf("internal.example"),
                ),
                issuance = WalletConfiguration.IssuanceOptions(
                    locales = listOf("de", "en"), batchSize = 3, requestRefresh = true,
                    profile = WalletConfiguration.IssuanceProfile.HAIP, proofKeyByJWK = true, proofKeyByIndex = true,
                ),
                presentation = WalletConfiguration.PresentationOptions(
                    copyPolicy = WalletConfiguration.CopyPolicy.PER_VERIFIER,
                    proximityDeviceAuth = WalletConfiguration.ProximityDeviceAuth.MAC_PREFERRED,
                    verifierRedirectSchemes = listOf("com.example.verifier"),
                ),
                development = Development(roots = "DR"),
            ),
            c,
        )
    }

    @Test
    fun readerRoundTrips() {
        val c = strict.decodeFromString(ProximityReaderConfiguration.serializer(), readerJSON)
        assertEquals(readerJSON, strict.encodeToString(ProximityReaderConfiguration.serializer(), c))
        assertEquals(
            ProximityReaderConfiguration(
                issuers = ProximityReaderConfiguration.IssuerTrust(
                    roots = "IR", rootsByDocType = mapOf("org.iso.18013.5.1.mDL" to "MDL"),
                    anyIssuerForAnyType = true, acceptMDLSignerWithoutEKU = true,
                ),
                readerAuthentication = ProximityReaderConfiguration.ReaderAuthentication(keyID = "reader", chain = "CHAIN"),
                maxClockSkewSeconds = 300,
                revocation = ProximityReaderConfiguration.Revocation(
                    roles = listOf(ProximityReaderConfiguration.RevocationRole.ISSUER),
                    declined = listOf(ProximityReaderConfiguration.RevocationRole.STATUS),
                    crls = "CRLS", crlIssuers = "CI",
                    distributionPoints = listOf(CRLDistributionPoint("https://ca.example/ca.crl", "CA")),
                    distributionPointsFromRoots = true, requireHTTPS = true,
                ),
                status = StatusLists(maxBytes = 2048, identifierListMaxBytes = 4096, cacheMaxAgeSeconds = 600, cacheDir = "/data/cache"),
                statusCheck = ProximityReaderConfiguration.StatusCheck.CHECK,
                development = Development(roots = "DR"),
            ),
            c,
        )
    }

    /** Defaults are left out, as before: only the locales, which always go. */
    @Test
    fun defaultsOmitted() {
        val wallet = WalletConfiguration(issuance = WalletConfiguration.IssuanceOptions(locales = listOf("en")))
        assertEquals("""{"locales":["en"]}""", strict.encodeToString(WalletConfiguration.serializer(), wallet))
        val reader = ProximityReaderConfiguration(ProximityReaderConfiguration.IssuerTrust(""))
        assertEquals("""{"issuer_roots":""}""", strict.encodeToString(ProximityReaderConfiguration.serializer(), reader))
        // An empty development configuration is still development.
        assertEquals(
            """{"issuer_roots":"","development":true}""",
            strict.encodeToString(ProximityReaderConfiguration.serializer(), reader.copy(development = Development())),
        )
    }

    @Test
    fun unknownKeyRefused() {
        assertThrows(SerializationException::class.java) {
            strict.decodeFromString(WalletConfiguration.serializer(), """{"locales":["en"],"issuerRoots":"IR"}""")
        }
        assertThrows(SerializationException::class.java) {
            strict.decodeFromString(ProximityReaderConfiguration.serializer(), """{"issuer_roots":"","issuerRoots":"IR"}""")
        }
    }

    /** The removed `require_mdl_signer_eku` is still read from old JSON, and ignored. */
    @Test
    fun requireMDLSignerEKUIgnored() {
        val c = strict.decodeFromString(ProximityReaderConfiguration.serializer(), """{"issuer_roots":"IR","require_mdl_signer_eku":true}""")
        assertEquals(ProximityReaderConfiguration(ProximityReaderConfiguration.IssuerTrust("IR")), c)
        assertEquals("""{"issuer_roots":"IR"}""", strict.encodeToString(ProximityReaderConfiguration.serializer(), c))
    }

    /** The removed `require_mdl_signer_eku` with `accept_mdl_signer_without_eku`, which Go refused, is refused. */
    @Test
    fun requireMDLSignerEKUWithAcceptRefused() {
        val e = assertThrows(SerializationException::class.java) {
            strict.decodeFromString(
                ProximityReaderConfiguration.serializer(),
                """{"issuer_roots":"IR","require_mdl_signer_eku":true,"accept_mdl_signer_without_eku":true}""",
            )
        }
        assertEquals("require_mdl_signer_eku and accept_mdl_signer_without_eku can't both be set", e.message)
        // false, the no-op, is accepted with it.
        val c = strict.decodeFromString(
            ProximityReaderConfiguration.serializer(),
            """{"issuer_roots":"IR","require_mdl_signer_eku":false,"accept_mdl_signer_without_eku":true}""",
        )
        assertEquals(true, c.issuers.acceptMDLSignerWithoutEKU)
        assertEquals("""{"issuer_roots":"IR","accept_mdl_signer_without_eku":true}""", strict.encodeToString(ProximityReaderConfiguration.serializer(), c))
    }

    /** development_roots without development, which Go refuses, is refused. */
    @Test
    fun developmentRootsNeedDevelopment() {
        assertThrows(SerializationException::class.java) {
            strict.decodeFromString(WalletConfiguration.serializer(), """{"locales":["en"],"development_roots":"DR"}""")
        }
        assertThrows(SerializationException::class.java) {
            strict.decodeFromString(ProximityReaderConfiguration.serializer(), """{"issuer_roots":"","development_roots":"DR"}""")
        }
    }

    /** A reader key without its chain is kept, for Go to refuse as before. */
    @Test
    fun partialReaderAuthenticationKept() {
        val c = strict.decodeFromString(ProximityReaderConfiguration.serializer(), """{"issuer_roots":"","reader_key_id":"reader"}""")
        assertEquals(ProximityReaderConfiguration.ReaderAuthentication("reader", ""), c.readerAuthentication)
    }
}
