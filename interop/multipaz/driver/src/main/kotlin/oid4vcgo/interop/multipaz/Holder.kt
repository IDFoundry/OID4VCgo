package oid4vcgo.interop.multipaz

import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.X509Cert
import org.multipaz.document.Document
import org.multipaz.document.DocumentStore
import org.multipaz.document.buildDocumentStore
import org.multipaz.documenttype.DocumentTypeRepository
import org.multipaz.documenttype.knowntypes.DrivingLicense
import org.multipaz.documenttype.knowntypes.EUPersonalID
import org.multipaz.mdoc.credential.MdocCredential
import org.multipaz.presentment.SimplePresentmentSource
import org.multipaz.request.TrustedRequesterIdentity
import org.multipaz.prompt.promptModelSilentConsent
import org.multipaz.securearea.SecureAreaRepository
import org.multipaz.securearea.software.SoftwareCreateKeySettings
import org.multipaz.securearea.software.SoftwareSecureArea
import org.multipaz.storage.ephemeral.EphemeralStorage
import org.multipaz.trustmanagement.TrustManager
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.util.truncateToWholeSeconds
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

/** The signature credential's domain, and the key agreement (deviceMac) one's. */
const val DOMAIN_SIGNATURE = "mdoc"
const val DOMAIN_MAC = "mdoc_mac"
const val DOMAIN_SDJWT = "sdjwt"

/**
 * Multipaz's holder: an mDL of Multipaz's sample data, issued under
 * [Pki]'s document signer, with two credentials, one whose key signs
 * and one whose key agrees (deviceMac), and an SD-JWT VC PID, trusting
 * OID4VCgo's reader CA.
 */
class Holder private constructor(
    val store: DocumentStore,
    val document: Document,
    private val types: DocumentTypeRepository,
    private val readerTrust: TrustManager,
) {
    /** Whether the last reader the holder was asked by was trusted. */
    var lastReaderTrusted: Boolean? = null

    /**
     * The holder's [SimplePresentmentSource]: consent is given to
     * everything asked, and [mac] prefers deviceMac.
     */
    fun source(mac: Boolean) = SimplePresentmentSource(
        documentStore = store,
        documentTypeRepository = types,
        resolveTrustFn = { requester ->
            var trusted: TrustedRequesterIdentity? = null
            for (identity in requester.requesterIdentities) {
                val result = readerTrust.verify(chain = identity.certChain.certificates)
                if (result.isTrusted) {
                    trusted = TrustedRequesterIdentity(identity, result.trustPoints.first().metadata)
                    break
                }
            }
            lastReaderTrusted = trusted != null
            trusted
        },
        showConsentPromptFn = ::promptModelSilentConsent,
        preferSignatureToKeyAgreement = !mac,
        domainsMdocSignature = listOf(DOMAIN_SIGNATURE),
        domainsMdocKeyAgreement = listOf(DOMAIN_MAC),
        domainsKeyBoundSdJwt = listOf(DOMAIN_SDJWT),
    )

    /** The credential of [domain]. */
    suspend fun credential(domain: String): MdocCredential =
        document.getCertifiedCredentialsForDomain(domain).first() as MdocCredential

    companion object {
        suspend fun create(pki: Pki, goReaderCA: X509Cert): Holder {
            val storage = EphemeralStorage()
            val secureArea = SoftwareSecureArea.create(storage)
            val store = buildDocumentStore(
                storage = storage,
                secureAreaRepository = SecureAreaRepository.Builder().add(secureArea).build(),
            ) {}
            val document = store.createDocument(displayName = "mDL")
            val now = Clock.System.now().truncateToWholeSeconds()
            for ((domain, algorithm) in listOf(DOMAIN_SIGNATURE to Algorithm.ESP256, DOMAIN_MAC to Algorithm.ECDH_P256)) {
                DrivingLicense.getDocumentType().createMdocCredentialWithSampleData(
                    document = document,
                    secureArea = secureArea,
                    createKeySettings = SoftwareCreateKeySettings.Builder().setAlgorithm(algorithm).build(),
                    dsKey = pki.ds,
                    signedAt = now - 1.hours,
                    validFrom = now - 1.hours,
                    validUntil = now + 1.days,
                    domain = domain,
                )
            }
            // And an SD-JWT VC PID, of Multipaz's sample PID data.
            EUPersonalID.getDocumentType().createKeyBoundSdJwtVcCredentialWithSampleData(
                document = store.createDocument(displayName = "PID"),
                secureArea = secureArea,
                createKeySettings = SoftwareCreateKeySettings.Builder().setAlgorithm(Algorithm.ESP256).build(),
                dsKey = pki.ds,
                signedAt = now - 1.hours,
                validFrom = now - 1.hours,
                validUntil = now + 1.days,
                domain = DOMAIN_SDJWT,
            )
            val types = DocumentTypeRepository().apply {
                addDocumentType(DrivingLicense.getDocumentType())
                addDocumentType(EUPersonalID.getDocumentType())
            }
            val readerTrust = TrustManager(storage)
            readerTrust.addX509Cert(goReaderCA, TrustMetadata(displayName = "OID4VCgo reader CA"))
            return Holder(store, document, types, readerTrust)
        }
    }
}
