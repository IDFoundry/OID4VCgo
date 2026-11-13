package oid4vcgo.interop.multipaz

import org.multipaz.asn1.ASN1Integer
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X500Name
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.mdoc.util.MdocUtil
import org.multipaz.util.truncateToWholeSeconds
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

/**
 * Multipaz's own certificates, from its own generators: an IACA and a
 * document signer for its holder's mDL, and two reader roots, each
 * with a reader certificate: the one OID4VCgo's holder trusts, and one
 * it doesn't. The trusted root has a second reader certificate,
 * [sibling], another Verifier the holder trusts.
 */
class Pki private constructor(
    val iaca: X509Cert,
    val ds: AsymmetricKey.X509Certified,
    val readerRoot: X509Cert,
    val reader: AsymmetricKey.X509CertifiedExplicit,
    val otherReader: AsymmetricKey.X509Certified,
    val sibling: AsymmetricKey.X509CertifiedExplicit,
) {
    companion object {
        suspend fun create(): Pki {
            val now = Clock.System.now().truncateToWholeSeconds()
            val from = now - 1.hours
            val until = now + 1.days

            val iacaKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val iaca = MdocUtil.generateIacaCertificate(
                iacaKey = AsymmetricKey.anonymous(iacaKey),
                subject = X500Name.fromName("C=US,CN=Multipaz interop IACA"),
                serial = ASN1Integer.fromRandom(numBits = 128),
                validFrom = from,
                validUntil = until,
                issuerAltNameUrl = "https://github.com/IDFoundry/OID4VCgo",
                crlUrl = "https://github.com/IDFoundry/OID4VCgo/crl",
            )
            val dsKey = Crypto.createEcPrivateKey(EcCurve.P256)
            val ds = MdocUtil.generateDsCertificate(
                iacaKey = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(iaca)), iacaKey),
                dsKey = dsKey.publicKey,
                subject = X500Name.fromName("C=US,CN=Multipaz interop DS"),
                serial = ASN1Integer.fromRandom(numBits = 128),
                validFrom = from,
                validUntil = until,
            )

            // A root and a reader certificate under it for each name, the first named for the root.
            suspend fun reader(vararg names: String): Pair<X509Cert, List<AsymmetricKey.X509CertifiedExplicit>> {
                val name = names.first()
                val rootKey = Crypto.createEcPrivateKey(EcCurve.P256)
                val root = MdocUtil.generateReaderRootCertificate(
                    readerRootKey = AsymmetricKey.anonymous(rootKey),
                    subject = X500Name.fromName("C=US,CN=$name root"),
                    serial = ASN1Integer.fromRandom(numBits = 128),
                    validFrom = from,
                    validUntil = until,
                    crlUrl = "https://github.com/IDFoundry/OID4VCgo/crl",
                )
                return root to names.map { readerName ->
                    val key = Crypto.createEcPrivateKey(EcCurve.P256)
                    val cert = MdocUtil.generateReaderCertificate(
                        readerRootKey = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(root)), rootKey),
                        readerKey = key.publicKey,
                        subject = X500Name.fromName("C=US,CN=$readerName"),
                        dnsName = null,
                        serial = ASN1Integer.fromRandom(numBits = 128),
                        validFrom = from,
                        validUntil = until,
                    )
                    AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(cert, root)), key)
                }
            }
            val (readerRoot, readers) = reader("Multipaz interop reader", "Multipaz interop second reader")
            val (_, others) = reader("Multipaz interop untrusted reader")
            return Pki(
                iaca = iaca,
                ds = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(ds)), dsKey),
                readerRoot = readerRoot,
                reader = readers[0],
                otherReader = others[0],
                sibling = readers[1],
            )
        }
    }
}
