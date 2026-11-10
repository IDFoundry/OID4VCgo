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
 * it doesn't.
 */
class Pki private constructor(
    val iaca: X509Cert,
    val ds: AsymmetricKey.X509Certified,
    val readerRoot: X509Cert,
    val reader: AsymmetricKey.X509Certified,
    val otherReader: AsymmetricKey.X509Certified,
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

            suspend fun reader(name: String): Pair<X509Cert, AsymmetricKey.X509Certified> {
                val rootKey = Crypto.createEcPrivateKey(EcCurve.P256)
                val root = MdocUtil.generateReaderRootCertificate(
                    readerRootKey = AsymmetricKey.anonymous(rootKey),
                    subject = X500Name.fromName("C=US,CN=$name root"),
                    serial = ASN1Integer.fromRandom(numBits = 128),
                    validFrom = from,
                    validUntil = until,
                    crlUrl = "https://github.com/IDFoundry/OID4VCgo/crl",
                )
                val key = Crypto.createEcPrivateKey(EcCurve.P256)
                val cert = MdocUtil.generateReaderCertificate(
                    readerRootKey = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(root)), rootKey),
                    readerKey = key.publicKey,
                    subject = X500Name.fromName("C=US,CN=$name"),
                    dnsName = null,
                    serial = ASN1Integer.fromRandom(numBits = 128),
                    validFrom = from,
                    validUntil = until,
                )
                return root to AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(cert, root)), key)
            }
            val (readerRoot, reader) = reader("Multipaz interop reader")
            val (_, otherReader) = reader("Multipaz interop untrusted reader")
            return Pki(
                iaca = iaca,
                ds = AsymmetricKey.X509CertifiedExplicit(X509CertChain(listOf(ds)), dsKey),
                readerRoot = readerRoot,
                reader = reader,
                otherReader = otherReader,
            )
        }
    }
}
