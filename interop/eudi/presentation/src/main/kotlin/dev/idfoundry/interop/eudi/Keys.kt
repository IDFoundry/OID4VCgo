package dev.idfoundry.interop.eudi

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.StringReader
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Date
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/** An EC P-256 key pair parsed from a PEM "EC PRIVATE KEY". */
fun parseKeyPair(pem: String): KeyPair {
    val parsed = PEMParser(StringReader(pem)).use { it.readObject() }
    require(parsed is PEMKeyPair) { "expected an EC PRIVATE KEY" }
    return JcaPEMKeyConverter().getKeyPair(parsed)
}

fun parseCertificates(pem: String): List<X509Certificate> =
    CertificateFactory
        .getInstance("X.509")
        .generateCertificates(pem.byteInputStream())
        .map { it as X509Certificate }

fun KeyPair.ecJwk(): ECKey =
    ECKey
        .Builder(Curve.P_256, public as ECPublicKey)
        .privateKey(private as ECPrivateKey)
        .build()

fun newP256KeyPair(): KeyPair =
    KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

private fun certificate(
    subject: String,
    subjectKey: KeyPair,
    issuer: String,
    issuerKey: KeyPair,
    ca: Boolean,
    serial: Long,
): X509Certificate {
    val now = System.currentTimeMillis()
    val builder =
        JcaX509v3CertificateBuilder(
            X500Name("CN=$issuer"),
            BigInteger.valueOf(serial),
            Date(now - 3_600_000),
            Date(now + 86_400_000),
            X500Name("CN=$subject"),
            subjectKey.public,
        )
    if (ca) {
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(true))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
    } else {
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
    }
    val holder = builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.private))
    return JcaX509CertificateConverter().getCertificate(holder)
}

/**
 * A fresh issuer key and its certificate (as a one-certificate chain)
 * under a fresh CA: an issuer no verifier was told to trust.
 */
fun untrustedIssuer(): Pair<KeyPair, List<X509Certificate>> {
    val caKey = newP256KeyPair()
    val leafKey = newP256KeyPair()
    val ca = certificate("an issuer CA no one trusts", caKey, "an issuer CA no one trusts", caKey, ca = true, serial = 1)
    val leaf = certificate("an issuer no one trusts", leafKey, "an issuer CA no one trusts", caKey, ca = false, serial = 2)
    return leafKey to listOf(leaf)
}

/**
 * Whether [chain] (leaf first, as an x5c header carries it) chains to
 * one of [anchors]: a PKIX path check, without revocation (the run's
 * throwaway CAs publish none).
 */
fun chainsTo(
    chain: List<X509Certificate>,
    anchors: List<X509Certificate>,
): Boolean =
    runCatching {
        val path = CertificateFactory.getInstance("X.509").generateCertPath(chain.filterNot { it in anchors })
        val params = PKIXParameters(anchors.map { TrustAnchor(it, null) }.toSet()).apply { isRevocationEnabled = false }
        CertPathValidator.getInstance("PKIX").validate(path, params)
    }.isSuccess

/** A TLS context trusting only [anchors]. */
fun sslContextTrusting(anchors: List<X509Certificate>): SSLContext {
    val store =
        KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            anchors.forEachIndexed { i, cert -> setCertificateEntry("anchor-$i", cert) }
        }
    val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
    return SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
}
