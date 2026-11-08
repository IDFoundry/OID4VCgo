package oid4vcgo.interop.eudi

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import eu.europa.ec.eudi.sdjwt.DefaultSdJwtOps
import eu.europa.ec.eudi.sdjwt.SdJwtVcVerifier
import eu.europa.ec.eudi.sdjwt.vc.IssuerVerificationMethod
import eu.europa.ec.eudi.sdjwt.vc.TypeMetadataPolicy
import eu.europa.ec.eudi.sdjwt.vc.X509CertificateTrust
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.Base64
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap

/** Whether [chain] (leaf first) chains to one of [anchors], checked as PKIX does (no revocation: none is published). */
fun chainsTo(
    chain: List<X509Certificate>,
    anchors: List<X509Certificate>,
): Boolean =
    runCatching {
        val path = CertificateFactory.getInstance("X.509").generateCertPath(chain.filter { c -> anchors.none { it == c } })
        val params = PKIXParameters(anchors.map { TrustAnchor(it, null) }.toSet()).apply { isRevocationEnabled = false }
        CertPathValidator.getInstance("PKIX").validate(path, params)
        true
    }.getOrDefault(false)

/**
 * Verifies an issued SD-JWT VC with EUDI's own verifier
 * (eudi-lib-jvm-sdjwt-kt): its signature, by the x5c leaf, whose chain
 * must lead to [anchors]; then checks its vct and that every claim the
 * issuer issues is disclosed with the value expected. Returns the
 * thumbprint of the key it's bound to (cnf.jwk).
 */
suspend fun verifySdJwtVc(
    credential: String,
    anchors: List<X509Certificate>,
    vct: String,
    claims: Map<String, String>,
): String {
    val verifier =
        DefaultSdJwtOps.SdJwtVcVerifier(
            IssuerVerificationMethod.usingX5c(X509CertificateTrust { chain: List<X509Certificate>, _ -> chainsTo(chain, anchors) }),
            TypeMetadataPolicy.NotUsed,
            null,
        )
    val sdJwt = verifier.verify(credential).getOrThrow()
    val recreated: JsonObject = with(DefaultSdJwtOps) { sdJwt.recreateClaimsAndDisclosuresPerClaim().first }
    check(recreated["vct"]?.jsonPrimitive?.content == vct) { "vct is ${recreated["vct"]}, not $vct" }
    for ((name, value) in claims) {
        check(recreated[name]?.jsonPrimitive?.content == value) { "claim $name is ${recreated[name]}, not $value" }
    }
    val cnf = checkNotNull(recreated["cnf"]?.jsonObject?.get("jwk")) { "no cnf.jwk" }
    return JWK.parse(cnf.toString()).computeThumbprint().toString()
}

private fun cbor(bytes: ByteArray): DataItem = CborDecoder(ByteArrayInputStream(bytes)).decode().single()

private fun encode(item: DataItem): ByteArray = ByteArrayOutputStream().also { CborEncoder(it).encode(item) }.toByteArray()

private operator fun CborMap.get(key: String): DataItem? = get(UnicodeString(key))

private operator fun CborMap.get(key: Long): DataItem? = get(if (key >= 0) UnsignedInteger(key) else NegativeInteger(key))

private fun DataItem.bytes(): ByteArray = (this as ByteString).bytes

/**
 * Verifies an issued mdoc (its base64url IssuerSigned, ISO/IEC 18013-5
 * §8.3.2.1.2.2): the issuerAuth COSE_Sign1 signature by the x5chain
 * leaf, whose chain must lead to [anchors]; that every IssuerSignedItem
 * matches its digest in the MSO; the docType, validity and the expected
 * claims. There's no EUDI JVM library to do this with, so it's checked
 * here, against the published structure. Returns the thumbprint of its
 * device key.
 */
fun verifyMdoc(
    credential: String,
    anchors: List<X509Certificate>,
    docType: String,
    namespace: String,
    claims: Map<String, String>,
): String {
    val issuerSigned = cbor(Base64.getUrlDecoder().decode(credential)) as CborMap
    val issuerAuth = (checkNotNull(issuerSigned["issuerAuth"]) { "no issuerAuth" } as CborArray).dataItems
    check(issuerAuth.size == 4) { "issuerAuth isn't a COSE_Sign1" }
    val protected = issuerAuth[0].bytes()
    val protectedHeader = cbor(protected) as CborMap
    check((protectedHeader[1L] as? NegativeInteger)?.value == BigInteger.valueOf(-7)) { "issuerAuth alg isn't ES256" }
    val unprotected = issuerAuth[1] as CborMap
    val x5chain = checkNotNull(unprotected[33L] ?: protectedHeader[33L]) { "issuerAuth has no x5chain" }
    val factory = CertificateFactory.getInstance("X.509")
    val chain =
        when (x5chain) {
            is ByteString -> listOf(x5chain.bytes)
            is CborArray -> x5chain.dataItems.map { it.bytes() }
            else -> error("x5chain is neither a bstr nor an array")
        }.map { factory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }
    check(chainsTo(chain, anchors)) { "the Document Signer certificate doesn't chain to the trusted IACA" }
    val payload = issuerAuth[2].bytes()
    val sigStructure =
        CborArray().apply {
            add(UnicodeString("Signature1"))
            add(ByteString(protected))
            add(ByteString(ByteArray(0)))
            add(ByteString(payload))
        }
    val signature = issuerAuth[3].bytes()
    check(signature.size == 64) { "the ES256 signature isn't 64 bytes" }
    val verified =
        Signature.getInstance(ES256_JAVA).run {
            initVerify(chain.first().publicKey)
            update(encode(sigStructure))
            verify(rawToDer(signature))
        }
    check(verified) { "the issuerAuth signature doesn't verify" }

    // The payload is #6.24(bstr .cbor MobileSecurityObject).
    val msoItem = cbor(payload)
    check(msoItem.tag?.value == 24L) { "the MSO isn't tagged 24" }
    val mso = cbor(msoItem.bytes()) as CborMap
    check((mso["docType"] as UnicodeString).string == docType) { "the MSO's docType isn't $docType" }
    check((mso["digestAlgorithm"] as UnicodeString).string == "SHA-256") { "digestAlgorithm isn't SHA-256" }
    val validity = mso["validityInfo"] as CborMap
    val now = Instant.now()
    val validFrom = Instant.parse((validity["validFrom"] as UnicodeString).string)
    val validUntil = Instant.parse((validity["validUntil"] as UnicodeString).string)
    check(!now.isBefore(validFrom) && now.isBefore(validUntil)) { "the MSO isn't valid now ($validFrom..$validUntil)" }
    val deviceKey = (mso["deviceKeyInfo"] as CborMap)["deviceKey"] as CborMap
    check((deviceKey[1L] as? UnsignedInteger)?.value == BigInteger.TWO && (deviceKey[-1L] as? UnsignedInteger)?.value == BigInteger.ONE) {
        "the deviceKey isn't an EC2 P-256 COSE_Key"
    }
    val bound =
        ECKey.Builder(Curve.P_256, Base64URL.encode(deviceKey[-2L]!!.bytes()), Base64URL.encode(deviceKey[-3L]!!.bytes())).build()

    val digests = ((mso["valueDigests"] as CborMap)[namespace] as? CborMap) ?: error("no valueDigests for $namespace")
    val items = ((issuerSigned["nameSpaces"] as CborMap)[namespace] as? CborArray) ?: error("no nameSpaces[$namespace]")
    val values = mutableMapOf<String, String>()
    for (tagged in items.dataItems) {
        check(tagged.tag?.value == 24L) { "an IssuerSignedItem isn't tagged 24" }
        val digest = MessageDigest.getInstance("SHA-256").digest(encode(tagged))
        val item = cbor(tagged.bytes()) as CborMap
        val digestId = item["digestID"] as UnsignedInteger
        val expected = digests[digestId.value.toLong()]?.bytes()
        val identifier = (item["elementIdentifier"] as UnicodeString).string
        check(expected != null && expected.contentEquals(digest)) { "$identifier doesn't match its digest in the MSO" }
        values[identifier] =
            when (val v = item["elementValue"]) {
                is UnicodeString -> v.string
                else -> v.toString()
            }
    }
    for ((name, value) in claims) {
        check(values[name] == value) { "element $name is ${values[name]}, not $value" }
    }
    return bound.computeThumbprint().toString()
}

/** An ES256 signature, r||s, as the DER SEQUENCE Java verifies. */
private fun rawToDer(raw: ByteArray): ByteArray {
    fun int(b: ByteArray): ByteArray {
        val v = BigInteger(1, b).toByteArray()
        return byteArrayOf(0x02, v.size.toByte()) + v
    }
    val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
    return byteArrayOf(0x30, body.size.toByte()) + body
}
