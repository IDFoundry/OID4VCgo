package dev.idfoundry.interop.eudi

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.util.Base64
import eu.europa.ec.eudi.sdjwt.NimbusSdJwtOps
import eu.europa.ec.eudi.sdjwt.cnf
import eu.europa.ec.eudi.sdjwt.dsl.values.sdJwt
import eu.europa.ec.eudi.sdjwt.vc.ClaimPath
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Simple
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.addCborArray
import org.multipaz.cbor.buildCborArray
import org.multipaz.cbor.toDataItem
import org.multipaz.cose.Cose
import org.multipaz.cose.CoseNumberLabel
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.AsymmetricKey
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.X509Cert
import org.multipaz.crypto.X509CertChain
import org.multipaz.crypto.toEcPrivateKey
import org.multipaz.crypto.toEcPublicKey
import org.multipaz.mdoc.devicesigned.DeviceNamespaces
import org.multipaz.mdoc.issuersigned.IssuerNamespaces
import org.multipaz.mdoc.issuersigned.buildIssuerNamespaces
import org.multipaz.mdoc.mso.MobileSecurityObject
import org.multipaz.mdoc.response.DeviceResponse
import org.multipaz.mdoc.response.MdocDocument
import org.multipaz.mdoc.response.buildDeviceResponse
import org.multipaz.revocation.RevocationStatus
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.io.encoding.Base64 as KBase64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/** The claim this run discloses beyond the query, for [Variant.EXTRA_CLAIM]. */
const val EXTRA_CLAIM = "birth_date"

/** The issuer's key and certificate chain: setup's, or a fresh, untrusted one. */
private fun issuerOf(
    wallet: WalletFile,
    variant: Variant,
    keyField: String,
    certField: String,
): Pair<KeyPair, List<X509Certificate>> =
    if (variant == Variant.UNTRUSTED_ISSUER) {
        untrustedIssuer()
    } else {
        parseKeyPair(wallet.string(keyField)) to parseCertificates(wallet.string(certField))
    }

private fun statusIndex(variant: Variant): Int = if (variant == Variant.REVOKED) 1 else 0

/**
 * Issues an SD-JWT VC with eudi-lib-jvm-sdjwt-kt, every claim selectively
 * disclosable, bound to the holder's key (cnf) and naming its status
 * list entry, and presents [claims] of it with a Key Binding JWT for
 * [nonce] and [audience] (unless [Variant.NO_KEY_BINDING]).
 */
suspend fun sdJwtVcPresentation(
    wallet: WalletFile,
    variant: Variant,
    holder: KeyPair,
    claims: List<String>,
    nonce: String,
    audience: String,
): String {
    val (issuerKey, issuerChain) = issuerOf(wallet, variant, "credential_issuer_private_key_pem", "credential_issuer_certificate_pem")
    val issuer =
        NimbusSdJwtOps.issuer(signer = ECDSASigner(issuerKey.ecJwk()), signAlgorithm = JWSAlgorithm.ES256) {
            type(JOSEObjectType("dc+sd-jwt"))
            x509CertChain(issuerChain.map { Base64.encode(it.encoded) })
        }
    val now = System.currentTimeMillis() / 1000
    val holderJwk = holder.ecJwk()
    val spec =
        sdJwt {
            claim("iss", "https://issuer.oid4vcgo-interop.example")
            claim("vct", wallet.string("vct"))
            claim("iat", now)
            claim("exp", now + 86_400)
            cnf(holderJwk.toPublicJWK())
            claim(
                "status",
                buildJsonObject {
                    putJsonObject("status_list") {
                        put("idx", statusIndex(variant))
                        put("uri", wallet.string("status_list_uri"))
                    }
                },
            )
            for ((name, value) in wallet.obj("claims")) sdClaim(name, value)
        }
    val issued = issuer.issue(spec).getOrThrow()

    val disclosed = if (variant == Variant.EXTRA_CLAIM) claims + EXTRA_CLAIM else claims
    return with(NimbusSdJwtOps) {
        val presented = issued.present(disclosed.map { ClaimPath.claim(it) }.toSet()) ?: error("no claims to present")
        if (variant == Variant.NO_KEY_BINDING) {
            presented.serialize()
        } else {
            val kbJwt =
                NimbusSdJwtOps.kbJwtIssuer(ECDSASigner(holderJwk), JWSAlgorithm.ES256, holderJwk.toPublicJWK()) {
                    audience(audience)
                    claim("nonce", nonce)
                    issueTime(Date())
                }
            presented.serializeWithKeyBinding(kbJwt).getOrThrow()
        }
    }
}

/**
 * The SessionTranscript of OpenID4VP 1.0 Appendix B.2.6.1 (redirects:
 * [responseUri] set) or B.2.6.2 (the Digital Credentials API, where
 * [clientIdOrOrigin] is the origin): built here, as the response's
 * caller builds the vp_token. [jwkThumbprint] is the verifier's
 * response encryption key's, when the response is encrypted.
 */
suspend fun sessionTranscript(
    clientIdOrOrigin: String,
    nonce: String,
    jwkThumbprint: ByteArray?,
    responseUri: String?,
): DataItem {
    val info =
        buildCborArray {
            add(clientIdOrOrigin)
            add(nonce)
            add(jwkThumbprint?.let { Bstr(it) } ?: Simple.NULL)
            if (responseUri != null) add(responseUri)
        }
    val digest = Crypto.digest(Algorithm.SHA256, Cbor.encode(info))
    return buildCborArray {
        add(Simple.NULL)
        add(Simple.NULL)
        addCborArray {
            add(if (responseUri != null) "OpenID4VPHandover" else "OpenID4VPDCAPIHandover")
            add(digest)
        }
    }
}

private fun JsonElement.toDataItem(): DataItem =
    when (this) {
        is JsonArray -> {
            buildCborArray { this@toDataItem.forEach { add(it.toDataItem()) } }
        }

        is JsonPrimitive -> {
            when {
                isString -> content.toDataItem()
                booleanOrNull != null -> booleanOrNull!!.toDataItem()
                longOrNull != null -> longOrNull!!.toDataItem()
                else -> error("unsupported claim value $this")
            }
        }

        else -> {
            error("unsupported claim value $this")
        }
    }

/**
 * Issues an mdoc with Multipaz — its MSO naming its status list entry
 * and the holder's device key, signed by the Document Signer with an
 * x5chain — and presents [elements] of it in a DeviceResponse, its
 * DeviceAuth signing [transcript].
 */
suspend fun mdocPresentation(
    wallet: WalletFile,
    variant: Variant,
    holder: KeyPair,
    docType: String,
    namespace: String,
    elements: List<String>,
    transcript: DataItem,
): String {
    val (dsKey, dsChain) = issuerOf(wallet, variant, "mdoc_issuer_private_key_pem", "mdoc_issuer_certificate_pem")
    val issuerNamespaces =
        buildIssuerNamespaces {
            addNamespace(namespace) {
                for ((name, value) in wallet.obj("mdoc_claims")) addDataElement(name, value.toDataItem())
            }
        }
    val now = Instant.fromEpochSeconds(Clock.System.now().epochSeconds)
    val mso =
        MobileSecurityObject(
            version = "1.0",
            docType = docType,
            signedAt = now,
            validFrom = now,
            validUntil = now + 1.days,
            expectedUpdate = null,
            digestAlgorithm = Algorithm.SHA256,
            valueDigests = issuerNamespaces.getValueDigests(Algorithm.SHA256),
            deviceKey = holder.public.toEcPublicKey(EcCurve.P256),
            revocationStatus = RevocationStatus.StatusList(statusIndex(variant), wallet.string("status_list_uri"), null),
        )
    val dsPrivate = dsKey.private.toEcPrivateKey(dsKey.public, EcCurve.P256)
    val issuerAuth =
        Cose.coseSign1Sign(
            signingKey = AsymmetricKey.anonymous(dsPrivate),
            message = Cbor.encode(Tagged(Tagged.ENCODED_CBOR, Bstr(Cbor.encode(mso.toDataItem())))),
            includeMessageInPayload = true,
            protectedHeaders = mapOf(CoseNumberLabel(Cose.COSE_LABEL_ALG) to Algorithm.ES256.coseAlgorithmIdentifier!!.toDataItem()),
            unprotectedHeaders =
                mapOf(
                    CoseNumberLabel(Cose.COSE_LABEL_X5CHAIN) to X509CertChain(dsChain.map { X509Cert(ByteString(it.encoded)) }).toDataItem(),
                ),
        )

    val disclosed = if (variant == Variant.EXTRA_CLAIM) elements + EXTRA_CLAIM else elements
    val document =
        MdocDocument.fromNamespaces(
            sessionTranscript = transcript,
            docType = docType,
            issuerAuth = issuerAuth,
            issuerNamespaces = IssuerNamespaces(mapOf(namespace to issuerNamespaces.data.getValue(namespace).filterKeys { it in disclosed })),
            deviceNamespaces = DeviceNamespaces(emptyMap()),
            deviceKey = AsymmetricKey.anonymous(holder.private.toEcPrivateKey(holder.public, EcCurve.P256)),
        )
    val response = buildDeviceResponse(sessionTranscript = transcript, status = DeviceResponse.STATUS_OK) { addDocument(document) }
    return KBase64.UrlSafe.withPadding(KBase64.PaddingOption.ABSENT).encode(Cbor.encode(response.toDataItem()))
}
