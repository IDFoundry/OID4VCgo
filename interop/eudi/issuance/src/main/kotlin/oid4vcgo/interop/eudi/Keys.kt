package oid4vcgo.interop.eudi

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.openid4vci.BatchSignOperation
import eu.europa.ec.eudi.openid4vci.BatchSigner
import eu.europa.ec.eudi.openid4vci.ClientAttestationJWT
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.DPoPConfig
import eu.europa.ec.eudi.openid4vci.HttpsUrl
import eu.europa.ec.eudi.openid4vci.JwsAlgorithm
import eu.europa.ec.eudi.openid4vci.JwtBindingKey
import eu.europa.ec.eudi.openid4vci.KeyAttestationJWT
import eu.europa.ec.eudi.openid4vci.Nonce
import eu.europa.ec.eudi.openid4vci.PositiveDuration
import eu.europa.ec.eudi.openid4vci.ProvisionClientAttestation
import eu.europa.ec.eudi.openid4vci.ProvisionDPoPSigner
import eu.europa.ec.eudi.openid4vci.SignFunction
import eu.europa.ec.eudi.openid4vci.SignOperation
import eu.europa.ec.eudi.openid4vci.Signer
import java.security.Signature
import java.time.Instant
import java.util.Date
import java.util.UUID

const val ES256_JAVA = "SHA256withECDSA"
val ES256 = JwsAlgorithm("ES256")

fun newKey(): ECKey = ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate()

private fun signFunction(key: ECKey) =
    SignFunction { input ->
        Signature.getInstance(ES256_JAVA).run {
            initSign(key.toECPrivateKey())
            update(input)
            sign()
        }
    }

/** A [Signer] over [key], handing the library [publicMaterial]. */
fun <P> ecSigner(
    key: ECKey,
    publicMaterial: P,
): Signer<P> =
    object : Signer<P> {
        override val javaAlgorithm: String = ES256_JAVA

        override suspend fun acquire(): SignOperation<P> = SignOperation(signFunction(key), publicMaterial)

        override suspend fun release(signOperation: SignOperation<P>?) = Unit
    }

/** A [BatchSigner] signing one jwt proof per key in [keys]. */
fun batchSigner(keys: List<ECKey>): BatchSigner<JwtBindingKey> =
    object : BatchSigner<JwtBindingKey> {
        override val javaAlgorithm: String = ES256_JAVA

        override suspend fun authenticate(): BatchSignOperation<JwtBindingKey> =
            BatchSignOperation(keys.map { SignOperation(signFunction(it), JwtBindingKey.Jwk(it.toPublicJWK())) })

        override suspend fun release(signOps: BatchSignOperation<JwtBindingKey>?) = Unit
    }

/** DPoP proofs signed by a fresh key per Issuer. */
fun dpopConfig(): DPoPConfig {
    val key = newKey()
    return DPoPConfig(
        object : ProvisionDPoPSigner {
            override val popAlgorithm: JwsAlgorithm = ES256

            override suspend fun invoke(authorizationServer: HttpsUrl): Signer<JWK> = ecSigner(key, key.toPublicJWK())
        },
    )
}

/**
 * Wallet Attestation client authentication (draft-ietf-oauth-attestation-based-client-auth-07):
 * a Client Attestation JWT for a fresh Client Instance Key, signed by
 * [attesterKey] under the certificate chain [x5c], as a Wallet Provider
 * issues one. The library makes the PoP JWT for each request itself.
 */
fun walletAttestation(
    clientId: String,
    attesterIssuer: String,
    attesterKey: ECKey,
    x5c: List<Base64>,
): ClientAuthentication.AttestationBased {
    val instanceKey = newKey()
    val now = Instant.now()
    val jwt =
        SignedJWT(
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("oauth-client-attestation+jwt"))
                .x509CertChain(x5c)
                .build(),
            JWTClaimsSet
                .Builder()
                .issuer(attesterIssuer)
                .subject(clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .claim("cnf", mapOf("jwk" to instanceKey.toPublicJWK().toJSONObject()))
                .build(),
        ).apply { sign(ECDSASigner(attesterKey)) }
    val provisioned = ProvisionClientAttestation.Provisioned(ClientAttestationJWT(jwt.serialize()), ecSigner(instanceKey, instanceKey.toPublicJWK()))
    return ClientAuthentication.AttestationBased(
        clientId,
        object : ProvisionClientAttestation {
            override val algorithm: JwsAlgorithm = ES256
            override val popAlgorithm: JwsAlgorithm = ES256

            override suspend fun invoke(
                authorizationServer: HttpsUrl,
                preferredClientStatusPeriod: PositiveDuration?,
            ): ProvisionClientAttestation.Provisioned = provisioned
        },
    )
}

/**
 * A Key Attestation JWT (OpenID4VCI 1.0 Appendix D.1) attesting
 * [attested], signed by [signer] as a Wallet Provider's key attestation
 * service would, carrying the issuer's c_nonce when it has one.
 */
fun keyAttestation(
    signer: ECKey,
    attested: List<ECKey>,
    nonce: Nonce?,
): KeyAttestationJWT {
    val now = Instant.now()
    val claims =
        JWTClaimsSet
            .Builder()
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(3600)))
            .claim("attested_keys", attested.map { it.toPublicJWK().toJSONObject() })
            .claim("key_storage", listOf("iso_18045_moderate"))
            .claim("user_authentication", listOf("iso_18045_moderate"))
    nonce?.let { claims.claim("nonce", it.value) }
    val jwt =
        SignedJWT(
            JWSHeader
                .Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType("key-attestation+jwt"))
                .build(),
            claims.build(),
        ).apply { sign(ECDSASigner(signer)) }
    return KeyAttestationJWT(jwt.serialize())
}
