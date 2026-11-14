package oid4vcgo.interop.eudi

import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import eu.europa.ec.eudi.openid4vci.AccessTokenOption
import eu.europa.ec.eudi.openid4vci.AuthorizationCode
import eu.europa.ec.eudi.openid4vci.AuthorizationResponseIssChecking
import eu.europa.ec.eudi.openid4vci.AuthorizeIssuanceConfig
import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.CertificateChainTrust
import eu.europa.ec.eudi.openid4vci.ClientAuthentication
import eu.europa.ec.eudi.openid4vci.Credential
import eu.europa.ec.eudi.openid4vci.CredentialConfigurationIdentifier
import eu.europa.ec.eudi.openid4vci.CredentialIssuerId
import eu.europa.ec.eudi.openid4vci.CredentialResponseEncryptionPolicy
import eu.europa.ec.eudi.openid4vci.DPoPUsage
import eu.europa.ec.eudi.openid4vci.EcConfig
import eu.europa.ec.eudi.openid4vci.EncryptionSupportConfig
import eu.europa.ec.eudi.openid4vci.IssuanceRequestPayload
import eu.europa.ec.eudi.openid4vci.IssuedCredential
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.IssuerMetadataPolicy
import eu.europa.ec.eudi.openid4vci.OpenId4VCIConfig
import eu.europa.ec.eudi.openid4vci.ParUsage
import eu.europa.ec.eudi.openid4vci.ProofSpecification
import eu.europa.ec.eudi.openid4vci.ProofsConfig
import eu.europa.ec.eudi.openid4vci.RequestEncryptionSpecFactory
import eu.europa.ec.eudi.openid4vci.ResponseEncryptionSpecFactory
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import eu.europa.ec.eudi.openid4vci.SupportedGrants
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.security.cert.X509Certificate

/** How a case configures the wallet. */
data class WalletOptions(
    val client: ClientAuthentication? = null,
    val encryption: Boolean = false,
    val signedMetadataTrust: List<X509Certificate>? = null,
    // Authorize by authorization_details (RFC 9396) rather than scopes.
    val authorizationDetails: Boolean = false,
)

/**
 * The wallet: eudi-lib-jvm-openid4vci-kt, configured as strictly as the
 * issuer allows: PAR required, DPoP required, the authorization
 * response's iss required (RFC 9207, which HAIP's FAPI 2.0 requires),
 * Wallet Attestation client authentication, and every proof type.
 */
class Wallet(
    val cfg: DriverConfig,
) {
    val ssl = sslContext(cfg.tlsTrust)
    val recorder = Recorder()
    val http = walletHttpClient(ssl, recorder)

    /**
     * The instance key of the last Wallet Attestation the Wallet
     * Provider's agent issued: the issuance's, which its Key
     * Attestations name.
     */
    var instanceKey: ECKey? = null

    /**
     * Wallet Attestation client authentication the issuer trusts: from
     * OID4VCgo's Wallet Provider when the driver has its agent (the
     * production profile), else signed with the attester key the
     * issuer's development configuration trusts.
     */
    fun trustedAttestation(): ClientAuthentication = cfg.agent?.let { attestationFrom(it) } ?: walletAttestation(cfg.clientId, cfg.attesterIssuer, cfg.attesterKey, cfg.attesterX5c)

    /** Wallet Attestation client authentication from [agent]'s provider, keeping its instance key. */
    fun attestationFrom(agent: ProviderAgent): ClientAuthentication {
        val (auth, key) = providerWalletAttestation(cfg.clientId, agent)
        instanceKey = key
        return auth
    }

    fun config(options: WalletOptions): OpenId4VCIConfig {
        val es256 = setOf(JWSAlgorithm.ES256)
        return OpenId4VCIConfig(
            clientAuthentication = options.client ?: trustedAttestation(),
            authFlowRedirectionURI = URI(cfg.redirectUri),
            encryptionSupportConfig =
                EncryptionSupportConfig(
                    compressionAlgorithms = listOf(CompressionAlgorithm.DEF),
                    credentialResponseEncryptionPolicy =
                        if (options.encryption) CredentialResponseEncryptionPolicy.REQUIRED else CredentialResponseEncryptionPolicy.SUPPORTED,
                    ecConfig = EcConfig(Curve.P_256),
                    rsaConfig = null,
                    supportedEncryptionMethods = listOf(EncryptionMethod.A128GCM, EncryptionMethod.A256GCM),
                ),
            authorizeIssuanceConfig = if (options.authorizationDetails) AuthorizeIssuanceConfig.AUTHORIZATION_DETAILS else AuthorizeIssuanceConfig.FAVOR_SCOPES,
            dPoPUsage = DPoPUsage.Required(dpopConfig()),
            parUsage = ParUsage.Required(authorizationCodeDPoPBinding = true),
            issuerMetadataPolicy =
                options.signedMetadataTrust?.let { anchors ->
                    IssuerMetadataPolicy.RequireSigned(CertificateChainTrust { chain -> chainsTo(chain, anchors) })
                } ?: IssuerMetadataPolicy.IgnoreSigned,
            proofs =
                ProofsConfig(
                    isNoProofSupported = false,
                    jwtProofWithKeyAttestation = ProofsConfig.SupportedJwtProof(es256),
                    attestationProof = ProofsConfig.SupportedAttestationProof(es256),
                    jwtProofsWithoutKeyAttestation = ProofsConfig.SupportedJwtProof(es256),
                ),
            authResponseIssChecking = AuthorizationResponseIssChecking.Required,
            grants = SupportedGrants.Both,
        )
    }

    private fun factories(options: WalletOptions): Pair<RequestEncryptionSpecFactory, ResponseEncryptionSpecFactory> =
        if (options.encryption) {
            RequestEncryptionSpecFactory.DEFAULT to ResponseEncryptionSpecFactory.DEFAULT
        } else {
            RequestEncryptionSpecFactory { _, _ -> null } to ResponseEncryptionSpecFactory { _, _ -> null }
        }

    suspend fun fromOffer(
        offerUri: String,
        options: WalletOptions = WalletOptions(),
    ): Issuer {
        val (req, resp) = factories(options)
        return Issuer.make(config(options), offerUri, http, req, resp).getOrThrow().first
    }

    suspend fun walletInitiated(
        configurationIds: List<String>,
        options: WalletOptions = WalletOptions(),
    ): Issuer {
        val (req, resp) = factories(options)
        return Issuer
            .makeWalletInitiated(
                config(options),
                CredentialIssuerId(cfg.credentialIssuer).getOrThrow(),
                configurationIds.map { CredentialConfigurationIdentifier(it) },
                http,
                null,
                req,
                resp,
            ).getOrThrow()
            .first
    }

    /** Mints an offer at the issuer's offer endpoint, returning its URI and issuer_state. */
    fun offer(
        grant: String,
        configurationIds: List<String>,
        txCode: String? = null,
        byReference: Boolean = false,
        credentialIdentifiers: Boolean = false,
    ): Pair<String, String?> {
        val body =
            buildString {
                append("{\"grant\":\"").append(grant).append("\",\"credential_configuration_ids\":[")
                append(configurationIds.joinToString(",") { "\"$it\"" })
                append("],\"by_reference\":").append(byReference)
                append(",\"credential_identifiers\":").append(credentialIdentifiers)
                txCode?.let { append(",\"tx_code\":\"").append(it).append("\"") }
                append("}")
            }
        val o = Json.parseToJsonElement(mintOffer(cfg.offersUrl, body)).jsonObject
        return o.getValue("uri").jsonPrimitive.content to o["issuer_state"]?.jsonPrimitive?.content
    }

    /** The authorization code flow, with the End-User approving (or denying) on the consent page. */
    suspend fun Issuer.authorizeByCode(approve: Boolean = true): AuthorizedRequest {
        val prepared = prepareAuthorizationRequest().getOrThrow()
        val response = consent(ssl, prepared.authorizationCodeURL.value.toURI(), cfg.redirectUri, cfg.subject, approve)
        if (response.error != null) throw AuthorizationRefused(response.error)
        return with(prepared) {
            authorizeWithAuthorizationCode(
                AuthorizationCode(checkNotNull(response.code) { "no code" }),
                checkNotNull(response.state) { "no state" },
                issuer = response.iss,
            ).getOrThrow()
        }
    }

    suspend fun Issuer.authorizeByPreAuthorizedCode(
        txCode: String? = null,
        requestAuthorizationDetails: Boolean = false,
    ): AuthorizedRequest =
        authorizeWithPreAuthorizationCode(
            txCode,
            if (requestAuthorizationDetails) AccessTokenOption.Limited { true } else AccessTokenOption.AsRequested,
        ).getOrThrow()

    /** One Credential Request for [configurationId], by its credential_identifier when the token granted one. */
    suspend fun Issuer.issue(
        authorized: AuthorizedRequest,
        configurationId: String,
        proof: ProofSpecification,
    ): Pair<AuthorizedRequest, SubmissionOutcome> {
        val id = CredentialConfigurationIdentifier(configurationId)
        val payload =
            authorized.credentialIdentifiers
                ?.get(id)
                ?.firstOrNull()
                ?.let { IssuanceRequestPayload.IdentifierBased(id, it) }
                ?: IssuanceRequestPayload.ConfigurationBased(id)
        return with(authorized) { request(payload, proof) }.getOrThrow()
    }

    /** Verifies [credentials] as [configurationId]'s format, returning the thumbprints of the keys they're bound to. */
    suspend fun verify(
        configurationId: String,
        credentials: List<IssuedCredential>,
        anchors: List<X509Certificate>? = null,
    ): List<String> =
        credentials.map {
            val value = (it.credential as Credential.Str).value
            if (configurationId == cfg.mdocConfigurationId) {
                verifyMdoc(value, anchors ?: cfg.iaca, cfg.docType, cfg.namespace, cfg.claims)
            } else {
                verifySdJwtVc(value, anchors ?: cfg.issuerCa, cfg.vct, cfg.claims)
            }
        }
}

/** The End-User didn't authorize: the authorization response's error. */
class AuthorizationRefused(
    val error: String,
) : Exception("authorization response error=$error")

/** Proofs, and the keys they prove possession of. */
class Proofs(
    val keys: List<ECKey>,
    val spec: ProofSpecification,
) {
    val thumbprints: Set<String> get() = keys.map { it.computeThumbprint().toString() }.toSet()

    companion object {
        /** [n] jwt proofs, none with a key attestation. */
        fun jwt(n: Int = 1): Proofs {
            val keys = List(n) { newKey() }
            return Proofs(keys, ProofSpecification.JwtProofsWithoutKeyAttestation(batchSigner(keys)))
        }

        /** One jwt proof carrying a key attestation of [n] keys, signed by the first (ETSI TS 119 472-3). */
        fun jwtWithKeyAttestation(
            signer: ECKey,
            n: Int = 1,
        ): Proofs {
            val keys = List(n) { newKey() }
            return Proofs(keys, ProofSpecification.JwtProofWithKeyAttestation { nonce, _ -> ecSigner(keys[0], keyAttestation(signer, keys, nonce)) })
        }

        /**
         * One jwt proof carrying a Key Attestation of [n] keys from
         * [wallet]'s Wallet Provider, for the issuance of its current
         * instance key, signed by the first key.
         */
        fun jwtWithProviderKeyAttestation(
            wallet: Wallet,
            n: Int = 1,
        ): Proofs {
            val keys = List(n) { newKey() }
            val agent = checkNotNull(wallet.cfg.agent) { "no Wallet Provider agent" }
            return Proofs(
                keys,
                ProofSpecification.JwtProofWithKeyAttestation { nonce, _ ->
                    ecSigner(keys[0], agent.keyAttestation(checkNotNull(wallet.instanceKey) { "no Wallet Attestation yet" }, keys, nonce))
                },
            )
        }

        /** One attestation proof: a key attestation of [n] keys. */
        fun attestation(
            signer: ECKey,
            n: Int = 1,
        ): Proofs {
            val keys = List(n) { newKey() }
            return Proofs(keys, ProofSpecification.AttestationProof { nonce, _ -> keyAttestation(signer, keys, nonce) })
        }
    }
}
