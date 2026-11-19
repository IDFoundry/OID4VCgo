package dev.idfoundry.oid4vcwallet

import android.content.Context
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Mobile
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.KSerializer
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.time.Instant
import java.util.Locale
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Issuance as MobileIssuance
import dev.idfoundry.oid4vcwallet.gomobile.mobile.MdocPresentation as MobileMdocPresentation
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Presentation as MobilePresentation
import dev.idfoundry.oid4vcwallet.gomobile.mobile.Wallet as MobileWallet

private const val NO_BLE_MODE = "no BLE mode"

/**
 * NewWallet's configuration, its options grouped by what they're for.
 * It serializes to the flat JSON object `NewWallet` reads (ABI.md), with
 * the same keys as before the options were grouped.
 */
@Serializable(with = WalletConfigurationSerializer::class)
public data class WalletConfiguration(
    /**
     * The wallet's registration with Authorization Servers: empty for a
     * wallet with no [WalletProvider], receiving credentials only from
     * pre-authorized codes redeemed with no client authentication.
     */
    val clientID: String = "",
    /**
     * Where the issuer's pages send the holder back to: a private-use URI
     * the app receives, in `reverse.domain:/path` form
     * (`com.example.wallet:/callback`), or with an authority
     * (`com.example.wallet://callback`). Empty for a wallet that receives
     * only pre-authorized codes.
     */
    val redirectURI: String = "",
    /** Which issuers' credentials the wallet accepts. */
    val issuers: IssuerTrust = IssuerTrust(),
    /** Which signed Credential Issuer Metadata the wallet trusts. */
    val issuerMetadata: IssuerMetadataTrust = IssuerMetadataTrust(),
    /** Which Verifiers, registrars and mdoc readers the wallet recognizes. */
    val verifiers: VerifierTrust = VerifierTrust(),
    /** Which trust roles' certificates are checked for revocation, and against which lists. */
    val revocation: Revocation = Revocation(),
    /** How [Wallet.checkStatus] reads and keeps status and identifier lists. */
    val status: StatusLists = StatusLists(),
    /** The wallet's own HTTPS requests. */
    val network: Network = Network(),
    /** How the wallet receives credentials. */
    val issuance: IssuanceOptions = IssuanceOptions(),
    /** How the wallet presents credentials. */
    val presentation: PresentationOptions = PresentationOptions(),
    /**
     * Relaxes what production requires, for a wallet talking to services
     * on a development machine; null, the default, is production. Never
     * ship an app with it set. It lets issuers, Authorization Servers,
     * Verifiers and status lists be on loopback addresses, over http there
     * too; makes requests through an ordinary HTTPS client, which reaches
     * private network addresses, instead of the hardened one (trusting
     * [Development.roots] too, when set); requires no revocation choice
     * for a trust role, so a role in neither [Revocation.roles] nor
     * [Revocation.declined] is checked for nothing; skips the check that
     * different roles' roots share no anchor; and skips the production
     * checks on receiving credentials: durable stores and keys, and the
     * random source. Refused (`invalid_input`) unless the app called
     * [OID4VC.allowDevelopment], from a debuggable build only.
     */
    val development: Development? = null,
) {
    /** Which issuers' credentials the wallet accepts. */
    public data class IssuerTrust(
        /** PEM certificates: the trust anchors for issuers' credentials. A credential signed by a certificate that doesn't chain to them is refused. */
        val roots: String = "",
        /**
         * A dotted object identifier: recognizes only issuer certificates
         * under [roots] with that extended key usage. Outside
         * [WalletConfiguration.development], required when [roots] may
         * share a trust anchor with another role's roots.
         */
        val requireEKU: String = "",
        /**
         * PEM certificates: the IACAs a received mdoc must chain to, in place
         * of [roots], so a [roots] anchor alone, an SD-JWT VC issuer's CA
         * say, can't sign an mDL. Empty: mdocs chain to [roots].
         */
        val mdocRoots: String = "",
        /**
         * Each document type's own IACAs, as PEM certificates: an mdoc of a
         * type named here must chain to them, not to [mdocRoots] or
         * [roots]. A type named with an empty string is refused.
         */
        val mdocRootsByDocType: Map<String, String> = emptyMap(),
        /**
         * A dotted object identifier: recognizes only document signer
         * certificates with that extended key usage (the mDL's is
         * 1.0.18013.5.1.2), in place of [requireEKU], so a wallet
         * receiving both formats can require each its own.
         */
        val mdocRequireEKU: String = "",
        /**
         * Also accepts a document signer certificate with no extended key
         * usage, which is refused by default for lacking the mDL document
         * signer's (1.0.18013.5.1.2), for issuers whose document signers have
         * none. Any certificate without one under the same IACAs, such as a
         * revocation list signer's, can then sign mdocs the wallet accepts.
         * It can't be set with [mdocRequireEKU], or with [requireEKU] unless
         * [mdocRoots] is set.
         */
        val acceptMDLSignerWithoutEKU: Boolean = false,
        /**
         * Refuses a received SD-JWT VC whose `iss` its signing certificate
         * doesn't name. SD-JWT VC doesn't require them to correspond: set it
         * where [roots] certify several issuers.
         */
        val requireIssuerName: Boolean = false,
        /**
         * Receives an SD-JWT VC whose `iss` isn't the `credential_issuer` it
         * was requested from, which is otherwise refused so an issuer can't
         * hand over another's credential as its own. Set it only for issuers
         * that name themselves differently, where [roots] certify them
         * alone.
         */
        val allowForeignIss: Boolean = false,
        /**
         * The Status Issuers that may sign a credential issuer's status lists
         * on its behalf: credential issuer (an SD-JWT VC's `iss`) → Status
         * Issuer identifiers, each recognized by a certificate under
         * [roots] naming it. Without it, [Wallet.checkStatus] accepts
         * only a status list the issuer signed itself.
         */
        val statusIssuers: Map<String, List<String>> = emptyMap(),
        /**
         * The only Credential Issuer Identifiers the wallet takes offers
         * from, each compared exactly with the offer's `credentialIssuer`:
         * [Wallet.startIssuance] refuses another's offer with
         * [WalletException.Code.untrustedIssuer] before fetching its
         * metadata, so the holder is never asked for a transaction code it
         * would send there. Resuming, refreshing and polling a deferred
         * credential refuse an issuer the list no longer names the same
         * way, keeping what the wallet holds from it.
         *
         * A wallet with [roots] (or the mdoc ones) must decide which
         * issuers' offers it takes, or the [Wallet] constructor throws
         * `invalidInput`: this list; signed issuer metadata naming its
         * issuer ([IssuerMetadataTrust] with `roots`, `requireSigned` and
         * `requireName`), which may be combined with it; or
         * [allowAnyCredentialIssuer], alone.
         */
        val credentialIssuers: List<String> = emptyList(),
        /**
         * Takes offers from any issuer, in place of [credentialIssuers] or
         * signed and named issuer metadata. A transaction code the holder
         * enters then reaches whichever issuer an offer names, so an
         * attacker's offer sent beside a genuine service's PIN phishes it:
         * guarding against that is the app's. Set it only for a wallet
         * whose issuers can't be told apart in advance.
         */
        val allowAnyCredentialIssuer: Boolean = false,
    )

    /** Which signed Credential Issuer Metadata the wallet trusts. */
    public data class IssuerMetadataTrust(
        /**
         * PEM certificates: the trust anchors for signed Credential Issuer
         * Metadata. With them, signed metadata is asked for and verified.
         */
        val roots: String = "",
        /**
         * A dotted object identifier: recognizes only issuer metadata signed
         * by a certificate under [roots] with that extended key usage.
         * Outside [WalletConfiguration.development], required when [roots]
         * may share a trust anchor with another role's roots.
         */
        val requireEKU: String = "",
        /**
         * Refuses an issuer whose metadata isn't signed under [roots],
         * before the holder signs in or enters a code.
         */
        val requireSigned: Boolean = false,
        /** Refuses signed metadata whose certificate doesn't name the issuer. */
        val requireName: Boolean = false,
        /** Refuses signed metadata signed longer ago than this many seconds; 0 doesn't limit it. */
        val maxAgeSeconds: Long = 0,
    )

    /** Which Verifiers, registrars and mdoc readers the wallet recognizes. */
    public data class VerifierTrust(
        /** PEM certificates: the trust anchors for Verifiers' requests. */
        val roots: String = "",
        /**
         * A dotted object identifier: recognizes only Verifier certificates
         * under [roots] with that extended key usage, the one your
         * ecosystem marks its Verifiers' certificates with. Outside
         * [WalletConfiguration.development], required when [roots] shares
         * a trust anchor with another role's roots.
         */
        val requireEKU: String = "",
        /**
         * Also answers Verifiers whose client ID has the `x509_san_dns`
         * prefix (OpenID4VP 1.0 §5.9.3), besides `x509_hash`, the one HAIP
         * 1.0 has Verifiers use: the DNS name must be one of the request's
         * signing certificate, which must chain to [roots], and, for
         * a request from a link, the host of its response URI; a Digital
         * Credentials API request is bound to the calling origin by its
         * `expected_origins` instead. Needs [roots]. Every name in a
         * certificate under [roots] is then a Verifier the wallet
         * answers, so set it only where those roots certify Verifiers alone,
         * or with [requireEKU].
         */
        val acceptX509SANDNS: Boolean = false,
        /**
         * PEM certificates: the registrars whose registrations of Verifiers
         * the wallet checks ([Presentation.Verifier.registration]). Empty:
         * registrations are ignored.
         */
        val registrarRoots: String = "",
        /**
         * A dotted object identifier: recognizes only registrar certificates
         * under [registrarRoots] with that extended key usage. Outside
         * [WalletConfiguration.development], required when [registrarRoots]
         * shares a trust anchor with another role's roots.
         */
        val registrarRequireEKU: String = "",
        /**
         * PEM certificates: the mdoc readers recognized when one signs an
         * `org-iso-mdoc` request ([MdocPresentation.Request.reader]). Empty:
         * every such request is shown by its origin.
         */
        val mdocReaderRoots: String = "",
        /**
         * Recognizes only reader certificates with the ISO/IEC 18013-5
         * reader authentication extended key usage (1.0.18013.5.1.6), so a
         * certificate issued for another role under [mdocReaderRoots] isn't
         * taken for a reader's.
         */
        val mdocReaderRequireEKU: Boolean = false,
        /**
         * Refuses an `org-iso-mdoc` request no recognized reader signed:
         * [Wallet.startMdocPresentation] throws `untrustedVerifier`, and
         * nothing is shown to the holder. Needs [mdocReaderRoots].
         */
        val requireTrustedMdocReader: Boolean = false,
        /**
         * Refuses an unsigned OpenID4VP request over the Digital Credentials
         * API: [Wallet.startDCAPIPresentation] throws `untrustedVerifier`,
         * before the holder sees it. Its only identity is the origin the
         * platform reports; HAIP requires a wallet to support unsigned
         * requests, so set it only where every Verifier must be one
         * [roots] accepts.
         */
        val requireSignedDCAPIRequests: Boolean = false,
    )

    /** Which trust roles' certificates are checked for revocation, and against which lists. */
    public data class Revocation(
        /**
         * The trust roles whose certificate chains must pass a CRL check
         * against [crls]. A role listed fails closed for any CA it has no
         * current CRL from, until [Wallet.setCRLs] supplies one. Outside
         * [WalletConfiguration.development], each role whose roots are set
         * must be listed here or in [declined], or the wallet isn't made
         * (`invalid_input`).
         */
        val roles: List<RevocationRole> = emptyList(),
        /**
         * The trust roles that decline checking revocation, as an explicit
         * choice: only where something else stands in for it, such as
         * certificates too short-lived to be worth revoking. A role can't be
         * in both this and [roles].
         */
        val declined: List<RevocationRole> = emptyList(),
        /**
         * PEM `X509 CRL` blocks: the Certificate Revocation Lists the roles
         * in [roles] are checked against. Replace them at runtime with
         * [Wallet.setCRLs] as they expire.
         */
        val crls: String = "",
        /**
         * PEM certificates of the CAs that issued certificates pinned in the
         * roots (a leaf in [VerifierTrust.roots], say), for a role in
         * [roles]: a pinned certificate is checked against its CA's CRL,
         * verified with the CA's certificate from here. They aren't trust
         * anchors. Without its CA here, a pinned certificate that isn't
         * self-signed is refused.
         */
        val crlIssuers: String = "",
        /**
         * Where [Wallet.refreshCRLs] fetches the lists from, each bound to the
         * CA whose list it serves.
         */
        val distributionPoints: List<CRLDistributionPoint> = emptyList(),
        /**
         * Also fetches, in [Wallet.refreshCRLs], the distribution point each
         * self-signed CA certificate names for its own list (as an IACA does),
         * among [crlIssuers] and the roots of the roles in [roles].
         */
        val distributionPointsFromRoots: Boolean = false,
        /** Refuses plain `http` distribution points, and leaves them out of [distributionPointsFromRoots]. */
        val requireHTTPS: Boolean = false,
    )

    /** The wallet's own HTTPS requests. */
    public data class Network(
        /**
         * Pins hosts' certificates for the wallet's own HTTPS requests:
         * host → base64 SHA-256 digests of a certificate's
         * SubjectPublicKeyInfo, one of which a certificate in the verified
         * chain must have, or the request fails as `tlsPin` before anything
         * is sent. A host is a name, or `*.` and one, matching any name a
         * label below it; not an IP address. Pins add to certificate
         * verification, never replace it: pin a CA's key, so a leaf renewal
         * doesn't break the app, and keep a backup pin. They cover the
         * requests the SDK makes (issuers, Authorization Servers, Verifiers,
         * status lists), not the app's own, such as to its Wallet Provider:
         * pin that client yourself (OkHttp's CertificatePinner, or a network
         * security configuration).
         */
        val tlsPins: Map<String, List<String>> = emptyMap(),
        /**
         * Hosts the wallet may reach at a private address (10/8, 172.16/12,
         * 192.168/16, fc00::/7) outside [WalletConfiguration.development]:
         * issuers, Verifiers, status lists and CRL distribution points inside
         * the deployment's own network, an enterprise's or a test
         * environment's. Each is a host name, matched exactly and without
         * case: no wildcard, IP address, port or loopback name. Nothing else
         * is lifted: a listed host is still refused at a loopback or
         * link-local address, and every request is still HTTPS with its
         * certificate verified. List only hosts the deployment runs: anyone
         * who can hand the wallet an offer or a request can have it send a
         * request to them.
         */
        val allowedPrivateHosts: List<String> = emptyList(),
    )

    /** How the wallet receives credentials. */
    public data class IssuanceOptions(
        /**
         * The holder's preferred languages (BCP 47, most preferred first),
         * for issuers' display metadata. The device's languages are the
         * usual choice, and the default.
         */
        val locales: List<String> = defaultLocales(),
        /**
         * How many copies of each credential to request when an issuer
         * offers batches, each bound to its own key, so each presentation
         * can use one no Verifier has seen. 0 means the SDK's default (5);
         * it's capped at the issuer's batch size.
         */
        val batchSize: Int = 0,
        /**
         * Asks Authorization Servers for a refresh token, so
         * [Wallet.refreshCredential] can later replace a credential's copies
         * without the holder signing in. The server must allow the wallet the
         * `offline_access` scope, or the authorization fails.
         */
        val requestRefresh: Boolean = false,
        /** The profile issuance follows. */
        val profile: IssuanceProfile = IssuanceProfile.OPENID4VCI,
        /**
         * Names the key of a jwt proof carrying a key attestation in `jwk`
         * rather than by its index in the attestation (`kid` `"0"`), the
         * default, which issuers following ETSI TS 119 472-3, such as the
         * EUDI reference PID issuer, require. Set it only for an issuer that
         * takes no index.
         */
        val proofKeyByJWK: Boolean = false,
        /**
         * Names the key of a jwt proof carrying a key attestation by its
         * index in the attestation, which is now the default: it has no
         * effect, and can't be set with [proofKeyByJWK].
         */
        val proofKeyByIndex: Boolean = false,
    )

    /** How the wallet presents credentials. */
    public data class PresentationOptions(
        /** Which copy of a credential a presentation uses. */
        val copyPolicy: CopyPolicy = CopyPolicy.PER_PRESENTATION,
        /**
         * How an in-person response authenticates the mdoc. [ProximityDeviceAuth.MAC_PREFERRED]
         * needs a key store that is also a [KeyAgreement].
         */
        val proximityDeviceAuth: ProximityDeviceAuth = ProximityDeviceAuth.SIGNATURE,
    )

    /** A trust role whose certificates can be checked for revocation. */
    @Serializable
    public enum class RevocationRole {
        /** The issuers' signing certificates ([IssuerTrust.roots] and the mdoc roots), on receipt, deferral and refresh. */
        @SerialName("issuer") ISSUER,

        /** The signers of Credential Issuer Metadata ([IssuerMetadataTrust.roots]). */
        @SerialName("issuer_metadata") ISSUER_METADATA,

        /** The registrars of Verifiers ([VerifierTrust.registrarRoots]). */
        @SerialName("registrar") REGISTRAR,

        /** The mdoc readers ([VerifierTrust.mdocReaderRoots]), online and in person. */
        @SerialName("mdoc_reader") MDOC_READER,

        /** The Verifiers' request-signing certificates ([VerifierTrust.roots]). */
        @SerialName("verifier") VERIFIER,

        /** The signers of status lists, in [Wallet.checkStatus]. */
        @SerialName("status") STATUS,
    }

    /** How an in-person response authenticates the mdoc (ISO/IEC 18013-5 §9.1.3). */
    @Serializable
    public enum class ProximityDeviceAuth {
        /** The holder key signs the session transcript (deviceSignature). The default. */
        @SerialName("signature") SIGNATURE,

        /**
         * The holder key agrees a key with the reader's ephemeral key and
         * the response carries a MAC (deviceMac). The reader can check it
         * but can't prove to anyone else that this device took part; the
         * issuer-signed elements stay provable. A holder key that can't
         * agree keys signs instead, without an error: the response is a
         * signature, as [SIGNATURE]'s.
         *
         * With [AndroidKeystoreKeyStore]'s default options its holder keys
         * can't: they sign only, and each signature requires the holder.
         * A holder key agrees keys when made with
         * [AndroidKeystoreKeyStore.Options.holderKeyAgreement] on API 31
         * or later, and either a positive
         * [AndroidKeystoreKeyStore.Options.holderAuthenticationTimeout] or
         * [AndroidKeystoreKeyStore.Options.holderUserAuthentication] off,
         * the app authenticating the holder itself. Keys made before keep
         * signing. A reader's [VerifiedMdoc.deviceAuth] says which it
         * got.
         */
        @SerialName("mac_preferred") MAC_PREFERRED,
    }

    /** The profile issuance follows. */
    @Serializable
    public enum class IssuanceProfile {
        /**
         * The issuer's and its Authorization Server's metadata, as
         * OpenID4VCI 1.0 has a wallet do: a Wallet Attestation and a key
         * attestation only where they ask for them. The default.
         */
        @SerialName("openid4vci") OPENID4VCI,

        /**
         * Also refuses an issuer that doesn't follow HAIP 1.0
         * ([WalletException.Code.profileViolation]). Needs a
         * [WalletProvider] and a `clientID`.
         */
        @SerialName("haip") HAIP,
    }

    /**
     * Which copy of a credential a presentation uses (OpenID4VCI 1.0: "a
     * unique Credential per presentation or per Verifier").
     */
    @Serializable
    public enum class CopyPolicy {
        /**
         * Every presentation uses a copy no Verifier has seen: not even
         * one Verifier can link two presentations. The default.
         */
        @SerialName("per_presentation") PER_PRESENTATION,

        /**
         * A Verifier is shown the copy it has seen before, and only a new
         * Verifier an unused one: Verifiers can't link presentations to
         * each other, but one can recognise a returning holder.
         */
        @SerialName("per_verifier") PER_VERIFIER,
    }

    /** The scheme of [redirectURI]: the scheme the authorization's redirect comes back on. */
    val callbackScheme: String? get() = runCatching { java.net.URI(redirectURI).scheme }.getOrNull()

    /** The configuration's defaults. */
    public companion object {
        /** The device's languages, most preferred first. */
        public fun defaultLocales(): List<String> {
            val list = android.os.LocaleList.getDefault()
            return (0 until list.size()).map { list[it].toLanguageTag() }.ifEmpty { listOf(Locale.getDefault().toLanguageTag()) }
        }
    }
}

/**
 * [WalletConfiguration]'s wire form: the flat JSON object `NewWallet`
 * reads (ABI.md), its keys and their order as they were before the
 * options were grouped, so a configuration encodes as it did and old
 * JSON decodes.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
internal data class WalletConfigurationJSON(
    @SerialName("client_id") val clientID: String = "",
    @SerialName("redirect_uri") val redirectURI: String = "",
    @SerialName("issuer_roots") val issuerRoots: String = "",
    @SerialName("verifier_roots") val verifierRoots: String = "",
    @SerialName("registrar_roots") val registrarRoots: String = "",
    @SerialName("mdoc_reader_roots") val mdocReaderRoots: String = "",
    @SerialName("mdoc_reader_require_eku") val mdocReaderRequireEKU: Boolean = false,
    @SerialName("require_trusted_mdoc_reader") val requireTrustedMdocReader: Boolean = false,
    @SerialName("require_signed_dcapi_requests") val requireSignedDCAPIRequests: Boolean = false,
    @SerialName("accept_x509_san_dns") val acceptX509SANDNS: Boolean = false,
    val development: Boolean = false,
    @SerialName("development_roots") val developmentRoots: String = "",
    @EncodeDefault val locales: List<String> = WalletConfiguration.defaultLocales(),
    @SerialName("batch_size") val batchSize: Int = 0,
    @SerialName("request_refresh") val requestRefresh: Boolean = false,
    @SerialName("copy_policy") val copyPolicy: WalletConfiguration.CopyPolicy = WalletConfiguration.CopyPolicy.PER_PRESENTATION,
    @SerialName("tls_pins") val tlsPins: Map<String, List<String>> = emptyMap(),
    @SerialName("allowed_private_hosts") val allowedPrivateHosts: List<String> = emptyList(),
    @SerialName("issuance_profile") val issuanceProfile: WalletConfiguration.IssuanceProfile = WalletConfiguration.IssuanceProfile.OPENID4VCI,
    @SerialName("proof_key_by_jwk") val proofKeyByJWK: Boolean = false,
    @SerialName("proof_key_by_index") val proofKeyByIndex: Boolean = false,
    @SerialName("proximity_device_auth") val proximityDeviceAuth: WalletConfiguration.ProximityDeviceAuth = WalletConfiguration.ProximityDeviceAuth.SIGNATURE,
    @SerialName("verifier_require_eku") val verifierRequireEKU: String = "",
    @SerialName("registrar_require_eku") val registrarRequireEKU: String = "",
    @SerialName("status_issuers") val statusIssuers: Map<String, List<String>> = emptyMap(),
    @SerialName("require_issuer_name") val requireIssuerName: Boolean = false,
    @SerialName("issuer_metadata_roots") val issuerMetadataRoots: String = "",
    @SerialName("require_signed_issuer_metadata") val requireSignedIssuerMetadata: Boolean = false,
    @SerialName("require_issuer_metadata_name") val requireIssuerMetadataName: Boolean = false,
    @SerialName("max_issuer_metadata_age_seconds") val maxIssuerMetadataAgeSeconds: Long = 0,
    @SerialName("issuer_require_eku") val issuerRequireEKU: String = "",
    @SerialName("issuer_metadata_require_eku") val issuerMetadataRequireEKU: String = "",
    @SerialName("allow_foreign_iss") val allowForeignIss: Boolean = false,
    @SerialName("credential_issuers") val credentialIssuers: List<String> = emptyList(),
    @SerialName("allow_any_credential_issuer") val allowAnyCredentialIssuer: Boolean = false,
    @SerialName("mdoc_issuer_roots") val mdocIssuerRoots: String = "",
    @SerialName("mdoc_issuer_roots_by_doctype") val mdocIssuerRootsByDocType: Map<String, String> = emptyMap(),
    @SerialName("mdoc_issuer_require_eku") val mdocIssuerRequireEKU: String = "",
    @SerialName("crls") val crls: String = "",
    @SerialName("revocation") val revocation: List<WalletConfiguration.RevocationRole> = emptyList(),
    @SerialName("crl_issuers") val crlIssuers: String = "",
    @SerialName("no_revocation_check") val noRevocationCheck: List<WalletConfiguration.RevocationRole> = emptyList(),
    @SerialName("accept_mdl_signer_without_eku") val acceptMDLSignerWithoutEKU: Boolean = false,
    @SerialName("crl_distribution_points") val crlDistributionPoints: List<CRLDistributionPoint> = emptyList(),
    @SerialName("crl_distribution_points_from_roots") val crlDistributionPointsFromRoots: Boolean = false,
    @SerialName("crl_require_https") val crlRequireHTTPS: Boolean = false,
    @SerialName("status_max_bytes") val statusMaxBytes: Int = 0,
    @SerialName("identifier_list_max_bytes") val identifierListMaxBytes: Int = 0,
    @SerialName("status_cache_max_age_seconds") val statusCacheMaxAgeSeconds: Long = 0,
    @SerialName("status_cache_dir") val statusCacheDir: String? = null,
)

/** Encodes a [WalletConfiguration] as its flat [WalletConfigurationJSON], and decodes one from it. */
internal object WalletConfigurationSerializer : KSerializer<WalletConfiguration> {
    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor("dev.idfoundry.oid4vcwallet.WalletConfiguration", WalletConfigurationJSON.serializer().descriptor)

    override fun serialize(encoder: Encoder, value: WalletConfiguration): Unit =
        encoder.encodeSerializableValue(WalletConfigurationJSON.serializer(), flat(value))

    override fun deserialize(decoder: Decoder): WalletConfiguration =
        grouped(decoder.decodeSerializableValue(WalletConfigurationJSON.serializer()))

    private fun flat(c: WalletConfiguration): WalletConfigurationJSON = WalletConfigurationJSON(
        clientID = c.clientID,
        redirectURI = c.redirectURI,
        issuerRoots = c.issuers.roots,
        verifierRoots = c.verifiers.roots,
        registrarRoots = c.verifiers.registrarRoots,
        mdocReaderRoots = c.verifiers.mdocReaderRoots,
        mdocReaderRequireEKU = c.verifiers.mdocReaderRequireEKU,
        requireTrustedMdocReader = c.verifiers.requireTrustedMdocReader,
        requireSignedDCAPIRequests = c.verifiers.requireSignedDCAPIRequests,
        acceptX509SANDNS = c.verifiers.acceptX509SANDNS,
        development = c.development != null,
        developmentRoots = c.development?.roots ?: "",
        locales = c.issuance.locales,
        batchSize = c.issuance.batchSize,
        requestRefresh = c.issuance.requestRefresh,
        copyPolicy = c.presentation.copyPolicy,
        tlsPins = c.network.tlsPins,
        allowedPrivateHosts = c.network.allowedPrivateHosts,
        issuanceProfile = c.issuance.profile,
        proofKeyByJWK = c.issuance.proofKeyByJWK,
        proofKeyByIndex = c.issuance.proofKeyByIndex,
        proximityDeviceAuth = c.presentation.proximityDeviceAuth,
        verifierRequireEKU = c.verifiers.requireEKU,
        registrarRequireEKU = c.verifiers.registrarRequireEKU,
        statusIssuers = c.issuers.statusIssuers,
        requireIssuerName = c.issuers.requireIssuerName,
        issuerMetadataRoots = c.issuerMetadata.roots,
        requireSignedIssuerMetadata = c.issuerMetadata.requireSigned,
        requireIssuerMetadataName = c.issuerMetadata.requireName,
        maxIssuerMetadataAgeSeconds = c.issuerMetadata.maxAgeSeconds,
        issuerRequireEKU = c.issuers.requireEKU,
        issuerMetadataRequireEKU = c.issuerMetadata.requireEKU,
        allowForeignIss = c.issuers.allowForeignIss,
        credentialIssuers = c.issuers.credentialIssuers,
        allowAnyCredentialIssuer = c.issuers.allowAnyCredentialIssuer,
        mdocIssuerRoots = c.issuers.mdocRoots,
        mdocIssuerRootsByDocType = c.issuers.mdocRootsByDocType,
        mdocIssuerRequireEKU = c.issuers.mdocRequireEKU,
        crls = c.revocation.crls,
        revocation = c.revocation.roles,
        crlIssuers = c.revocation.crlIssuers,
        noRevocationCheck = c.revocation.declined,
        acceptMDLSignerWithoutEKU = c.issuers.acceptMDLSignerWithoutEKU,
        crlDistributionPoints = c.revocation.distributionPoints,
        crlDistributionPointsFromRoots = c.revocation.distributionPointsFromRoots,
        crlRequireHTTPS = c.revocation.requireHTTPS,
        statusMaxBytes = c.status.maxBytes,
        identifierListMaxBytes = c.status.identifierListMaxBytes,
        statusCacheMaxAgeSeconds = c.status.cacheMaxAgeSeconds,
        statusCacheDir = c.status.cacheDir,
    )

    private fun grouped(j: WalletConfigurationJSON): WalletConfiguration = WalletConfiguration(
        clientID = j.clientID,
        redirectURI = j.redirectURI,
        issuers = WalletConfiguration.IssuerTrust(
            roots = j.issuerRoots,
            requireEKU = j.issuerRequireEKU,
            mdocRoots = j.mdocIssuerRoots,
            mdocRootsByDocType = j.mdocIssuerRootsByDocType,
            mdocRequireEKU = j.mdocIssuerRequireEKU,
            acceptMDLSignerWithoutEKU = j.acceptMDLSignerWithoutEKU,
            requireIssuerName = j.requireIssuerName,
            allowForeignIss = j.allowForeignIss,
            statusIssuers = j.statusIssuers,
            credentialIssuers = j.credentialIssuers,
            allowAnyCredentialIssuer = j.allowAnyCredentialIssuer,
        ),
        issuerMetadata = WalletConfiguration.IssuerMetadataTrust(
            roots = j.issuerMetadataRoots,
            requireEKU = j.issuerMetadataRequireEKU,
            requireSigned = j.requireSignedIssuerMetadata,
            requireName = j.requireIssuerMetadataName,
            maxAgeSeconds = j.maxIssuerMetadataAgeSeconds,
        ),
        verifiers = WalletConfiguration.VerifierTrust(
            roots = j.verifierRoots,
            requireEKU = j.verifierRequireEKU,
            acceptX509SANDNS = j.acceptX509SANDNS,
            registrarRoots = j.registrarRoots,
            registrarRequireEKU = j.registrarRequireEKU,
            mdocReaderRoots = j.mdocReaderRoots,
            mdocReaderRequireEKU = j.mdocReaderRequireEKU,
            requireTrustedMdocReader = j.requireTrustedMdocReader,
            requireSignedDCAPIRequests = j.requireSignedDCAPIRequests,
        ),
        revocation = WalletConfiguration.Revocation(
            roles = j.revocation,
            declined = j.noRevocationCheck,
            crls = j.crls,
            crlIssuers = j.crlIssuers,
            distributionPoints = j.crlDistributionPoints,
            distributionPointsFromRoots = j.crlDistributionPointsFromRoots,
            requireHTTPS = j.crlRequireHTTPS,
        ),
        status = StatusLists(j.statusMaxBytes, j.identifierListMaxBytes, j.statusCacheMaxAgeSeconds, j.statusCacheDir),
        network = WalletConfiguration.Network(tlsPins = j.tlsPins, allowedPrivateHosts = j.allowedPrivateHosts),
        issuance = WalletConfiguration.IssuanceOptions(
            locales = j.locales,
            batchSize = j.batchSize,
            requestRefresh = j.requestRefresh,
            profile = j.issuanceProfile,
            proofKeyByJWK = j.proofKeyByJWK,
            proofKeyByIndex = j.proofKeyByIndex,
        ),
        presentation = WalletConfiguration.PresentationOptions(copyPolicy = j.copyPolicy, proximityDeviceAuth = j.proximityDeviceAuth),
        development = Development.decoded(j.development, j.developmentRoots),
    )
}

/**
 * An image the issuer names for display: an https URL or a data: image
 * (nothing else reaches the app, nor an https URL naming an IP address or
 * localhost), with alternative text. Loading the URL tells whoever serves
 * it that the holder is looking: fetch it once, when the holder accepts
 * the credential rather than on the offer's preview, and keep it.
 *
 * @property uri The image: an https URL or a `data:` URL.
 * @property altText Text describing the image, for accessibility.
 */
@Serializable
public data class Logo(val uri: String, @SerialName("alt_text") val altText: String? = null)

/**
 * How to show a credential, from the issuer's metadata (OpenID4VCI 1.0
 * §12.2.4) in the holder's language: each part only when the issuer
 * gives it. Colours are CSS colours, such as "#12107c".
 */
@Serializable
public data class CredentialDisplay(
    /** The issuer's name. */
    @SerialName("issuer_name") val issuerName: String? = null,
    /** The issuer's logo. */
    @SerialName("issuer_logo") val issuerLogo: Logo? = null,
    /** The credential's name. */
    val name: String? = null,
    /** A description of the credential. */
    val description: String? = null,
    /** The credential's logo. */
    val logo: Logo? = null,
    /** The card's background colour. */
    @SerialName("background_color") val backgroundColor: String? = null,
    /** The card's text colour. */
    @SerialName("text_color") val textColor: String? = null,
)

/**
 * A credential's revocation status, as last checked ([Wallet.checkStatus]):
 * in the issuer's status list, and, from OID4VCWallet 0.27.0, its issuer's
 * certificate chain against the revocation lists held then.
 */
@Serializable
public data class CredentialStatus(
    /**
     * The status as the issuer's list names it: `valid`, `invalid`, `suspended`, or "0x" and a
     * value of the list's own; or `unknown`, for a status naming no mechanism the wallet knows.
     * [value] reads it.
     */
    @SerialName("value") val rawValue: String,
    /** When it was checked. */
    @SerialName("checked_at") @Serializable(InstantSerializer::class) val checkedAt: Instant,
    /**
     * Why the status is what it is, as the Go side names it, such as
     * `issuer_certificate_revoked`; null for `valid`, and for a status
     * recorded before OID4VCWallet 0.27.0. [reason] reads it.
     */
    @SerialName("reason") val rawReason: String? = null,
) {
    /** Why a status is what it is. */
    public sealed interface Reason {
        /** The issuer's Token Status List gives it: [Value.Revoked] (final), [Value.Suspended] or [Value.Other]. */
        public data object StatusList : Reason

        /** The mdoc is on its issuer's identifier list: [Value.Revoked], final. */
        public data object IdentifierList : Reason

        /**
         * [Value.Revoked]: the issuer's signing certificate, or a CA above it, is on its CA's
         * revocation list. Not final: a later check with a list that no longer names it makes
         * it valid again.
         */
        public data object IssuerCertificateRevoked : Reason

        /** [Value.Revoked]: the issuer's certificate chain no longer verifies under the configured roots, or has expired. */
        public data object IssuerUntrusted : Reason

        /**
         * [Value.Unknown]: there's no current revocation list to check the issuer's chain, or
         * its status list's signer's, against. Refresh them ([Wallet.refreshCRLs]) and check again.
         */
        public data object NoCurrentCRL : Reason

        /** [Value.Unknown]: a status naming no mechanism the wallet knows. */
        public data object UnrecognizedStatus : Reason

        /**
         * A reason this version doesn't know.
         *
         * @property value The reason, as the Go side names it.
         */
        public data class Other(val value: String) : Reason
    }

    /** [rawReason], read: null when there's none. */
    val reason: Reason?
        get() = when (rawReason) {
            null -> null
            "status_list" -> Reason.StatusList
            "identifier_list" -> Reason.IdentifierList
            "issuer_certificate_revoked" -> Reason.IssuerCertificateRevoked
            "issuer_untrusted" -> Reason.IssuerUntrusted
            "no_current_crl" -> Reason.NoCurrentCRL
            "unrecognized_status" -> Reason.UnrecognizedStatus
            else -> Reason.Other(rawReason)
        }

    /** A status in the issuer's list. */
    public sealed interface Value {
        /** Not revoked or suspended. */
        public data object Valid : Value
        /** Revoked for good (the list's `invalid`). */
        public data object Revoked : Value
        /** Suspended, for now. */
        public data object Suspended : Value

        /**
         * A status the issuer's list defines itself, as "0x" and its value.
         *
         * @property value The status, as "0x" and its value.
         */
        public data class Other(val value: String) : Value

        /**
         * A status naming no mechanism the wallet knows, and no list saying otherwise than
         * valid: the status isn't known. Before OID4VCWallet 0.22.0, also an mdoc naming an
         * identifier list (ISO/IEC 18013-5 §12.3.6.4), which is now checked.
         */
        public data object Unknown : Value
    }

    /** [rawValue], read. */
    val value: Value
        get() = when (rawValue) {
            "valid" -> Value.Valid
            "invalid" -> Value.Revoked
            "suspended" -> Value.Suspended
            "unknown" -> Value.Unknown
            else -> Value.Other(rawValue)
        }
}

/** A credential the wallet holds, as the app shows it. */
@Serializable
public data class CredentialSummary(
    /** The credential's ID in the wallet. */
    val id: String,
    /** The issuer's identifier, an https URL. */
    @SerialName("credential_issuer") val credentialIssuer: String,
    /** The issuer's credential configuration it was issued under. */
    @SerialName("configuration_id") val configurationID: String,
    /** Its format: `dc+sd-jwt` or `mso_mdoc`. */
    val format: String,
    /** An SD-JWT VC's type. */
    val vct: String? = null,
    /** An mdoc's document type. */
    val doctype: String? = null,
    /** When the wallet received it. */
    @SerialName("received_at") @Serializable(InstantSerializer::class) val receivedAt: Instant,
    /**
     * Whether the key store still holds the credential's key: without it
     * (restored to another device, say) it can't be presented. Set in
     * [Wallet.credentials] and [Wallet.credential].
     */
    @SerialName("holder_key_present") val holderKeyPresent: Boolean? = null,
    /** How to show it, from the issuer's metadata when it was received. */
    val display: CredentialDisplay? = null,
    /** When it expires, if it says. */
    @SerialName("valid_until") @Serializable(InstantSerializer::class) val validUntil: Instant? = null,
    /** Its revocation status, as last checked; null before any check. */
    val status: CredentialStatus? = null,
    /**
     * How many copies the wallet holds, each bound to its own key, and
     * how many no Verifier has seen. Each presentation uses one of
     * those; once none is left, presentations can be linked.
     */
    val copies: Int = 0,
    /** How many copies no Verifier has seen. */
    @SerialName("copies_left") val copiesLeft: Int = 0,
    /**
     * Whether its issuance kept a refresh token
     * ([WalletConfiguration.IssuanceOptions.requestRefresh]), so
     * [Wallet.refreshCredential] can replace its copies. The
     * Authorization Server may still refuse
     * ([WalletException.Code.reissueRequired]).
     */
    val refreshable: Boolean = false,
    /**
     * Whether a copy has been presented to more than one Verifier, so
     * those Verifiers could link the holder's presentations. Refreshing
     * gives it copies no Verifier has seen.
     */
    val linkable: Boolean = false,
    /**
     * Whether a Verifier could accept it now, as far as the wallet
     * knows: a copy is neither expired nor found revoked, and its status
     * as last checked isn't revoked or suspended. A presentation lists
     * the others after it, and the default selection never picks them.
     */
    val presentable: Boolean = true,
    /**
     * Set only on a presentation's candidates ([Presentation.queries]):
     * whether the Verifier asking has been shown this credential before,
     * and whether presenting it now would hand it a copy another
     * Verifier has seen.
     */
    @SerialName("shown_to_verifier") val shownToVerifier: Boolean? = null,
    /**
     * Whether presenting it to the Verifier asking would hand it a copy
     * another Verifier has seen. Set only on a presentation's candidates.
     */
    @SerialName("linkable_here") val linkableHere: Boolean? = null,
) {
    /** Whether it has expired by [now]. */
    public fun isExpired(now: Instant = Instant.now()): Boolean = validUntil?.let { !it.isAfter(now) } ?: false
}

/**
 * A credential an issuer will issue later (OpenID4VCI 1.0 §9). It's
 * kept in the credential store until it's issued, denied or abandoned,
 * so it survives the app quitting.
 */
@Serializable
public data class DeferredCredential(
    /** The deferred credential's ID, for [Wallet.pollDeferred]. */
    val id: String,
    /** The issuer's identifier, an https URL. */
    @SerialName("credential_issuer") val credentialIssuer: String,
    /** The issuer's credential configuration requested. */
    @SerialName("configuration_id") val configurationID: String,
    /** How long the issuer asked the wallet to wait between polls. */
    @SerialName("interval_seconds") val intervalSeconds: Double,
    /** When the issuer deferred it. */
    @SerialName("deferred_at") @Serializable(InstantSerializer::class) val deferredAt: Instant,
    /**
     * When the access token it's polled with expires, if the issuer
     * said: after it, polls fail and it can only be abandoned.
     */
    @SerialName("access_token_expires_at") @Serializable(InstantSerializer::class) val accessTokenExpiresAt: Instant? = null,
)

/** A deferred credential's state, from [Wallet.pollDeferred]. */
public sealed interface DeferredStatus {
    /**
     * Not issued yet: poll again after [intervalSeconds].
     *
     * @property intervalSeconds How long to wait before polling again, in seconds.
     */
    public data class Pending(val intervalSeconds: Double) : DeferredStatus
    /**
     * Issued, and stored: [credential].
     *
     * @property credential The credential, now stored.
     */
    public data class Issued(val credential: CredentialSummary) : DeferredStatus
}

/** A credential with its claims, for display. */
public data class CredentialDetail(
    /** The credential. */
    val summary: CredentialSummary,
    /**
     * An SD-JWT VC's claims, or an mdoc's namespace → element → value;
     * byte strings (a portrait) are base64.
     */
    val claims: JsonElement,
)

/** One claim path element: a key, an array index, or every element. */
@Serializable(PathElementSerializer::class)
public sealed interface PathElement {
    /**
     * A claim name: [key].
     *
     * @property key The claim's name.
     */
    public data class Key(val key: String) : PathElement
    /**
     * An array element: [index].
     *
     * @property index The element's index.
     */
    public data class Index(val index: Int) : PathElement
    /** Every element of an array. */
    public data object All : PathElement
}

/**
 * A holder's wallet: OID4VCgo's walletflow over the app's key store,
 * credential store and Wallet Provider. Creating it makes no network
 * calls; [provider] is needed to receive credentials, not to present
 * them. Each key the wallet makes is made over the challenge
 * [WalletProvider.attestationChallenge] gives for it, and reaches the
 * provider's attestation calls with its ID and attestation chain
 * ([KeyEvidence]).
 */
public class Wallet(
    configuration: WalletConfiguration,
    keyStore: KeyStore,
    credentialStore: CredentialStore,
    provider: WalletProvider?,
) {
    private val handle: MobileWallet

    // Go holds these too; the wallet keeps them alive with it.
    private val adapters: List<Any>

    init {
        if (OID4VC.abiVersion != OID4VC.expectedABIVersion) {
            throw WalletException(
                WalletException.Code.internal, null,
                "the linked Go library has ABI ${OID4VC.abiVersion}, these sources ABI ${OID4VC.expectedABIVersion}: rebuild it",
            )
        }
        OID4VC.checkDevelopment(configuration.development != null)
        // Keys are made over the provider's attestation challenges, and
        // reach it with their attestation chains.
        val created = CreatedKeys()
        val keys = KeyStoreAdapter(keyStore, provider, created)
        val credentials = CredentialStoreAdapter(credentialStore)
        val wp = provider?.let { WalletProviderAdapter(it, keyStore, created) }
        val config = StatusCacheKey.configuration(json.encodeToString(WalletConfiguration.serializer(), configuration), configuration.status.cacheDir)
        handle = OID4VC.wrap { Mobile.newWallet(config, keys, credentials, wp) }
        val agreement = (keyStore as? KeyAgreement)?.let(::KeyAgreementAdapter)
        agreement?.let(handle::setKeyAgreement)
        // A call cancelled while it waits for the holder or the provider
        // ends that wait.
        val canceller = CallbackCancellerAdapter(keyStore, wp)
        handle.setCallbackCanceller(canceller)
        adapters = listOfNotNull(keys, credentials, wp, agreement, canceller)
    }

    /**
     * Deletes every key in [keyStore] that none of the wallet's
     * credentials is bound to — left by an issuance the app quit or
     * crashed in the middle of, or one dropped without [Issuance.close]
     * — and returns how many. Call it at launch, before any issuance or
     * refresh: one in progress holds keys of its own.
     *
     * What it may delete: key pairs under [keyStore]'s
     * [AndroidKeystoreKeyStore.Options.aliasPrefix] — holder, instance
     * and DPoP keys — that no credential is bound to. Pass the wallet's
     * own key store, under a prefix of its own: another key pair of the
     * app's under that prefix would be deleted too. Secret keys — the
     * credential store's and the status cache's — are never deleted.
     *
     * @throws IllegalArgumentException, deleting nothing, for a store
     *   whose prefix covers or falls under
     *   [HttpWalletProvider.REGISTRATION_KEY_ALIAS_PREFIX]: that would
     *   delete the Wallet Provider registration key, which
     *   [HttpWalletProvider.sweepOrphanedRegistrationKeys] sweeps instead.
     */
    public suspend fun sweepOrphanedKeys(keyStore: AndroidKeystoreKeyStore): Int {
        walletSweepRefusal(keyStore.options.aliasPrefix)?.let { throw IllegalArgumentException(it) }
        val keep = decode<KeyIDsResult>(OID4VC.offMain { handle.holderKeyIDs() }).keyIDs.toSet()
        return OID4VC.offMain { keyStore.deleteKeys(keep) }
    }

    internal companion object {
        /**
         * Why [sweepOrphanedKeys] refuses a key store under [aliasPrefix],
         * or null: an empty prefix covers every key, and one overlapping
         * the registration key's prefix covers that key.
         */
        internal fun walletSweepRefusal(aliasPrefix: String): String? {
            val registration = HttpWalletProvider.REGISTRATION_KEY_ALIAS_PREFIX
            return when {
                aliasPrefix.isEmpty() -> "sweep keys: the key store's aliasPrefix is empty, which covers every key"
                aliasPrefix.startsWith(registration) || registration.startsWith(aliasPrefix) ->
                    "sweep keys: the key store's aliasPrefix $aliasPrefix overlaps the Wallet Provider registration key's, $registration"
                else -> null
            }
        }
    }

    /** Every credential the wallet holds. */
    public suspend fun credentials(): List<CredentialSummary> {
        return decode<CredentialsResult>(OID4VC.offMain { handle.credentials() }).credentials
    }

    /** One credential with its claims. */
    public suspend fun credential(id: String): CredentialDetail {
        val text = OID4VC.offMain { handle.credential(id) }
        val summary = decode<CredentialSummary>(text)
        val claims = decode<JsonObject>(text)["claims"] ?: JsonNull
        return CredentialDetail(summary, claims)
    }

    /**
     * Fetches the issuer's status list for a credential, and an mdoc's
     * identifier list, checks their signatures, and returns the
     * credential with its revocation status recorded. Each list covers
     * many credentials, so fetching it doesn't tell the issuer which
     * one is checked. A credential without a status or identifier list
     * is returned as it is. Revocation is final: a credential found
     * revoked stays so, its lists not fetched again, until the revoked
     * copy expires or the credential is refreshed.
     */
    public suspend fun checkStatus(id: String): CredentialSummary =
        decode(OID4VC.cancellable { op -> handle.checkStatus(op, id) })

    /** What [refreshCredential] obtained. */
    @Serializable
    public data class Refreshed(
        /**
         * The credential, its ID unchanged: with every copy unused, or as
         * it was when the issuer deferred the new one.
         */
        val credential: CredentialSummary,
        /** The deferred credential to poll, when the issuer deferred it: once issued, it replaces the credential under the same ID. */
        val deferred: DeferredCredential? = null,
    )

    /**
     * Replaces a `refreshable` credential's copies with a fresh batch,
     * each bound to a new holder key, without the holder signing in
     * (OpenID4VCI 1.0 §13.5). The new holder keys sign the Credential
     * Request's proof, so with
     * [AndroidKeystoreKeyStore.Options.holderUserAuthentication] on it
     * asks the holder. Use it when `copiesLeft` runs low. Throws
     * [WalletException.Code.reissueRequired] when it can't be refreshed:
     * receive it again from a new offer.
     */
    public suspend fun refreshCredential(id: String): Refreshed =
        decode(OID4VC.cancellable { op -> handle.refreshCredential(op, id) })

    /**
     * Replaces the Certificate Revocation Lists the configuration's
     * [WalletConfiguration.Revocation.roles] are checked against with
     * [pem]'s `X509 CRL` blocks, for every check from now on. CRLs expire
     * at their nextUpdate: fetch fresh ones and call this before then.
     * Text holding anything else, a list that doesn't parse, or a CA's
     * list older than the one held (a lower CRL number, or an earlier
     * thisUpdate) throws `invalidInput` and keeps the lists as they were,
     * so a replayed list can't un-revoke a certificate; empty text
     * removes them all, and a role checked then fails closed. Makes no
     * network calls.
     */
    public suspend fun setCRLs(pem: String) {
        OID4VC.offMain { handle.setCRLs(pem) }
    }

    /**
     * Fetches the Certificate Revocation Lists of the configuration's
     * [WalletConfiguration.Revocation.distributionPoints] (and, with
     * [WalletConfiguration.Revocation.distributionPointsFromRoots], those its
     * roots name) and keeps each one its CA signed that is current and not
     * older than the one held, for every check from now on, presentations
     * already running included. A failed point keeps its list. Fetches go
     * to public addresses only outside development, over `http` or
     * `https` (the lists are signed). Persist the result's
     * [CRLRefreshResult.crls] for the next launch and schedule the next
     * refresh at its [CRLRefreshResult.nextRefresh] (see
     * GoingToProduction). Throws `invalidInput` (`not_configured`) with no
     * distribution points configured; cancelled with its coroutine.
     */
    public suspend fun refreshCRLs(): CRLRefreshResult =
        CRLRefreshResult.of(OID4VC.cancellable { op -> handle.refreshCRLs(op) })

    /**
     * Deletes a credential and its holder keys, and its refresh grant
     * once no other credential uses it, first revoking the refresh token
     * at the Authorization Server, best effort.
     */
    public suspend fun deleteCredential(id: String) {
        OID4VC.offMain { handle.deleteCredential(id) }
    }

    /**
     * The credentials issuers have deferred and not yet settled, oldest
     * first — including ones from before the app last quit. Makes no
     * network calls: poll each at its interval.
     */
    public suspend fun deferredCredentials(): List<DeferredCredential> {
        return decode<DeferredResult>(OID4VC.offMain { handle.deferred() }).deferred
    }

    /**
     * Asks the issuer once about a deferred credential. A refused one
     * throws [WalletException.Code.credentialDenied], and is then no
     * longer pending.
     */
    public suspend fun pollDeferred(id: String): DeferredStatus {
        val s = decode<PollResult>(OID4VC.cancellable { op -> handle.pollDeferred(op, id) })
        if (s.status == Mobile.DeferredIssued && s.credential != null) return DeferredStatus.Issued(s.credential)
        return DeferredStatus.Pending(s.intervalSeconds)
    }

    /**
     * Gives up on a deferred credential — its access token has expired,
     * say, or the holder no longer wants it — deleting it and its keys.
     */
    public suspend fun abandonDeferred(id: String) {
        OID4VC.offMain { handle.abandonDeferred(id) }
    }

    /** Resolves a Credential Offer (openid-credential-offer://…) and the issuer's metadata. */
    public suspend fun startIssuance(offer: String): Issuance =
        Issuance(OID4VC.cancellable { op -> handle.startIssuance(op, offer) })

    /**
     * Completes an authorization begun before the app was killed:
     * [redirect] is the issuer's redirect back to the redirect URI,
     * delivered to the app. Returns the issuance ready for
     * [Issuance.requestCredentials]. A redirect matching no
     * authorization in progress — not this wallet's, already completed,
     * or expired — throws [WalletException.Code.notFound].
     */
    public suspend fun resumeIssuance(redirect: String): Issuance =
        Issuance(OID4VC.cancellable { op -> handle.resumeIssuance(op, redirect) })

    /**
     * Fetches and verifies an OpenID4VP request (openid4vp://…), and
     * finds the credentials that can answer it. A request the wallet
     * refuses throws [WalletException.Code.requestRefused], whose
     * [WalletException.refusalRedirect] is where the Verifier asked to
     * take the holder.
     */
    public suspend fun startPresentation(request: String): Presentation =
        Presentation(
            OID4VC.cancellable { op ->
                try {
                    OID4VC.wrap { handle.startPresentation(op, request) }
                } catch (e: WalletException) {
                    // This call's own, not the latest of any call's.
                    if (e.code == WalletException.Code.requestRefused) e.refusalRedirect = op.takeRefusalRedirect().ifEmpty { null }
                    throw e
                }
            },
        )

    /**
     * Where the Verifier asked to take the holder after the wallet
     * refused its request: when [startPresentation] throws
     * [WalletException.Code.requestRefused], open this URL, if any, as
     * OpenID4VP §8.2 has a wallet do. It's returned once. It holds the
     * latest refusal of any call: with presentations started
     * concurrently, open the exception's own
     * [WalletException.refusalRedirect] instead, or one Verifier's
     * redirect may be opened for another's refusal.
     */
    public fun takeRefusalRedirect(): String? = handle.takeRefusalRedirect().ifEmpty { null }

    /**
     * Parses an OpenID4VP request delivered through the Digital
     * Credentials API (OpenID4VP 1.0 Appendix A), as Credential Manager
     * hands it over: [protocol] (`openid4vp-v1-unsigned`, `-signed` or
     * `-multisigned`), its [requestData] (the request's `data` object, as
     * JSON) and the calling page's or app's [origin]. It's answered as a
     * presentation from [startPresentation], but [Presentation.respond]
     * and [Presentation.decline] send nothing: each returns, in
     * [Presentation.Presented.dcapiResponse], the response's data for the
     * platform to hand back.
     *
     * [origin] must be one the platform verified: Credential Manager's
     * `CallingAppInfo.getOrigin` for a privileged browser, or the calling
     * app's signing-certificate origin. Never take it from the request:
     * an unsigned request names no Verifier but its origin, and presented
     * copies are bound to it. A request that can't be parsed is
     * [WalletException.Code.invalidInput].
     */
    public suspend fun startDCAPIPresentation(protocol: String, requestData: ByteArray, origin: String): Presentation =
        Presentation(OID4VC.cancellable { op -> handle.startDCAPIPresentation(op, protocol, requestData, origin) })

    /**
     * The held mdocs, each with whether the page at [origin] has been
     * shown it and whether presenting it there now would be linkable
     * (`shownToVerifier`, `linkableHere`): for a consent screen shown
     * before the platform releases the request itself.
     * [MdocPresentation.request] says the same once it has. Every held
     * mdoc is listed, an expired, revoked or suspended one too: offer the
     * holder only those whose [CredentialSummary.presentable] is true.
     */
    public suspend fun mdocCandidates(origin: String): List<CredentialSummary> {
        return decode<CredentialsResult>(OID4VC.offMain { handle.mdocCandidates(origin) }).credentials
    }

    /**
     * Parses an `org-iso-mdoc` request — an mdoc asked for over the
     * Digital Credentials API — and finds the held mdocs that can answer
     * it. [origin] is the requesting page's origin, as
     * [MdocPresentation.origin] serializes it.
     */
    public suspend fun startMdocPresentation(requestData: ByteArray, origin: String): MdocPresentation =
        MdocPresentation(OID4VC.cancellable { op -> handle.startMdocPresentation(op, requestData, origin) })

    /**
     * Starts an ISO/IEC 18013-5 in-person presentation over BLE: show
     * its [ProximityPresentation.qrCode]. In [modes], both by default, it
     * advertises for a reader (peripheral server mode) and scans for one
     * (central client mode) until a reader connects either way; a reader
     * offered both should choose central client mode. It needs
     * Bluetooth on and [ProximityPermissions.holder] for [modes] granted
     * ([ProximityException] otherwise).
     */
    public fun startProximityPresentation(
        context: Context,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
        modes: Set<ProximityBLEMode> = ProximityBLEMode.entries.toSet(),
    ): ProximityPresentation {
        require(modes.isNotEmpty()) { NO_BLE_MODE }
        ProximityPermissions.require(context, ProximityPermissions.holder(modes))
        val app = context.applicationContext
        return ProximityPresentation(start(modes), { it.transport(app) }, timeouts)
    }

    /**
     * Arms static NFC-to-BLE engagement, closing any previous NFC presentation
     * before replacing it. Declare an [NfcEngagementService] in the app manifest.
     * NFC reads start BLE once; consent follows [NfcPresentation.presentation].
     * [negotiated] enables TNEP service selection and Hr/Hs negotiation.
     * [nfcData] uses classic NFC-only retrieval, with [negotiated] selecting its handover;
     * Bluetooth permissions are unnecessary in that mode.
     */
    public suspend fun startNfcPresentation(
        context: Context,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
        modes: Set<ProximityBLEMode> = ProximityBLEMode.entries.toSet(),
        negotiated: Boolean = false,
        nfcData: Boolean = false,
    ): NfcPresentation {
        require(modes.isNotEmpty()) { NO_BLE_MODE }
        require(android.nfc.NfcAdapter.getDefaultAdapter(context)?.isEnabled == true) { "NFC unavailable or disabled" }
        if (!nfcData) ProximityPermissions.require(context, ProximityPermissions.holder(modes))
        val app = context.applicationContext
        return startNfcPresentation(timeouts, modes, negotiated, nfcData) { it.transport(app) }
    }

    /**
     * [startNfcPresentation] with its handover and transport named by
     * [options] rather than by two adjacent Booleans:
     * `startNfcPresentation(context, options = NfcEngagementOptions(nfcData = true))`.
     */
    public suspend fun startNfcPresentation(
        context: Context,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
        modes: Set<ProximityBLEMode> = ProximityBLEMode.entries.toSet(),
        options: NfcEngagementOptions,
    ): NfcPresentation = startNfcPresentation(context, timeouts, modes, options.negotiated, options.nfcData)

    /**
     * Offers QR/BLE and NFC with independent keys and one consent flow. A valid
     * NFC-to-BLE handover (full Hs read), NFC data application SELECT, or a
     * QR BLE session started wins permanently. Type 4 discovery keeps QR available.
     * A QR BLE session starts when any device in range first writes State 0x01 to
     * the holder's GATT server (or, in central client mode, once the holder starts
     * one with the reader), which needs no QR code: a device that never saw it can
     * select QR, leaving NFC unavailable for the session.
     * NFC-only remains available without Bluetooth permission; then QR is omitted.
     * Closing a previous app-level NFC/combined owner finishes before replacement.
     */
    public suspend fun startCombinedPresentation(
        context: Context,
        timeouts: ProximityTimeouts = ProximityTimeouts(),
        modes: Set<ProximityBLEMode> = ProximityBLEMode.entries.toSet(),
        nfc: NfcEngagementOptions = NfcEngagementOptions(),
    ): CombinedPresentation {
        require(modes.isNotEmpty()) { NO_BLE_MODE }
        require(android.nfc.NfcAdapter.getDefaultAdapter(context)?.isEnabled == true) { "NFC unavailable or disabled" }
        val missing = ProximityPermissions.missing(context, ProximityPermissions.holder(modes))
        if (!nfc.nfcData) ProximityPermissions.require(context, ProximityPermissions.holder(modes))
        val app = context.applicationContext
        return startCombinedPresentation(timeouts, modes, nfc, missing.isNotEmpty()) { it.transport(app) }
    }

    internal suspend fun startCombinedPresentation(
        timeouts: ProximityTimeouts,
        modes: Set<ProximityBLEMode>,
        options: NfcEngagementOptions,
        omitQR: Boolean = false,
        transportFor: (HolderEngagement) -> ProximityTransport,
    ): CombinedPresentation = CombinedPresentation(NfcPresentations.replace {
        val encoded = json.encodeToString(ListSerializer(String.serializer()), ProximityBLEMode.entries.filter { it in modes }.map { it.rawValue })
        val session = OID4VC.wrap { handle.startCombinedProximityPresentation(encoded, options.negotiated, options.nfcData, omitQR) }
        NfcPresentation(session, timeouts, options.negotiated, if (options.nfcData) NfcDataHolderTransport(timeouts.idle) else null, transportFor)
    })

    internal suspend fun startNfcPresentation(
        timeouts: ProximityTimeouts,
        modes: Set<ProximityBLEMode>,
        negotiated: Boolean,
        nfcData: Boolean = false,
        transportFor: (HolderEngagement) -> ProximityTransport,
    ): NfcPresentation {
        return NfcPresentations.replace {
            val encoded = json.encodeToString(ListSerializer(String.serializer()), ProximityBLEMode.entries.filter { it in modes }.map { it.rawValue })
            val nfc = OID4VC.wrap {
                when {
                    nfcData && negotiated -> handle.startNFCNegotiatedDataProximityPresentation(255, 256)
                    nfcData -> handle.startNFCDataProximityPresentation(255, 256)
                    negotiated -> handle.startNFCNegotiatedProximityPresentationWithModes(encoded)
                    else -> handle.startNFCProximityPresentationWithModes(encoded)
                }
            }
            NfcPresentation(nfc, timeouts, negotiated, if (nfcData) NfcDataHolderTransport(timeouts.idle) else null, transportFor)
        }
    }

    internal fun startProximityPresentation(timeouts: ProximityTimeouts, transport: ProximityTransport, modes: Set<ProximityBLEMode> = setOf(ProximityBLEMode.PERIPHERAL_SERVER)): ProximityPresentation =
        ProximityPresentation(start(modes), { transport }, timeouts)

    private fun start(modes: Set<ProximityBLEMode>) = OID4VC.wrap {
        // In the order Go lists them: peripheral server mode first.
        handle.startProximityPresentationWithModes(json.encodeToString(ListSerializer(String.serializer()), ProximityBLEMode.entries.filter { it in modes }.map { it.rawValue }))
    }
}

/** What a Credential Offer offers. */
@Serializable
public data class Offer(
    /** The issuer's identifier, an https URL. */
    @SerialName("credential_issuer") val credentialIssuer: String,
    /** The issuer's name, in the holder's language. */
    @SerialName("issuer_name") val issuerName: String? = null,
    /** The issuer's logo. */
    @SerialName("issuer_logo") val issuerLogo: Logo? = null,
    /** The grant the offer names. */
    val grant: Grant,
    /** The PIN to ask the holder for, for a pre-authorized code offer. */
    @SerialName("tx_code") val txCode: TxCode? = null,
    /** The offered credentials. */
    val credentials: List<Credential>,
) {
    /** The PIN a pre-authorized code offer asks for, as the issuer describes it. */
    @Serializable
    public data class TxCode(
        /** `numeric` or `text`, if the issuer says. */
        @SerialName("input_mode") val inputMode: String? = null,
        /** How many characters it has, if the issuer says. */
        val length: Int? = null,
        /** The issuer's description, to show the holder: where to find the PIN, say. */
        val description: String? = null,
    )

    /** One offered credential. */
    @Serializable
    public data class Credential(
        /** The issuer's credential configuration. */
        @SerialName("configuration_id") val configurationID: String,
        /** Its format: `dc+sd-jwt` or `mso_mdoc`. */
        val format: String,
        /** An SD-JWT VC's type. */
        val vct: String? = null,
        /** An mdoc's document type. */
        val doctype: String? = null,
        /** The issuer's display metadata for it, in the holder's language. */
        val name: String? = null,
        /** The issuer's description of it. */
        val description: String? = null,
        /** Its logo. */
        val logo: Logo? = null,
        /** The card's background colour. */
        @SerialName("background_color") val backgroundColor: String? = null,
        /** The card's text colour. */
        @SerialName("text_color") val textColor: String? = null,
    )

    /** How the holder is authorized. */
    @Serializable
    public enum class Grant {
        /** The holder signs in at the issuer's pages, in a browser. */
        @SerialName("authorization_code") AUTHORIZATION_CODE,

        /** The issuer has already authenticated the holder, and may ask for a PIN ([Offer.txCode]). */
        @SerialName("pre-authorized_code") PRE_AUTHORIZED_CODE,
    }
}

/**
 * Receives one offer's credentials: show [offer]; then
 * [beginAuthorization], open the URL in an Auth Tab or Custom Tab and
 * [completeAuthorization], or [redeemPreAuthorizedCode]; then
 * [requestCredentials]; [close] when done. An issuance dropped without
 * [close] leaves its keys until [Wallet.sweepOrphanedKeys].
 */
public class Issuance internal constructor(private val session: MobileIssuance) {
    /** What's offered: show it before going on. */
    public val offer: Offer = decode(session.offer())

    /**
     * Begins the authorization code grant, returning the issuer's authorization URL to open in an
     * Auth Tab or Custom Tab. Calling it again begins again: after the holder closed the page,
     * say.
     */
    public suspend fun beginAuthorization(): String = OID4VC.cancellable { op -> session.beginAuthorization(op) }

    /**
     * Completes the authorization with the issuer's redirect back. The
     * redirect is used up whatever happens: if this fails — the token
     * request didn't get through, say — call [beginAuthorization] again,
     * rather than retrying this.
     */
    public suspend fun completeAuthorization(redirect: String) {
        OID4VC.cancellable { op -> session.completeAuthorization(op, redirect) }
    }

    /**
     * Redeems a pre-authorized code offer, with the PIN the holder typed when [Offer.txCode] asks
     * for one. A wrong PIN throws a retryable `protocol` error (`invalid_grant`): ask again.
     */
    public suspend fun redeemPreAuthorizedCode(pin: String = "") {
        OID4VC.cancellable { op -> session.redeemPreAuthorizedCode(op, pin) }
    }

    /** What [Issuance.requestCredentials] obtained. */
    @Serializable
    public data class Result(
        /** The credentials received and stored. */
        val credentials: List<CredentialSummary>,
        /**
         * Credentials the issuer will issue later: poll them with
         * [Wallet.pollDeferred], after [close] and relaunches too.
         */
        val deferred: List<DeferredCredential>,
        /**
         * Credentials the issuer refused for good, or that failed the
         * wallet's checks: they don't hold up the rest.
         */
        val failed: List<FailedCredential> = emptyList(),
    )

    /**
     * An offered credential that couldn't be obtained: its error's code
     * and, when the issuer gave one, its OAuth error code.
     */
    @Serializable
    public data class FailedCredential(
        /** The offered credential's configuration. */
        @SerialName("configuration_id") val configurationID: String,
        /** Why it failed, as the Go side names it: [code] reads it. */
        @SerialName("code") val rawCode: String,
        /** The issuer's OAuth error code, when it gave one. */
        @SerialName("detail") val protocolError: String? = null,
    ) {
        /** Why it failed. */
        val code: WalletException.Code get() = WalletException.Code(rawCode)
    }

    /** Requests, checks and stores every offered credential. */
    public suspend fun requestCredentials(): Result = decode(OID4VC.cancellable { op -> session.requestCredentials(op) })

    /** Ends the issuance, deleting its keys but those its deferred credentials still poll with. */
    public suspend fun close() {
        OID4VC.offMain { session.close() }
    }
}

/**
 * Answers one OpenID4VP request: show [verifier], [queries] and
 * [credentialSets], choose a selection (or start from
 * [defaultSelection]), [preview] it, then [respond] or [decline]. The
 * wallet presents exactly the selection, after checking it answers the
 * request ([WalletException.Code.invalidSelection] otherwise).
 */
public class Presentation internal constructor(private val handle: MobilePresentation) {
    /** Who is asking. */
    @Serializable
    public data class Verifier(
        /**
         * The Verifier's client ID; "" for an unsigned Digital Credentials API request, whose only
         * identity is its origin.
         */
        @SerialName("client_id") val clientID: String = "",
        /** A name to show for the Verifier. */
        val name: String = "",
        /**
         * Where the response is sent; "" for a Digital Credentials API request, answered through
         * the platform.
         */
        @SerialName("response_uri") val responseURI: String = "",
        /**
         * The Verifier's registration, from its request, checked against
         * [WalletConfiguration.VerifierTrust.registrarRoots].
         */
        val registration: Registration,
        /**
         * For a Digital Credentials API request ([Wallet.startDCAPIPresentation]),
         * the calling page's or app's origin: all that names the Verifier
         * of an unsigned request, which has no [clientID] or [name].
         */
        val origin: String? = null,
    )

    /**
     * A Verifier's registration with a registrar: who it is and what it
     * may request, as the registrar attests.
     */
    @Serializable
    public data class Registration(
        /** Whether the registration verified. */
        val status: Status,
        /** The rest are set when [status] is [Status.VERIFIED]. */
        val name: String? = null,
        /** Why it asks, as registered. */
        val purpose: String? = null,
        /** Its privacy policy's URL. */
        @SerialName("privacy_policy") val privacyPolicy: String? = null,
        /** The registrar that registered it. */
        val registrar: String? = null,
        /** The claims paths it's registered to request. */
        val claims: List<List<PathElement>> = emptyList(),
        /** When the registration expires. */
        @Serializable(InstantSerializer::class) val expires: Instant? = null,
    ) {
        /** Whether a registration verified. */
        @Serializable
        public enum class Status {
            /** A registrar the wallet trusts registered this Verifier. */
            @SerialName("verified") VERIFIED,

            /** The request carries a registration that didn't verify: it isn't relied on. */
            @SerialName("invalid") INVALID,

            /** No registration, or no registrar roots to check one. */
            @SerialName("none") NONE,
        }
    }

    /**
     * One of the request's credential queries, with the credentials
     * that can answer it: none when nothing held can.
     */
    @Serializable
    public data class Query(
        /** The query's ID: a key in a [Selection]. */
        @SerialName("query_id") val queryID: String,
        /** Whether it takes more than one credential; otherwise a selection gives it exactly one. */
        val multiple: Boolean = false,
        /** The held credentials that can answer it. */
        val credentials: List<CredentialSummary> = emptyList(),
        /**
         * For a Verifier with a verified registration: the claims paths
         * this query asks for beyond it, then those its credentials would
         * disclose along with them beyond it (the rest of an array
         * disclosed as one, say). Nothing is refused for them: the holder decides.
         */
        val unregistered: List<List<PathElement>> = emptyList(),
        /**
         * Whether it names no claims, beyond a verified registration. Such a
         * query is flagged in full, though OpenID4VP 1.0 §6.4.1 reads it as
         * asking for no selectively disclosable claims.
         */
        @SerialName("unregistered_all") val unregisteredAll: Boolean = false,
    )

    /**
     * One of the request's sets of alternatives: each option is the
     * query IDs that together answer it, most preferred first. A
     * required set must be answered by one option.
     *
     * @property options Each option's query IDs, most preferred first.
     * @property required Whether one of the options must be answered.
     */
    @Serializable
    public data class CredentialSet(val options: List<List<String>>, val required: Boolean = true)

    /** What a selection would disclose from one credential. */
    @Serializable
    public data class Disclosure(
        /** The query it answers. */
        @SerialName("query_id") val queryID: String,
        /** The credential. */
        @SerialName("credential_id") val credentialID: String,
        /** The claims it would disclose, as paths. */
        val claims: List<List<PathElement>>,
        /**
         * The SD-JWT VC claims the Verifier receives beyond [claims]:
         * those its issuer didn't make selectively disclosable, and what
         * shares a Disclosure with a claim: the plaintext members of a
         * disclosed object or array element a claim sits within, and the
         * other elements of an array disclosed as one. Show them with
         * [claims].
         */
        @SerialName("always_disclosed") val alwaysDisclosed: List<List<PathElement>> = emptyList(),
        /**
         * The claims the Verifier says it will keep (an mdoc query's
         * `intent_to_retain`): show that with them.
         */
        val retained: List<List<PathElement>> = emptyList(),
    )

    /** What responding or declining sent. */
    @Serializable
    public data class Presented(
        /** The queries answered. */
        @SerialName("query_ids") val queryIDs: List<String> = emptyList(),
        /** Where to send the browser, when the Verifier asks. */
        @SerialName("redirect_uri") val redirectURI: String? = null,
        /**
         * For a Digital Credentials API request, the response's data — a
         * JSON object, `{"response": …}` — to hand back to the platform:
         * nothing was sent.
         */
        @SerialName("dcapi_response") val dcapiResponse: String? = null,
    )

    @Serializable
    private data class All(
        val queries: List<Query>,
        @SerialName("credential_sets") val credentialSets: List<CredentialSet> = emptyList(),
    )

    /** Who is asking. */
    public val verifier: Verifier = decode(handle.verifier())
    private val all: All = decode(handle.queries())

    /** The request's credential queries, in its order. */
    public val queries: List<Query> = all.queries

    /** The request's sets of alternatives; none means every query must be answered. */
    public val credentialSets: List<CredentialSet> = all.credentialSets

    /** Whether some credential can answer some query: if not, decline. */
    public val isAnswerable: Boolean get() = queries.any { it.credentials.isNotEmpty() }

    /**
     * The selection the wallet would make itself, for an app with no
     * policy of its own, or to start from: the first answerable option
     * of each credential set, and each query's first credential, even
     * when it takes several: the holder adds the others. Throws
     * `noMatchingCredential` when the request can't be answered.
     */
    public suspend fun defaultSelection(): Selection {
        return decode<SelectionResult>(OID4VC.offMain { handle.defaultSelection() }).selection
    }

    /** What responding with [selection] would disclose, without signing or sending anything. */
    public suspend fun preview(selection: Selection): List<Disclosure> {
        val text = selectionJSON(selection)
        return decode<DisclosuresResult>(OID4VC.offMain { handle.preview(text) }).disclosures
    }

    /**
     * Presents exactly [selection]: holder keys sign now, so a key store
     * requiring the holder prompts.
     */
    public suspend fun respond(selection: Selection): Presented {
        val text = selectionJSON(selection)
        return decode(OID4VC.cancellable { op -> handle.respond(op, text) })
    }

    /** Tells the Verifier the holder declined. */
    public suspend fun decline(): Presented = decode(OID4VC.cancellable { op -> handle.decline(op) })

    private fun selectionJSON(selection: Selection): String =
        json.encodeToString(MapSerializer(String.serializer(), ListSerializer(String.serializer())), selection)
}

/** What to present: for each query ID, the IDs of the credentials chosen to answer it. */
public typealias Selection = Map<String, List<String>>

/**
 * An `org-iso-mdoc` request (ISO/IEC TS 18013-7 Annex C): show
 * [request] for the holder's consent, then [respond] once; to decline,
 * cancel the platform's request — nothing is sent to the reader.
 */
public class MdocPresentation internal constructor(private val handle: MobileMdocPresentation) {
    /** What the page asks for. */
    @Serializable
    public data class Request(
        /** The requesting page's origin. */
        val origin: String,
        /**
         * The subject common name of the reader that signed the request,
         * when its certificate chains to
         * [WalletConfiguration.VerifierTrust.mdocReaderRoots]; "" when the holder can
         * only be shown [origin].
         */
        val reader: String = "",
        /** The requested documents, in the request's order. */
        val documents: List<Document>,
    )

    /** One requested document. */
    @Serializable
    public data class Document(
        /** Its document type. */
        val doctype: String,
        /** The elements requested. */
        val elements: List<Element>,
        /** The held mdocs of [doctype]; none when nothing can answer. */
        val credentials: List<CredentialSummary> = emptyList(),
    )

    /** One requested element. */
    @Serializable
    public data class Element(
        /** Its namespace. */
        val namespace: String,
        /** Its identifier in the namespace. */
        val identifier: String,
        /** Whether the reader says it will keep the value. */
        val retain: Boolean = false,
    )

    /** The answer to hand back to the platform. */
    @Serializable
    public data class Response(
        /** The CBOR EncryptedResponse, to hand back to the platform. */
        @Serializable(Base64Serializer::class) val response: ByteArray,
        /** Whether a copy presented had been seen by another Verifier: for several documents, whether any was. */
        val linkable: Boolean = false,
        /** The credentials presented with such a copy, by ID. */
        @SerialName("linkable_credentials") val linkableCredentials: List<String> = emptyList(),
    ) {
        /**
         * The response as the data member of a platform's Digital
         * Credentials API response, for a platform that takes the whole
         * object (ISO/IEC TS 18013-7 Annex C): `{"response":
         * base64url(EncryptedResponse)}`, as JSON. iOS takes [response]
         * itself; on Android, [DigitalCredentials.response] wraps it.
         */
        public fun responseData(): String =
            json.encodeToString(JsonObject.serializer(), JsonObject(mapOf("response" to JsonPrimitive(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(response)))))
    }

    /** What's asked: show it for the holder's consent. */
    public val request: Request = decode(handle.request())

    /**
     * One requested document to answer.
     *
     * @property document Its number among the request's documents.
     * @property credentialID The held mdoc that answers it.
     * @property elements The elements to disclose, each one that document requested.
     */
    public data class Answer(val document: Int, val credentialID: String, val elements: List<Element>)

    /**
     * Presents the held mdoc [credentialID] for document number
     * [document], disclosing exactly [elements], each one it requested.
     * The holder key signs now, so a key store requiring the holder
     * prompts. It is [respond] with one answer.
     */
    public suspend fun respond(document: Int, credentialID: String, elements: List<Element>): Response =
        respond(listOf(Answer(document, credentialID, elements)))

    /**
     * Presents several of the request's documents in one
     * EncryptedResponse, each of [answers] as the one-document [respond]
     * presents one. A document left out isn't in the response. No
     * document may be answered twice, nor one credential answer two.
     * Each holder key signs now, in the request's order, so each key
     * store requiring the holder prompts in turn; on a
     * [WalletException] — one prompt cancelled, say — nothing is
     * returned, and the request can be answered again.
     */
    public suspend fun respond(answers: List<Answer>): Response {
        val answersJSON = answersJSON(answers)
        return decode(OID4VC.cancellable { op -> handle.respondDocuments(op, answersJSON) })
    }

    /** Origins, as the platform reports them. */
    public companion object {
        /** [answers] as the gomobile layer takes them: `[{"document", "credential_id", "elements"}]`. */
        internal fun answersJSON(answers: List<Answer>): String =
            json.encodeToString(
                ListSerializer(AnswerJSON.serializer()),
                answers.map { a -> AnswerJSON(a.document, a.credentialID, a.elements.map { listOf(it.namespace, it.identifier) }) },
            )

        @Serializable
        private data class AnswerJSON(
            val document: Int,
            @SerialName("credential_id") val credentialID: String,
            val elements: List<List<String>>,
        )

        /**
         * [url]'s web origin, as a browser serializes it and the session
         * transcript binds it: `scheme://host`, with the port only when it
         * isn't the scheme's default, and no path — the form
         * [Wallet.startMdocPresentation] takes. For a platform that
         * reports a page's URL; Credential Manager reports the origin
         * itself ([DigitalCredentials.Request.origin]).
         */
        public fun origin(url: String): String? {
            val uri = runCatching { java.net.URI(url) }.getOrNull() ?: return null
            val scheme = uri.scheme?.lowercase() ?: return null
            val host = uri.host?.lowercase()
            if (host.isNullOrEmpty()) return null
            val defaultPort = mapOf("https" to 443, "http" to 80)[scheme]
            return if (uri.port < 0 || uri.port == defaultPort) "$scheme://$host" else "$scheme://$host:${uri.port}"
        }
    }
}

/** A credential store in memory, for tests and development. */
public class InMemoryCredentialStore : CredentialStore {
    private val stored = LinkedHashMap<String, ByteArray>()

    @Synchronized override fun put(id: String, record: ByteArray) {
        stored.remove(id)
        stored[id] = record
    }

    @Synchronized override fun record(id: String): ByteArray? = stored[id]

    @Synchronized override fun records(): List<ByteArray> = stored.values.toList()

    @Synchronized override fun records(idFilter: (String) -> Boolean): List<ByteArray> =
        stored.filterKeys(idFilter).values.toList()

    @Synchronized override fun delete(id: String) {
        stored.remove(id)
    }

    /** Atomic within this process, which is all an in-memory store has. */
    @Synchronized override fun compareAndSwap(id: String, expected: ByteArray?, record: ByteArray?): ByteArray? {
        val current = stored[id]
        if (!current.contentEquals(expected)) return current
        if (record == null) stored.remove(id) else put(id, record)
        return current
    }
}

// The Go side's JSON results' envelopes.

@Serializable
private data class KeyIDsResult(@SerialName("key_ids") val keyIDs: List<String>)

@Serializable
private data class CredentialsResult(val credentials: List<CredentialSummary>)

@Serializable
private data class DeferredResult(val deferred: List<DeferredCredential>)

@Serializable
private data class PollResult(
    val status: String,
    val credential: CredentialSummary? = null,
    @SerialName("interval_seconds") val intervalSeconds: Double = 0.0,
)

@Serializable
private data class SelectionResult(val selection: Map<String, List<String>>)

@Serializable
private data class DisclosuresResult(val disclosures: List<Presentation.Disclosure>)
