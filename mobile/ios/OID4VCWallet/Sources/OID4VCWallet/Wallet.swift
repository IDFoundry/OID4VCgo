import Foundation
import Mobile

/// A ``Wallet``'s configuration, its options grouped by what they
/// concern: issuers, issuer metadata, Verifiers, revocation, status
/// lists, the network, issuance and presentation. Its JSON form is flat,
/// one key per option, and unchanged by the grouping.
public struct WalletConfiguration: Codable, Sendable {
    /// The wallet's registration with Authorization Servers. Empty for a
    /// wallet with no `WalletProvider`.
    public var clientID: String
    /// Where the issuer's pages send the holder back to: a private-use URI the
    /// app opens, registered with the issuers' Authorization Servers, in
    /// `reverse.domain:/path` form (`com.example.wallet:/callback`), or with
    /// an authority (`com.example.wallet://callback`). Empty
    /// for a wallet that receives only pre-authorized codes.
    public var redirectURI: String
    /// Which issuers' credentials the wallet accepts.
    public var issuers: IssuerTrust
    /// Which signed Credential Issuer Metadata the wallet trusts.
    public var issuerMetadata: IssuerMetadataTrust
    /// Which Verifiers, registrars and mdoc readers the wallet recognizes.
    public var verifiers: VerifierTrust
    /// How the trust roles' certificates are checked for revocation.
    public var revocation: Revocation
    /// How `checkStatus` fetches and keeps status and identifier lists.
    public var status: StatusLists
    /// The wallet's own HTTPS requests: pins and private hosts.
    public var network: Network
    /// How credentials are requested.
    public var issuance: IssuanceOptions
    /// How credentials are presented.
    public var presentation: PresentationOptions
    /// Relaxes what production requires, for a wallet talking to services
    /// on a development machine; nil, the default, is production. Never
    /// ship an app with it set. It lets issuers, Authorization Servers,
    /// Verifiers and status lists be on loopback addresses, over http
    /// there too; makes requests through an ordinary HTTPS client, which
    /// reaches private network addresses, instead of the hardened one;
    /// requires no revocation choice for a trust role, so a role in
    /// neither `revocation.roles` nor `revocation.declined` is checked for
    /// nothing; skips the check that different roles' roots share no
    /// anchor; and skips the production checks on receiving credentials:
    /// durable stores and keys, and the random source. A release build
    /// refuses it (`invalidInput`) unless the app called
    /// `OID4VC.allowDevelopmentInRelease()`. Its ``Development/roots``
    /// are PEM certificates the wallet's HTTPS requests, and
    /// ``Wallet/refreshCRLs()``'s fetches, trust besides the system's: a
    /// development service's own CA, without installing and trusting a
    /// profile on the device (from OID4VCWallet 0.27.0).
    public var development: Development?

    /// Which issuers' credentials the wallet accepts.
    public struct IssuerTrust: Sendable {
        /// PEM certificates: the trust anchors for issuers' credentials. A
        /// credential signed by a certificate that doesn't chain to them is
        /// refused.
        public var roots: String
        /// A dotted object identifier: recognizes only issuer certificates
        /// under `roots` with that extended key usage. Outside
        /// `development`, required when `roots` may share a trust
        /// anchor with another role's roots.
        public var requireEKU: String
        /// PEM certificates: the IACAs a received mdoc must chain to, in place
        /// of `roots`, so a `roots` anchor alone, an SD-JWT VC
        /// issuer's CA say, can't sign an mDL. Empty: mdocs chain to
        /// `roots`.
        public var mdocRoots: String
        /// Each document type's own IACAs, as PEM certificates: an mdoc of a
        /// type named here must chain to them, not to `mdocRoots` or
        /// `roots`. A type named with an empty string is refused.
        public var mdocRootsByDocType: [String: String]
        /// A dotted object identifier: recognizes only document signer
        /// certificates with that extended key usage (the mDL's is
        /// 1.0.18013.5.1.2), in place of `requireEKU`, so a wallet
        /// receiving both formats can require each its own.
        public var mdocRequireEKU: String
        /// Also accepts a document signer certificate with no extended key
        /// usage, which is refused by default for lacking the mDL document
        /// signer's (1.0.18013.5.1.2), for issuers whose document signers have
        /// none. Any certificate without one under the same IACAs, such as a
        /// revocation list signer's, can then sign mdocs the wallet accepts.
        /// It can't be set with `mdocRequireEKU`, or with
        /// `requireEKU` unless `mdocRoots` is set.
        public var acceptMDLSignerWithoutEKU: Bool
        /// Refuses a received SD-JWT VC whose `iss` its signing certificate
        /// doesn't name. SD-JWT VC doesn't require them to correspond: set it
        /// where `roots` certify several issuers.
        public var requireIssuerName: Bool
        /// Receives an SD-JWT VC whose `iss` isn't the `credential_issuer` it
        /// was requested from, which is otherwise refused so an issuer can't
        /// hand over another's credential as its own. Set it only for issuers
        /// that name themselves differently, where `roots` certify them
        /// alone.
        public var allowForeignIss: Bool
        /// The Status Issuers that may sign a credential issuer's status lists
        /// on its behalf: credential issuer (an SD-JWT VC's `iss`) → Status
        /// Issuer identifiers, each recognized by a certificate under
        /// `roots` naming it. Without it, `checkStatus` accepts only a
        /// status list the issuer signed itself.
        public var statusIssuers: [String: [String]]
        /// The only Credential Issuer Identifiers the wallet takes offers
        /// from, each compared exactly with the offer's
        /// `credentialIssuer`: `startIssuance` refuses another's offer with
        /// ``WalletError/Code/untrustedIssuer`` before fetching its
        /// metadata, so the holder is never asked for a transaction code
        /// it would send there. Resuming, refreshing and polling a
        /// deferred credential refuse an issuer the list no longer names
        /// the same way, keeping what the wallet holds from it.
        ///
        /// A wallet with `roots` (or the mdoc ones) must decide which
        /// issuers' offers it takes, or `Wallet(configuration:)` throws
        /// `invalidInput`: this list; signed issuer metadata naming its
        /// issuer (``IssuerMetadataTrust`` with `roots`, `requireSigned`
        /// and `requireName`), which may be combined with it; or
        /// `allowAnyCredentialIssuer`, alone.
        public var credentialIssuers: [String]
        /// Takes offers from any issuer, in place of `credentialIssuers` or
        /// signed and named issuer metadata. A transaction code the holder
        /// enters then reaches whichever issuer an offer names, so an
        /// attacker's offer sent beside a genuine service's PIN phishes
        /// it: guarding against that is the app's. Set it only for a
        /// wallet whose issuers can't be told apart in advance.
        public var allowAnyCredentialIssuer: Bool

        /// Issuer trust: every field has a default.
        public init(roots: String = "", requireEKU: String = "", mdocRoots: String = "",
                    mdocRootsByDocType: [String: String] = [:], mdocRequireEKU: String = "",
                    acceptMDLSignerWithoutEKU: Bool = false, requireIssuerName: Bool = false,
                    allowForeignIss: Bool = false, statusIssuers: [String: [String]] = [:],
                    credentialIssuers: [String] = [], allowAnyCredentialIssuer: Bool = false) {
            self.roots = roots
            self.requireEKU = requireEKU
            self.mdocRoots = mdocRoots
            self.mdocRootsByDocType = mdocRootsByDocType
            self.mdocRequireEKU = mdocRequireEKU
            self.acceptMDLSignerWithoutEKU = acceptMDLSignerWithoutEKU
            self.requireIssuerName = requireIssuerName
            self.allowForeignIss = allowForeignIss
            self.statusIssuers = statusIssuers
            self.credentialIssuers = credentialIssuers
            self.allowAnyCredentialIssuer = allowAnyCredentialIssuer
        }
    }

    /// Which signed Credential Issuer Metadata the wallet trusts.
    public struct IssuerMetadataTrust: Sendable {
        /// PEM certificates: the trust anchors for signed Credential Issuer
        /// Metadata. With them, signed metadata is asked for and verified.
        public var roots: String
        /// A dotted object identifier: recognizes only issuer metadata signed
        /// by a certificate under `roots` with that extended key
        /// usage. Outside `development`, required when `roots`
        /// may share a trust anchor with another role's roots.
        public var requireEKU: String
        /// Refuses an issuer whose metadata isn't signed under
        /// `roots`, before the holder signs in or enters a code.
        public var requireSigned: Bool
        /// Refuses signed metadata whose certificate doesn't name the issuer.
        public var requireName: Bool
        /// Refuses signed metadata signed longer ago than this many seconds;
        /// 0 doesn't limit it.
        public var maxAgeSeconds: Int

        /// Issuer metadata trust: every field has a default.
        public init(roots: String = "", requireEKU: String = "", requireSigned: Bool = false,
                    requireName: Bool = false, maxAgeSeconds: Int = 0) {
            self.roots = roots
            self.requireEKU = requireEKU
            self.requireSigned = requireSigned
            self.requireName = requireName
            self.maxAgeSeconds = maxAgeSeconds
        }
    }

    /// Which Verifiers, registrars and mdoc readers the wallet recognizes.
    public struct VerifierTrust: Sendable {
        /// PEM certificates: the trust anchors for Verifiers' requests. A request
        /// signed by a certificate that doesn't chain to them is refused unread.
        public var roots: String
        /// A dotted object identifier: recognizes only Verifier certificates
        /// under `roots` with that extended key usage, the one your
        /// ecosystem marks its Verifiers' certificates with. Outside
        /// `development`, required when `roots` shares a trust anchor
        /// with another role's roots.
        public var requireEKU: String
        /// Also answers Verifiers whose client ID has the `x509_san_dns`
        /// prefix (OpenID4VP 1.0 §5.9.3), besides `x509_hash`, the one HAIP
        /// 1.0 has Verifiers use: the DNS name must be one of the request's
        /// signing certificate, which must chain to `roots`, and the
        /// host of its response URI. Needs `roots`. Every name in a
        /// certificate under `roots` is then a Verifier the wallet
        /// answers, so set it only where those roots certify Verifiers alone,
        /// or with `requireEKU`.
        public var acceptX509SANDNS: Bool
        /// PEM certificates: the registrars whose registrations of Verifiers
        /// the wallet checks (`Presentation.Verifier.registration`). Empty:
        /// registrations are ignored.
        public var registrarRoots: String
        /// A dotted object identifier: recognizes only registrar certificates
        /// under `registrarRoots` with that extended key usage. Outside
        /// `development`, required when `registrarRoots` shares a trust anchor
        /// with another role's roots.
        public var registrarRequireEKU: String
        /// PEM certificates: the mdoc readers recognized when one signs an
        /// `org-iso-mdoc` request (`MdocPresentation.Request.reader`). Empty:
        /// every such request is shown by its origin.
        public var mdocReaderRoots: String
        /// Recognizes only reader certificates with the ISO/IEC 18013-5
        /// reader authentication extended key usage (1.0.18013.5.1.6), so a
        /// certificate issued for another role under `mdocReaderRoots`
        /// isn't taken for a reader's.
        public var mdocReaderRequireEKU: Bool
        /// Refuses an `org-iso-mdoc` request no recognized reader signed:
        /// `startMdocPresentation` throws `untrustedVerifier`, and nothing is
        /// shown to the holder. Needs `mdocReaderRoots`.
        public var requireTrustedMdocReader: Bool

        /// Verifier trust: every field has a default.
        public init(roots: String = "", requireEKU: String = "", acceptX509SANDNS: Bool = false,
                    registrarRoots: String = "", registrarRequireEKU: String = "",
                    mdocReaderRoots: String = "", mdocReaderRequireEKU: Bool = false,
                    requireTrustedMdocReader: Bool = false) {
            self.roots = roots
            self.requireEKU = requireEKU
            self.acceptX509SANDNS = acceptX509SANDNS
            self.registrarRoots = registrarRoots
            self.registrarRequireEKU = registrarRequireEKU
            self.mdocReaderRoots = mdocReaderRoots
            self.mdocReaderRequireEKU = mdocReaderRequireEKU
            self.requireTrustedMdocReader = requireTrustedMdocReader
        }
    }

    /// How the trust roles' certificates are checked for revocation.
    public typealias Revocation = RevocationChecking<RevocationRole>
    /// The wallet's own HTTPS requests.
    public struct Network: Sendable {
        /// Pins hosts' certificates for the wallet's own HTTPS requests:
        /// host → base64 SHA-256 digests of a certificate's
        /// SubjectPublicKeyInfo, one of which a certificate in the verified
        /// chain must have, or the request fails as `tlsPin` before anything
        /// is sent. A host is a name, or `*.` and one, matching any name a
        /// label below it; not an IP address. Pins add to certificate
        /// verification, never replace it: pin a CA's key, so a leaf renewal
        /// doesn't break the app, and keep a backup pin. They cover the
        /// requests the SDK makes (issuers, Authorization Servers,
        /// Verifiers, status lists), not the app's own, such as to its
        /// Wallet Provider: pin that client yourself.
        public var tlsPins: [String: [String]]
        /// Hosts the wallet may reach at a private address (10/8, 172.16/12,
        /// 192.168/16, fc00::/7) outside `development`: issuers, Verifiers,
        /// status lists and CRL distribution points inside the deployment's
        /// own network, an enterprise's or a test environment's. Each is a
        /// host name, matched exactly and without case: no wildcard, IP
        /// address, port or loopback name. Nothing else is lifted: a listed
        /// host is still refused at a loopback or link-local address, and
        /// every request is still HTTPS with its certificate verified. List
        /// only hosts the deployment runs: anyone who can hand the wallet an
        /// offer or a request can have it send a request to them.
        public var allowedPrivateHosts: [String]

        /// Network options: every field has a default.
        public init(tlsPins: [String: [String]] = [:], allowedPrivateHosts: [String] = []) {
            self.tlsPins = tlsPins
            self.allowedPrivateHosts = allowedPrivateHosts
        }
    }

    /// How credentials are requested.
    public struct IssuanceOptions: Sendable {
        /// The holder's preferred languages (BCP 47, most preferred first),
        /// for issuers' display metadata. `Locale.preferredLanguages`, the
        /// default, is the usual choice.
        public var locales: [String]
        /// How many copies of each credential to request when an issuer
        /// offers batches, each bound to its own key, so each presentation
        /// can use one no Verifier has seen. 0 means the SDK's default (5);
        /// it's capped at the issuer's batch size.
        public var batchSize: Int
        /// Asks Authorization Servers for a refresh token, so
        /// `Wallet.refreshCredential(id:)` can later replace a credential's
        /// copies without the holder signing in. The server must allow the
        /// wallet the `offline_access` scope, or the authorization fails.
        public var requestRefresh: Bool
        /// The profile issuance follows.
        public var profile: IssuanceProfile
        /// Names the key of a jwt proof carrying a key attestation in `jwk`
        /// rather than by its index in the attestation (`kid` `"0"`), the
        /// default, which issuers following ETSI TS 119 472-3, such as the
        /// EUDI reference PID issuer, require. Set it only for an issuer that
        /// takes no index.
        public var proofKeyByJWK: Bool
        /// Names the key of a jwt proof carrying a key attestation by its
        /// index in the attestation, which is now the default: it has no
        /// effect, and can't be set with `proofKeyByJWK`.
        public var proofKeyByIndex: Bool

        /// Issuance options: every field has a default.
        public init(locales: [String] = Locale.preferredLanguages, batchSize: Int = 0, requestRefresh: Bool = false,
                    profile: IssuanceProfile = .openID4VCI, proofKeyByJWK: Bool = false, proofKeyByIndex: Bool = false) {
            self.locales = locales
            self.batchSize = batchSize
            self.requestRefresh = requestRefresh
            self.profile = profile
            self.proofKeyByJWK = proofKeyByJWK
            self.proofKeyByIndex = proofKeyByIndex
        }
    }

    /// How credentials are presented.
    public struct PresentationOptions: Sendable {
        /// Which copy of a credential a presentation uses.
        public var copyPolicy: CopyPolicy
        /// How an in-person response authenticates the mdoc. `.macPreferred`
        /// needs a key store that is also a `KeyAgreement`.
        public var proximityDeviceAuth: ProximityDeviceAuth

        /// Presentation options: every field has a default.
        public init(copyPolicy: CopyPolicy = .perPresentation, proximityDeviceAuth: ProximityDeviceAuth = .signature) {
            self.copyPolicy = copyPolicy
            self.proximityDeviceAuth = proximityDeviceAuth
        }
    }

    /// A trust role whose certificates can be checked for revocation.
    public enum RevocationRole: String, Codable, Sendable, CaseIterable {
        /// The issuers' signing certificates (`issuers.roots` and the mdoc
        /// roots), on receipt, deferral and refresh.
        case issuer
        /// The signers of Credential Issuer Metadata (`issuerMetadata.roots`).
        case issuerMetadata = "issuer_metadata"
        /// The registrars of Verifiers (`verifiers.registrarRoots`).
        case registrar
        /// The mdoc readers (`verifiers.mdocReaderRoots`), online and in person.
        case mdocReader = "mdoc_reader"
        /// The Verifiers' request-signing certificates (`verifiers.roots`).
        case verifier
        /// The signers of status lists, in `checkStatus`.
        case status
    }

    /// How an in-person response authenticates the mdoc (ISO/IEC 18013-5
    /// §9.1.3).
    public enum ProximityDeviceAuth: String, Codable, Sendable, CaseIterable {
        /// The holder key signs the session transcript (deviceSignature).
        /// The default.
        case signature
        /// The holder key agrees a key with the reader's ephemeral key and
        /// the response carries a MAC (deviceMac). The reader can check it
        /// but can't prove to anyone else that this device took part; the
        /// issuer-signed elements stay provable. A holder key that can't
        /// agree keys signs instead.
        case macPreferred = "mac_preferred"
    }

    /// The profile issuance follows.
    public enum IssuanceProfile: String, Codable, Sendable, CaseIterable {
        /// The issuer's and its Authorization Server's metadata, as
        /// OpenID4VCI 1.0 has a wallet do: a Wallet Attestation and a key
        /// attestation only where they ask for them. The default.
        case openID4VCI = "openid4vci"
        /// Also refuses an issuer that doesn't follow HAIP 1.0
        /// (`WalletError.Code.profileViolation`). Needs a `WalletProvider`
        /// and a `clientID`.
        case haip
    }

    /// Which copy of a credential a presentation uses (OpenID4VCI 1.0: "a
    /// unique Credential per presentation or per Verifier").
    public enum CopyPolicy: String, Codable, Sendable, CaseIterable {
        /// Every presentation uses a copy no Verifier has seen: not even
        /// one Verifier can link two presentations. The default.
        case perPresentation = "per_presentation"
        /// A Verifier is shown the copy it has seen before, and only a new
        /// Verifier an unused one: Verifiers can't link presentations to
        /// each other, but one can recognise a returning holder.
        case perVerifier = "per_verifier"
    }

    /// A configuration: every field has a default. A wallet with no
    /// `WalletProvider`, receiving credentials only from pre-authorized
    /// codes redeemed with no client authentication, leaves the client ID
    /// and the redirect URI empty.
    public init(clientID: String = "", redirectURI: String = "",
                issuers: IssuerTrust = IssuerTrust(), issuerMetadata: IssuerMetadataTrust = IssuerMetadataTrust(),
                verifiers: VerifierTrust = VerifierTrust(), revocation: Revocation = Revocation(),
                status: StatusLists = StatusLists(), network: Network = Network(),
                issuance: IssuanceOptions = IssuanceOptions(), presentation: PresentationOptions = PresentationOptions(),
                development: Development? = nil) {
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.issuers = issuers
        self.issuerMetadata = issuerMetadata
        self.verifiers = verifiers
        self.revocation = revocation
        self.status = status
        self.network = network
        self.issuance = issuance
        self.presentation = presentation
        self.development = development
    }

    // The flat JSON keys, one per option, as NewWallet reads them.
    enum CodingKeys: String, CodingKey {
        case clientID = "client_id", redirectURI = "redirect_uri", issuerRoots = "issuer_roots"
        case verifierRoots = "verifier_roots", registrarRoots = "registrar_roots", mdocReaderRoots = "mdoc_reader_roots"
        case mdocReaderRequireEKU = "mdoc_reader_require_eku", requireTrustedMdocReader = "require_trusted_mdoc_reader"
        case development, developmentRoots = "development_roots", locales, batchSize = "batch_size"
        case requestRefresh = "request_refresh", copyPolicy = "copy_policy", issuanceProfile = "issuance_profile"
        case proofKeyByJWK = "proof_key_by_jwk", proofKeyByIndex = "proof_key_by_index"
        case acceptX509SANDNS = "accept_x509_san_dns"
        case tlsPins = "tls_pins", allowedPrivateHosts = "allowed_private_hosts", proximityDeviceAuth = "proximity_device_auth"
        case verifierRequireEKU = "verifier_require_eku", registrarRequireEKU = "registrar_require_eku"
        case issuerRequireEKU = "issuer_require_eku", issuerMetadataRequireEKU = "issuer_metadata_require_eku"
        case statusIssuers = "status_issuers", requireIssuerName = "require_issuer_name"
        case issuerMetadataRoots = "issuer_metadata_roots", requireSignedIssuerMetadata = "require_signed_issuer_metadata"
        case requireIssuerMetadataName = "require_issuer_metadata_name", maxIssuerMetadataAgeSeconds = "max_issuer_metadata_age_seconds"
        case allowForeignIss = "allow_foreign_iss", credentialIssuers = "credential_issuers"
        case allowAnyCredentialIssuer = "allow_any_credential_issuer"
        case mdocIssuerRoots = "mdoc_issuer_roots", mdocIssuerRootsByDocType = "mdoc_issuer_roots_by_doctype"
        case mdocIssuerRequireEKU = "mdoc_issuer_require_eku", acceptMDLSignerWithoutEKU = "accept_mdl_signer_without_eku"
        case crls, revocation, crlIssuers = "crl_issuers", noRevocationCheck = "no_revocation_check"
        case crlDistributionPoints = "crl_distribution_points"
        case crlDistributionPointsFromRoots = "crl_distribution_points_from_roots", crlRequireHTTPS = "crl_require_https"
        case statusMaxBytes = "status_max_bytes", identifierListMaxBytes = "identifier_list_max_bytes"
        case statusCacheMaxAgeSeconds = "status_cache_max_age_seconds", statusCacheDir = "status_cache_dir"
    }

    /// Decodes a configuration from its flat JSON, refusing a key it
    /// doesn't know: a misspelled option would otherwise be dropped here,
    /// before the wallet could refuse it, and silently left at its
    /// default.
    public init(from decoder: Decoder) throws {
        let all = try decoder.container(keyedBy: AnyCodingKey.self)
        if let unknown = all.allKeys.first(where: { CodingKeys(stringValue: $0.stringValue) == nil }) {
            throw DecodingError.dataCorruptedError(forKey: unknown, in: all, debugDescription: "unknown configuration key \(unknown.stringValue)")
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) throws -> T {
            try c.decodeIfPresent(T.self, forKey: key) ?? fallback
        }
        self.init(
            clientID: try value(.clientID, ""),
            redirectURI: try value(.redirectURI, ""),
            issuers: IssuerTrust(
                roots: try value(.issuerRoots, ""),
                requireEKU: try value(.issuerRequireEKU, ""),
                mdocRoots: try value(.mdocIssuerRoots, ""),
                mdocRootsByDocType: try value(.mdocIssuerRootsByDocType, [:]),
                mdocRequireEKU: try value(.mdocIssuerRequireEKU, ""),
                acceptMDLSignerWithoutEKU: try value(.acceptMDLSignerWithoutEKU, false),
                requireIssuerName: try value(.requireIssuerName, false),
                allowForeignIss: try value(.allowForeignIss, false),
                statusIssuers: try value(.statusIssuers, [:]),
                credentialIssuers: try value(.credentialIssuers, []),
                allowAnyCredentialIssuer: try value(.allowAnyCredentialIssuer, false)),
            issuerMetadata: IssuerMetadataTrust(
                roots: try value(.issuerMetadataRoots, ""),
                requireEKU: try value(.issuerMetadataRequireEKU, ""),
                requireSigned: try value(.requireSignedIssuerMetadata, false),
                requireName: try value(.requireIssuerMetadataName, false),
                maxAgeSeconds: try value(.maxIssuerMetadataAgeSeconds, 0)),
            verifiers: VerifierTrust(
                roots: try value(.verifierRoots, ""),
                requireEKU: try value(.verifierRequireEKU, ""),
                acceptX509SANDNS: try value(.acceptX509SANDNS, false),
                registrarRoots: try value(.registrarRoots, ""),
                registrarRequireEKU: try value(.registrarRequireEKU, ""),
                mdocReaderRoots: try value(.mdocReaderRoots, ""),
                mdocReaderRequireEKU: try value(.mdocReaderRequireEKU, false),
                requireTrustedMdocReader: try value(.requireTrustedMdocReader, false)),
            revocation: try Revocation(decodingFrom: c),
            status: try StatusLists(decodingFrom: c),
            network: Network(
                tlsPins: try value(.tlsPins, [:]),
                allowedPrivateHosts: try value(.allowedPrivateHosts, [])),
            issuance: IssuanceOptions(
                locales: try value(.locales, Locale.preferredLanguages),
                batchSize: try value(.batchSize, 0),
                requestRefresh: try value(.requestRefresh, false),
                profile: try value(.issuanceProfile, IssuanceProfile.openID4VCI),
                proofKeyByJWK: try value(.proofKeyByJWK, false),
                proofKeyByIndex: try value(.proofKeyByIndex, false)),
            presentation: PresentationOptions(
                copyPolicy: try value(.copyPolicy, CopyPolicy.perPresentation),
                proximityDeviceAuth: try value(.proximityDeviceAuth, ProximityDeviceAuth.signature)),
            development: try Development.decode(c))
    }

    /// Encodes the configuration as its flat JSON, every option's key,
    /// `status_cache_dir` only when `status.cacheDir` is set.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(clientID, forKey: .clientID)
        try c.encode(redirectURI, forKey: .redirectURI)
        try c.encode(issuers.roots, forKey: .issuerRoots)
        try c.encode(issuers.requireEKU, forKey: .issuerRequireEKU)
        try c.encode(issuers.mdocRoots, forKey: .mdocIssuerRoots)
        try c.encode(issuers.mdocRootsByDocType, forKey: .mdocIssuerRootsByDocType)
        try c.encode(issuers.mdocRequireEKU, forKey: .mdocIssuerRequireEKU)
        try c.encode(issuers.acceptMDLSignerWithoutEKU, forKey: .acceptMDLSignerWithoutEKU)
        try c.encode(issuers.requireIssuerName, forKey: .requireIssuerName)
        try c.encode(issuers.allowForeignIss, forKey: .allowForeignIss)
        try c.encode(issuers.statusIssuers, forKey: .statusIssuers)
        try c.encode(issuers.credentialIssuers, forKey: .credentialIssuers)
        try c.encode(issuers.allowAnyCredentialIssuer, forKey: .allowAnyCredentialIssuer)
        try c.encode(issuerMetadata.roots, forKey: .issuerMetadataRoots)
        try c.encode(issuerMetadata.requireEKU, forKey: .issuerMetadataRequireEKU)
        try c.encode(issuerMetadata.requireSigned, forKey: .requireSignedIssuerMetadata)
        try c.encode(issuerMetadata.requireName, forKey: .requireIssuerMetadataName)
        try c.encode(issuerMetadata.maxAgeSeconds, forKey: .maxIssuerMetadataAgeSeconds)
        try c.encode(verifiers.roots, forKey: .verifierRoots)
        try c.encode(verifiers.requireEKU, forKey: .verifierRequireEKU)
        try c.encode(verifiers.acceptX509SANDNS, forKey: .acceptX509SANDNS)
        try c.encode(verifiers.registrarRoots, forKey: .registrarRoots)
        try c.encode(verifiers.registrarRequireEKU, forKey: .registrarRequireEKU)
        try c.encode(verifiers.mdocReaderRoots, forKey: .mdocReaderRoots)
        try c.encode(verifiers.mdocReaderRequireEKU, forKey: .mdocReaderRequireEKU)
        try c.encode(verifiers.requireTrustedMdocReader, forKey: .requireTrustedMdocReader)
        try revocation.encode(into: &c)
        try status.encode(into: &c)
        try c.encode(network.tlsPins, forKey: .tlsPins)
        try c.encode(network.allowedPrivateHosts, forKey: .allowedPrivateHosts)
        try c.encode(issuance.locales, forKey: .locales)
        try c.encode(issuance.batchSize, forKey: .batchSize)
        try c.encode(issuance.requestRefresh, forKey: .requestRefresh)
        try c.encode(issuance.profile, forKey: .issuanceProfile)
        try c.encode(issuance.proofKeyByJWK, forKey: .proofKeyByJWK)
        try c.encode(issuance.proofKeyByIndex, forKey: .proofKeyByIndex)
        try c.encode(presentation.copyPolicy, forKey: .copyPolicy)
        try c.encode(presentation.proximityDeviceAuth, forKey: .proximityDeviceAuth)
        try Development.encode(development, into: &c)
    }

    /// The scheme of `redirectURI`: the callback scheme an
    /// ASWebAuthenticationSession waits for.
    public var callbackScheme: String? { URL(string: redirectURI)?.scheme }
}

/// An image the issuer names for display: an https URL or a data: image
/// (nothing else reaches the app, nor an https URL naming an IP address or
/// a local name), with alternative text. Its host is judged by its name,
/// and a public name can resolve to a private address: load the URL
/// through a session that refuses to connect to a loopback, private or
/// link-local address. Loading the URL tells whoever serves it that the
/// holder is looking: fetch it once, when the holder accepts the
/// credential rather than on the offer's preview, and keep it.
public struct Logo: Decodable, Equatable, Sendable {
    /// The image: an https URL or a `data:` URL.
    public let uri: String
    /// Text describing the image, for accessibility.
    public let altText: String?
    /// `uri` as a URL, to load as ``Logo`` says.
    public var url: URL? { URL(string: uri) }
    enum CodingKeys: String, CodingKey { case uri, altText = "alt_text" }
}

/// How to show a credential, from the issuer's metadata (OpenID4VCI 1.0
/// §12.2.4) in the holder's language: each part only when the issuer
/// gives it. Colours are CSS colours, such as "#12107c".
public struct CredentialDisplay: Decodable, Equatable, Sendable {
    /// The issuer's name.
    public let issuerName: String?
    /// The issuer's logo.
    public let issuerLogo: Logo?
    /// The credential's name.
    public let name: String?
    /// A description of the credential.
    public let description: String?
    /// The credential's logo.
    public let logo: Logo?
    /// The card's background colour.
    public let backgroundColor: String?
    /// The card's text colour.
    public let textColor: String?
    enum CodingKeys: String, CodingKey {
        case issuerName = "issuer_name", issuerLogo = "issuer_logo", name, description, logo
        case backgroundColor = "background_color", textColor = "text_color"
    }
}

/// A credential's revocation status, as last checked
/// (`Wallet.checkStatus(id:)`): in the issuer's status list, and, from
/// OID4VCWallet 0.27.0, its issuer's certificate chain against the
/// revocation lists held then.
public struct CredentialStatus: Decodable, Equatable, Sendable {
    /// A status in the issuer's list.
    public enum Value: Equatable, Sendable {
        case valid, revoked, suspended
        /// A status the issuer's list defines itself, as "0x" and its value.
        case other(String)
        /// A status naming no mechanism the wallet knows, and no list
        /// saying otherwise than valid: the status isn't known. Before
        /// OID4VCWallet 0.22.0, also an mdoc naming an identifier list
        /// (ISO/IEC 18013-5 §12.3.6.4), which is now checked.
        case unknown
    }
    /// Why the status is what it is.
    public enum Reason: Equatable, Sendable {
        /// The issuer's Token Status List gives it: ``Value/revoked``
        /// (final), ``Value/suspended`` or ``Value/other(_:)``.
        case statusList
        /// The mdoc is on its issuer's identifier list: ``Value/revoked``,
        /// final.
        case identifierList
        /// ``Value/revoked``: the issuer's signing certificate, or a CA
        /// above it, is on its CA's revocation list. Not final: a later
        /// check with a list that no longer names it makes it valid again.
        case issuerCertificateRevoked
        /// ``Value/revoked``: the issuer's certificate chain no longer
        /// verifies under the configured roots, or has expired.
        case issuerUntrusted
        /// ``Value/unknown``: there's no current revocation list to check
        /// the issuer's chain, or its status list's signer's, against.
        /// Refresh them (``Wallet/refreshCRLs()``) and check again.
        case noCurrentCRL
        /// ``Value/unknown``: a status naming no mechanism the wallet
        /// knows.
        case unrecognizedStatus
        /// A reason this version doesn't know, as the library gave it.
        case other(String)

        init(_ raw: String) {
            switch raw {
            case "status_list": self = .statusList
            case "identifier_list": self = .identifierList
            case "issuer_certificate_revoked": self = .issuerCertificateRevoked
            case "issuer_untrusted": self = .issuerUntrusted
            case "no_current_crl": self = .noCurrentCRL
            case "unrecognized_status": self = .unrecognizedStatus
            default: self = .other(raw)
            }
        }
    }
    /// The status found.
    public let value: Value
    /// Why, for the app to tell the holder: nil for ``Value/valid``, and
    /// for a status recorded before OID4VCWallet 0.27.0.
    public let reason: Reason?
    /// When it was checked.
    public let checkedAt: Date

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .value) {
        case "valid": value = .valid
        case "invalid": value = .revoked
        case "suspended": value = .suspended
        case "unknown": value = .unknown
        case let v: value = .other(v)
        }
        reason = try c.decodeIfPresent(String.self, forKey: .reason).map(Reason.init)
        checkedAt = try c.decode(Date.self, forKey: .checkedAt)
    }
    enum Keys: String, CodingKey { case value, reason, checkedAt = "checked_at" }
}

/// A credential the wallet holds, as the app shows it.
public struct CredentialSummary: Decodable, Equatable, Sendable {
    /// The credential's ID in the wallet.
    public let id: String
    /// The issuer's identifier, an https URL.
    public let credentialIssuer: String
    /// The issuer's credential configuration it was issued under.
    public let configurationID: String
    /// Its format: `dc+sd-jwt` or `mso_mdoc`.
    public let format: String
    /// An SD-JWT VC's type.
    public let vct: String?
    /// An mdoc's document type.
    public let doctype: String?
    /// When the wallet received it.
    public let receivedAt: Date
    /// Whether the key store still holds the credential's key: without it
    /// (restored to another device, say) it can't be presented. Set in
    /// `Wallet.credentials()` and `Wallet.credential(id:)`.
    public let holderKeyPresent: Bool?
    /// How to show it, from the issuer's metadata when it was received.
    public let display: CredentialDisplay?
    /// When it expires, if it says.
    public let validUntil: Date?
    /// Its revocation status, as last checked; nil before any check.
    public let status: CredentialStatus?
    /// How many copies the wallet holds, each bound to its own key, and
    /// how many no Verifier has seen. Each presentation uses one of
    /// those; once none is left, presentations can be linked.
    public let copies: Int
    /// How many copies no Verifier has seen.
    public let copiesLeft: Int
    /// Whether its issuance kept a refresh token
    /// (`WalletConfiguration.issuance.requestRefresh`), so
    /// `Wallet.refreshCredential(id:)` can replace its copies. The
    /// Authorization Server may still refuse
    /// (`WalletError.Code.reissueRequired`).
    public let refreshable: Bool
    /// Whether a copy has been presented to more than one Verifier, so
    /// those Verifiers could link the holder's presentations. Refreshing
    /// gives it copies no Verifier has seen.
    public let linkable: Bool
    /// Whether a Verifier could accept it now, as far as the wallet
    /// knows: a copy is neither expired nor found revoked, and its status
    /// as last checked isn't revoked or suspended. A presentation lists
    /// the others after it, and the default selection never picks them.
    public let presentable: Bool
    /// Set only on a presentation's candidates (`Presentation.queries`):
    /// whether the Verifier asking has been shown this credential before,
    /// and whether presenting it now would hand it a copy another
    /// Verifier has seen.
    public let shownToVerifier: Bool?
    /// Whether presenting it to the Verifier asking would hand it a copy
    /// another Verifier has seen. Set only on a presentation's candidates.
    public let linkableHere: Bool?

    /// Whether it has expired by `now`.
    public func isExpired(at now: Date = Date()) -> Bool { validUntil.map { $0 <= now } ?? false }

    enum CodingKeys: String, CodingKey {
        case id, format, vct, doctype, display, status
        case credentialIssuer = "credential_issuer", configurationID = "configuration_id", receivedAt = "received_at"
        case holderKeyPresent = "holder_key_present", validUntil = "valid_until"
        case copies, copiesLeft = "copies_left", refreshable, linkable, presentable
        case shownToVerifier = "shown_to_verifier", linkableHere = "linkable_here"
    }
}

/// A credential an issuer will issue later (OpenID4VCI 1.0 §9). It's
/// kept in the credential store until it's issued, denied or abandoned,
/// so it survives the app quitting.
public struct DeferredCredential: Decodable, Equatable, Sendable {
    /// The deferred credential's ID, for `Wallet.pollDeferred(id:)`.
    public let id: String
    /// The issuer's identifier, an https URL.
    public let credentialIssuer: String
    /// The issuer's credential configuration requested.
    public let configurationID: String
    /// How long the issuer asked the wallet to wait between polls.
    public let intervalSeconds: Double
    /// When the issuer deferred it.
    public let deferredAt: Date
    /// When the access token it's polled with expires, if the issuer
    /// said: after it, polls fail and it can only be abandoned.
    public let accessTokenExpiresAt: Date?

    enum CodingKeys: String, CodingKey {
        case id, deferredAt = "deferred_at", accessTokenExpiresAt = "access_token_expires_at"
        case credentialIssuer = "credential_issuer", configurationID = "configuration_id", intervalSeconds = "interval_seconds"
    }
}

/// A deferred credential's state, from `Wallet.pollDeferred(id:)`.
public enum DeferredStatus: Sendable, Equatable {
    case pending(intervalSeconds: Double)
    case issued(CredentialSummary)
}

/// A credential with its claims, for display.
public struct CredentialDetail: Decodable, Sendable {
    /// The credential.
    public let summary: CredentialSummary
    /// An SD-JWT VC's claims, or an mdoc's namespace → element → value;
    /// byte strings (a portrait) are base64.
    public let claims: JSONValue

    public init(from decoder: Decoder) throws {
        summary = try CredentialSummary(from: decoder)
        let c = try decoder.container(keyedBy: Keys.self)
        claims = try c.decodeIfPresent(JSONValue.self, forKey: .claims) ?? .null
    }

    enum Keys: String, CodingKey { case claims }
}

/// A JSON value.
public enum JSONValue: Decodable, Sendable, Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let n = try? c.decode(Double.self) {
            self = .number(n)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else if let a = try? c.decode([JSONValue].self) {
            self = .array(a)
        } else {
            self = .object(try c.decode([String: JSONValue].self))
        }
    }

    /// The value at `key`, for an object.
    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }
}

/// A holder's wallet: OID4VCgo's walletflow over the app's key store,
/// credential store and Wallet Provider.
public final class Wallet: @unchecked Sendable {
    let handle: MobileWallet
    // Go holds these too; the wallet keeps them alive with it.
    private let adapters: [AnyObject]

    /// A wallet over `keyStore`, `credentialStore` and `provider` (which
    /// receiving credentials needs; presenting doesn't). Creating it
    /// makes no network calls.
    public convenience init(configuration: WalletConfiguration, keyStore: some KeyStore, credentialStore: some CredentialStore,
                            provider: (any WalletProvider)?) throws {
        try self.init(configuration: configuration, keys: KeyStoreAdapter(keyStore), credentials: CredentialStoreAdapter(credentialStore),
                      provider: provider.map(WalletProviderAdapter.init),
                      agreement: (keyStore as? any KeyAgreement).map(KeyAgreementAdapter.init))
    }

    init(configuration: WalletConfiguration, keys: KeyStoreAdapter, credentials: CredentialStoreAdapter,
         provider: (any MobileWalletProviderProtocol)?, agreement: KeyAgreementAdapter? = nil) throws {
        guard OID4VC.abiVersion == OID4VC.expectedABIVersion else {
            throw WalletError(code: .internalError,
                              message: "the linked framework has ABI \(OID4VC.abiVersion), these sources ABI \(OID4VC.expectedABIVersion): rebuild it")
        }
        try OID4VC.checkDevelopment(configuration.development != nil)
        let json = try StatusCacheKey.configuration(try JSONEncoder().encode(configuration), cacheDir: configuration.status.cacheDir)
        handle = try OID4VC.call { MobileNewWallet(json, keys, credentials, provider, $0) }!
        // A key store that also agrees keys answers in person with deviceMac
        // under .macPreferred; Go keeps signing without one.
        if let agreement { handle.setKeyAgreement(agreement) }
        // A call cancelled while it waits for the holder or the provider
        // ends that wait.
        let canceller = CallbackCancellerAdapter(keys.store, provider as? WalletProviderAdapter)
        handle.setCallbackCanceller(canceller)
        adapters = [keys, credentials, canceller] + (provider.map { [$0 as AnyObject] } ?? []) + (agreement.map { [$0 as AnyObject] } ?? [])
    }

    /// Deletes every key in `keyStore` that none of the wallet's
    /// credentials is bound to — left by an issuance the app quit or
    /// crashed in the middle of — and returns how many. Call it at launch,
    /// before any issuance or refresh: one in progress holds keys of its
    /// own.
    ///
    /// What it may delete: keys a ``KeychainKeyStore`` made — holder,
    /// instance and DPoP keys — under `keyStore`'s
    /// ``KeychainKeyStore/Options/tagPrefix``, that no credential is
    /// bound to. Pass the wallet's own key store, under a prefix of its
    /// own. It throws a ``StoreError``, deleting nothing, for a store
    /// whose prefix is empty, or covers or falls under
    /// ``HttpWalletProvider/registrationKeyTagPrefix``: that would
    /// delete the Wallet Provider registration key, which
    /// ``HttpWalletProvider/sweepOrphanedRegistrationKeys()`` sweeps
    /// instead. The credential store's files and the status cache's key
    /// aren't Keychain keys, and are never touched.
    @discardableResult
    public func sweepOrphanedKeys(in keyStore: KeychainKeyStore) async throws -> Int {
        if let refusal = Self.sweepRefusal(tagPrefix: keyStore.options.tagPrefix) {
            throw StoreError(refusal)
        }
        struct Keys: Decodable {
            let keyIDs: [String]
            enum CodingKeys: String, CodingKey { case keyIDs = "key_ids" }
        }
        let wallet = handle
        let json = try await OID4VC.offMain { try OID4VC.call { wallet.holderKeyIDs($0) } }
        let keep = Set(try decode(Keys.self, json).keyIDs)
        return try await OID4VC.offMain { try keyStore.deleteKeys(except: keep) }
    }

    /// Why ``sweepOrphanedKeys(in:)`` refuses a key store under
    /// `tagPrefix`, or nil: an empty prefix covers every tagged key, and
    /// one overlapping the registration key's prefix covers that key.
    static func sweepRefusal(tagPrefix: String) -> String? {
        let registration = HttpWalletProvider.registrationKeyTagPrefix
        if tagPrefix.isEmpty {
            return "sweep keys: the key store's tagPrefix is empty, which covers every tagged key"
        }
        if tagPrefix.hasPrefix(registration) || registration.hasPrefix(tagPrefix) {
            return "sweep keys: the key store's tagPrefix \(tagPrefix) overlaps the Wallet Provider registration key's, \(registration)"
        }
        return nil
    }

    /// Every credential the wallet holds.
    public func credentials() async throws -> [CredentialSummary] {
        struct Result: Decodable { let credentials: [CredentialSummary] }
        let wallet = handle
        let json = try await OID4VC.offMain { try OID4VC.call { wallet.credentials($0) } }
        return try decode(Result.self, json).credentials
    }

    /// One credential with its claims.
    public func credential(id: String) async throws -> CredentialDetail {
        let wallet = handle
        let json = try await OID4VC.offMain { try OID4VC.call { wallet.credential(id, error: $0) } }
        return try decode(CredentialDetail.self, json)
    }

    /// Fetches the issuer's status list for a credential, and an mdoc's
    /// identifier list, checks their signatures, and returns the
    /// credential with its revocation status recorded. Each list covers
    /// many credentials, so fetching it doesn't tell the issuer which
    /// one is checked. A credential without a status or identifier list
    /// is returned as it is. Revocation is final: a credential found
    /// revoked stays so, its lists not fetched again, until the revoked
    /// copy expires or the credential is refreshed.
    public func checkStatus(id: String) async throws -> CredentialSummary {
        let wallet = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { wallet.checkStatus(op, credentialID: id, error: $0) } }
        return try decode(CredentialSummary.self, json)
    }

    /// What `refreshCredential(id:)` obtained.
    public struct Refreshed: Decodable, Sendable {
        /// The credential, its ID unchanged: with every copy unused, or
        /// as it was when the issuer deferred the new one.
        public let credential: CredentialSummary
        /// The deferred credential to poll, when the issuer deferred it:
        /// once issued, it replaces the credential under the same ID.
        public let deferred: DeferredCredential?
    }

    /// Replaces a `refreshable` credential's copies with a fresh batch,
    /// each bound to a new holder key, without the holder signing in
    /// (OpenID4VCI 1.0 §13.5). The new holder keys sign the Credential
    /// Request's proof, so with `KeychainKeyStore.Options.holderUserPresence`
    /// on it asks the holder. Use it when `copiesLeft` runs low. Throws
    /// `WalletError.Code.reissueRequired` when it can't be refreshed:
    /// receive it again from a new offer.
    public func refreshCredential(id: String) async throws -> Refreshed {
        let wallet = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { wallet.refreshCredential(op, credentialID: id, error: $0) } }
        return try decode(Refreshed.self, json)
    }

    /// Replaces the Certificate Revocation Lists the configuration's
    /// `revocation.roles` are checked against with `pem`'s `X509 CRL`
    /// blocks, for every check from now on. CRLs expire at their
    /// nextUpdate: fetch fresh ones and call this before then. Text
    /// holding anything else, a list that doesn't parse, or a CA's list
    /// older than the one held (a lower CRL number, or an earlier
    /// thisUpdate) throws `invalidInput` and keeps the lists as they were,
    /// so a replayed list can't un-revoke a certificate; empty text
    /// removes them all, and a role checked then fails closed. Makes no
    /// network calls.
    public func setCRLs(_ pem: String) async throws {
        let wallet = handle
        try await OID4VC.offMain { try OID4VC.wrap { try wallet.setCRLs(pem) } }
    }

    /// Fetches the Certificate Revocation Lists of the configuration's
    /// `revocation.distributionPoints` (and, with `revocation.distributionPointsFromRoots`,
    /// those its roots name) and keeps each one its CA signed that is
    /// current and not older than the one held, for every check from now
    /// on, presentations already running included. A failed point keeps
    /// its list. Fetches go to public addresses only outside
    /// `development`, over `http` or `https` (the lists are signed).
    /// Persist the result's `crls` for the next launch and schedule the
    /// next refresh at its `nextRefresh` (see <doc:GoingToProduction>).
    /// Throws `invalidInput` (`not_configured`) with no distribution
    /// points configured, and `cancelled` when its task is cancelled.
    public func refreshCRLs() async throws -> CRLRefreshResult {
        let wallet = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { wallet.refreshCRLs(op, error: $0) } }
        return try CRLRefreshResult.from(json: json)
    }

    /// Deletes a credential and its holder keys, and its refresh grant
    /// once no other credential uses it, first revoking the refresh token
    /// at the Authorization Server, best effort.
    public func deleteCredential(id: String) async throws {
        let wallet = handle
        try await OID4VC.offMain { try OID4VC.wrap { try wallet.deleteCredential(id) } }
    }

    /// The credentials issuers have deferred and not yet settled, oldest
    /// first — including ones from before the app last quit. Makes no
    /// network calls: poll each at its interval.
    public func deferredCredentials() async throws -> [DeferredCredential] {
        struct Result: Decodable { let deferred: [DeferredCredential] }
        let wallet = handle
        let json = try await OID4VC.offMain { try OID4VC.call { wallet.deferred($0) } }
        return try decode(Result.self, json).deferred
    }

    /// Asks the issuer once about a deferred credential. A refused one
    /// throws `.credentialDenied`, and is then no longer pending.
    public func pollDeferred(id: String) async throws -> DeferredStatus {
        struct Status: Decodable {
            let status: String
            let credential: CredentialSummary?
            let intervalSeconds: Double
            enum CodingKeys: String, CodingKey { case status, credential, intervalSeconds = "interval_seconds" }
        }
        let wallet = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { wallet.pollDeferred(op, deferredID: id, error: $0) } }
        let s = try decode(Status.self, json)
        if s.status == MobileDeferredIssued, let c = s.credential { return .issued(c) }
        return .pending(intervalSeconds: s.intervalSeconds)
    }

    /// Gives up on a deferred credential — its access token has expired,
    /// say, or the holder no longer wants it — deleting it and its keys.
    public func abandonDeferred(id: String) async throws {
        let wallet = handle
        try await OID4VC.offMain { try OID4VC.wrap { try wallet.abandonDeferred(id) } }
    }

    /// Resolves a Credential Offer (openid-credential-offer://…) and the
    /// issuer's metadata.
    public func startIssuance(offer: String) async throws -> Issuance {
        let wallet = handle
        let s = try await OID4VC.cancellable { op in try OID4VC.wrap { try wallet.startIssuance(op, offerURI: offer) } }
        return try Issuance(s)
    }

    /// Completes an authorization begun before the app was suspended or
    /// relaunched: `redirect` is the issuer's redirect back to the
    /// redirect URI, delivered to the app (`onOpenURL`). Returns the
    /// issuance ready for `requestCredentials()`. A redirect matching no
    /// authorization in progress — not this wallet's, already completed,
    /// or expired — throws `.notFound`.
    public func resumeIssuance(redirect: URL) async throws -> Issuance {
        let wallet = handle
        let link = redirect.absoluteString
        let s = try await OID4VC.cancellable { op in try OID4VC.wrap { try wallet.resumeIssuance(op, redirect: link) } }
        return try Issuance(s)
    }

    /// Fetches and verifies an OpenID4VP request (openid4vp://…), and
    /// finds the credentials that can answer it. A request the wallet
    /// refuses throws ``WalletError/Code/requestRefused``,
    /// whose ``WalletError/refusalRedirect`` is where the Verifier asked
    /// to take the holder.
    public func startPresentation(request: String) async throws -> Presentation {
        let wallet = handle
        let p = try await OID4VC.cancellable { op in
            do {
                return try OID4VC.wrap { try wallet.startPresentation(op, requestLink: request) }
            } catch var e as WalletError where e.code == .requestRefused {
                // This call's own, not the latest of any call's.
                e.refusalRedirect = URL(string: op.takeRefusalRedirect())
                throw e
            }
        }
        return try Presentation(p)
    }

    /// Where the Verifier asked to take the holder after the wallet
    /// refused its request: when `startPresentation` throws
    /// `requestRefused`, open this URL, if any, as OpenID4VP §8.2 has a
    /// wallet do. It's returned once. It holds the latest refusal of
    /// any call: with presentations started concurrently, open the
    /// error's own ``WalletError/refusalRedirect`` instead, or one
    /// Verifier's redirect may be opened for another's refusal.
    public func takeRefusalRedirect() -> URL? {
        URL(string: handle.takeRefusalRedirect())
    }

    /// The held mdocs, each with whether the page at `origin` has been
    /// shown it and whether presenting it there now would be linkable
    /// (`shownToVerifier`, `linkableHere`): for a document provider's
    /// consent screen, shown before iOS releases the request itself.
    /// `MdocPresentation.request` says the same once it has. Every held
    /// mdoc is listed, an expired, revoked or suspended one too: offer the
    /// holder only those whose `presentable` is true.
    public func mdocCandidates(origin: String) async throws -> [CredentialSummary] {
        struct All: Decodable { let credentials: [CredentialSummary] }
        let wallet = handle
        let json = try await OID4VC.offMain { try OID4VC.call { wallet.mdocCandidates(origin, error: $0) } }
        return try decode(All.self, json).credentials
    }

    /// Parses an `org-iso-mdoc` request — an mdoc asked for over the
    /// Digital Credentials API, as iOS hands one to a document provider
    /// extension — and finds the held mdocs that can answer it.
    /// `requestData` is `IdentityDocumentWebPresentmentRawRequest.requestData`;
    /// `origin` the requesting page's origin
    /// (`ISO18013MobileDocumentRequestContext.requestingWebsiteOrigin`),
    /// as `MdocPresentation.origin(of:)` serializes it.
    public func startMdocPresentation(requestData: Data, origin: String) async throws -> MdocPresentation {
        let wallet = handle
        let p = try await OID4VC.cancellable { op in
            try OID4VC.wrap { try wallet.startMdocPresentation(op, request: requestData, origin: origin) }
        }
        return try MdocPresentation(p)
    }
}

/// What a Credential Offer offers.
public struct Offer: Decodable, Sendable {
    /// The PIN a pre-authorized code offer asks for, as the issuer describes
    /// it.
    public struct TxCode: Decodable, Sendable {
        /// `numeric` or `text`, if the issuer says.
        public let inputMode: String?
        /// How many characters it has, if the issuer says.
        public let length: Int?
        /// The issuer's description, to show the holder: where to find the PIN,
        /// say.
        public let description: String?
        enum CodingKeys: String, CodingKey { case inputMode = "input_mode", length, description }
    }

    /// One offered credential.
    public struct Credential: Decodable, Sendable {
        /// The issuer's credential configuration.
        public let configurationID: String
        /// Its format: `dc+sd-jwt` or `mso_mdoc`.
        public let format: String
        /// An SD-JWT VC's type.
        public let vct: String?
        /// An mdoc's document type.
        public let doctype: String?
        /// The issuer's display metadata for it, in the holder's language.
        public let name: String?
        /// The issuer's description of it.
        public let description: String?
        /// Its logo.
        public let logo: Logo?
        /// The card's background colour.
        public let backgroundColor: String?
        /// The card's text colour.
        public let textColor: String?
        enum CodingKeys: String, CodingKey {
            case configurationID = "configuration_id", format, vct, doctype, name, description, logo
            case backgroundColor = "background_color", textColor = "text_color"
        }
    }

    /// How the holder is authorized.
    public enum Grant: String, Decodable, Sendable {
        case authorizationCode = "authorization_code"
        case preAuthorizedCode = "pre-authorized_code"
    }

    /// The issuer's identifier, an https URL.
    public let credentialIssuer: String
    /// The issuer's name, in the holder's language.
    public let issuerName: String?
    /// The issuer's logo.
    public let issuerLogo: Logo?
    /// The grant the offer names.
    public let grant: Grant
    /// The PIN to ask the holder for, for a pre-authorized code offer.
    public let txCode: TxCode?
    /// The offered credentials.
    public let credentials: [Credential]

    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer", issuerName = "issuer_name", issuerLogo = "issuer_logo"
        case grant, txCode = "tx_code", credentials
    }
}

/// Receives one offer's credentials: show `offer`; then
/// `beginAuthorization()`, open the URL in ASWebAuthenticationSession and
/// `completeAuthorization(redirect:)`, or `redeemPreAuthorizedCode(pin:)`;
/// then `requestCredentials()`; `close()` when done.
public final class Issuance: @unchecked Sendable {
    let session: MobileIssuance
    /// What's offered: show it before going on.
    public let offer: Offer

    init(_ session: MobileIssuance) throws {
        self.session = session
        offer = try decode(Offer.self, session.offer())
    }

    // An issuance dropped without close() still deletes its keys.
    deinit {
        let session = self.session
        Task.detached { try? session.close() }
    }

    /// Begins the authorization code grant, returning the issuer's
    /// authorization URL to open in an `ASWebAuthenticationSession`. Calling it
    /// again begins again: after the holder closed the page, say.
    public func beginAuthorization() async throws -> URL {
        let session = self.session
        let text = try await OID4VC.cancellable { op in try OID4VC.call { session.beginAuthorization(op, error: $0) } }
        guard let url = URL(string: text) else { throw WalletError(code: .internalError, message: "malformed authorization URL") }
        return url
    }

    /// Completes the authorization with the issuer's redirect back. The
    /// redirect is used up whatever happens: if this fails — the token
    /// request didn't get through, say — call `beginAuthorization()`
    /// again, rather than retrying this.
    public func completeAuthorization(redirect: URL) async throws {
        let session = self.session
        try await OID4VC.cancellable { op in try OID4VC.wrap { try session.completeAuthorization(op, redirect: redirect.absoluteString) } }
    }

    /// Redeems a pre-authorized code offer, with the PIN the holder typed when
    /// `offer.txCode` asks for one. A wrong PIN throws a retryable
    /// `.protocolError` (`invalid_grant`): ask again.
    public func redeemPreAuthorizedCode(pin: String = "") async throws {
        let session = self.session
        try await OID4VC.cancellable { op in try OID4VC.wrap { try session.redeemPreAuthorizedCode(op, txCode: pin) } }
    }

    /// What `requestCredentials()` obtained.
    public struct Result: Decodable, Sendable {
        /// The credentials received and stored.
        public let credentials: [CredentialSummary]
        /// Credentials the issuer will issue later: poll them with
        /// `Wallet.pollDeferred(id:)`, after `close()` and relaunches too.
        public let deferred: [DeferredCredential]
        /// Credentials the issuer refused for good, or that failed the
        /// wallet's checks: they don't hold up the rest.
        public let failed: [FailedCredential]

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: Keys.self)
            credentials = try c.decode([CredentialSummary].self, forKey: .credentials)
            deferred = try c.decode([DeferredCredential].self, forKey: .deferred)
            failed = try c.decodeIfPresent([FailedCredential].self, forKey: .failed) ?? []
        }

        enum Keys: String, CodingKey { case credentials, deferred, failed }
    }

    /// An offered credential that couldn't be obtained: its error's code
    /// and, when the issuer gave one, its OAuth error code.
    public struct FailedCredential: Decodable, Sendable, Equatable {
        /// The offered credential's configuration.
        public let configurationID: String
        /// Why it failed.
        public let code: WalletError.Code
        /// The issuer's OAuth error code, when it gave one.
        public let protocolError: String?

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: Keys.self)
            configurationID = try c.decode(String.self, forKey: .configurationID)
            code = WalletError.Code(rawValue: try c.decode(String.self, forKey: .code))
            protocolError = try c.decodeIfPresent(String.self, forKey: .detail)
        }

        enum Keys: String, CodingKey { case configurationID = "configuration_id", code, detail }
    }

    /// Requests, checks and stores every offered credential.
    public func requestCredentials() async throws -> Result {
        let session = self.session
        let json = try await OID4VC.cancellable { op in try OID4VC.call { session.requestCredentials(op, error: $0) } }
        return try decode(Result.self, json)
    }

    /// Ends the issuance, deleting its keys but those its deferred
    /// credentials still poll with.
    public func close() async throws {
        let session = self.session
        try await OID4VC.offMain { try OID4VC.wrap { try session.close() } }
    }
}

/// Answers one OpenID4VP request: show `verifier`, `queries` and
/// `credentialSets`, choose a `Selection` (or start from
/// `defaultSelection()`), `preview(selection:)` it, then
/// `respond(selection:)` or `decline()`. The wallet presents exactly the
/// selection, after checking it answers the request
/// (`WalletError.Code.invalidSelection` otherwise).
public final class Presentation: @unchecked Sendable {
    /// Who is asking.
    public struct Verifier: Decodable, Sendable {
        /// The Verifier's client ID.
        public let clientID: String
        /// A name to show for the Verifier.
        public let name: String
        /// Where the response is sent.
        public let responseURI: String
        /// The Verifier's registration, from its request, checked against
        /// `WalletConfiguration.verifiers.registrarRoots`.
        public let registration: Registration
        enum CodingKeys: String, CodingKey { case clientID = "client_id", name, responseURI = "response_uri", registration }
    }

    /// A Verifier's registration with a registrar: who it is and what it
    /// may request, as the registrar attests.
    public struct Registration: Decodable, Sendable {
        /// Whether the registration verified.
        public enum Status: String, Decodable, Sendable {
            /// A registrar the wallet trusts registered this Verifier.
            case verified
            /// The request carries a registration that didn't verify: it
            /// isn't relied on.
            case invalid
            /// No registration, or no registrar roots to check one.
            case none
        }
        /// Whether the registration verified.
        public let status: Status
        /// The rest are set when `status` is `.verified`.
        public let name: String?
        /// Why it asks, as registered.
        public let purpose: String?
        /// Its privacy policy.
        public let privacyPolicy: URL?
        /// The registrar that registered it.
        public let registrar: String?
        /// The claims paths it's registered to request.
        public let claims: [[PathElement]]
        /// When the registration expires.
        public let expires: Date?

        enum CodingKeys: String, CodingKey { case status, name, purpose, privacyPolicy = "privacy_policy", registrar, claims, expires }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            status = try c.decode(Status.self, forKey: .status)
            name = try c.decodeIfPresent(String.self, forKey: .name)
            purpose = try c.decodeIfPresent(String.self, forKey: .purpose)
            privacyPolicy = try c.decodeIfPresent(URL.self, forKey: .privacyPolicy)
            registrar = try c.decodeIfPresent(String.self, forKey: .registrar)
            claims = try c.decodeIfPresent([[PathElement]].self, forKey: .claims) ?? []
            expires = try c.decodeIfPresent(Date.self, forKey: .expires)
        }
    }

    /// One of the request's credential queries, with the credentials
    /// that can answer it: none when nothing held can.
    public struct Query: Decodable, Sendable {
        /// The query's ID: a key in a `Selection`.
        public let queryID: String
        /// Whether it takes more than one credential; otherwise a
        /// selection gives it exactly one.
        public let multiple: Bool
        /// The held credentials that can answer it.
        public let credentials: [CredentialSummary]
        /// For a Verifier with a verified registration: the claims paths
        /// this query asks for beyond it, then those its credentials would
        /// disclose along with them beyond it (the rest of an array
        /// disclosed as one, say). Nothing is refused for them: the holder decides.
        public let unregistered: [[PathElement]]
        /// Whether it names no claims, beyond a verified registration. Such a
        /// query is flagged in full, though OpenID4VP 1.0 §6.4.1 reads it as
        /// asking for no selectively disclosable claims.
        public let unregisteredAll: Bool
        enum CodingKeys: String, CodingKey {
            case queryID = "query_id", multiple, credentials, unregistered, unregisteredAll = "unregistered_all"
        }
    }

    /// One of the request's sets of alternatives: each option is the
    /// query IDs that together answer it, most preferred first. A
    /// required set must be answered by one option.
    public struct CredentialSet: Decodable, Sendable {
        /// Each option's query IDs, most preferred first.
        public let options: [[String]]
        /// Whether the request needs one of the options answered.
        public let required: Bool
    }

    /// What to present: for each query ID, the IDs of the credentials
    /// chosen to answer it.
    public typealias Selection = [String: [String]]

    /// One claim path element: a key, an array index, or every element.
    public enum PathElement: Decodable, Sendable, Equatable {
        case key(String), index(Int), all

        public init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if c.decodeNil() { self = .all } else if let i = try? c.decode(Int.self) { self = .index(i) } else { self = .key(try c.decode(String.self)) }
        }
    }

    /// What a selection would disclose from one credential.
    public struct Disclosure: Decodable, Sendable {
        /// The query it answers.
        public let queryID: String
        /// The credential.
        public let credentialID: String
        /// The claims it would disclose, as paths.
        public let claims: [[PathElement]]
        /// The SD-JWT VC claims the Verifier receives beyond `claims`:
        /// those its issuer didn't make selectively disclosable, and what
        /// shares a Disclosure with a claim: the plaintext members of a
        /// disclosed object or array element a claim sits within, and the
        /// other elements of an array disclosed as one. Show them with
        /// `claims`.
        public let alwaysDisclosed: [[PathElement]]
        /// The claims the Verifier says it will keep (an mdoc query's
        /// `intent_to_retain`): show that with them.
        public let retained: [[PathElement]]
        enum CodingKeys: String, CodingKey { case queryID = "query_id", credentialID = "credential_id", claims, alwaysDisclosed = "always_disclosed", retained }
    }

    /// What responding or declining sent.
    public struct Presented: Decodable, Sendable {
        /// The queries answered.
        public let queryIDs: [String]
        /// Where to send the browser, when the Verifier asks.
        public let redirectURI: URL?
        enum CodingKeys: String, CodingKey { case queryIDs = "query_ids", redirectURI = "redirect_uri" }
    }

    let handle: MobilePresentation
    /// Who is asking.
    public let verifier: Verifier
    /// The request's credential queries, in its order.
    public let queries: [Query]
    /// The request's sets of alternatives; none means every query must
    /// be answered.
    public let credentialSets: [CredentialSet]

    init(_ p: MobilePresentation) throws {
        handle = p
        verifier = try decode(Verifier.self, p.verifier())
        struct All: Decodable {
            let queries: [Query]
            let credentialSets: [CredentialSet]
            enum CodingKeys: String, CodingKey { case queries, credentialSets = "credential_sets" }
        }
        let all = try decode(All.self, p.queries())
        queries = all.queries
        credentialSets = all.credentialSets
    }

    /// Whether some credential can answer some query: if not, decline.
    public var isAnswerable: Bool { queries.contains { !$0.credentials.isEmpty } }

    /// The selection the wallet would make itself, for an app with no
    /// policy of its own, or to start from: the first answerable option
    /// of each credential set, and each query's first credential, even
    /// when it takes several: the holder adds the others. Throws
    /// `noMatchingCredential` when the request can't be answered.
    public func defaultSelection() async throws -> Selection {
        struct All: Decodable { let selection: Selection }
        let p = handle
        let json = try await OID4VC.offMain { try OID4VC.call { p.defaultSelection($0) } }
        return try decode(All.self, json).selection
    }

    /// What responding with `selection` would disclose, without signing
    /// or sending anything.
    public func preview(selection: Selection) async throws -> [Disclosure] {
        struct All: Decodable { let disclosures: [Disclosure] }
        let p = handle
        let json = try selectionJSON(selection)
        let out = try await OID4VC.offMain { try OID4VC.call { p.preview(json, error: $0) } }
        return try decode(All.self, out).disclosures
    }

    /// Presents exactly `selection`: holder keys sign now, so a key
    /// store requiring user presence prompts.
    public func respond(selection: Selection) async throws -> Presented {
        let p = handle
        let json = try selectionJSON(selection)
        let out = try await OID4VC.cancellable { op in try OID4VC.call { p.respond(op, selectionJSON: json, error: $0) } }
        return try decode(Presented.self, out)
    }

    /// Tells the Verifier the holder declined.
    public func decline() async throws -> Presented {
        let p = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { p.decline(op, error: $0) } }
        return try decode(Presented.self, json)
    }

    private func selectionJSON(_ selection: Selection) throws -> String {
        String(decoding: try JSONEncoder().encode(selection), as: UTF8.self)
    }
}

/// An `org-iso-mdoc` request (ISO/IEC TS 18013-7 Annex C): show
/// `request` for the holder's consent, then `respond` once; to decline,
/// cancel the platform's request — nothing is sent to the reader.
public final class MdocPresentation: @unchecked Sendable {
    /// What the page asks for.
    public struct Request: Decodable, Sendable {
        /// The requesting page's origin.
        public let origin: String
        /// The subject common name of the reader that signed the request,
        /// when its certificate chains to
        /// `WalletConfiguration.verifiers.mdocReaderRoots`, without control or
        /// invisible format characters; "" when the holder can only be
        /// shown `origin`.
        public let reader: String
        /// That reader's certificate, DER; nil without one. Compare
        /// certificates, not names: two can share a name.
        public let readerCertificate: Data?
        /// The requested documents, in the request's order.
        public let documents: [Document]

        enum CodingKeys: String, CodingKey {
            case origin, reader, documents
            case readerCertificate = "reader_certificate"
        }
    }

    /// One requested document.
    public struct Document: Decodable, Sendable {
        /// Its document type.
        public let doctype: String
        /// The elements requested.
        public let elements: [Element]
        /// The held mdocs of `doctype`; none when nothing can answer.
        public let credentials: [CredentialSummary]
    }

    /// One requested element.
    public struct Element: Decodable, Sendable, Hashable {
        /// Its namespace.
        public let namespace: String
        /// Its identifier in the namespace.
        public let identifier: String
        /// Whether the reader says it will keep the value.
        public let retain: Bool

        /// An element.
        public init(namespace: String, identifier: String, retain: Bool) {
            self.namespace = namespace
            self.identifier = identifier
            self.retain = retain
        }
    }

    /// The answer to hand iOS.
    public struct Response: Decodable, Sendable {
        /// The CBOR EncryptedResponse, for
        /// `ISO18013MobileDocumentResponse(responseData:)`.
        public let response: Data
        /// Whether a copy presented had been seen by another Verifier: for
        /// several documents, whether any was.
        public let linkable: Bool
        /// The credentials presented with such a copy, by ID.
        public let linkableCredentials: [String]

        enum CodingKeys: String, CodingKey {
            case response, linkable
            case linkableCredentials = "linkable_credentials"
        }

        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            response = try c.decode(Data.self, forKey: .response)
            linkable = try c.decode(Bool.self, forKey: .linkable)
            linkableCredentials = try c.decodeIfPresent([String].self, forKey: .linkableCredentials) ?? []
        }
    }

    /// One requested document to answer: number `document` of
    /// `request.documents`, with the held mdoc `credentialID`, disclosing
    /// exactly `elements`, each one that document requested.
    public struct Answer: Sendable, Hashable {
        public let document: Int
        public let credentialID: String
        public let elements: [Element]

        /// An answer.
        public init(document: Int, credentialID: String, elements: [Element]) {
            self.document = document
            self.credentialID = credentialID
            self.elements = elements
        }
    }

    /// `answers` as the gomobile layer takes them:
    /// `[{"document", "credential_id", "elements"}]`.
    static func answersJSON(_ answers: [Answer]) throws -> String {
        struct AnswerJSON: Encodable {
            let document: Int
            let credentialID: String
            let elements: [[String]]
            enum CodingKeys: String, CodingKey { case document, credentialID = "credential_id", elements }
        }
        let out = answers.map { a in AnswerJSON(document: a.document, credentialID: a.credentialID, elements: a.elements.map { [$0.namespace, $0.identifier] }) }
        return String(decoding: try JSONEncoder().encode(out), as: UTF8.self)
    }

    let handle: MobileMdocPresentation
    /// What's asked: show it for the holder's consent.
    public let request: Request

    init(_ p: MobileMdocPresentation) throws {
        handle = p
        request = try decode(Request.self, p.request())
    }

    /// Presents the held mdoc `credentialID` for document number
    /// `document`, disclosing exactly `elements`, each one it requested.
    /// The holder key signs now, so a key store requiring user presence
    /// prompts. It is `respond(answers:)` with one answer.
    public func respond(document: Int, credentialID: String, elements: [Element]) async throws -> Response {
        try await respond(answers: [Answer(document: document, credentialID: credentialID, elements: elements)])
    }

    /// Presents several of the request's documents in one
    /// EncryptedResponse, each of `answers` as
    /// `respond(document:credentialID:elements:)` presents one. A document
    /// left out isn't in the response. No document may be answered twice,
    /// nor one credential answer two. Each holder key signs now, in the
    /// request's order; a `KeychainKeyStore` requiring user presence asks
    /// the holder once for them all. On a `WalletError` — the prompt
    /// cancelled, say — nothing is returned, and the request can be
    /// answered again.
    public func respond(answers: [Answer]) async throws -> Response {
        let p = handle
        let json = try Self.answersJSON(answers)
        // The shared prompt is scoped to the thread making the Go call,
        // so it goes inside cancellable's background work.
        let out = try await OID4VC.cancellable { op in
            try OID4VC.callSharingHolderPrompt { p.respondDocuments(op, answersJSON: json, error: $0) }
        }
        return try decode(Response.self, out)
    }

    /// `url`'s web origin, as a browser serializes it and the session
    /// transcript binds it: `scheme://host`, with the port only when it
    /// isn't the scheme's default, and no path — the form
    /// `startMdocPresentation(requestData:origin:)` takes. iOS reports the
    /// origin as a URL, whose `absoluteString` can end in "/".
    public static func origin(of url: URL) -> String? {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false), let scheme = c.scheme?.lowercased() else { return nil }
        // `encodedHost` is iOS 16 and later; `percentEncodedHost` is its iOS 15 form.
        let encodedHost: String?
        if #available(iOS 16.0, macOS 13.0, *) { encodedHost = c.encodedHost } else { encodedHost = c.percentEncodedHost }
        guard let host = encodedHost ?? c.host, !host.isEmpty else { return nil }
        let defaultPorts = ["https": 443, "http": 80]
        let defaultPort = defaultPorts[scheme]
        guard let port = c.port, port != defaultPort else { return "\(scheme)://\(host)" }
        return "\(scheme)://\(host):\(port)"
    }
}

/// A credential store in memory, for tests and development.
public final class InMemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [(id: String, record: Data)] = []

    /// An empty store.
    public init() {}

    public func put(id: String, record: Data) throws {
        lock.withLock {
            stored.removeAll { $0.id == id }
            stored.append((id, record))
        }
    }

    public func record(id: String) throws -> Data? {
        lock.withLock { stored.first { $0.id == id }?.record }
    }

    public func records() throws -> [Data] {
        lock.withLock { stored.map(\.record) }
    }

    public func records(where isIncluded: (String) -> Bool) throws -> [Data] {
        lock.withLock { stored.filter { isIncluded($0.id) }.map(\.record) }
    }

    public func delete(id: String) throws {
        lock.withLock { stored.removeAll { $0.id == id } }
    }

    /// Atomic within this process, which is all an in-memory store has.
    public func compareAndSwap(id: String, expected: Data?, record: Data?) throws -> Data? {
        lock.withLock {
            let current = stored.first { $0.id == id }?.record
            guard current == expected else { return current }
            stored.removeAll { $0.id == id }
            if let record { stored.append((id, record)) }
            return current
        }
    }
}

// The Go objects are safe to use from any thread: gomobile's references
// are, and walletflow's sessions serialize their own steps.
extension MobileWallet: @retroactive @unchecked Sendable {}
extension MobileIssuance: @retroactive @unchecked Sendable {}
extension MobilePresentation: @retroactive @unchecked Sendable {}
extension MobileMdocPresentation: @retroactive @unchecked Sendable {}

/// Decodes one of the Go side's JSON results.
func decode<T: Decodable>(_ type: T.Type, _ json: String) throws -> T {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .custom { d in
        let text = try d.singleValueContainer().decode(String.self)
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = f.date(from: text) { return date }
        f.formatOptions = [.withInternetDateTime]
        if let date = f.date(from: text) { return date }
        throw DecodingError.dataCorrupted(.init(codingPath: d.codingPath, debugDescription: "not an RFC 3339 time"))
    }
    do {
        return try decoder.decode(type, from: Data(json.utf8))
    } catch {
        // Only where: the decoder's own text can quote a value, a claim.
        throw WalletError(code: .internalError, message: "malformed result from the Go side at \(codingPath(error))")
    }
}

/// The coding path a decoding error names, as "a.b[2]", or "the top".
func codingPath(_ error: Error) -> String {
    let path: [CodingKey]
    switch error as? DecodingError {
    case .dataCorrupted(let c), .keyNotFound(_, let c), .typeMismatch(_, let c), .valueNotFound(_, let c): path = c.codingPath
    default: return "the top"
    }
    return path.isEmpty ? "the top" : path.map { $0.intValue.map { "[\($0)]" } ?? $0.stringValue }.joined(separator: ".")
}

/// Any key, to list every key a JSON object has.
struct AnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int?
    init(stringValue: String) { self.stringValue = stringValue; intValue = nil }
    init?(intValue: Int) { stringValue = String(intValue); self.intValue = intValue }
}
