import Foundation

// The option groups WalletConfiguration and ProximityReaderConfiguration
// share, and the flat JSON keys they read and write.

/// How trust roles' certificates are checked for revocation: a
/// ``WalletConfiguration``'s (``WalletConfiguration/Revocation``, over
/// ``WalletConfiguration/RevocationRole``) or a
/// ``ProximityReaderConfiguration``'s
/// (``ProximityReaderConfiguration/Revocation``, over
/// ``ProximityReaderConfiguration/RevocationRole``).
public struct RevocationChecking<Role: Codable & Sendable>: Sendable {
    /// The trust roles whose certificate chains must pass a CRL check
    /// against `crls`. A role listed fails closed for any CA it has no
    /// current CRL from, until ``Wallet/setCRLs(_:)`` (or
    /// ``ProximityReader/setCRLs(_:)``) supplies one. Outside
    /// `development`, each role must be listed here or in `declined` (a
    /// wallet's, each whose roots are set), or the wallet or reader isn't
    /// made (`invalidInput`).
    public var roles: [Role]
    /// The trust roles that decline checking revocation, as an explicit
    /// choice: only where something else stands in for it, such as
    /// certificates too short-lived to be worth revoking. A role can't be
    /// in both this and `roles`.
    public var declined: [Role]
    /// PEM `X509 CRL` blocks: the Certificate Revocation Lists the roles
    /// in `roles` are checked against. Replace them at runtime with
    /// ``Wallet/setCRLs(_:)`` (or ``ProximityReader/setCRLs(_:)``) as
    /// they expire.
    public var crls: String
    /// PEM certificates of the CAs that issued certificates pinned in the
    /// roots (a leaf in a wallet's `verifiers.roots`, say), for a role in
    /// `roles`: a pinned certificate is checked against its CA's CRL,
    /// verified with the CA's certificate from here. They aren't trust
    /// anchors. Without its CA here, a pinned certificate that isn't
    /// self-signed is refused.
    public var crlIssuers: String
    /// Where ``Wallet/refreshCRLs()`` (or
    /// ``ProximityReader/refreshCRLs()``) fetches the lists from, each
    /// bound to the CA whose list it serves.
    public var distributionPoints: [CRLDistributionPoint]
    /// Also fetches, in ``Wallet/refreshCRLs()`` (or
    /// ``ProximityReader/refreshCRLs()``), the distribution point each
    /// self-signed CA certificate names for its own list (as an IACA
    /// does), among `crlIssuers` and the roots of the roles in `roles`: a
    /// reader's `issuers.roots` and `issuers.rootsByDocType`.
    public var distributionPointsFromRoots: Bool
    /// Refuses plain `http` distribution points, and leaves them out of
    /// `distributionPointsFromRoots`.
    public var requireHTTPS: Bool

    /// Revocation checking: every field has a default.
    public init(roles: [Role] = [], declined: [Role] = [], crls: String = "",
                crlIssuers: String = "", distributionPoints: [CRLDistributionPoint] = [],
                distributionPointsFromRoots: Bool = false, requireHTTPS: Bool = false) {
        self.roles = roles
        self.declined = declined
        self.crls = crls
        self.crlIssuers = crlIssuers
        self.distributionPoints = distributionPoints
        self.distributionPointsFromRoots = distributionPointsFromRoots
        self.requireHTTPS = requireHTTPS
    }

    /// The group from its flat keys in `c`.
    init<Key: CodingKey>(decodingFrom c: KeyedDecodingContainer<Key>) throws {
        self.init(roles: try c.flat("revocation", []),
                  declined: try c.flat("no_revocation_check", []),
                  crls: try c.flat("crls", ""),
                  crlIssuers: try c.flat("crl_issuers", ""),
                  distributionPoints: try c.flat("crl_distribution_points", []),
                  distributionPointsFromRoots: try c.flat("crl_distribution_points_from_roots", false),
                  requireHTTPS: try c.flat("crl_require_https", false))
    }

    /// Writes the group's flat keys, every one, to `c`.
    func encode<Key: CodingKey>(into c: inout KeyedEncodingContainer<Key>) throws {
        try c.encode(roles, forKey: flatKey("revocation"))
        try c.encode(declined, forKey: flatKey("no_revocation_check"))
        try c.encode(crls, forKey: flatKey("crls"))
        try c.encode(crlIssuers, forKey: flatKey("crl_issuers"))
        try c.encode(distributionPoints, forKey: flatKey("crl_distribution_points"))
        try c.encode(distributionPointsFromRoots, forKey: flatKey("crl_distribution_points_from_roots"))
        try c.encode(requireHTTPS, forKey: flatKey("crl_require_https"))
    }
}

/// How `checkStatus` fetches and keeps status lists and mdoc identifier
/// lists, for a ``WalletConfiguration`` or a
/// ``ProximityReaderConfiguration``.
public struct StatusLists: Sendable {
    /// The largest status list `checkStatus` reads, in bytes; 0 means 1
    /// MiB. Raise it for issuers whose lists are larger.
    public var maxBytes: Int
    /// The largest mdoc identifier list `checkStatus` reads, in bytes; 0
    /// means 4 MiB.
    public var identifierListMaxBytes: Int
    /// How long `checkStatus` uses a status or identifier list it fetched
    /// before revalidating it, in seconds: 0 means 5 minutes, at most a
    /// day, and never past the list's own `ttl` or `exp`. Longer means
    /// fewer requests, and a revocation seen that much later.
    public var cacheMaxAgeSeconds: Int
    /// Where `checkStatus` keeps the lists it verified across launches: a
    /// launch then asks each list's server whether the list it kept is
    /// current, a `304 Not Modified` rather than the list, and never uses
    /// one the server hasn't confirmed. The lists are authenticated with
    /// a key the library makes and keeps in the Keychain, so one anyone
    /// else wrote to the directory is dropped. Nil, the default, keeps
    /// them in `oid4vcwallet-status-lists` in the app's Caches directory,
    /// with complete file protection, or in memory only when that key
    /// can't be had or the directory made, and on macOS; an absolute
    /// path, the app's own, keeps them there, with the protection the
    /// app gives it; empty keeps them in memory only. The directory shows
    /// whoever can read it which status lists the wallet checks (their
    /// URIs, so the issuers of its credentials, not which entries), the
    /// lists themselves, and when each was last checked. A check while
    /// the device is locked can't read this directory under complete
    /// protection, and with ``FileCredentialStore``'s default complete
    /// protection it can't read the credential either: it fails as
    /// `.platform`. Check status when the app comes to the foreground.
    public var cacheDir: String?

    /// Status list options: every field has a default.
    public init(maxBytes: Int = 0, identifierListMaxBytes: Int = 0, cacheMaxAgeSeconds: Int = 0, cacheDir: String? = nil) {
        self.maxBytes = maxBytes
        self.identifierListMaxBytes = identifierListMaxBytes
        self.cacheMaxAgeSeconds = cacheMaxAgeSeconds
        self.cacheDir = cacheDir
    }

    /// The group from its flat keys in `c`.
    init<Key: CodingKey>(decodingFrom c: KeyedDecodingContainer<Key>) throws {
        self.init(maxBytes: try c.flat("status_max_bytes", 0),
                  identifierListMaxBytes: try c.flat("identifier_list_max_bytes", 0),
                  cacheMaxAgeSeconds: try c.flat("status_cache_max_age_seconds", 0),
                  cacheDir: try c.decodeIfPresent(String.self, forKey: flatKey("status_cache_dir")))
    }

    /// Writes the group's flat keys to `c`: `status_cache_dir` only when
    /// `cacheDir` is set.
    func encode<Key: CodingKey>(into c: inout KeyedEncodingContainer<Key>) throws {
        try c.encode(maxBytes, forKey: flatKey("status_max_bytes"))
        try c.encode(identifierListMaxBytes, forKey: flatKey("identifier_list_max_bytes"))
        try c.encode(cacheMaxAgeSeconds, forKey: flatKey("status_cache_max_age_seconds"))
        try c.encodeIfPresent(cacheDir, forKey: flatKey("status_cache_dir"))
    }
}

/// A development configuration, for a ``WalletConfiguration`` or a
/// ``ProximityReaderConfiguration``: set, it relaxes what production
/// requires, as each configuration's `development` says. Never ship an
/// app with it set.
public struct Development: Sendable {
    /// PEM certificates the HTTPS requests and CRL fetches trust besides
    /// the system's: a development service's own CA. Empty: only the
    /// system's.
    public var roots: String

    /// Development, trusting `roots` besides the system's certificates.
    public init(roots: String = "") {
        self.roots = roots
    }

    /// The flat `development` and `development_roots` keys' value: nil
    /// unless `development` is true. Roots without `development` are
    /// refused, as the library refuses them.
    static func decode<Key: CodingKey>(_ c: KeyedDecodingContainer<Key>) throws -> Development? {
        let development: Key = flatKey("development")
        let roots: String = try c.flat("development_roots", "")
        guard try c.flat("development", false) else {
            if !roots.isEmpty {
                throw DecodingError.dataCorruptedError(forKey: development, in: c, debugDescription: "development_roots is set without development")
            }
            return nil
        }
        return Development(roots: roots)
    }

    /// Writes `development`'s flat keys, both always, to `c`.
    static func encode<Key: CodingKey>(_ development: Development?, into c: inout KeyedEncodingContainer<Key>) throws {
        try c.encode(development != nil, forKey: flatKey("development"))
        try c.encode(development?.roots ?? "", forKey: flatKey("development_roots"))
    }
}

/// The configuration's coding key for the flat JSON key `name`, which
/// every configuration sharing a group lists in its `CodingKeys`.
func flatKey<Key: CodingKey>(_ name: String) -> Key {
    guard let key = Key(stringValue: name) else {
        preconditionFailure("\(Key.self) has no configuration key \(name)")
    }
    return key
}

extension KeyedDecodingContainer {
    /// The flat key `name`'s value, or `fallback` when it's absent.
    func flat<T: Decodable>(_ name: String, _ fallback: T) throws -> T {
        try decodeIfPresent(T.self, forKey: flatKey(name)) ?? fallback
    }
}
