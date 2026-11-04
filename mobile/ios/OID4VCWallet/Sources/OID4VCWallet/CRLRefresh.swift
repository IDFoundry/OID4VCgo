import Foundation

/// Where `Wallet.refreshCRLs()` or `ProximityReader.refreshCRLs()`
/// fetches a CA's Certificate Revocation List from, bound to that CA: a
/// list the URL serves is kept only when this CA signed it.
public struct CRLDistributionPoint: Codable, Sendable, Equatable {
    /// An `http` or `https` URL: the CRL distribution point the CA's
    /// certificates name. `http` is usual, since a CRL is signed.
    public var url: String
    /// The CA's certificate, PEM.
    public var issuer: String

    public init(url: String, issuer: String) {
        self.url = url
        self.issuer = issuer
    }
}

/// What a CRL refresh did: each distribution point's outcome, the lists
/// now held, and when to refresh again.
public struct CRLRefreshResult: Decodable, Sendable, Equatable {
    /// One distribution point's outcome.
    public struct Point: Decodable, Sendable, Equatable {
        /// The distribution point, its password (if any) redacted.
        public let url: String
        /// What the fetch did.
        public let outcome: Outcome
        /// Why it failed, as `[code] message`, for logs; nil unless
        /// `outcome` is `.failed`.
        public let error: String?
    }

    /// A distribution point's outcome.
    public enum Outcome: String, Decodable, Sendable {
        /// A newer list now replaces the one held for its CA, for every
        /// check from now on.
        case updated
        /// The list served is the one held already.
        case unchanged
        /// Nothing was kept: the point couldn't be reached, answered with
        /// an error, or served a list that's refused (another CA's, not
        /// current, or older than the one held). The list held stays.
        case failed
    }

    /// One per configured distribution point, in configuration order.
    public let results: [Point]
    /// Every list now held, as PEM `X509 CRL` blocks: persist it, and
    /// pass it back as the configuration's `crls` at the next launch, so
    /// checks work before the first refresh and an older list is still
    /// refused after a restart.
    public let crls: String
    /// When to refresh again: halfway to the earliest list's nextUpdate,
    /// at most an hour away, or in minutes after a failure. Use it as
    /// `BGAppRefreshTaskRequest.earliestBeginDate`; the system may run
    /// the task later.
    public let nextRefresh: Date

    enum CodingKeys: String, CodingKey {
        case results, crls, nextRefresh = "next_refresh"
    }

    /// Whether any distribution point failed.
    public var anyFailed: Bool { results.contains { $0.outcome == .failed } }

    /// Decodes the Go side's JSON (also for tests).
    static func from(json: String) throws -> CRLRefreshResult { try decode(CRLRefreshResult.self, json) }
}
