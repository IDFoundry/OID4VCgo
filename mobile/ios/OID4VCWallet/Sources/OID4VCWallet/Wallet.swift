import Foundation
import Mobile

/// NewWallet's configuration.
public struct WalletConfiguration: Codable, Sendable {
    /// The wallet's registration with Authorization Servers.
    public var clientID: String
    public var redirectURI: String
    /// PEM certificates: the trust anchors for issuers' credentials, and
    /// for Verifiers' requests.
    public var issuerRoots: String
    public var verifierRoots: String
    /// Allows services on loopback addresses.
    public var development: Bool
    /// The holder's preferred languages (BCP 47, most preferred first),
    /// for issuers' display metadata. `Locale.preferredLanguages` is the
    /// usual choice.
    public var locales: [String]
    /// How many copies of each credential to request when an issuer
    /// offers batches, each bound to its own key, so each presentation
    /// can use one no Verifier has seen. 0 means the SDK's default (5);
    /// it's capped at the issuer's batch size.
    public var batchSize: Int
    /// Asks Authorization Servers for a refresh token, so
    /// `Wallet.refreshCredential(id:)` can later replace a credential's
    /// copies without the holder. The server must allow the wallet the
    /// `offline_access` scope, or the authorization fails.
    public var requestRefresh: Bool
    /// Which copy of a credential a presentation uses.
    public var copyPolicy: CopyPolicy

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

    public init(clientID: String, redirectURI: String, issuerRoots: String = "", verifierRoots: String = "", development: Bool = false,
                locales: [String] = Locale.preferredLanguages, batchSize: Int = 0, requestRefresh: Bool = false,
                copyPolicy: CopyPolicy = .perPresentation) {
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.issuerRoots = issuerRoots
        self.verifierRoots = verifierRoots
        self.development = development
        self.locales = locales
        self.batchSize = batchSize
        self.requestRefresh = requestRefresh
        self.copyPolicy = copyPolicy
    }

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id", redirectURI = "redirect_uri", issuerRoots = "issuer_roots"
        case verifierRoots = "verifier_roots", development, locales, batchSize = "batch_size"
        case requestRefresh = "request_refresh", copyPolicy = "copy_policy"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(clientID: try c.decode(String.self, forKey: .clientID),
                  redirectURI: try c.decode(String.self, forKey: .redirectURI),
                  issuerRoots: try c.decodeIfPresent(String.self, forKey: .issuerRoots) ?? "",
                  verifierRoots: try c.decodeIfPresent(String.self, forKey: .verifierRoots) ?? "",
                  development: try c.decodeIfPresent(Bool.self, forKey: .development) ?? false,
                  locales: try c.decodeIfPresent([String].self, forKey: .locales) ?? Locale.preferredLanguages,
                  batchSize: try c.decodeIfPresent(Int.self, forKey: .batchSize) ?? 0,
                  requestRefresh: try c.decodeIfPresent(Bool.self, forKey: .requestRefresh) ?? false,
                  copyPolicy: try c.decodeIfPresent(CopyPolicy.self, forKey: .copyPolicy) ?? .perPresentation)
    }

    /// The scheme of `redirectURI`: the callback scheme an
    /// ASWebAuthenticationSession waits for.
    public var callbackScheme: String? { URL(string: redirectURI)?.scheme }
}

/// An image the issuer names for display: an https URL or a data: image
/// (nothing else reaches the app), with alternative text.
public struct Logo: Decodable, Equatable, Sendable {
    public let uri: String
    public let altText: String?
    /// `uri` as a URL, for `AsyncImage`.
    public var url: URL? { URL(string: uri) }
    enum CodingKeys: String, CodingKey { case uri, altText = "alt_text" }
}

/// How to show a credential, from the issuer's metadata (OpenID4VCI 1.0
/// §12.2.4) in the holder's language: each part only when the issuer
/// gives it. Colours are CSS colours, such as "#12107c".
public struct CredentialDisplay: Decodable, Equatable, Sendable {
    public let issuerName: String?
    public let issuerLogo: Logo?
    public let name: String?
    public let description: String?
    public let logo: Logo?
    public let backgroundColor: String?
    public let textColor: String?
    enum CodingKeys: String, CodingKey {
        case issuerName = "issuer_name", issuerLogo = "issuer_logo", name, description, logo
        case backgroundColor = "background_color", textColor = "text_color"
    }
}

/// A credential's revocation status in the issuer's status list, as last
/// checked (`Wallet.checkStatus(id:)`).
public struct CredentialStatus: Decodable, Equatable, Sendable {
    public enum Value: Equatable, Sendable {
        case valid, revoked, suspended
        /// A status the issuer's list defines itself, as "0x" and its value.
        case other(String)
    }
    public let value: Value
    public let checkedAt: Date

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Keys.self)
        switch try c.decode(String.self, forKey: .value) {
        case "valid": value = .valid
        case "invalid": value = .revoked
        case "suspended": value = .suspended
        case let v: value = .other(v)
        }
        checkedAt = try c.decode(Date.self, forKey: .checkedAt)
    }
    enum Keys: String, CodingKey { case value, checkedAt = "checked_at" }
}

/// A credential the wallet holds, as the app shows it.
public struct CredentialSummary: Decodable, Equatable, Sendable {
    public let id: String
    public let credentialIssuer: String
    public let configurationID: String
    public let format: String
    public let vct: String?
    public let doctype: String?
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
    public let copiesLeft: Int
    /// Whether its issuance kept a refresh token
    /// (`Configuration.requestRefresh`), so
    /// `Wallet.refreshCredential(id:)` can replace its copies. The
    /// Authorization Server may still refuse
    /// (`WalletError.Code.reissueRequired`).
    public let refreshable: Bool
    /// Whether a copy has been presented to more than one Verifier, so
    /// those Verifiers could link the holder's presentations. Refreshing
    /// gives it copies no Verifier has seen.
    public let linkable: Bool
    /// Set only on a presentation's candidates (`Presentation.queries`):
    /// whether the Verifier asking has been shown this credential before,
    /// and whether presenting it now would hand it a copy another
    /// Verifier has seen.
    public let shownToVerifier: Bool?
    public let linkableHere: Bool?

    /// Whether it has expired by `now`.
    public func isExpired(at now: Date = Date()) -> Bool { validUntil.map { $0 <= now } ?? false }

    enum CodingKeys: String, CodingKey {
        case id, format, vct, doctype, display, status
        case credentialIssuer = "credential_issuer", configurationID = "configuration_id", receivedAt = "received_at"
        case holderKeyPresent = "holder_key_present", validUntil = "valid_until"
        case copies, copiesLeft = "copies_left", refreshable, linkable
        case shownToVerifier = "shown_to_verifier", linkableHere = "linkable_here"
    }
}

/// A credential an issuer will issue later (OpenID4VCI 1.0 §9). It's
/// kept in the credential store until it's issued, denied or abandoned,
/// so it survives the app quitting.
public struct DeferredCredential: Decodable, Equatable, Sendable {
    public let id: String
    public let credentialIssuer: String
    public let configurationID: String
    /// How long the issuer asked the wallet to wait between polls.
    public let intervalSeconds: Double
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
                      provider: provider.map(WalletProviderAdapter.init))
    }

    init(configuration: WalletConfiguration, keys: KeyStoreAdapter, credentials: CredentialStoreAdapter,
         provider: (any MobileWalletProviderProtocol)?) throws {
        let json = String(decoding: try JSONEncoder().encode(configuration), as: UTF8.self)
        handle = try OID4VC.call { MobileNewWallet(json, keys, credentials, provider, $0) }!
        adapters = [keys, credentials] + (provider.map { [$0 as AnyObject] } ?? [])
    }

    /// Deletes every key in `keyStore` that none of the wallet's
    /// credentials is bound to — left by an issuance the app quit or
    /// crashed in the middle of — and returns how many. Call it at launch,
    /// before any issuance or refresh: one in progress holds keys of its
    /// own.
    @discardableResult
    public func sweepOrphanedKeys(in keyStore: KeychainKeyStore) async throws -> Int {
        struct Keys: Decodable {
            let keyIDs: [String]
            enum CodingKeys: String, CodingKey { case keyIDs = "key_ids" }
        }
        let wallet = handle
        let json = try await OID4VC.offMain { try OID4VC.call { wallet.holderKeyIDs($0) } }
        let keep = Set(try decode(Keys.self, json).keyIDs)
        return try await OID4VC.offMain { try keyStore.deleteKeys(except: keep) }
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

    /// Fetches the issuer's status list for a credential, checks its
    /// signature, and returns the credential with its revocation status
    /// recorded. The list covers many credentials, so fetching it
    /// doesn't tell the issuer which one is checked. A credential without
    /// a status list is returned as it is.
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
        /// it settles as a new credential.
        public let deferred: DeferredCredential?
    }

    /// Replaces a `refreshable` credential's copies with a fresh batch,
    /// each bound to a new attested key, without the holder (OpenID4VCI
    /// 1.0 §13.5). Use it when `copiesLeft` runs low. Throws
    /// `WalletError.Code.reissueRequired` when it can't be refreshed:
    /// receive it again from a new offer.
    public func refreshCredential(id: String) async throws -> Refreshed {
        let wallet = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { wallet.refreshCredential(op, credentialID: id, error: $0) } }
        return try decode(Refreshed.self, json)
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
    /// finds the credentials that can answer it.
    public func startPresentation(request: String) async throws -> Presentation {
        let wallet = handle
        let p = try await OID4VC.cancellable { op in try OID4VC.wrap { try wallet.startPresentation(op, requestLink: request) } }
        return try Presentation(p)
    }
}

/// What a Credential Offer offers.
public struct Offer: Decodable, Sendable {
    public struct TxCode: Decodable, Sendable {
        public let inputMode: String?
        public let length: Int?
        public let description: String?
        enum CodingKeys: String, CodingKey { case inputMode = "input_mode", length, description }
    }

    public struct Credential: Decodable, Sendable {
        public let configurationID: String
        public let format: String
        public let vct: String?
        public let doctype: String?
        /// The issuer's display metadata for it, in the holder's language.
        public let name: String?
        public let description: String?
        public let logo: Logo?
        public let backgroundColor: String?
        public let textColor: String?
        enum CodingKeys: String, CodingKey {
            case configurationID = "configuration_id", format, vct, doctype, name, description, logo
            case backgroundColor = "background_color", textColor = "text_color"
        }
    }

    public enum Grant: String, Decodable, Sendable {
        case authorizationCode = "authorization_code"
        case preAuthorizedCode = "pre-authorized_code"
    }

    public let credentialIssuer: String
    public let issuerName: String?
    public let issuerLogo: Logo?
    public let grant: Grant
    /// The PIN to ask the holder for, for a pre-authorized code offer.
    public let txCode: TxCode?
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

    public func redeemPreAuthorizedCode(pin: String = "") async throws {
        let session = self.session
        try await OID4VC.cancellable { op in try OID4VC.wrap { try session.redeemPreAuthorizedCode(op, txCode: pin) } }
    }

    public struct Result: Decodable, Sendable {
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
        public let configurationID: String
        public let code: WalletError.Code
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
    public struct Verifier: Decodable, Sendable {
        public let clientID: String
        public let name: String
        public let responseURI: String
        enum CodingKeys: String, CodingKey { case clientID = "client_id", name, responseURI = "response_uri" }
    }

    /// One of the request's credential queries, with the credentials
    /// that can answer it: none when nothing held can.
    public struct Query: Decodable, Sendable {
        public let queryID: String
        /// Whether it takes more than one credential; otherwise a
        /// selection gives it exactly one.
        public let multiple: Bool
        public let credentials: [CredentialSummary]
        enum CodingKeys: String, CodingKey { case queryID = "query_id", multiple, credentials }
    }

    /// One of the request's sets of alternatives: each option is the
    /// query IDs that together answer it, most preferred first. A
    /// required set must be answered by one option.
    public struct CredentialSet: Decodable, Sendable {
        public let options: [[String]]
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

    public struct Disclosure: Decodable, Sendable {
        public let queryID: String
        public let credentialID: String
        public let claims: [[PathElement]]
        enum CodingKeys: String, CodingKey { case queryID = "query_id", credentialID = "credential_id", claims }
    }

    public struct Presented: Decodable, Sendable {
        public let queryIDs: [String]
        /// Where to send the browser, when the Verifier asks.
        public let redirectURI: URL?
        enum CodingKeys: String, CodingKey { case queryIDs = "query_ids", redirectURI = "redirect_uri" }
    }

    let handle: MobilePresentation
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
    /// of each credential set, and each query's first credential (all of
    /// them when it takes several). Throws `noMatchingCredential` when
    /// the request can't be answered.
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

/// A credential store in memory, for tests and development.
public final class InMemoryCredentialStore: CredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [(id: String, record: Data)] = []

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

    public func delete(id: String) throws {
        lock.withLock { stored.removeAll { $0.id == id } }
    }
}

// The Go objects are safe to use from any thread: gomobile's references
// are, and walletflow's sessions serialize their own steps.
extension MobileWallet: @retroactive @unchecked Sendable {}
extension MobileIssuance: @retroactive @unchecked Sendable {}
extension MobilePresentation: @retroactive @unchecked Sendable {}

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
