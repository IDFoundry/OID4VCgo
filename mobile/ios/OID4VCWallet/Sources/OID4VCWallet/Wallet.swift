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

    public init(clientID: String, redirectURI: String, issuerRoots: String = "", verifierRoots: String = "", development: Bool = false) {
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.issuerRoots = issuerRoots
        self.verifierRoots = verifierRoots
        self.development = development
    }

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id", redirectURI = "redirect_uri", issuerRoots = "issuer_roots"
        case verifierRoots = "verifier_roots", development
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(clientID: try c.decode(String.self, forKey: .clientID),
                  redirectURI: try c.decode(String.self, forKey: .redirectURI),
                  issuerRoots: try c.decodeIfPresent(String.self, forKey: .issuerRoots) ?? "",
                  verifierRoots: try c.decodeIfPresent(String.self, forKey: .verifierRoots) ?? "",
                  development: try c.decodeIfPresent(Bool.self, forKey: .development) ?? false)
    }

    /// The scheme of `redirectURI`: the callback scheme an
    /// ASWebAuthenticationSession waits for.
    public var callbackScheme: String? { URL(string: redirectURI)?.scheme }
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

    enum CodingKeys: String, CodingKey {
        case id, format, vct, doctype
        case credentialIssuer = "credential_issuer", configurationID = "configuration_id", receivedAt = "received_at"
        case holderKeyPresent = "holder_key_present"
    }
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
    /// before any issuance: an issuance in progress holds keys of its own.
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

    /// Deletes a credential and its holder key.
    public func deleteCredential(id: String) async throws {
        let wallet = handle
        try await OID4VC.offMain { try OID4VC.wrap { try wallet.deleteCredential(id) } }
    }

    /// Resolves a Credential Offer (openid-credential-offer://…) and the
    /// issuer's metadata.
    public func startIssuance(offer: String) async throws -> Issuance {
        let wallet = handle
        let s = try await OID4VC.cancellable { op in try OID4VC.wrap { try wallet.startIssuance(op, offerURI: offer) } }
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
        public let name: String?
        enum CodingKeys: String, CodingKey { case configurationID = "configuration_id", format, vct, doctype, name }
    }

    public enum Grant: String, Decodable, Sendable {
        case authorizationCode = "authorization_code"
        case preAuthorizedCode = "pre-authorized_code"
    }

    public let credentialIssuer: String
    public let issuerName: String?
    public let grant: Grant
    /// The PIN to ask the holder for, for a pre-authorized code offer.
    public let txCode: TxCode?
    public let credentials: [Credential]

    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer", issuerName = "issuer_name", grant, txCode = "tx_code", credentials
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

    public func completeAuthorization(redirect: URL) async throws {
        let session = self.session
        try await OID4VC.cancellable { op in try OID4VC.wrap { try session.completeAuthorization(op, redirect: redirect.absoluteString) } }
    }

    public func redeemPreAuthorizedCode(pin: String = "") async throws {
        let session = self.session
        try await OID4VC.cancellable { op in try OID4VC.wrap { try session.redeemPreAuthorizedCode(op, txCode: pin) } }
    }

    public struct Deferred: Decodable, Sendable {
        public let id: String
        public let configurationID: String
        public let intervalSeconds: Double
        enum CodingKeys: String, CodingKey { case id, configurationID = "configuration_id", intervalSeconds = "interval_seconds" }
    }

    public struct Result: Decodable, Sendable {
        public let credentials: [CredentialSummary]
        public let deferred: [Deferred]
    }

    /// Requests, checks and stores every offered credential.
    public func requestCredentials() async throws -> Result {
        let session = self.session
        let json = try await OID4VC.cancellable { op in try OID4VC.call { session.requestCredentials(op, error: $0) } }
        return try decode(Result.self, json)
    }

    public enum DeferredStatus: Sendable, Equatable {
        case pending(intervalSeconds: Double)
        case issued(CredentialSummary)
    }

    /// Asks the issuer once about a deferred credential. A refused one
    /// throws `.credentialDenied`.
    public func pollDeferred(id: String) async throws -> DeferredStatus {
        struct Status: Decodable {
            let status: String
            let credential: CredentialSummary?
            let intervalSeconds: Double
            enum CodingKeys: String, CodingKey { case status, credential, intervalSeconds = "interval_seconds" }
        }
        let session = self.session
        let json = try await OID4VC.cancellable { op in try OID4VC.call { session.pollDeferred(op, deferredID: id, error: $0) } }
        let s = try decode(Status.self, json)
        if s.status == MobileDeferredIssued, let c = s.credential { return .issued(c) }
        return .pending(intervalSeconds: s.intervalSeconds)
    }

    /// Ends the issuance, deleting its keys.
    public func close() async throws {
        let session = self.session
        try await OID4VC.offMain { try OID4VC.wrap { try session.close() } }
    }
}

/// Answers one OpenID4VP request: show `verifier` and `candidates`,
/// `preview(credentialIDs:)` the holder's choice, then `respond` or
/// `decline`.
public final class Presentation: @unchecked Sendable {
    public struct Verifier: Decodable, Sendable {
        public let clientID: String
        public let name: String
        public let responseURI: String
        enum CodingKeys: String, CodingKey { case clientID = "client_id", name, responseURI = "response_uri" }
    }

    public struct Candidates: Decodable, Sendable {
        public let queryID: String
        public let credentials: [CredentialSummary]
        enum CodingKeys: String, CodingKey { case queryID = "query_id", credentials }
    }

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
    public let candidates: [Candidates]

    init(_ p: MobilePresentation) throws {
        handle = p
        verifier = try decode(Verifier.self, p.verifier())
        struct All: Decodable { let queries: [Candidates] }
        candidates = try decode(All.self, p.candidates()).queries
    }

    /// What responding with `credentialIDs` (nil: the request's own
    /// choice) would disclose.
    public func preview(credentialIDs: [String]? = nil) async throws -> [Disclosure] {
        struct All: Decodable { let disclosures: [Disclosure] }
        let p = handle
        let ids = try idsJSON(credentialIDs)
        let json = try await OID4VC.offMain { try OID4VC.call { p.preview(ids, error: $0) } }
        return try decode(All.self, json).disclosures
    }

    /// Presents `credentialIDs`: holder keys sign now, so a key store
    /// requiring user presence prompts.
    public func respond(credentialIDs: [String]? = nil) async throws -> Presented {
        let p = handle
        let ids = try idsJSON(credentialIDs)
        let json = try await OID4VC.cancellable { op in try OID4VC.call { p.respond(op, credentialIDsJSON: ids, error: $0) } }
        return try decode(Presented.self, json)
    }

    /// Tells the Verifier the holder declined.
    public func decline() async throws -> Presented {
        let p = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { p.decline(op, error: $0) } }
        return try decode(Presented.self, json)
    }

    private func idsJSON(_ ids: [String]?) throws -> String {
        guard let ids else { return "" }
        return String(decoding: try JSONEncoder().encode(ids), as: UTF8.self)
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
        throw DecodingError.dataCorrupted(.init(codingPath: d.codingPath, debugDescription: "not an RFC 3339 time: \(text)"))
    }
    do {
        return try decoder.decode(type, from: Data(json.utf8))
    } catch {
        throw WalletError(code: .internalError, message: "malformed result from the Go side: \(error)")
    }
}
