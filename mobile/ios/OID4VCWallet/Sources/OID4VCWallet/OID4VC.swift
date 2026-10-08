import Foundation
import Mobile

/// An error from OID4VCgo: a stable `code`, the issuer's, Authorization
/// Server's or Verifier's own error code when it gave one
/// (`protocolError`), and a message for logs: it never carries personal
/// data, a remote party's own description, a URL's path or query, or
/// control characters. `localizedDescription` is
/// a sentence fit to show the holder; `isRetryable` says whether trying
/// the same step again may succeed.
public struct WalletError: Error, Equatable, CustomStringConvertible, LocalizedError {
    /// What kind of failure an error is: stable across releases, so an app can
    /// act on it.
    public struct Code: RawRepresentable, Hashable, Sendable {
        /// The code as the Go side names it, such as `network`.
        public let rawValue: String
        /// A code from its raw value.
        public init(rawValue: String) { self.rawValue = rawValue }

        /// An argument, a link or the configuration is malformed.
        public static let invalidInput = Code(rawValue: MobileCodeInvalidInput)
        /// A key store, credential store or Wallet Provider call failed; its
        /// message follows.
        public static let platform = Code(rawValue: MobileCodePlatform)
        /// A request couldn't be made, got no answer, or timed out. Retryable.
        public static let network = Code(rawValue: MobileCodeNetwork)
        /// The service answered with HTTP 5xx or 429. Retryable later.
        public static let unavailable = Code(rawValue: MobileCodeUnavailable)
        /// The calling task was cancelled.
        public static let cancelled = Code(rawValue: MobileCodeCancelled)
        /// No key, credential, deferred credential or authorization in progress
        /// with that ID.
        public static let notFound = Code(rawValue: MobileCodeNotFound)
        /// A session method was called out of turn, or after the session ended.
        public static let wrongStep = Code(rawValue: MobileCodeWrongStep)
        /// The Authorization Server refused the authorization: the holder
        /// declined, say.
        public static let authorizationDenied = Code(rawValue: MobileCodeAuthorizationDenied)
        /// The issuer refused a deferred credential.
        public static let credentialDenied = Code(rawValue: MobileCodeCredentialDenied)
        /// Nothing held answers the Verifier's request.
        public static let noMatchingCredential = Code(rawValue: MobileCodeNoMatchingCredential)
        /// A presentation's selection doesn't answer the request as it
        /// asks: an unknown query or credential, one that doesn't answer
        /// its query, more than one for a query that takes one, or a
        /// required credential set left unanswered.
        public static let invalidSelection = Code(rawValue: MobileCodeInvalidSelection)
        /// A credential can't be refreshed: no refresh token was kept, or
        /// the Authorization Server no longer accepts it. Receive it again
        /// from a new offer.
        public static let reissueRequired = Code(rawValue: MobileCodeReissueRequired)
        /// Sending a presentation failed in a way that leaves it unknown
        /// whether the Verifier received it: it's not sent again.
        public static let deliveryUnknown = Code(rawValue: MobileCodeDeliveryUnknown)
        /// The Verifier's request is signed with a certificate that
        /// doesn't chain to `verifierRoots`: it's refused unread.
        public static let untrustedVerifier = Code(rawValue: MobileCodeUntrustedVerifier)
        /// An issuer, Authorization Server or Verifier answered with an error,
        /// or with something the wallet refuses. `WalletError.protocolError`
        /// carries its OAuth error code, when it gave one.
        public static let protocolError = Code(rawValue: MobileCodeProtocol)
        /// A bug.
        public static let internalError = Code(rawValue: MobileCodeInternal)
    }

    /// What kind of failure this is.
    public let code: Code
    /// The remote party's OAuth error code, such as `invalid_grant` (a
    /// wrong PIN) or `access_denied`, when it gave one.
    public let protocolError: String?
    /// Detail for logs: at most 300 characters, with no personal data, no
    /// remote party's own description, and no URL's path or query.
    public let message: String

    /// The code, the remote party's error code if any, and the message, for
    /// logs.
    public var description: String {
        protocolError.map { "[\(code.rawValue):\($0)] \(message)" } ?? "[\(code.rawValue)] \(message)"
    }

    /// Whether the same step may succeed if tried again: the network
    /// failed or timed out, the service was unavailable, the issuer
    /// refused the PIN (`invalid_grant`, up to its limit) or a stale
    /// nonce (`invalid_nonce`: a retry fetches a fresh one), or asked to
    /// be tried later.
    public var isRetryable: Bool {
        switch code {
        case .network, .unavailable: true
        case .protocolError: ["invalid_grant", "invalid_nonce", "temporarily_unavailable", "slow_down"].contains(protocolError ?? "")
        default: false
        }
    }

    /// A sentence fit to show the holder.
    public var errorDescription: String? {
        switch code {
        case .network: "The service couldn't be reached. Check your connection and try again."
        case .unavailable: "The service is unavailable just now. Try again later."
        case .cancelled: "Cancelled."
        case .authorizationDenied: "The issuer didn't authorize the request."
        case .credentialDenied: "The issuer declined to issue the credential."
        case .noMatchingCredential: "You have no credential that answers this request."
        case .invalidSelection: "Those credentials don't answer this request."
        case .reissueRequired: "This credential can't be refreshed. Receive it again from the issuer."
        case .deliveryUnknown: "Your response may not have reached the verifier. Check with them before sharing again."
        case .untrustedVerifier: "This verifier isn't one your wallet trusts, so its request wasn't opened."
        case .protocolError where protocolError == "invalid_grant": "That code or PIN wasn't accepted."
        case .protocolError: "The service refused the request."
        case .platform: "The wallet couldn't use its keys or storage."
        case .invalidInput: "That link or code isn't valid."
        case .notFound: "That credential is no longer in the wallet."
        case .wrongStep: "That step isn't available now."
        default: "Something went wrong."
        }
    }

    init(code: Code, protocolError: String? = nil, message: String) {
        self.code = code
        self.protocolError = protocolError
        self.message = message
    }

    /// Parses an error crossing the boundary: its text is "[code] message"
    /// or "[code:detail] message".
    init(_ error: Error) {
        let text = (error as NSError).localizedDescription
        guard text.hasPrefix("["), let close = text.firstIndex(of: "]") else {
            self.init(code: .internalError, message: text)
            return
        }
        let tag = text[text.index(after: text.startIndex)..<close]
        let message = String(text[text.index(after: close)...]).trimmingCharacters(in: .whitespaces)
        if let colon = tag.firstIndex(of: ":") {
            self.init(code: Code(rawValue: String(tag[..<colon])), protocolError: String(tag[tag.index(after: colon)...]), message: message)
        } else {
            self.init(code: Code(rawValue: String(tag)), message: message)
        }
    }
}

/// An OpenID4VP request link's parts.
public struct RequestLink: Decodable, Equatable, Sendable {
    /// The Verifier's client ID.
    public let clientID: String
    /// Where the request object is fetched from.
    public let requestURI: String
    /// How to fetch it: `post` when the Verifier asks for POST; nil means GET.
    public let requestURIMethod: String?

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id", requestURI = "request_uri", requestURIMethod = "request_uri_method"
    }
}

/// OID4VCgo's mobile API. Every call runs off the caller's thread: Go
/// calls block, and must never run on the main thread.
public enum OID4VC {
    /// The ABI version of the Go side this package was built against.
    public static let abiVersion = Int(MobileABIVersion)

    /// The ABI version these Swift sources were written for. A wallet
    /// isn't made on a framework of another — a stale build, or the Go
    /// side changed without these sources — rather than misreading its
    /// JSON. The Go tests keep it equal to the mobile package's.
    public static let expectedABIVersion = 12

    /// Whether the linked framework is the test build, carrying an
    /// in-process test issuer and Verifier (`-tags mobiletest`): an app
    /// should refuse to run on it.
    public static let isTestBuild = MobileIsTestBuild()

    /// Parses an OpenID4VP request link (`openid4vp://…`) into its parts,
    /// without fetching anything. `Wallet.startPresentation(request:)` does
    /// this itself.
    public static func parseRequestLink(_ link: String) async throws -> RequestLink {
        let json = try await offMain { try call { MobileParseRequestLink(link, $0) } }
        return try decode(RequestLink.self, json)
    }

    /// Exercises `keyStore` as the wallet will — for each purpose: create
    /// a key, sign with it, look it up, delete it — and returns the
    /// purposes checked. A store asking for user presence on holder keys
    /// prompts once.
    public static func checkKeyStore(_ keyStore: some KeyStore) async throws -> [KeyPurpose] {
        let adapter = KeyStoreAdapter(keyStore)
        let json = try await offMain { try call { MobileCheckKeyStore(adapter, $0) } }
        return try decode(KeyStoreReport.self, json).checked.compactMap(KeyPurpose.init(rawValue:))
    }

    /// Runs `body` with an Operation, off the caller's thread; cancelling
    /// the calling Task cancels the Operation, and the Go call returns a
    /// `.cancelled` WalletError.
    static func cancellable<T: Sendable>(_ body: @escaping @Sendable (MobileOperation) throws -> T) async throws -> T {
        let op = Operation(MobileNewOperation(0)!)
        return try await withTaskCancellationHandler {
            try await offMain { try body(op.op) }
        } onCancel: {
            op.op.cancel()
        }
    }

    /// Runs body on a background queue.
    static func offMain<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                cont.resume(with: Result { try body() })
            }
        }
    }

    /// Runs a throwing gomobile method, turning its error into a
    /// WalletError.
    static func wrap<T>(_ fn: () throws -> T) throws -> T {
        do {
            return try fn()
        } catch let error as WalletError {
            throw error
        } catch {
            throw WalletError(error)
        }
    }

    /// Calls a gomobile function taking an NSError out-parameter, turning
    /// its error into a WalletError.
    static func call<T>(_ fn: (NSErrorPointer) -> T) throws -> T {
        var error: NSError?
        let value = fn(&error)
        if let error { throw WalletError(error) }
        return value
    }
}

/// CheckKeyStore's result.
struct KeyStoreReport: Decodable { let checked: [String] }

/// MobileOperation, which Go makes safe to cancel from any thread.
final class Operation: @unchecked Sendable {
    let op: MobileOperation
    init(_ op: MobileOperation) { self.op = op }
}
