import Foundation
import Mobile

/// An error from OID4VCgo: a stable `code` (see `WalletError.Code`) and
/// a message for logs.
public struct WalletError: Error, Equatable, CustomStringConvertible {
    public struct Code: RawRepresentable, Hashable, Sendable {
        public let rawValue: String
        public init(rawValue: String) { self.rawValue = rawValue }

        public static let invalidInput = Code(rawValue: MobileCodeInvalidInput)
        public static let platform = Code(rawValue: MobileCodePlatform)
        public static let network = Code(rawValue: MobileCodeNetwork)
        public static let cancelled = Code(rawValue: MobileCodeCancelled)
        public static let notFound = Code(rawValue: MobileCodeNotFound)
        public static let wrongStep = Code(rawValue: MobileCodeWrongStep)
        public static let authorizationDenied = Code(rawValue: MobileCodeAuthorizationDenied)
        public static let credentialDenied = Code(rawValue: MobileCodeCredentialDenied)
        public static let noMatchingCredential = Code(rawValue: MobileCodeNoMatchingCredential)
        public static let protocolError = Code(rawValue: MobileCodeProtocol)
        public static let internalError = Code(rawValue: MobileCodeInternal)
    }

    public let code: Code
    public let message: String

    public var description: String { "[\(code.rawValue)] \(message)" }

    init(code: Code, message: String) {
        self.code = code
        self.message = message
    }

    /// Parses an error crossing the boundary: its text is "[code] message".
    init(_ error: Error) {
        let text = (error as NSError).localizedDescription
        if text.hasPrefix("["), let close = text.firstIndex(of: "]") {
            code = Code(rawValue: String(text[text.index(after: text.startIndex)..<close]))
            message = String(text[text.index(after: close)...]).trimmingCharacters(in: .whitespaces)
        } else {
            code = .internalError
            message = text
        }
    }
}

/// An OpenID4VP request link's parts.
public struct RequestLink: Decodable, Equatable, Sendable {
    public let clientID: String
    public let requestURI: String
    public let requestURIMethod: String?

    enum CodingKeys: String, CodingKey {
        case clientID = "client_id", requestURI = "request_uri", requestURIMethod = "request_uri_method"
    }
}

/// The wallet's key store, implemented by the app and called by Go:
/// `createKey(_:)` makes a P-256 key for a purpose (`KeyPurpose`) and
/// returns its ID; `publicKey(_:)` returns a key's X9.63 point (0x04 ||
/// X || Y), or empty data when there's no such key; `sign(_:digest:)`
/// signs a SHA-256 digest, returning ASN.1 DER; `deleteKey(_:)` deletes
/// one. A thrown error reaches Go, and comes back as a `.platform`
/// WalletError. `KeychainKeyStore` is the standard implementation.
public typealias PlatformKeyStore = MobileKeyStoreProtocol & Sendable

/// What a key is for, as `PlatformKeyStore.createKey(_:)` receives it.
public enum KeyPurpose {
    /// The wallet instance key a Wallet Attestation binds.
    public static let instance = MobilePurposeInstance
    /// The key access tokens are bound to.
    public static let dpop = MobilePurposeDPoP
    /// The key a credential is bound to, used only when presenting it.
    public static let holder = MobilePurposeHolder
}

/// OID4VCgo's mobile API. Every call runs off the caller's thread: Go
/// calls block, and must never run on the main thread.
public enum OID4VC {
    /// The ABI version of the Go side this package was built against.
    public static let abiVersion = Int(MobileABIVersion)

    public static func parseRequestLink(_ link: String) async throws -> RequestLink {
        let json = try await offMain { try call { MobileParseRequestLink(link, $0) } }
        return try JSONDecoder().decode(RequestLink.self, from: Data(json.utf8))
    }

    /// Exercises `keyStore` as the wallet will — for each purpose: create
    /// a key, sign with it, look it up, delete it — and returns the
    /// purposes checked. A store asking for user presence on holder keys
    /// prompts once.
    public static func checkKeyStore(_ keyStore: some PlatformKeyStore) async throws -> [String] {
        let json = try await offMain { try call { MobileCheckKeyStore(keyStore, $0) } }
        return try JSONDecoder().decode(KeyStoreReport.self, from: Data(json.utf8)).checked
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
