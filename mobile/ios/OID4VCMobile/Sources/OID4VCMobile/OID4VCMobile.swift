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
        public static let `internal` = Code(rawValue: MobileCodeInternal)
    }

    public let code: Code
    public let message: String

    public var description: String { "[\(code.rawValue)] \(message)" }

    /// Parses an error crossing the boundary: its text is "[code] message".
    init(_ error: Error) {
        let text = (error as NSError).localizedDescription
        if text.hasPrefix("["), let close = text.firstIndex(of: "]") {
            code = Code(rawValue: String(text[text.index(after: text.startIndex)..<close]))
            message = String(text[text.index(after: close)...]).trimmingCharacters(in: .whitespaces)
        } else {
            code = .internal
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

/// A P-256 key the app holds — implemented by the app, called by Go to
/// sign. `publicKey()` returns the X9.63 point (0x04 || X || Y);
/// `sign(_:)` signs a SHA-256 digest, returning ASN.1 DER. A thrown
/// error reaches Go, and comes back as a `.platform` WalletError.
public typealias PlatformSigner = MobileSignerProtocol & Sendable

/// A P-256 key the app holds, signing SHA-256 digests. Backed by the
/// Security framework, so the same type serves a software key and a
/// Secure Enclave key.
public final class SecKeySigner: NSObject, MobileSignerProtocol, @unchecked Sendable {
    let privateKey: SecKey

    public init(privateKey: SecKey) { self.privateKey = privateKey }

    /// A new software key, for tests and development.
    public static func software() throws -> SecKeySigner {
        var error: Unmanaged<CFError>?
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return SecKeySigner(privateKey: key)
    }

    public func publicKey() throws -> Data {
        guard let pub = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(domain: "OID4VCMobile", code: 1, userInfo: [NSLocalizedDescriptionKey: "no public key"])
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(pub, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return raw as Data // X9.63: 0x04 || X || Y
    }

    public func sign(_ digest: Data?) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(privateKey, .ecdsaSignatureDigestX962SHA256, (digest ?? Data()) as CFData, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return sig as Data // ASN.1 DER
    }
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

    /// A DPoP proof for `method` `url`, signed by `signer`.
    public static func dpopProof(signer: some PlatformSigner, method: String, url: String) async throws -> String {
        try await offMain { try call { MobileDPoPProof(signer, method, url, $0) } }
    }

    /// GETs `url`. Cancelling the calling Task cancels the request.
    public static func fetch(_ url: String, timeout: Duration = .seconds(30)) async throws -> String {
        let ms = timeout.components.seconds * 1000 + timeout.components.attoseconds / 1_000_000_000_000_000
        let op = Operation(MobileNewOperation(ms)!)
        return try await withTaskCancellationHandler {
            try await offMain { try call { MobileFetch(op.op, url, $0) } }
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

    /// Calls a gomobile function taking an NSError out-parameter, turning
    /// its error into a WalletError.
    static func call<T>(_ fn: (NSErrorPointer) -> T) throws -> T {
        var error: NSError?
        let value = fn(&error)
        if let error { throw WalletError(error) }
        return value
    }
}

/// MobileOperation, which Go makes safe to cancel from any thread.
final class Operation: @unchecked Sendable {
    let op: MobileOperation
    init(_ op: MobileOperation) { self.op = op }
}
