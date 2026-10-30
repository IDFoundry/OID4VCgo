import Foundation
import Mobile

/// What a key is for.
public enum KeyPurpose: String, Sendable, CaseIterable {
    /// The wallet instance key a Wallet Attestation binds; it signs
    /// silently, at each issuance's authorization.
    case instance
    /// The key access tokens are bound to; it signs silently, on every
    /// request to the issuer.
    case dpop
    /// The key a credential is bound to; it signs only when presenting,
    /// and may require user presence.
    case holder
}

/// The wallet's keys: P-256 keys whose private halves never leave the
/// store (the Secure Enclave). `KeychainKeyStore` is the standard one.
/// A thrown error reaches Go and comes back as a `.platform` WalletError.
public protocol KeyStore: Sendable {
    /// Creates a P-256 key for `purpose` and returns its ID.
    func createKey(purpose: KeyPurpose) throws -> String
    /// The key's public key as an uncompressed X9.63 point
    /// (0x04 || X || Y), or nil when there's no such key.
    func publicKey(id: String) throws -> Data?
    /// Signs a SHA-256 digest with the key, returning an ASN.1 DER ECDSA
    /// signature. A holder key may ask for Face ID here.
    func sign(id: String, digest: Data) throws -> Data
    /// Deletes the key; deleting one that doesn't exist isn't an error.
    func deleteKey(id: String) throws
    /// Whether keys survive the app quitting. Receiving credentials needs
    /// a durable store unless the configuration is for development; the
    /// default is false.
    var isDurable: Bool { get }
}

public extension KeyStore {
    var isDurable: Bool { false }
}

/// ECDH with the wallet's holder keys inside the key store, for deviceMac
/// in person (ISO/IEC 18013-5 §9.1.3.5). A `KeyStore` that is also one is
/// used for it when `WalletConfiguration.proximityDeviceAuth` is
/// `.macPreferred`. `KeychainKeyStore` is one.
public protocol KeyAgreement: Sendable {
    /// Runs ECDH between key `id` and `peerPublicKey`, an uncompressed
    /// X9.63 P-256 point, and returns the 32-byte shared secret. Throws
    /// `KeyAgreementUnsupported` for a key that can't agree keys: the
    /// wallet then signs instead. A holder key may ask for Face ID here.
    func agree(id: String, peerPublicKey: Data) throws -> Data
}

/// A key that can't agree keys: the wallet signs instead of using a MAC.
public struct KeyAgreementUnsupported: LocalizedError, Sendable {
    /// Why.
    public let message: String
    /// An error carrying `message`.
    public init(_ message: String) { self.message = message }
    /// The message.
    public var errorDescription: String? { message }
}

/// The wallet's credentials, as opaque records kept by ID under the
/// platform's data protection. `FileCredentialStore` is the standard one.
public protocol CredentialStore: Sendable {
    /// Stores `record` under `id`, replacing any record with that ID.
    func put(id: String, record: Data) throws
    /// The record stored under `id`, or nil.
    func record(id: String) throws -> Data?
    /// Every record.
    func records() throws -> [Data]
    /// Deletes the record; deleting one that doesn't exist isn't an
    /// error.
    func delete(id: String) throws
    /// Replaces the record under `id` with `record` — or deletes it, when
    /// `record` is nil — only if what's stored there is, byte for byte,
    /// `expected` (nil: no record), and returns what was stored before,
    /// whether or not it replaced it.
    ///
    /// It must be atomic across every process sharing the store — an
    /// app and its document provider extension: nothing may write the
    /// record between its read and its write, so ``put(id:record:)`` and
    /// ``delete(id:)`` take the same lock, one both processes see (a file
    /// lock, not an `NSLock`). The wallet changes records only this way,
    /// so two processes never both present one copy as unused, complete
    /// one authorization, or redeem one refresh token.
    /// ``FileCredentialStore`` locks a file in its directory.
    func compareAndSwap(id: String, expected: Data?, record: Data?) throws -> Data?
    /// Whether records survive the app quitting. Receiving credentials
    /// needs a durable store unless the configuration is for development:
    /// it also keeps an authorization in progress while the holder is at
    /// the issuer's pages. The default is false.
    var isDurable: Bool { get }
}

public extension CredentialStore {
    var isDurable: Bool { false }
}

/// The Wallet Provider's backend, which attests the wallet and its keys
/// (HAIP 1.0 §4.4.1, §4.5.1). Keys are public JWKs, as JSON; the results
/// are compact JWTs. A real one attests only after checking platform
/// evidence (App Attest) that it's talking to the genuine app.
public protocol WalletProvider: Sendable {
    /// A Wallet Attestation binding `instanceKey` to `clientID`.
    func walletAttestation(clientID: String, instanceKey: Data) async throws -> String
    /// A Key Attestation over `keys`, carrying the issuer's `nonce`.
    func keyAttestation(keys: [Data], nonce: String) async throws -> String
}

// MARK: Adapters to gomobile's protocols

/// A KeyStore as gomobile's MobileKeyStore.
final class KeyStoreAdapter: NSObject, MobileKeyStoreProtocol, @unchecked Sendable {
    let store: any KeyStore
    init(_ store: any KeyStore) { self.store = store }

    // gomobile returns a Go string as a non-optional NSString, so this
    // callback reports failure through `error` rather than by throwing.
    func createKey(_ purpose: String?, error: NSErrorPointer) -> String {
        do {
            guard let p = KeyPurpose(rawValue: purpose ?? "") else {
                throw StoreError("unknown key purpose \(purpose ?? "")")
            }
            return try store.createKey(purpose: p)
        } catch let failure {
            error?.pointee = failure as NSError
            return ""
        }
    }

    func publicKey(_ id: String?) throws -> Data { try store.publicKey(id: id ?? "") ?? Data() }

    func sign(_ id: String?, digest: Data?) throws -> Data { try store.sign(id: id ?? "", digest: digest ?? Data()) }

    func deleteKey(_ id: String?) throws { try store.deleteKey(id: id ?? "") }

    func durable() -> Bool { store.isDurable }
}

/// A KeyAgreement as gomobile's MobileKeyAgreement: a key that can't
/// agree keys is marked so Go signs instead.
final class KeyAgreementAdapter: NSObject, MobileKeyAgreementProtocol, @unchecked Sendable {
    let agreement: any KeyAgreement
    init(_ agreement: any KeyAgreement) { self.agreement = agreement }

    func agree(_ id: String?, peerPublicKey: Data?) throws -> Data {
        do {
            return try agreement.agree(id: id ?? "", peerPublicKey: peerPublicKey ?? Data())
        } catch let e as KeyAgreementUnsupported {
            throw StoreError("[no_key_agreement] " + e.message)
        }
    }
}

/// A CredentialStore as gomobile's MobileCredentialStore.
final class CredentialStoreAdapter: NSObject, MobileCredentialStoreProtocol, @unchecked Sendable {
    let store: any CredentialStore
    init(_ store: any CredentialStore) { self.store = store }

    func put(_ id: String?, record: Data?) throws { try store.put(id: id ?? "", record: record ?? Data()) }

    func get(_ id: String?) throws -> Data { try store.record(id: id ?? "") ?? Data() }

    func list() throws -> Data {
        let records = try store.records()
        var out = Data("[".utf8)
        for (i, r) in records.enumerated() {
            if i > 0 { out.append(contentsOf: Data(",".utf8)) }
            out.append(r)
        }
        out.append(contentsOf: Data("]".utf8))
        return out
    }

    func delete(_ id: String?) throws { try store.delete(id: id ?? "") }

    // Go's empty record is no record, either way.
    func compareAndSwap(_ id: String?, expected: Data?, record: Data?) throws -> Data {
        let nonEmpty = { (d: Data?) -> Data? in d?.isEmpty == false ? d : nil }
        return try store.compareAndSwap(id: id ?? "", expected: nonEmpty(expected), record: nonEmpty(record)) ?? Data()
    }

    func durable() -> Bool { store.isDurable }
}

/// A WalletProvider as gomobile's MobileWalletProvider. Go calls it on
/// its own thread — never the main thread, since every Go call is made
/// off it — and waits; this bridges that wait to the async provider.
final class WalletProviderAdapter: NSObject, MobileWalletProviderProtocol, @unchecked Sendable {
    let provider: any WalletProvider
    init(_ provider: any WalletProvider) { self.provider = provider }

    func walletAttestation(_ clientID: String?, instanceKeyJWK: Data?) throws -> Data {
        let provider = self.provider
        let id = clientID ?? ""
        let key = instanceKeyJWK ?? Data()
        return Data(try Self.wait { try await provider.walletAttestation(clientID: id, instanceKey: key) }.utf8)
    }

    func keyAttestation(_ keysJWK: Data?, nonce: String?) throws -> Data {
        guard let array = try JSONSerialization.jsonObject(with: keysJWK ?? Data()) as? [Any] else {
            throw StoreError("the keys to attest aren't a JSON array")
        }
        let keys = try array.map { try JSONSerialization.data(withJSONObject: $0) }
        let provider = self.provider
        let n = nonce ?? ""
        return Data(try Self.wait { try await provider.keyAttestation(keys: keys, nonce: n) }.utf8)
    }

    /// Runs `body` and blocks this (Go's) thread until it finishes. A
    /// URLError is marked as a network failure, which Go reports as
    /// `.network` (retryable) rather than `.platform`.
    static func wait<T: Sendable>(_ body: @escaping @Sendable () async throws -> T) throws -> T {
        let done = DispatchSemaphore(value: 0)
        let box = ResultBox<T>()
        Task.detached {
            do {
                box.set(.success(try await body()))
            } catch let e as URLError {
                box.set(.failure(StoreError("[network] " + e.localizedDescription)))
            } catch {
                box.set(.failure(error))
            }
            done.signal()
        }
        done.wait()
        return try box.get()
    }
}

/// A result handed from a Task to the thread waiting for it.
final class ResultBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<T, Error>?
    func set(_ r: Result<T, Error>) { lock.withLock { result = r } }
    func get() throws -> T {
        guard let r = lock.withLock({ result }) else { throw StoreError("no result") }
        return try r.get()
    }
}

/// A store's or provider's own failure.
public struct StoreError: LocalizedError, Sendable {
    /// What went wrong.
    public let message: String
    /// An error carrying `message`.
    public init(_ message: String) { self.message = message }
    /// The message.
    public var errorDescription: String? { message }
}
