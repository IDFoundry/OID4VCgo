import CryptoKit
import Foundation

/// A ``WalletProvider`` over the Wallet Provider HTTP protocol, version
/// 1, that OID4VCgo's `walletprovider.Provider.Handler` serves
/// ([WALLET_PROVIDER.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/WALLET_PROVIDER.md)),
/// with Apple App Attest (`apple-app-attest`) as its evidence:
///
/// - The installation registers once, at its first Wallet Attestation:
///   over a `registration` challenge, it makes a *registration key* in a
///   key store of its own (``registrationKeyStore()``) and an App Attest
///   key, has Apple attest the App Attest key over the client data
///   naming the registration key, registers both (`POST /v1/instances`),
///   and keeps the instance ID and the two keys' IDs in its
///   ``InstanceRegistry``. The registration key signs every later
///   request (`Wallet-Provider-Request`); no attestation names it. If
///   the registration, its key or the App Attest key is lost, the next
///   Wallet Attestation registers again, with new keys. An App Attest
///   key a registration made but couldn't register — App Attest's
///   server or the provider unavailable, or no connection — is kept, in
///   this process, and tried again by the next registration, as Apple
///   asks; it's dropped when the provider or App Attest refuses it.
/// - ``walletAttestation(clientID:instanceKey:)`` asks for a Wallet
///   Attestation for the instance key (`instance_key`). The first time,
///   it sends an App Attest assertion over a fresh `instance` challenge
///   and the key, which the provider records the key with; once it has,
///   the key alone — and the assertion again if the provider no longer
///   has its record (`evidence_required`).
/// - ``keyAttestation(instanceKey:keys:nonce:)`` asks for a Key
///   Attestation over the holder keys, with one assertion over a
///   `holder` challenge and all of them, for the issuance of its
///   instance key, which a Wallet Attestation recorded.
///
/// App Attest attests the app, not the wallet's keys: the provider
/// learns that a genuine copy of the app on a genuine Apple device asked
/// for them, not where they are. Make them in the Secure Enclave all the
/// same (``KeychainKeyStore``'s default). Where App Attest isn't
/// supported — the Simulator, some older devices — the wallet can't
/// register, and every attestation fails as `.platform`: there's no
/// unattested path, in development either. A development build (the
/// `com.apple.developer.devicecheck.appattest-environment` entitlement
/// set to `development`) makes development-environment keys, which only
/// a provider configured for them accepts.
///
/// Assertions are made one at a time, each sent before the next is made,
/// as the provider accepts only an assertion whose counter exceeds the
/// last it took, and the installation registers once. Every
/// `HttpWalletProvider` over the same ``FileInstanceRegistry`` file (or
/// the same ``InMemoryInstanceRegistry``) in the process shares that
/// order, so a wallet rebuilt mid-issuance with a new provider is still
/// serialised with the old one. Over a registry of its own type, a
/// provider serialises only its own calls: keep one provider for it.
///
/// It sends nothing but to its base URL, over https, following no
/// redirect, with its timeout for each request, and reads at most
/// 256 KiB of an answer. It checks a Wallet Attestation is for the
/// client and the instance key, and a Key Attestation is over the nonce
/// sent and attests only keys sent; their signatures are the issuer's to
/// verify.
///
/// Failures reach the wallet as `WalletError`s: one the network or the
/// provider's availability caused (no connection, a timeout, HTTP 5xx or
/// 429, a challenge that expired before it was used, App Attest's server
/// unavailable) as `.network`, which may be retried
/// (``WalletProviderUnavailableError``); a refusal
/// (``WalletProviderRefusedError``) as `.platform`, its message naming the
/// protocol's error code. On `instance_revoked`, it forgets the
/// registration and deletes its registration key: the next Wallet
/// Attestation registers the installation again. The revoked instance's
/// instance keys stay its own (`instance_key_registered`), so a
/// credential whose refresh needs one must be received again. On
/// `instance_not_active` (suspended) it keeps the registration: tell the
/// holder, as the provider may resume it. A signed request refused as
/// `invalid_signed_request` isn't retried: check the device's clock, and
/// that the provider still knows the instance.
public final class HttpWalletProvider: WalletProvider, @unchecked Sendable {
    /// The Keychain tag prefix of ``registrationKeyStore()``'s keys. The
    /// wallet's own ``KeychainKeyStore`` mustn't cover it, as its default
    /// prefix doesn't: ``Wallet/sweepOrphanedKeys(in:)`` would
    /// delete the registration key.
    public static let registrationKeyTagPrefix = "org.idfoundry.oid4vcgo.walletprovider."

    /// The registration key's store: Secure Enclave keys in the Keychain
    /// under ``registrationKeyTagPrefix``, apart from the wallet's keys,
    /// signing without the holder, as instance keys do, and usable only
    /// while the device is unlocked
    /// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`).
    ///
    /// The key is made in the app's default Keychain access group: the
    /// first group of its `keychain-access-groups` entitlement, or its
    /// App ID's when it has none. Every app and extension that lists
    /// that group can sign with the key, and so speak for the instance:
    /// list a group only the app has first, and one it shares with an
    /// extension (a document provider's, for holder keys:
    /// ``KeychainKeyStore/Options/holderAccessGroup``) after it. There's
    /// no option to choose another group.
    public static func registrationKeyStore() -> KeychainKeyStore {
        KeychainKeyStore(options: KeychainKeyStore.Options(tagPrefix: registrationKeyTagPrefix))
    }

    /// The default timeout of each request, as the Go client's.
    public static let defaultTimeout: TimeInterval = 30

    private let base: URL
    /// The base URL's path, percent-encoded.
    private let basePath: String
    private let instances: any InstanceRegistry
    private let registrationKeys: any KeyStore
    private let appAttest: any AppAttestService
    private let transport: any WalletProviderTransport
    private let clock: @Sendable () -> Int64

    /// The locks and memory this provider shares with every other over
    /// the same registry.
    private let state: WalletProviderState

    /// A client of the provider at `baseURL`.
    ///
    /// - Parameters:
    ///   - baseURL: Where the provider's protocol is mounted: an absolute
    ///     `https` URL without user info, query or fragment. Its path is
    ///     the prefix of every protocol path (`https://wp.example/wp`
    ///     gives `https://wp.example/wp/v1/challenge`).
    ///   - instances: Where the registration is kept:
    ///     ``FileInstanceRegistry/standard()`` in an app.
    ///   - registrationKeys: Where the registration key is made (for
    ///     ``KeyPurpose/instance``) and kept, and signs requests: a store
    ///     nothing else deletes from. By default
    ///     ``registrationKeyStore()``. Not the wallet's key store:
    ///     ``Wallet/sweepOrphanedKeys(in:)`` deletes every key there
    ///     that no credential is bound to.
    ///   - appAttest: App Attest: by default the device's.
    ///   - timeout: The timeout of each request.
    /// - Throws: `StoreError` when `baseURL` isn't an absolute https URL
    ///   without user info, query or fragment, or `timeout` isn't
    ///   positive.
    public convenience init(baseURL: URL, instances: any InstanceRegistry,
                            registrationKeys: any KeyStore = HttpWalletProvider.registrationKeyStore(),
                            appAttest: any AppAttestService = DeviceAppAttestService(),
                            timeout: TimeInterval = HttpWalletProvider.defaultTimeout) throws {
        guard timeout > 0 else { throw StoreError("the timeout must be positive") }
        try self.init(baseURL: baseURL, instances: instances, registrationKeys: registrationKeys, appAttest: appAttest,
                      transport: URLSessionTransport(timeout: timeout), clock: { Int64(Date().timeIntervalSince1970) },
                      allowHTTP: false)
    }

    init(baseURL: URL, instances: any InstanceRegistry, registrationKeys: any KeyStore, appAttest: any AppAttestService,
         transport: any WalletProviderTransport, clock: @escaping @Sendable () -> Int64, allowHTTP: Bool) throws {
        self.base = try Self.parseBaseURL(baseURL, allowHTTP: allowHTTP)
        self.basePath = URLComponents(url: base, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? ""
        self.instances = instances
        self.state = (instances as? SharesWalletProviderState)?.walletProviderState ?? WalletProviderState()
        self.registrationKeys = registrationKeys
        self.appAttest = appAttest
        self.transport = transport
        self.clock = clock
    }

    /// A Wallet Attestation for `clientID` and `instanceKey`, registering
    /// the installation first if it isn't yet, with an assertion for the
    /// key unless the provider recorded it already.
    public func walletAttestation(clientID: String, instanceKey: Data) async throws -> String {
        let point = try jwkPoint(instanceKey, what: "the instance key")
        let instance = try await registered()
        do {
            return try await walletAttestation(clientID: clientID, point: point, instance: instance)
        } catch is AppAttestKeyLostError {
            // Restored or reinstalled: forget the registration whose App
            // Attest key is gone — not one another call has made since —
            // register again, with a new App Attest key, and attest the
            // (new) instance key under it.
            try await forget(instance)
            return try await walletAttestation(clientID: clientID, point: point, instance: try await registered())
        }
    }

    private func walletAttestation(clientID: String, point: Data, instance: RegisteredInstance) async throws -> String {
        let thumbprint = jwkThumbprint(point: point)
        var body: [String: Any] = ["client_id": clientID, "instance_key": jwk(point: point)]
        var jwt: String?
        if state.recorded.withLock({ $0.contains(thumbprint) }) {
            do {
                jwt = try await signed(instance, Self.walletAttestationPath, body).string("wallet_attestation")
            } catch let e as WalletProviderRefusedError where e.error == "evidence_required" {
                // The provider deleted its record (retention): assert again.
            }
        }
        if jwt == nil {
            jwt = try await state.asserting.locked {
                let challenge = try await self.challenge(Self.purposeInstance)
                let hash = AppAttestClientData.hash(purpose: Self.purposeInstance, challenge: challenge.value, keys: [point])
                let assertion = try await self.appAttest.generateAssertion(instance.appAttestKeyID, clientDataHash: hash)
                body["challenge"] = challenge.value
                body["evidence"] = appAttestEvidence(assertion)
                return try await self.signed(instance, Self.walletAttestationPath, body).string("wallet_attestation")
            }
            state.recorded.withLock { _ = $0.insert(thumbprint) }
        }
        guard let jwt, let claims = unverifiedClaims(jwt) else { throw StoreError("the Wallet Attestation isn't a JWT") }
        let cnf = ((claims["cnf"] as? [String: Any])?["jwk"] as? [String: Any]).flatMap { try? jwkPoint($0) }
        guard claims["sub"] as? String == clientID, cnf == point else {
            throw StoreError("the Wallet Attestation isn't for client \(clientID) and the instance key")
        }
        return jwt
    }

    /// A Key Attestation over `keys`, for the issuance of `instanceKey`,
    /// with one assertion over a `holder` challenge and every key, signed
    /// with the registration key.
    public func keyAttestation(instanceKey: Data, keys: [Data], nonce: String) async throws -> String {
        guard !keys.isEmpty else { throw StoreError("no holder keys to attest") }
        let instancePoint = try jwkPoint(instanceKey, what: "the instance key")
        let points = try keys.map { try jwkPoint($0, what: "a holder key") }
        guard let instance = try kept() else {
            throw StoreError("the wallet isn't registered with the Wallet Provider: a Key Attestation follows a Wallet Attestation")
        }
        let jwt: String
        do {
            jwt = try await state.asserting.locked {
                let challenge = try await self.challenge(Self.purposeHolder)
                let hash = AppAttestClientData.hash(purpose: Self.purposeHolder, challenge: challenge.value, keys: points)
                let assertion = try await self.appAttest.generateAssertion(instance.appAttestKeyID, clientDataHash: hash)
                let body: [String: Any] = [
                    "instance_key": jwk(point: instancePoint),
                    "challenge": challenge.value,
                    "keys": points.map { jwk(point: $0) },
                    "evidence": [appAttestEvidence(assertion)],
                    "nonce": nonce,
                ]
                return try await self.signed(instance, Self.keyAttestationPath, body).string("key_attestation")
            }
        } catch let e as AppAttestKeyLostError {
            // The instance key is the lost instance's: the next Wallet
            // Attestation registers again, and its issuance asks anew.
            try await forget(instance)
            throw e
        }
        try checkKeyAttestation(jwt, points: points, nonce: nonce)
        return jwt
    }

    /// The registration kept, after registering the installation if it
    /// has none.
    private func registered() async throws -> RegisteredInstance {
        try await state.registering.locked {
            if let kept = try self.kept() { return kept }
            return try await self.register()
        }
    }

    /// The registration kept, if the registration key store still holds
    /// its key; one whose key is gone, or another, is forgotten, and that
    /// other key deleted.
    private func kept() throws -> RegisteredInstance? {
        guard let kept = try instances.instance() else { return nil }
        let point = try registrationKeys.publicKey(id: kept.keyID)
        if let point, jwkThumbprint(point: point) == kept.keyThumbprint {
            return kept
        }
        if point != nil { try registrationKeys.deleteKey(id: kept.keyID) }
        try instances.remove(kept)
        return nil
    }

    /// Deletes every key in the registration key store but the kept
    /// registration's, and returns how many it deleted: the keys of
    /// registrations that never finished — the app ended in the middle
    /// of one, or was deleted and installed again, which keeps its
    /// Keychain items but not its registry — which nothing else
    /// deletes. Call it at launch. It takes its turn with registrations
    /// over the same registry, so it never deletes the key of one in
    /// progress.
    ///
    /// Only a ``KeychainKeyStore`` lists its keys: over another store it
    /// deletes nothing, and returns 0. Call it only where this provider's
    /// registration keys are the only ones in that store: every
    /// provider made with the default ``registrationKeyStore()`` shares
    /// it, so an app with more than one Wallet Provider gives each a
    /// ``KeychainKeyStore`` of its own tag prefix (under
    /// ``registrationKeyTagPrefix``, which the wallet's mustn't cover)
    /// before sweeping either.
    @discardableResult
    public func sweepOrphanedRegistrationKeys() async throws -> Int {
        guard let store = registrationKeys as? KeychainKeyStore else { return 0 }
        return try await state.registering.locked {
            let keep = try self.kept().map { Set([$0.keyID]) } ?? []
            return try store.deleteKeys(except: keep)
        }
    }

    /// Registers the installation with a new registration key — and with
    /// another if the provider has seen that one (`instance_key_registered`).
    private func register() async throws -> RegisteredInstance {
        guard appAttest.isSupported else { throw StoreError(appAttestUnsupported) }
        do {
            return try await registerKey()
        } catch let e as WalletProviderRefusedError where e.error == Self.instanceKeyRegistered {
            return try await registerKey()
        }
    }

    /// Makes a registration key and an App Attest key over a fresh
    /// `registration` challenge, registers them and keeps the
    /// registration; the registration key is deleted if it isn't
    /// registered. The App Attest key is the one a transient failure
    /// left unregistered, if there is one (WALLET_PROVIDER.md, The App
    /// Attest key), and is kept for the next registration after another.
    private func registerKey() async throws -> RegisteredInstance {
        let challenge = try await challenge(Self.purposeRegistration)
        let id = try registrationKeys.createKey(purpose: .instance)
        var registered = false
        defer { if !registered { try? registrationKeys.deleteKey(id: id) } }
        guard let point = try registrationKeys.publicKey(id: id) else {
            throw StoreError("the registration key store lost the key it made")
        }
        let hash = AppAttestClientData.hash(purpose: Self.purposeRegistration, challenge: challenge.value, keys: [point])
        do {
            let (appAttestKeyID, attestation) = try await attestedAppAttestKey(hash)
            let body: [String: Any] = [
                "challenge": challenge.value,
                "registration_key": jwk(point: point),
                "evidence": appAttestEvidence(attestation),
            ]
            let instanceID = try await post(Self.instancesPath, body, sign: nil, want: 201).string("instance_id")
            let instance = RegisteredInstance(keyThumbprint: jwkThumbprint(point: point), keyID: id,
                                              instanceID: instanceID, appAttestKeyID: appAttestKeyID)
            try instances.put(instance)
            state.unregisteredAppAttestKeyID.withLock { $0 = nil }
            state.recorded.withLock { $0.removeAll() }
            registered = true
            return instance
        } catch {
            // The App Attest key is kept for the next registration after
            // a failure that may pass; any other needs a new key.
            if !isTransient(error) { state.unregisteredAppAttestKeyID.withLock { $0 = nil } }
            throw error
        }
    }

    /// An App Attest key and Apple's attestation of it over
    /// `clientDataHash`: the key a registration left unregistered, if
    /// App Attest attests it again, or a new one, kept as unregistered
    /// until ``registerKey()`` registers it.
    private func attestedAppAttestKey(_ clientDataHash: Data) async throws -> (String, Data) {
        if let kept = state.unregisteredAppAttestKeyID.withLock({ $0 }) {
            do {
                return (kept, try await appAttest.attestKey(kept, clientDataHash: clientDataHash))
            } catch is AppAttestKeyLostError {
                // App Attest won't attest it again: a new one.
            }
        }
        let key = try await appAttest.generateKey()
        state.unregisteredAppAttestKeyID.withLock { $0 = key }
        return (key, try await appAttest.attestKey(key, clientDataHash: clientDataHash))
    }

    /// Deletes `instance`'s registration key and forgets it — in that
    /// order, so a failure leaves no key behind: a registration whose
    /// key is gone is forgotten when next read (``kept()``). (An App
    /// Attest key can't be deleted; it's simply never used again.)
    private func forget(_ instance: RegisteredInstance) async throws {
        try await state.registering.locked {
            try self.registrationKeys.deleteKey(id: instance.keyID)
            try self.instances.remove(instance)
            self.state.recorded.withLock { $0.removeAll() }
        }
    }

    /// Posts `body` to `path`, signed with `instance`'s registration key
    /// over a fresh `request` challenge. On `instance_revoked`, forgets
    /// the instance.
    private func signed(_ instance: RegisteredInstance, _ path: String, _ body: [String: Any]) async throws -> [String: Any] {
        let challenge = try await challenge(Self.purposeRequest)
        do {
            return try await post(path, body, sign: { target, bytes in
                try self.signRequest(instance, challenge: challenge.value, path: target, body: bytes)
            }, want: 200)
        } catch let e as WalletProviderRefusedError where e.error == Self.instanceRevoked {
            try await forget(instance)
            throw e
        }
    }

    /// The `Wallet-Provider-Request` JWT for a POST of `body` to `path`.
    private func signRequest(_ instance: RegisteredInstance, challenge: String, path: String, body: Data) throws -> String {
        let claims = requestClaims(instanceID: instance.instanceID, method: "POST", path: path, body: body,
                                   challenge: challenge, iat: clock())
        return try signES256(header: Self.requestJWTHeader, claims: claims) { digest in
            try self.registrationKeys.sign(id: instance.keyID, digest: digest)
        }
    }

    /// A fresh challenge for `purpose`.
    private func challenge(_ purpose: String) async throws -> IssuedChallenge {
        let answer = try await post(Self.challengePath, ["purpose": purpose], sign: nil, want: 200)
        let value = try answer.string("challenge")
        guard answer["purpose"] as? String == purpose else {
            throw StoreError("the Wallet Provider answered with a challenge for another purpose")
        }
        guard let bytes = decodeBase64URL(value), bytes.count >= Self.minChallengeBytes else {
            throw StoreError("the Wallet Provider's challenge isn't at least \(Self.minChallengeBytes) bytes of base64url")
        }
        guard let expiresAt = answer["expires_at"] as? NSNumber, CFGetTypeID(expiresAt) != CFBooleanGetTypeID() else {
            throw StoreError("the Wallet Provider's challenge has no expires_at")
        }
        return IssuedChallenge(value: value, expiresAt: expiresAt.int64Value)
    }

    /// Posts `body` to `path` — signed with `sign`, given the escaped
    /// path and the body bytes, if set — and returns the answer, which
    /// must have status `want`.
    private func post(_ path: String, _ body: [String: Any], sign: ((String, Data) throws -> String)?,
                      want: Int) async throws -> [String: Any] {
        // The path as sent, percent-encoded, as the provider checks it.
        let targetPath = basePath + path
        let bytes = try JSONSerialization.data(withJSONObject: body, options: [.withoutEscapingSlashes])
        var headers = ["Content-Type": Self.jsonType, "Accept": Self.jsonType]
        if let sign { headers[Self.requestHeader] = try sign(targetPath, bytes) }
        guard let url = URL(string: base.absoluteString + path) else { throw StoreError("the Wallet Provider URL is malformed") }
        let answer = try await transport.post(url: url, headers: headers, body: bytes)
        let isJSON = answer.contentType?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == Self.jsonType
        guard answer.status == want else { throw failure(path, answer, isJSON: isJSON) }
        guard isJSON else {
            throw StoreError("the Wallet Provider answered \(path) with content type \(answer.contentType ?? "none")")
        }
        guard let object = parseObject(answer.body) else { throw StoreError("the Wallet Provider's answer to \(path) is malformed") }
        return object
    }

    /// The error for an answer other than the one documented.
    private func failure(_ path: String, _ answer: WalletProviderAnswer, isJSON: Bool) -> Error {
        let object = isJSON ? parseObject(answer.body) : nil
        let code = (object?["error"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        if answer.status >= 500 || answer.status == 429 || code == "invalid_challenge" {
            return WalletProviderUnavailableError(status: answer.status, error: code,
                                                  message: "the Wallet Provider couldn't answer \(path): HTTP \(answer.status)" + (code.map { " " + $0 } ?? ""))
        }
        return WalletProviderRefusedError(status: answer.status, error: code,
                                          description: object?["error_description"] as? String, path: path)
    }

    static func parseBaseURL(_ url: URL, allowHTTP: Bool) throws -> URL {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              c.scheme == "https" || (allowHTTP && c.scheme == "http"),
              let host = c.host, !host.isEmpty, c.user == nil, c.password == nil, c.query == nil, c.fragment == nil else {
            throw StoreError("the Wallet Provider URL must be an absolute https URL without user info, query or fragment")
        }
        var out = c
        while out.percentEncodedPath.hasSuffix("/") { out.percentEncodedPath.removeLast() }
        guard let u = out.url else { throw StoreError("the Wallet Provider URL is malformed") }
        return u
    }

    static let challengePath = "/v1/challenge"
    static let instancesPath = "/v1/instances"
    static let walletAttestationPath = "/v1/wallet-attestation"
    static let keyAttestationPath = "/v1/key-attestation"
    static let requestHeader = "Wallet-Provider-Request"
    static let requestJWTHeader = #"{"alg":"ES256","typ":"wallet-provider-request+jwt"}"#
    static let jsonType = "application/json"

    static let purposeRegistration = "registration"
    static let purposeInstance = "instance"
    static let purposeHolder = "holder"
    static let purposeRequest = "request"

    static let instanceRevoked = "instance_revoked"
    static let instanceKeyRegistered = "instance_key_registered"

    /// The largest answer read, as the protocol's request limit.
    static let maxResponseBytes = 256 * 1024
    static let minChallengeBytes = 16
}

/// The Wallet Provider refused a request with one of the protocol's
/// errors, or answered other than the protocol documents (a redirect, a
/// path it doesn't serve). It reaches the wallet as `.platform`, its
/// message naming ``error``.
public struct WalletProviderRefusedError: LocalizedError, Sendable {
    /// The HTTP status code.
    public let status: Int
    /// The protocol's error code (`evidence_rejected`, `instance_revoked`,
    /// `unknown_instance_key`, …), or nil when the answer had none.
    public let error: String?
    /// The provider's fixed text for ``error``, for logs; never decide on
    /// it.
    public let description: String?
    /// The protocol path refused.
    public let path: String

    /// The message.
    public var errorDescription: String? {
        "the Wallet Provider refused \(path): HTTP \(status)" + (error.map { " " + $0 } ?? "")
    }
}

/// The Wallet Provider couldn't answer — HTTP 5xx or 429 — or the
/// challenge a request named expired or was used before it arrived
/// (`invalid_challenge`), or App Attest's server is unavailable. It
/// reaches the wallet as `.network`: try again, which gets new
/// challenges.
public struct WalletProviderUnavailableError: LocalizedError, Sendable {
    /// The HTTP status code; nil when App Attest, not the provider,
    /// failed.
    public let status: Int?
    /// The protocol's error code, or nil when the answer had none.
    public let error: String?
    /// What failed.
    public let message: String

    /// The message, marked for Go as a network failure.
    public var errorDescription: String? { "[network] " + message }
}

/// A challenge the provider issued.
struct IssuedChallenge: Sendable {
    let value: String
    let expiresAt: Int64
}

/// An HTTP answer: status, content type and body, read to at most
/// ``HttpWalletProvider/maxResponseBytes``.
struct WalletProviderAnswer: Sendable {
    let status: Int
    let contentType: String?
    let body: Data
}

/// Posts a request to the Wallet Provider; throws for no answer.
protocol WalletProviderTransport: Sendable {
    func post(url: URL, headers: [String: String], body: Data) async throws -> WalletProviderAnswer
}

/// The transport over an ephemeral URLSession: no redirects, no caching,
/// no cookies, bounded answers.
final class URLSessionTransport: NSObject, WalletProviderTransport, URLSessionTaskDelegate, @unchecked Sendable {
    private let session: URLSession

    init(timeout: TimeInterval, protocolClasses: [AnyClass]? = nil) {
        let config = URLSessionConfiguration.ephemeral
        if let protocolClasses { config.protocolClasses = protocolClasses }
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout
        session = URLSession(configuration: config)
    }

    func post(url: URL, headers: [String: String], body: Data) async throws -> WalletProviderAnswer {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        let (bytes, response) = try await session.bytes(for: request, delegate: self)
        guard let http = response as? HTTPURLResponse else { throw StoreError("the Wallet Provider's answer isn't HTTP") }
        var data = Data()
        for try await b in bytes {
            data.append(b)
            if data.count > HttpWalletProvider.maxResponseBytes {
                throw StoreError("the Wallet Provider's answer is larger than \(HttpWalletProvider.maxResponseBytes) bytes")
            }
        }
        return WalletProviderAnswer(status: http.statusCode, contentType: http.value(forHTTPHeaderField: "Content-Type"), body: data)
    }

    // A redirect is answered as the 3xx it is, which the client refuses.
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}

/// Fails unless `jwt` is a Key Attestation over `nonce` attesting at
/// least one of `points`, and nothing else. An empty `nonce` (an issuer
/// without a Nonce Endpoint) is one the provider omits.
private func checkKeyAttestation(_ jwt: String, points: [Data], nonce: String) throws {
    guard let claims = unverifiedClaims(jwt) else { throw StoreError("the Key Attestation isn't a JWT") }
    let overNonce = claims["nonce"] == nil ? nonce.isEmpty : claims["nonce"] as? String == nonce
    guard overNonce, let attested = claims["attested_keys"] as? [Any], !attested.isEmpty else {
        throw StoreError("the Key Attestation isn't over the nonce sent, or attests no key")
    }
    for k in attested {
        guard let o = k as? [String: Any], let p = try? jwkPoint(o), points.contains(p) else {
            throw StoreError("the Key Attestation attests a key that wasn't sent")
        }
    }
}

/// Whether `error` may pass: the network, the provider's availability
/// or App Attest's server.
private func isTransient(_ error: Error) -> Bool {
    error is WalletProviderUnavailableError || error is URLError
}

/// What every ``HttpWalletProvider`` over one registry shares in the
/// process: its locks, and what it remembers of the registration.
final class WalletProviderState: @unchecked Sendable {
    /// Held while the installation registers or forgets its
    /// registration, so it registers once.
    let registering = AsyncMutex()
    /// Held from making an assertion until the request carrying it is
    /// answered, so assertions reach the provider in the order made.
    let asserting = AsyncMutex()
    /// Thumbprints of the instance keys the provider recorded for the
    /// registration, in this process.
    let recorded = Locked<Set<String>>(initialState: [])
    /// The App Attest key a registration made but a transient failure
    /// left unregistered: the next registration tries it again.
    let unregisteredAppAttestKeyID = Locked<String?>(initialState: nil)
}

/// A registry whose providers share a ``WalletProviderState``.
protocol SharesWalletProviderState {
    var walletProviderState: WalletProviderState { get }
}

/// An `apple-app-attest` evidence object for `data`, an attestation
/// object or an assertion.
func appAttestEvidence(_ data: Data) -> [String: Any] {
    ["kind": "apple-app-attest", "data": encodeBase64URL(data)]
}

func encodeBase64URL(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

/// Unpadded base64url, as the protocol writes binary values; nil for
/// anything else.
func decodeBase64URL(_ s: String) -> Data? {
    guard !s.isEmpty, s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else { return nil }
    var b = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while b.count % 4 != 0 { b += "=" }
    return Data(base64Encoded: b)
}

/// An uncompressed P-256 point as a public JWK, with only its required
/// members.
func jwk(point: Data) -> [String: Any] {
    let p = [UInt8](point)
    return ["kty": "EC", "crv": "P-256", "x": encodeBase64URL(Data(p[1..<33])), "y": encodeBase64URL(Data(p[33..<65]))]
}

/// An uncompressed P-256 point's JWK SHA-256 thumbprint (RFC 7638),
/// base64url.
func jwkThumbprint(point: Data) -> String {
    let p = [UInt8](point)
    let x = encodeBase64URL(Data(p[1..<33]))
    let y = encodeBase64URL(Data(p[33..<65]))
    return encodeBase64URL(Data(SHA256.hash(data: Data(#"{"crv":"P-256","kty":"EC","x":"\#(x)","y":"\#(y)"}"#.utf8))))
}

/// A P-256 public JWK's uncompressed point.
func jwkPoint(_ object: [String: Any]) throws -> Data {
    guard object["kty"] as? String == "EC", object["crv"] as? String == "P-256",
          let x = (object["x"] as? String).flatMap(decodeBase64URL), x.count == 32,
          let y = (object["y"] as? String).flatMap(decodeBase64URL), y.count == 32 else {
        throw StoreError("not a P-256 JWK")
    }
    return Data([0x04]) + x + y
}

/// The uncompressed point of a P-256 public JWK given as JSON.
func jwkPoint(_ json: Data, what: String) throws -> Data {
    guard let object = parseObject(json), let point = try? jwkPoint(object) else { throw StoreError("\(what) isn't a P-256 JWK") }
    return point
}

/// A signed request's claims (WALLET_PROVIDER.md, Signed requests).
func requestClaims(instanceID: String, method: String, path: String, body: Data, challenge: String, iat: Int64) -> [String: Any] {
    [
        "sub": instanceID,
        "method": method,
        "path": path,
        "body_sha256": encodeBase64URL(Data(SHA256.hash(data: body))),
        "challenge": challenge,
        "iat": iat,
    ]
}

/// A compact JWS of `claims` under `header`, ES256: `sign` signs the
/// signing input's SHA-256 digest, answering a DER ECDSA signature,
/// which becomes JWS's r || s.
func signES256(header: String, claims: [String: Any], sign: (Data) throws -> Data) throws -> String {
    let payload = try JSONSerialization.data(withJSONObject: claims, options: [.withoutEscapingSlashes])
    let input = encodeBase64URL(Data(header.utf8)) + "." + encodeBase64URL(payload)
    let der = try sign(Data(SHA256.hash(data: Data(input.utf8))))
    guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: der) else {
        throw StoreError("the key store's signature isn't DER ECDSA")
    }
    return input + "." + encodeBase64URL(signature.rawRepresentation)
}

/// A compact JWS's payload, decoded but not verified: a check the
/// provider answered what was asked.
func unverifiedClaims(_ jwt: String) -> [String: Any]? {
    let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 3 else { return nil }
    return decodeBase64URL(String(parts[1])).flatMap(parseObject)
}

private func parseObject(_ data: Data) -> [String: Any]? {
    (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
}

private extension Dictionary where Key == String, Value == Any {
    func string(_ name: String) throws -> String {
        guard let s = self[name] as? String, !s.isEmpty else { throw StoreError("the Wallet Provider's answer has no \(name)") }
        return s
    }
}
