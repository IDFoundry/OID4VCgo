import Foundation
import Mobile
import os
import Security

extension MobileProximityPresentation: @retroactive @unchecked Sendable {}
extension MobileProximityReader: @retroactive @unchecked Sendable {}
extension MobileProximityReaderSession: @retroactive @unchecked Sendable {}

/// How long an in-person session waits (ISO/IEC 18013-5 recommends at
/// least 30 seconds from engagement to the request, §8.2.3, and 300
/// seconds of inactivity before ending a session, §9.1.1.4).
public struct ProximityTimeouts: Sendable {
    /// For the other device to connect, after the QR code is shown or scanned.
    public var connect: Duration
    /// For the reader's request, once connected.
    public var request: Duration
    /// For the holder to decide, or the holder's answer to arrive.
    public var idle: Duration

    /// Timeouts: by default 60 seconds to connect, 30 for the request, and 300
    /// idle.
    public init(connect: Duration = .seconds(60), request: Duration = .seconds(30), idle: Duration = .seconds(300)) {
        self.connect = connect
        self.request = request
        self.idle = idle
    }
}

/// An in-person session failed over Bluetooth, rather than in the
/// protocol (`WalletError`).
public struct ProximityError: Error, Sendable, CustomStringConvertible {
    /// Why a session failed.
    public enum Reason: Sendable {
        /// Bluetooth is off, or not allowed for this app.
        case bluetoothUnavailable
        /// A `ProximityTimeouts` timeout passed.
        case timedOut
        /// The connection was lost, or the other device broke the transport's rules.
        case connectionLost
    }

    /// Why the session failed.
    public let reason: Reason
    /// Detail for logs.
    public let message: String

    /// The message.
    public var description: String { message }

    /// A sentence fit to show the holder.
    public var localizedDescription: String {
        switch reason {
        case .bluetoothUnavailable: "Turn on Bluetooth, and allow the app to use it, then try again."
        case .timedOut: "The other device didn't respond in time."
        case .connectionLost: "The connection to the other device was lost."
        }
    }

    init(_ reason: Reason, _ message: String) {
        self.reason = reason
        self.message = message
    }

    init(_ e: ProximityTransportError) {
        self.init(e.bluetoothUnavailable ? .bluetoothUnavailable : .connectionLost, e.message)
    }
}

/// Who sent a request, as the holder sees it.
public struct ProximityReaderIdentity: Sendable {
    /// How far the request's reader authentication goes.
    public enum Status: String, Sendable {
        /// Signed by a certificate that chains to `WalletConfiguration.mdocReaderRoots`.
        case trusted
        /// Signed, by a certificate that doesn't chain to them: its name is unproven.
        case untrusted
        /// Not signed: anyone who scanned the QR code could have asked.
        case unauthenticated
        /// A signature that doesn't verify for this session: possibly replayed.
        case invalid
    }

    /// Whether the request was signed, and by a reader the wallet recognizes.
    public let status: Status
    /// The reader certificate's subject common name: its verified name only
    /// when `status` is `.trusted`; "" when the request wasn't signed.
    public let name: String
    /// The certificate chain the request carried, leaf first.
    public let chain: [SecCertificate]
    /// `chain`'s certificates' fields, which the platform can't read
    /// itself: for showing them.
    public let certificates: [CertificateDetails]
    /// Why `status` isn't `.trusted`, for logs.
    public let error: String?

    /// A certificate's fields.
    public struct CertificateDetails: Decodable, Sendable {
        /// The certificate's subject.
        public let subject: String
        /// The certificate's issuer.
        public let issuer: String
        /// When it becomes valid.
        public let notBefore: Date
        /// When it expires.
        public let notAfter: Date
        /// Hexadecimal.
        public let serial: String
        /// Its subject alternative names.
        public let subjectAltNames: [String]
        /// Its extended key usages.
        public let extendedKeyUsages: [String]
        /// Its key usages.
        public let keyUsages: [String]
        /// Whether it's a CA certificate.
        public let isCA: Bool
        /// The algorithm its issuer signed it with.
        public let signatureAlgorithm: String
        /// The extensions' OIDs, "(critical)" after the critical ones'.
        public let extensions: [String]
        /// The certificate's SHA-256, hexadecimal.
        public let sha256: String

        enum CodingKeys: String, CodingKey {
            case subject, issuer, serial, extensions, sha256
            case notBefore = "not_before", notAfter = "not_after", subjectAltNames = "subject_alt_names"
            case extendedKeyUsages = "extended_key_usages", keyUsages = "key_usages", isCA = "is_ca"
            case signatureAlgorithm = "signature_algorithm"
        }
    }
}

/// Publishes a session's state to any number of observers.
final class StateBroadcast<State: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var current: State
    private var observers: [UUID: AsyncStream<State>.Continuation] = [:]

    init(_ initial: State) { current = initial }

    var value: State {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    /// Moves to `next` if `allowed` accepts the current state.
    @discardableResult
    func update(_ next: State, if allowed: (State) -> Bool) -> Bool {
        lock.lock()
        guard allowed(current) else { lock.unlock(); return false }
        current = next
        let os = Array(observers.values)
        lock.unlock()
        for o in os { o.yield(next) }
        return true
    }

    func stream() -> AsyncStream<State> {
        AsyncStream { continuation in
            let id = UUID()
            lock.lock()
            observers[id] = continuation
            let now = current
            lock.unlock()
            continuation.yield(now)
            continuation.onTermination = { [weak self] _ in
                guard let self else { return }
                self.lock.lock()
                self.observers[id] = nil
                self.lock.unlock()
            }
        }
    }
}

/// The holder's side of an ISO/IEC 18013-5 in-person presentation over
/// BLE, in mdoc peripheral server mode: show `qrCode`, and the reader
/// that scans it connects. Follow `states`: on `.requestReceived`, ask
/// the holder, then `respond` or `decline`. `cancel` ends it at any
/// point. One request per session. The app's Info.plist needs
/// NSBluetoothAlwaysUsageDescription.
public final class ProximityPresentation: @unchecked Sendable {
    /// Where the session is: follow `states`.
    public enum State: Sendable {
        /// Showing the QR code, advertising, waiting for a reader.
        case waitingForReader
        /// A reader connected; its request is on its way.
        case connected
        /// The reader's request, for the holder's consent.
        case requestReceived(Request)
        /// Answering: the holder key is signing, or the response is being sent.
        case responding
        /// The response was sent; `linkable`: the copy presented had been seen by another Verifier.
        case presented(linkable: Bool)
        /// The holder declined: nothing was disclosed.
        case declined
        /// The reader ended the session first.
        case readerEnded
        /// `cancel` was called.
        case cancelled
        /// The session failed: a `ProximityError` or `WalletError`.
        case failed(any Error & Sendable)

        /// Whether the session is over.
        public var isFinal: Bool {
            switch self {
            case .presented, .declined, .readerEnded, .cancelled, .failed: true
            default: false
            }
        }
    }

    /// The reader's request.
    public struct Request: Sendable {
        /// Who sent the request.
        public let reader: ProximityReaderIdentity
        /// The requested documents, in the request's order, each with the held mdocs of its doctype.
        public let documents: [MdocPresentation.Document]
    }

    private let handle: MobileProximityPresentation
    private let transport: any ProximityTransport
    private let timeouts: ProximityTimeouts
    private let broadcast = StateBroadcast<State>(.waitingForReader)
    private var task: Task<Void, Never>?

    /// The QR code to show: "mdoc:" and the device engagement.
    public let qrCode: String

    /// The current state.
    public var state: State { broadcast.value }

    /// The current state, then each change.
    public var states: AsyncStream<State> { broadcast.stream() }

    init(_ handle: MobileProximityPresentation, timeouts: ProximityTimeouts, transport: (UUID) -> any ProximityTransport) throws {
        struct Engagement: Decodable {
            let qrCode: String
            let serviceUUID: String
            enum CodingKeys: String, CodingKey { case qrCode = "qr_code", serviceUUID = "service_uuid" }
        }
        let e = try decode(Engagement.self, handle.engagement())
        guard let uuid = UUID(uuidString: e.serviceUUID) else {
            throw WalletError(code: .internalError, message: "a malformed service UUID")
        }
        self.handle = handle
        self.timeouts = timeouts
        self.qrCode = e.qrCode
        self.transport = transport(uuid)
        task = Task.detached { [self] in await run() }
    }

    private func run() async {
        do {
            try await within(timeouts.connect, "no reader connected") { try await self.transport.connect() }
            broadcast.update(.connected) { if case .waitingForReader = $0 { true } else { false } }
            let first = try await within(timeouts.request, "the reader sent no request") { try await self.transport.receive() }
            guard try await handleMessage(first) == "request" else { return }
            let request = try decode(RequestJSON.self, handle.request()).request
            guard broadcast.update(.requestReceived(request), if: { if case .connected = $0 { true } else { false } }) else { return }
            // The holder decides; meanwhile the reader can only end the
            // session. The idle timeout runs only while the request waits.
            while !state.isFinal {
                do {
                    let next = try await withTimeout(timeouts.idle) { try await self.transport.receive() }
                    _ = try await handleMessage(next)
                } catch is ProximityTimeout {
                    if case .requestReceived = state {
                        await sendTermination()
                        finish(.failed(ProximityError(.timedOut, "the holder didn't decide in time")))
                    }
                }
            }
        } catch let e as ProximityTransportError {
            if case .responding = state { return } // respond reports it
            finish(e.peerEnded ? .readerEnded : .failed(ProximityError(e)))
        } catch let e as ProximityError {
            await sendTermination()
            finish(.failed(e))
        } catch is CancellationError {
            finish(.cancelled)
        } catch let e as WalletError {
            finish(.failed(e))
        } catch {
            finish(.failed(WalletError(code: .internalError, message: "\(error)")))
        }
    }

    /// Hands `message` to Go, sends its reply, and ends the session on an
    /// "ended" event; returns the event.
    private func handleMessage(_ message: Data) async throws -> String {
        let p = handle
        let json = try await OID4VC.cancellable { op in p.handleMessage(op, message: message) }
        let event = try decode(EventJSON.self, json)
        if let send = event.send { try await transport.send(send) }
        if event.event == "ended" {
            finish(event.reason == "reader_ended" ? .readerEnded : .failed(WalletError(text: event.error ?? "[protocol] the session failed")))
        }
        return event.event
    }

    /// Presents the held mdoc `credentialID` for document number
    /// `document`, disclosing exactly `elements`, each one it requested,
    /// and sends the response, which ends the session. The holder key
    /// signs now, so a key store requiring user presence prompts. It
    /// returns whether the copy presented had been seen by another
    /// Verifier. On a `WalletError` nothing was sent and the request
    /// stands: try again, or `decline`.
    @discardableResult
    public func respond(document: Int, credentialID: String, elements: [MdocPresentation.Element]) async throws -> Bool {
        guard case .requestReceived(let request) = state,
              broadcast.update(.responding, if: { if case .requestReceived = $0 { true } else { false } }) else {
            throw WalletError(code: .wrongStep, message: "no request to answer")
        }
        struct Responded: Decodable { let send: Data; let linkable: Bool }
        let p = handle
        let pairs = String(decoding: try JSONEncoder().encode(elements.map { [$0.namespace, $0.identifier] }), as: UTF8.self)
        let answer: Responded
        do {
            let json = try await OID4VC.cancellable { op in
                try OID4VC.call { p.respond(op, document: document, credentialID: credentialID, elementsJSON: pairs, error: $0) }
            }
            answer = try decode(Responded.self, json)
        } catch {
            broadcast.update(.requestReceived(request)) { if case .responding = $0 { true } else { false } }
            throw error
        }
        do {
            try await transport.send(answer.send)
        } catch let e as ProximityTransportError {
            let error = ProximityError(e)
            finish(.failed(error))
            throw error
        }
        finish(.presented(linkable: answer.linkable), letReaderEnd: true)
        return answer.linkable
    }

    /// Declines the request, or ends the session before one: the reader
    /// is told, and nothing is disclosed.
    public func decline() async {
        switch state {
        case .responding: return
        case let s where s.isFinal: return
        default: break
        }
        ending.withLock { $0 = .declined }
        await sendTermination()
        finish(.declined)
    }

    /// Ends the session now, from any state.
    public func cancel() {
        guard !state.isFinal else { return }
        ending.withLock { $0 = .cancelled }
        Task.detached { [self] in
            _ = try? await withTimeout(.seconds(2)) { await self.sendTermination() }
            finish(.cancelled)
        }
    }

    /// How the holder chose to end the session, once they did: the
    /// reader disconnecting on the termination sent then doesn't end it
    /// as anything else.
    private enum Ending { case declined, cancelled }
    private let ending = OSAllocatedUnfairLock<Ending?>(initialState: nil)

    /// Sends status 20, if a reader is connected.
    private func sendTermination() async {
        guard let message = try? decode(SendJSON.self, handle.terminate()).send else { return }
        if case .waitingForReader = state { return }
        try? await transport.send(message)
    }

    /// Moves to `final` unless the session is over, then closes the
    /// transport: at once, or with `letReaderEnd` once the reader
    /// disconnects or a few seconds pass, so the last message reaches it.
    private func finish(_ final: State, letReaderEnd: Bool = false) {
        switch ending.withLock({ $0 }) {
        case .declined?: guard case .declined = final else { return }
        case .cancelled?: guard case .cancelled = final else { return }
        case nil: break
        }
        guard broadcast.update(final, if: { !$0.isFinal }) else { return }
        let transport = self.transport
        Task.detached {
            if letReaderEnd {
                // Until the reader disconnects or ends: receive throws then.
                _ = try? await withTimeout(.seconds(5)) { while true { _ = try await transport.receive() } }
            }
            transport.close()
        }
    }

    private func within<T: Sendable>(_ timeout: Duration, _ what: String, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        do {
            return try await withTimeout(timeout, body)
        } catch is ProximityTimeout {
            throw ProximityError(.timedOut, what)
        }
    }

    private struct RequestJSON: Decodable {
        let reader: ReaderJSON
        let documents: [MdocPresentation.Document]
        var request: Request { Request(reader: reader.identity, documents: documents) }
    }
}

struct ReaderJSON: Decodable {
    let status: String
    let name: String
    let chain: [Data]
    let certificates: [ProximityReaderIdentity.CertificateDetails]?
    let error: String?

    var identity: ProximityReaderIdentity {
        ProximityReaderIdentity(
            status: ProximityReaderIdentity.Status(rawValue: status) ?? .unauthenticated,
            name: name,
            chain: chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) },
            certificates: certificates ?? [],
            error: error)
    }
}

struct EventJSON: Decodable {
    let event: String
    let send: Data?
    let reason: String?
    let error: String?
}

struct SendJSON: Decodable { let send: Data }

extension WalletError {
    /// Parses a failing call's text, "[code] message", as a JSON result
    /// carries it.
    init(text: String) {
        self.init(NSError(domain: "OID4VCWallet", code: 0, userInfo: [NSLocalizedDescriptionKey: text]))
    }
}

public extension Wallet {
    /// Starts an ISO/IEC 18013-5 in-person presentation over BLE: show
    /// its `qrCode`; it advertises until a reader connects. Bluetooth
    /// failures end it as `.failed` with a `ProximityError`.
    func startProximityPresentation(timeouts: ProximityTimeouts = ProximityTimeouts()) throws -> ProximityPresentation {
        try startProximityPresentation(timeouts: timeouts) { uuid in
            GattServerTransport(serviceUUID: uuid, characteristics: .peripheralServer)
        }
    }
}

extension Wallet {
    func startProximityPresentation(timeouts: ProximityTimeouts, transport: (UUID) -> any ProximityTransport) throws -> ProximityPresentation {
        let wallet = handle
        let p = try OID4VC.wrap { try wallet.startProximityPresentation() }
        return try ProximityPresentation(p, timeouts: timeouts, transport: transport)
    }
}

/// A `ProximityReader`'s configuration.
public struct ProximityReaderConfiguration: Codable, Sendable {
    /// PEM certificates: the IACAs whose mdocs the reader accepts.
    public var issuerRoots: String
    /// The reader's key in the `KeyStore` and its PEM certificate chain,
    /// leaf first: with both, requests are signed (reader authentication),
    /// so holders see who is asking. The leaf should carry the mdoc reader
    /// authentication extended key usage (1.0.18013.5.1.6).
    public var readerKeyID: String?
    /// The reader's PEM certificate chain, leaf first, for `readerKeyID`.
    public var readerChain: String?
    /// Tolerates an issuer's clock this far off the reader's, at most an hour.
    public var maxClockSkewSeconds: Int?
    /// Accepts only document signers with the mDL document signer extended key usage.
    public var requireMDLSignerEKU: Bool

    /// A configuration accepting mdocs under `issuerRoots`; with `readerKeyID`
    /// and `readerChain`, requests are signed.
    public init(issuerRoots: String, readerKeyID: String? = nil, readerChain: String? = nil,
                maxClockSkewSeconds: Int? = nil, requireMDLSignerEKU: Bool = false) {
        self.issuerRoots = issuerRoots
        self.readerKeyID = readerKeyID
        self.readerChain = readerChain
        self.maxClockSkewSeconds = maxClockSkewSeconds
        self.requireMDLSignerEKU = requireMDLSignerEKU
    }

    enum CodingKeys: String, CodingKey {
        case issuerRoots = "issuer_roots", readerKeyID = "reader_key_id", readerChain = "reader_chain"
        case maxClockSkewSeconds = "max_clock_skew_seconds", requireMDLSignerEKU = "require_mdl_signer_eku"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        issuerRoots = try c.decode(String.self, forKey: .issuerRoots)
        readerKeyID = try c.decodeIfPresent(String.self, forKey: .readerKeyID)
        readerChain = try c.decodeIfPresent(String.self, forKey: .readerChain)
        maxClockSkewSeconds = try c.decodeIfPresent(Int.self, forKey: .maxClockSkewSeconds)
        requireMDLSignerEKU = try c.decodeIfPresent(Bool.self, forKey: .requireMDLSignerEKU) ?? false
    }
}

/// An ISO/IEC 18013-5 mdoc reader: a verifier asking for an mdoc in
/// person over BLE. It needs no `Wallet`. The key store holds the
/// reader's key, `ProximityReaderConfiguration.readerKeyID`; none for a
/// reader that doesn't sign.
public final class ProximityReader: @unchecked Sendable {
    private let handle: MobileProximityReader
    private let adapter: KeyStoreAdapter?

    /// A reader configured by `configuration`; `keyStore` holds its key, when
    /// it signs requests.
    public convenience init(configuration: ProximityReaderConfiguration, keyStore: (any KeyStore)? = nil) throws {
        try self.init(configuration: configuration, keys: keyStore.map(KeyStoreAdapter.init))
    }

    init(configuration: ProximityReaderConfiguration, keys: KeyStoreAdapter?) throws {
        let json = String(decoding: try JSONEncoder().encode(configuration), as: UTF8.self)
        adapter = keys
        handle = try OID4VC.call { MobileNewProximityReader(json, keys, $0) }!
    }

    /// Reads the holder's `qrCode` and starts a session asking for
    /// `docType`'s `elements` (namespace → identifiers): it scans for the
    /// holder, or advertises for it, as the holder's QR code offers. A QR
    /// code it can't use is `WalletError` `.invalidInput`.
    public func start(qrCode: String, docType: String, elements: [String: [String]],
                      timeouts: ProximityTimeouts = ProximityTimeouts()) throws -> ProximityReaderSession {
        try start(qrCode: qrCode, docType: docType, elements: elements, timeouts: timeouts) { e in
            if e.bleMode == "central_client" {
                GattServerTransport(serviceUUID: e.uuid, characteristics: .centralClient, ident: e.ident)
            } else {
                GattClientTransport(serviceUUID: e.uuid, characteristics: .peripheralServer)
            }
        }
    }

    func start(qrCode: String, docType: String, elements: [String: [String]], timeouts: ProximityTimeouts,
               transport: (ReaderEngagement) -> any ProximityTransport) throws -> ProximityReaderSession {
        let reader = handle
        let session = try OID4VC.wrap { try reader.start(qrCode) }
        return try ProximityReaderSession(session, docType: docType, elements: elements, timeouts: timeouts, transport: transport)
    }
}

/// A reader session's engagement.
struct ReaderEngagement: Decodable {
    let serviceUUID: String
    let bleMode: String
    let ident: Data
    let signed: Bool

    var uuid: UUID { UUID(uuidString: serviceUUID) ?? UUID() }

    enum CodingKeys: String, CodingKey {
        case serviceUUID = "service_uuid", bleMode = "ble_mode", ident, signed
    }
}

/// One reader session: follow `states` to `.verified` or another final state.
public final class ProximityReaderSession: @unchecked Sendable {
    /// Where the session is: follow `states`.
    public enum State: Sendable {
        /// Looking for the holder's device, or waiting for it to connect.
        case connecting
        /// Connected: the request is sent, and the holder is deciding.
        case waitingForResponse
        /// The mdoc verified.
        case verified(VerifiedMdoc)
        /// The holder declined (not authenticated: anyone nearby could send that).
        case declined
        /// `cancel` was called.
        case cancelled
        /// The session failed: a `ProximityError` or `WalletError`.
        case failed(any Error & Sendable)

        /// Whether the session is over.
        public var isFinal: Bool {
            switch self {
            case .verified, .declined, .cancelled, .failed: true
            default: false
            }
        }
    }

    private let handle: MobileProximityReaderSession
    private let transport: any ProximityTransport
    private let timeouts: ProximityTimeouts
    private let docType: String
    private let elementsJSON: String
    private let broadcast = StateBroadcast<State>(.connecting)
    private var task: Task<Void, Never>?

    /// Whether requests carry reader authentication.
    public let signed: Bool

    /// The current state.
    public var state: State { broadcast.value }
    /// The current state, then each change.
    public var states: AsyncStream<State> { broadcast.stream() }

    init(_ handle: MobileProximityReaderSession, docType: String, elements: [String: [String]], timeouts: ProximityTimeouts,
         transport: (ReaderEngagement) -> any ProximityTransport) throws {
        let e = try decode(ReaderEngagement.self, handle.engagement())
        self.handle = handle
        self.docType = docType
        self.elementsJSON = String(decoding: try JSONEncoder().encode(elements), as: UTF8.self)
        self.timeouts = timeouts
        self.signed = e.signed
        self.transport = transport(e)
        task = Task.detached { [self] in await run() }
    }

    private func run() async {
        do {
            do {
                try await withTimeout(timeouts.connect) { try await self.transport.connect() }
            } catch is ProximityTimeout {
                throw ProximityError(.timedOut, "the holder's device wasn't found")
            }
            let s = handle
            let (docType, elementsJSON) = (self.docType, self.elementsJSON)
            let json = try await OID4VC.offMain { try OID4VC.call { s.request(docType, elementsJSON: elementsJSON, error: $0) } }
            try await transport.send(try decode(SendJSON.self, json).send)
            broadcast.update(.waitingForResponse) { if case .connecting = $0 { true } else { false } }
            let answer: Data
            do {
                answer = try await withTimeout(timeouts.idle) { try await self.transport.receive() }
            } catch is ProximityTimeout {
                throw ProximityError(.timedOut, "the holder didn't respond in time")
            }
            let event = try decode(ReaderEventJSON.self, handle.handleMessage(answer))
            if let send = event.send { try? await transport.send(send) }
            if event.event == "verified", let v = event.verified {
                finish(.verified(v.mdoc))
            } else if event.reason == "declined" {
                finish(.declined)
            } else {
                finish(.failed(WalletError(text: event.error ?? "[protocol] the session failed")))
            }
        } catch let e as ProximityTransportError {
            finish(.failed(ProximityError(e)))
        } catch let e as ProximityError {
            await terminate()
            finish(.failed(e))
        } catch is CancellationError {
            finish(.cancelled)
        } catch let e as WalletError {
            await terminate()
            finish(.failed(e))
        } catch {
            finish(.failed(WalletError(code: .internalError, message: "\(error)")))
        }
    }

    /// Ends the session now, from any state.
    public func cancel() {
        guard !state.isFinal else { return }
        cancelling.withLock { $0 = true }
        Task.detached { [self] in
            _ = try? await withTimeout(.seconds(2)) { await self.terminate() }
            finish(.cancelled)
        }
    }

    /// Set by cancel: the holder disconnecting on its termination
    /// doesn't end the session as a failure.
    private let cancelling = OSAllocatedUnfairLock(initialState: false)

    private func terminate() async {
        guard let message = try? decode(SendJSON.self, handle.terminate()).send else { return }
        if case .waitingForResponse = state { try? await transport.send(message) }
    }

    private func finish(_ final: State) {
        if cancelling.withLock({ $0 }) { guard case .cancelled = final else { return } }
        guard broadcast.update(final, if: { !$0.isFinal }) else { return }
        transport.close()
    }
}

/// A verified mdoc, as a `ProximityReaderSession` received it.
public struct VerifiedMdoc: Sendable {
    /// The mdoc's document type.
    public let doctype: String
    /// The disclosed elements: namespace → identifier → value, byte
    /// strings as base64 and dates as their text.
    public let claims: [String: JSONValue]
    /// Any device-signed elements.
    public let deviceSignedClaims: [String: JSONValue]?
    /// The document signer certificate's subject common name.
    public let issuer: String
    /// The common name of the IACA it chains to.
    public let trustAnchor: String
    /// When the mdoc's signed data (its MSO) became valid.
    public let validFrom: Date
    /// When it expires.
    public let validUntil: Date
    /// "signature" or "mac".
    public let deviceAuth: String
    /// The MSO's status list reference, unchecked: check it before
    /// relying on the document.
    public let statusList: StatusListReference?

    /// Where the mdoc's status is published: a Token Status List, and its index
    /// in it.
    public struct StatusListReference: Sendable {
        /// The status list's URL.
        public let uri: String
        /// The mdoc's index in the list.
        public let index: Int
    }
}

struct ReaderEventJSON: Decodable {
    let event: String
    let verified: VerifiedJSON?
    let send: Data?
    let reason: String?
    let error: String?
}

struct VerifiedJSON: Decodable {
    let doctype: String
    let claims: [String: JSONValue]
    let deviceSignedClaims: [String: JSONValue]?
    let issuer: String
    let trustAnchor: String
    let validFrom: Date
    let validUntil: Date
    let deviceAuth: String
    let status: Status?

    struct Status: Decodable { let uri: String; let idx: Int }

    enum CodingKeys: String, CodingKey {
        case doctype, claims, issuer, status
        case deviceSignedClaims = "device_signed_claims", trustAnchor = "trust_anchor"
        case validFrom = "valid_from", validUntil = "valid_until", deviceAuth = "device_auth"
    }

    var mdoc: VerifiedMdoc {
        VerifiedMdoc(doctype: doctype, claims: claims, deviceSignedClaims: deviceSignedClaims, issuer: issuer,
                     trustAnchor: trustAnchor, validFrom: validFrom, validUntil: validUntil, deviceAuth: deviceAuth,
                     statusList: status.map { VerifiedMdoc.StatusListReference(uri: $0.uri, index: $0.idx) })
    }
}
