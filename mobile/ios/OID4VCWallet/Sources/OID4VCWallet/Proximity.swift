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
///
/// Times are in seconds (`TimeInterval`) on every OS version. On iOS 16
/// and later, `Duration` properties and an initializer do the same.
public struct ProximityTimeouts: Sendable {
    /// Seconds to wait for the other device to connect, after the QR code
    /// is shown or scanned. A reader in mdoc peripheral server mode
    /// connects to whichever device advertises the holder's service, so
    /// within these seconds it also passes over devices whose answers
    /// aren't the holder's and sends its request to the next: a bare
    /// "declined", which isn't authenticated, is reported once no other
    /// device advertises the holder's service for 5 seconds, or these end.
    public var connectSeconds: TimeInterval
    /// Seconds to wait for the reader's request, once connected. As the
    /// holder's GATT server, connected is when any device first starts a
    /// session (State 0x01), not necessarily the reader: the reader's
    /// whole window may be this, not `connectSeconds` and this.
    public var requestSeconds: TimeInterval
    /// Seconds to wait for the holder to decide, or the holder's answer to
    /// arrive.
    public var idleSeconds: TimeInterval

    /// The default timeouts: 60 seconds to connect, 30 for the request, and
    /// 300 idle. (Spelled out so `ProximityTimeouts()` isn't ambiguous
    /// between the two initializers below on iOS 16 and later.)
    public init() {
        self.init(connectSeconds: 60, requestSeconds: 30, idleSeconds: 300)
    }

    /// Timeouts in seconds: by default 60 to connect, 30 for the request,
    /// and 300 idle.
    public init(connectSeconds: TimeInterval = 60, requestSeconds: TimeInterval = 30, idleSeconds: TimeInterval = 300) {
        self.connectSeconds = connectSeconds
        self.requestSeconds = requestSeconds
        self.idleSeconds = idleSeconds
    }

    /// Timeouts: by default 60 seconds to connect, 30 for the request, and
    /// 300 idle.
    @available(iOS 16.0, macOS 13.0, *)
    public init(connect: Duration = .seconds(60), request: Duration = .seconds(30), idle: Duration = .seconds(300)) {
        self.init(connectSeconds: connect.timeInterval, requestSeconds: request.timeInterval, idleSeconds: idle.timeInterval)
    }

    /// For the other device to connect, after the QR code is shown or scanned.
    @available(iOS 16.0, macOS 13.0, *)
    public var connect: Duration {
        get { .seconds(connectSeconds) }
        set { connectSeconds = newValue.timeInterval }
    }
    /// For the reader's request, once connected.
    @available(iOS 16.0, macOS 13.0, *)
    public var request: Duration {
        get { .seconds(requestSeconds) }
        set { requestSeconds = newValue.timeInterval }
    }
    /// For the holder to decide, or the holder's answer to arrive.
    @available(iOS 16.0, macOS 13.0, *)
    public var idle: Duration {
        get { .seconds(idleSeconds) }
        set { idleSeconds = newValue.timeInterval }
    }
}

@available(iOS 16.0, macOS 13.0, *)
private extension Duration {
    var timeInterval: TimeInterval {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
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
        /// Signed by a certificate that chains to `WalletConfiguration.verifiers.mdocReaderRoots`.
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
    /// The reader's name, from a certificate that chains to
    /// `WalletConfiguration.verifiers.mdocReaderRoots`: set only when
    /// `status` is `.trusted`.
    public let name: String
    /// The certificate chain the request carried, leaf first.
    public let chain: [SecCertificate]
    /// `chain`'s certificates' fields, which the platform can't read
    /// itself: for showing them.
    public let certificates: [CertificateDetails]
    /// Why `status` isn't `.trusted`, for logs.
    public let error: String?
    /// `certificate_revoked` or `no_current_crl` (`MobileDetailCertificateRevoked`,
    /// `MobileDetailNoCurrentCRL`) when `error` is the reader certificate's
    /// revocation check, nil otherwise. From OID4VCWallet 0.27.0.
    public var errorDetail: String? = nil
    /// The name an untrusted or invalid request's certificate gives
    /// itself: anyone can claim any name, so never show it as the
    /// reader's. "" when the reader is trusted or didn't sign.
    public var claimedName: String = ""

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
/// BLE: show `qrCode`, and the reader that scans it connects, or
/// advertises for the holder to connect, in one of the
/// `ProximityBLEMode`s the session offers. Follow `states`: on `.requestReceived`, ask
/// the holder, then `respond` or `decline`. `cancel` ends it at any
/// point. One request per session. The app's Info.plist needs
/// NSBluetoothAlwaysUsageDescription.
public final class ProximityPresentation: @unchecked Sendable {
    /// Where the session is: follow `states`.
    public enum State: Sendable {
        /// Showing the QR code, advertising or scanning, waiting for a reader.
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
        /// `cancel` was called, or the caller of `respond` was cancelled
        /// while the response was being sent.
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
        /// The request's use cases and purpose hints (ISO/IEC 18013-5 second edition), or nil
        /// when the reader sent none — a first-edition reader, say. ``RequestInfo/signed`` says
        /// whether a verified whole-request signature covers it; ``reader`` says whether that
        /// signer is trusted. Neither shows that a purpose is true, or that the reader may ask
        /// for it.
        public let requestInfo: RequestInfo?

        init(reader: ProximityReaderIdentity, documents: [MdocPresentation.Document], requestInfo: RequestInfo? = nil) {
            self.reader = reader
            self.documents = documents
            self.requestInfo = requestInfo
        }
    }

    /// A request's second-edition information, as the reader sent it.
    public struct RequestInfo: Sendable, Decodable, Equatable {
        /// The use cases, in the request's order.
        public let useCases: [UseCase]
        /// Whether a verified whole-request signature (readerAuthAll) covers this information,
        /// every signature the request carries having verified. It isn't reader trust: see
        /// ``Request/reader``.
        public let signed: Bool

        enum CodingKeys: String, CodingKey { case useCases = "use_cases", signed }
    }

    /// One use case of a request.
    public struct UseCase: Sendable, Decodable, Equatable {
        /// The use case's mandatory flag, as the reader sent it; what it obliges the holder to is
        /// the app's decision.
        public let mandatory: Bool
        /// The use case's document sets: each lists indices into ``Request/documents``, in order,
        /// repeats kept.
        public let documentSets: [[Int]]
        /// Purpose codes by controller ID, as the reader sent them: neither translated nor checked
        /// against what the reader's certificate allows.
        public let purposeHints: [String: Int32]

        enum CodingKeys: String, CodingKey { case mandatory, documentSets = "document_sets", purposeHints = "purpose_hints" }
    }

    /// Decodes the Go side's Request() JSON into the request snapshot: the one decoding path for
    /// the session and for tests.
    static func decodeRequest(_ json: String) throws -> Request {
        try decode(RequestJSON.self, json).request
    }

    private let handle: MobileProximityPresentation
    private let transport: any ProximityTransport
    private let timeouts: ProximityTimeouts
    private let broadcast = StateBroadcast<State>(.waitingForReader)
    private var task: Task<Void, Never>?
    /// Set once the transport is closed, after the final state.
    private let closed = Signal()

    /// The QR code to show: "mdoc:" and the device engagement.
    public let qrCode: String

    /// The current state.
    public var state: State { broadcast.value }

    /// The current state, then each change.
    public var states: AsyncStream<State> { broadcast.stream() }

    init(_ handle: MobileProximityPresentation, timeouts: ProximityTimeouts, transport: (HolderEngagement) -> any ProximityTransport) throws {
        struct Mode: Decodable {
            let mode: String
            let serviceUUID: String
            enum CodingKeys: String, CodingKey { case mode, serviceUUID = "service_uuid" }
        }
        struct Engagement: Decodable {
            let qrCode: String
            let bleModes: [Mode]
            let ident: String?
            enum CodingKeys: String, CodingKey { case qrCode = "qr_code", bleModes = "ble_modes", ident }
        }
        let e = try decode(Engagement.self, handle.engagement())
        let modes = try e.bleModes.map { m in
            guard let mode = ProximityBLEMode(rawValue: m.mode), let uuid = UUID(uuidString: m.serviceUUID) else {
                throw WalletError(code: .internalError, message: "a malformed BLE mode")
            }
            return (mode, uuid)
        }
        self.handle = handle
        self.timeouts = timeouts
        self.qrCode = e.qrCode
        // Central client mode checks the reader's Ident (§8.3.3.1.1.4):
        // without one, any device advertising the service would do.
        let ident = e.ident.flatMap { Data(base64Encoded: $0) }
        if modes.contains(where: { $0.0 == .centralClient }), ident?.count != 16 {
            throw WalletError(code: .internalError, message: "central client mode without the reader's Ident")
        }
        self.transport = transport(HolderEngagement(modes: modes, ident: ident))
        task = Task.detached { [self] in await run() }
    }

    private func run() async {
        do {
            try await within(timeouts.connectSeconds, "no reader connected") { try await self.transport.connect() }
            broadcast.update(.connected) { if case .waitingForReader = $0 { true } else { false } }
            let event = try await within(timeouts.requestSeconds, "the reader sent no request") { try await self.firstEvent() }
            // An "ended" event has finished the session; any other ("none")
            // carried no request, so nothing would ever end it.
            guard event == "request" else {
                if event != "ended" {
                    await sendTermination()
                    finish(.failed(WalletError(text: "[protocol] the reader's first message carried no request")))
                }
                return
            }
            let request = try Self.decodeRequest(handle.request())
            guard broadcast.update(.requestReceived(request), if: { if case .connected = $0 { true } else { false } }) else { return }
            // The holder decides; meanwhile the reader can only end the
            // session. The idle timeout runs only while the request waits.
            while !state.isFinal {
                do {
                    let next = try await withTimeout(timeouts.idleSeconds) { try await self.transport.receive() }
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

    /// The event for the first message Go accepts. Any device in range
    /// can write to a GATT server first: one whose message Go rejects
    /// (it never saw the QR code) is dropped, and the next first message,
    /// from any device, is handed to Go.
    private func firstEvent() async throws -> String {
        while true {
            let event = try await handleMessage(try await transport.receive())
            guard event == "rejected" else { return event }
            transport.reject()
        }
    }

    /// Hands `message` to Go, sends its reply, and ends the session on an
    /// "ended" event; returns the event. Any event but "rejected" commits
    /// the transport to the device that sent `message`.
    private func handleMessage(_ message: Data) async throws -> String {
        let p = handle
        let json = try await OID4VC.cancellable { op in p.handleMessage(op, message: message) }
        let event = try decode(EventJSON.self, json)
        if event.event == "rejected" { return event.event }
        transport.commit()
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
    /// stands: try again, or `decline`. It is `respond(answers:)` with
    /// one answer.
    @discardableResult
    public func respond(document: Int, credentialID: String, elements: [MdocPresentation.Element]) async throws -> Bool {
        try await respond(answers: [MdocPresentation.Answer(document: document, credentialID: credentialID, elements: elements)]).linkable
    }

    /// What `respond(answers:)` presented.
    public struct Responded: Sendable {
        /// Whether any copy presented had been seen by another Verifier.
        public let linkable: Bool
        /// The credentials presented with such a copy, by ID.
        public let linkableCredentials: [String]
    }

    /// Presents several of the request's documents in one response, each
    /// of `answers` as `respond(document:credentialID:elements:)` presents
    /// one, and sends it, which ends the session. A document left out
    /// isn't in the response: the reader may ask for more than the holder
    /// shares. No document may be answered twice, nor one credential
    /// answer two. Each holder key signs now, in the request's order; a
    /// `KeychainKeyStore` requiring user presence asks the holder once for
    /// them all (`KeychainKeyStore.Options.holderUserPresence`). On a
    /// `WalletError` — the prompt cancelled, say — nothing was sent and
    /// the request stands: try again, or `decline`.
    ///
    /// It never leaves the session in `.responding`:
    /// - Returning: the response was sent, and the state is `.presented`.
    /// - A `WalletError`, or the caller's cancellation, before anything
    ///   was sent: the state is `.requestReceived` again.
    /// - A `ProximityError`: the response couldn't be delivered, and the
    ///   state is `.failed` with it.
    /// - A `CancellationError` while the response was being sent: the
    ///   reader may hold part of it, so the state is `.cancelled`.
    /// - A `WalletError` with code `.internalError` from sending: the
    ///   state is `.failed` with it.
    ///
    /// After `cancel`, the state is `.cancelled` whatever it throws.
    @discardableResult
    public func respond(answers: [MdocPresentation.Answer]) async throws -> Responded {
        guard case .requestReceived(let request) = state,
              broadcast.update(.responding, if: { if case .requestReceived = $0 { true } else { false } }) else {
            throw WalletError(code: .wrongStep, message: "no request to answer")
        }
        struct RespondedJSON: Decodable {
            let send: Data
            let linkable: Bool
            let linkableCredentials: [String]?
            enum CodingKeys: String, CodingKey { case send, linkable, linkableCredentials = "linkable_credentials" }
        }
        let p = handle
        let answer: RespondedJSON
        do {
            let answersJSON = try MdocPresentation.answersJSON(answers)
            // The shared prompt is scoped to the thread making the Go
            // call, so it goes inside cancellable's background work.
            let json = try await OID4VC.cancellable { op in
                try OID4VC.callSharingHolderPrompt { p.respondDocuments(op, answersJSON: answersJSON, error: $0) }
            }
            answer = try decode(RespondedJSON.self, json)
        } catch {
            broadcast.update(.requestReceived(request)) { if case .responding = $0 { true } else { false } }
            throw error
        }
        // Cancelled once Go's Respond had returned (cancelled before, it
        // gives nothing to send): the response stays here.
        if ending.withLock({ $0 }) != nil {
            throw WalletError(code: .cancelled, message: "the session was cancelled")
        }
        do {
            try await transport.send(answer.send)
        } catch let e as ProximityTransportError {
            let error = ProximityError(e)
            finish(.failed(error))
            throw error
        } catch is CancellationError {
            // The caller's own cancellation, mid-send: the reader may hold
            // part of the response, so it can't be sent again.
            finish(.cancelled)
            throw CancellationError()
        } catch {
            let error = WalletError(code: .internalError, message: "\(error)")
            finish(.failed(error))
            throw error
        }
        finish(.presented(linkable: answer.linkable), letReaderEnd: true)
        // run's idle wait for a reader message is over: finish's own wait
        // for the reader to end reads now. Cancelled after the state is
        // final, run's CancellationError changes nothing.
        task?.cancel()
        return Responded(linkable: answer.linkable, linkableCredentials: answer.linkableCredentials ?? [])
    }

    /// Declines the request, or ends the session before one: the reader
    /// is told, and nothing is disclosed. The state is final at once; the
    /// transport stays open until the reader disconnects or a few seconds
    /// pass, as after a response, so the termination reaches it rather
    /// than being dropped with the link (the reader would then report a
    /// lost connection, not a decline).
    public func decline() async {
        switch state {
        case .responding: return
        case let s where s.isFinal: return
        default: break
        }
        ending.withLock { $0 = .declined }
        let sent = await sendTermination()
        finish(.declined, letReaderEnd: sent)
        // As in respond: run's wait for a reader message is over, and
        // finish's own wait reads now.
        if sent { task?.cancel() }
    }

    /// Ends the session now, from any state. It returns at once: to know
    /// the session has let go of Bluetooth, wait on ``awaitClosed()``.
    public func cancel() {
        guard !state.isFinal else { return }
        ending.withLock { $0 = .cancelled }
        Task.detached { [self] in
            _ = try? await withTimeout(2) { await self.sendTermination() }
            finish(.cancelled)
        }
    }

    /// How the holder chose to end the session, once they did: the
    /// reader disconnecting on the termination sent then doesn't end it
    /// as anything else.
    private enum Ending { case declined, cancelled }
    private let ending = Locked<Ending?>(initialState: nil)

    /// Sends status 20, if a reader is connected.
    /// Sends the session termination, once a reader is connected, and
    /// reports whether it was sent.
    @discardableResult
    private func sendTermination() async -> Bool {
        guard let message = try? decode(SendJSON.self, handle.terminate()).send else { return false }
        if case .waitingForReader = state { return false }
        do {
            try await transport.send(message)
            return true
        } catch {
            return false
        }
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
        let closed = self.closed
        Task.detached {
            if letReaderEnd {
                // Until the reader disconnects or ends: receive throws then.
                _ = try? await withTimeout(Self.readerEndSeconds) { while true { _ = try await transport.receive() } }
            }
            transport.close()
            closed.signal()
        }
    }

    /// How long, after the response is sent, the session waits for the
    /// reader to end before closing the transport itself.
    static let readerEndSeconds: TimeInterval = 5

    /// Waits until the session is over and has closed its Bluetooth
    /// transport, on every path: after `.presented`, that is once the
    /// reader disconnects, or 5 seconds later. The state is
    /// final before then. Wait on it before starting the next session,
    /// so two never hold Bluetooth at once. A cancelled wait throws
    /// `CancellationError`; the session goes on closing.
    public func awaitClosed() async throws {
        try await closed.wait()
    }

    private func within<T: Sendable>(_ timeout: TimeInterval, _ what: String, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        do {
            return try await withTimeout(timeout, body)
        } catch is ProximityTimeout {
            throw ProximityError(.timedOut, what)
        }
    }

    /// Request()'s JSON. request_info is nil when missing, for a Go side that predates it.
    private struct RequestJSON: Decodable {
        let reader: ReaderJSON
        let documents: [MdocPresentation.Document]
        let requestInfo: RequestInfo?
        enum CodingKeys: String, CodingKey { case reader, documents, requestInfo = "request_info" }
        var request: Request { Request(reader: reader.identity, documents: documents, requestInfo: requestInfo) }
    }
}

struct ReaderJSON: Decodable {
    let status: String
    let name: String
    let claimedName: String?
    let chain: [Data]
    let certificates: [ProximityReaderIdentity.CertificateDetails]?
    let error: String?
    let errorDetail: String?

    enum CodingKeys: String, CodingKey { case status, name, claimedName = "claimed_name", chain, certificates, error, errorDetail = "error_detail" }

    var identity: ProximityReaderIdentity {
        ProximityReaderIdentity(
            status: ProximityReaderIdentity.Status(rawValue: status) ?? .unauthenticated,
            name: name,
            chain: chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) },
            certificates: certificates ?? [],
            error: error,
            errorDetail: errorDetail,
            claimedName: claimedName ?? "")
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

/// The BLE roles a holder offers in its QR code (ISO/IEC 18013-5
/// §8.3.3.1.1); the reader picks one, central client mode when offered
/// both.
public enum ProximityBLEMode: String, CaseIterable, Sendable {
    /// The holder advertises and is the GATT server; the reader connects.
    case peripheralServer = "peripheral_server"
    /// The reader advertises and is the GATT server; the holder scans and connects.
    case centralClient = "central_client"
}

/// The modes a holder's session offers, each with its service UUID, and
/// the Ident a central client checks.
struct HolderEngagement {
    let modes: [(ProximityBLEMode, UUID)]
    let ident: Data?

    /// The BLE transports for these modes: one, or `EitherTransport`
    /// over both.
    func transport() -> any ProximityTransport {
        let transports: [any ProximityTransport] = modes.map { mode, uuid in
            switch mode {
            case .peripheralServer: GattServerTransport(serviceUUID: uuid, characteristics: .peripheralServer)
            case .centralClient: GattClientTransport(serviceUUID: uuid, characteristics: .centralClient, ident: ident)
            }
        }
        return transports.count == 1 ? transports[0] : EitherTransport(transports)
    }
}

public extension Wallet {
    /// Starts an ISO/IEC 18013-5 in-person presentation over BLE: show
    /// its `qrCode`. In `modes`, both by default, it advertises for a
    /// reader (peripheral server mode) and scans for one (central client
    /// mode) until a reader connects either way; a reader offered both
    /// should choose central client mode. Bluetooth failures end it as
    /// `.failed` with a `ProximityError`.
    func startProximityPresentation(timeouts: ProximityTimeouts = ProximityTimeouts(),
                                    modes: Set<ProximityBLEMode> = Set(ProximityBLEMode.allCases)) throws -> ProximityPresentation {
        try startProximityPresentation(timeouts: timeouts, modes: modes) { $0.transport() }
    }
}

extension Wallet {
    func startProximityPresentation(timeouts: ProximityTimeouts, modes: Set<ProximityBLEMode> = [.peripheralServer],
                                    transport: (HolderEngagement) -> any ProximityTransport) throws -> ProximityPresentation {
        guard !modes.isEmpty else { throw WalletError(code: .invalidInput, message: "no BLE mode") }
        // In the order Go lists them: peripheral server mode first.
        let names = ProximityBLEMode.allCases.filter(modes.contains).map(\.rawValue)
        let modesJSON = String(decoding: try JSONEncoder().encode(names), as: UTF8.self)
        let wallet = handle
        let p = try OID4VC.wrap { try wallet.startProximityPresentation(withModes: modesJSON) }
        return try ProximityPresentation(p, timeouts: timeouts, transport: transport)
    }
}

/// A `ProximityReader`'s configuration, its options grouped by what they
/// concern. Its JSON form is flat, one key per option, and unchanged by
/// the grouping.
public struct ProximityReaderConfiguration: Codable, Sendable {
    /// Which issuers' documents the reader accepts.
    public var issuers: IssuerTrust
    /// The reader's key and certificate chain: with them, requests are
    /// signed (reader authentication), so holders see who is asking. Nil:
    /// requests aren't signed.
    public var readerAuthentication: ReaderAuthentication?
    /// Tolerates an issuer's clock this far off the reader's, at most an hour.
    public var maxClockSkewSeconds: Int?
    /// How the reader's trust roles' certificates are checked for revocation.
    public var revocation: Revocation
    /// How `checkStatus` fetches and keeps status and identifier lists, as
    /// ``WalletConfiguration/status``.
    public var status: StatusLists
    /// Whether a session checks a verified document's revocation status
    /// before reporting it. Outside `development`, it's required: nil
    /// fails with `invalidInput`. With `.check`, a session reports
    /// `.verified` only for a document whose status is valid, or that
    /// has none (`VerifiedMdoc.status`), and fails with `.documentNotValid`
    /// otherwise; with `.decline`, nothing checks it, for a reader where
    /// something else stands in. In development, nil is `.decline`.
    public var statusCheck: StatusCheck?
    /// Relaxes what production requires, for a reader trying out a
    /// development issuer's documents; nil, the default, is production.
    /// Never ship an app with it set. Without it, `ProximityReader`
    /// requires a production reader's decisions, failing with
    /// `invalidInput` otherwise: each role in `revocation.roles` or
    /// `revocation.declined`, and `issuers.anyIssuerForAnyType` with
    /// `issuers.roots`. With it, a role in neither checks no revocation,
    /// and any IACA in `issuers.roots` may issue any document type. A
    /// release build refuses it (`invalidInput`) unless the app called
    /// `OID4VC.allowDevelopmentInRelease()`. Its ``Development/roots``
    /// are PEM certificates ``ProximityReader/refreshCRLs()``'s `https`
    /// fetches trust besides the system's: a development CA's
    /// distribution points served under its own TLS certificate (from
    /// OID4VCWallet 0.27.0).
    public var development: Development?

    /// Which issuers' documents the reader accepts.
    public struct IssuerTrust: Sendable {
        /// PEM certificates: the IACAs whose mdocs the reader accepts.
        public var roots: String
        /// Each document type's own IACAs, as PEM certificates: a document of a
        /// type named here must chain to them, not to `roots`, so an
        /// issuer trusted for one document type can't sign another. With it,
        /// `roots` may be empty, and then only the types named here are
        /// accepted.
        public var rootsByDocType: [String: String]
        /// Declares that every IACA in `roots` may issue every document
        /// type the reader asks for. Outside `development`, `roots`
        /// needs it; otherwise name each type's IACAs in `rootsByDocType`.
        public var anyIssuerForAnyType: Bool
        /// Also accepts a document signer certificate with no extended key
        /// usage, which is refused by default for lacking the mDL document
        /// signer's, for issuers whose document signers have none.
        public var acceptMDLSignerWithoutEKU: Bool

        /// Issuer trust in the IACAs `roots`.
        public init(roots: String, rootsByDocType: [String: String] = [:], anyIssuerForAnyType: Bool = false,
                    acceptMDLSignerWithoutEKU: Bool = false) {
            self.roots = roots
            self.rootsByDocType = rootsByDocType
            self.anyIssuerForAnyType = anyIssuerForAnyType
            self.acceptMDLSignerWithoutEKU = acceptMDLSignerWithoutEKU
        }
    }

    /// The reader's key and its certificate chain, for signing requests.
    public struct ReaderAuthentication: Sendable {
        /// The reader's key in the `KeyStore`.
        public var keyID: String
        /// The reader's PEM certificate chain, leaf first, for `keyID`. The
        /// leaf should carry the mdoc reader authentication extended key
        /// usage (1.0.18013.5.1.6).
        public var chain: String

        /// Reader authentication with the key `keyID` and its `chain`.
        public init(keyID: String, chain: String) {
            self.keyID = keyID
            self.chain = chain
        }
    }

    /// How the reader's trust roles' certificates are checked for revocation.
    public typealias Revocation = RevocationChecking<RevocationRole>
    /// A reader's trust role whose certificates can be checked for
    /// revocation.
    public enum RevocationRole: String, Codable, Sendable, CaseIterable {
        /// The document signer's certificate chain, when a document is
        /// verified.
        case issuer
        /// A status list signer's, in `checkStatus`.
        case status
    }

    /// Whether a reader session checks a verified document's revocation
    /// status before reporting it.
    public enum StatusCheck: String, Codable, Sendable {
        /// Checked: a session reports `.verified` only for a document
        /// whose status is valid, or that has none.
        case check
        /// Not checked, for a reader where something else stands in.
        case decline
    }

    /// A configuration accepting mdocs under `issuers`; with
    /// `readerAuthentication`, requests are signed.
    public init(issuers: IssuerTrust, readerAuthentication: ReaderAuthentication? = nil, maxClockSkewSeconds: Int? = nil,
                revocation: Revocation = Revocation(), status: StatusLists = StatusLists(),
                statusCheck: StatusCheck? = nil, development: Development? = nil) {
        self.issuers = issuers
        self.readerAuthentication = readerAuthentication
        self.maxClockSkewSeconds = maxClockSkewSeconds
        self.revocation = revocation
        self.status = status
        self.statusCheck = statusCheck
        self.development = development
    }

    // The flat JSON keys, one per option, as NewProximityReader reads
    // them. require_mdl_signer_eku, which did nothing, is still read
    // and ignored (refused with accept_mdl_signer_without_eku), and
    // never written.
    enum CodingKeys: String, CodingKey {
        case issuerRoots = "issuer_roots", readerKeyID = "reader_key_id", readerChain = "reader_chain"
        case maxClockSkewSeconds = "max_clock_skew_seconds", requireMDLSignerEKU = "require_mdl_signer_eku"
        case acceptMDLSignerWithoutEKU = "accept_mdl_signer_without_eku"
        case issuerRootsByDocType = "issuer_roots_by_doctype"
        case crls, revocation, crlIssuers = "crl_issuers"
        case noRevocationCheck = "no_revocation_check", anyIssuerForAnyType = "any_issuer_for_any_type", development
        case statusCheck = "status"
        case crlDistributionPoints = "crl_distribution_points"
        case crlDistributionPointsFromRoots = "crl_distribution_points_from_roots", crlRequireHTTPS = "crl_require_https"
        case developmentRoots = "development_roots"
        case statusMaxBytes = "status_max_bytes", identifierListMaxBytes = "identifier_list_max_bytes"
        case statusCacheMaxAgeSeconds = "status_cache_max_age_seconds", statusCacheDir = "status_cache_dir"
    }

    /// Decodes a configuration from its flat JSON, refusing a key it
    /// doesn't know, as ``WalletConfiguration`` does: a misspelled option
    /// would otherwise be dropped here and silently left at its default.
    /// `reader_key_id` or `reader_chain` alone makes a
    /// `readerAuthentication` with the other empty, which the reader
    /// refuses. `require_mdl_signer_eku`, which did nothing, is read and
    /// ignored, but refused with `accept_mdl_signer_without_eku`, as the
    /// library refused it.
    public init(from decoder: any Decoder) throws {
        let all = try decoder.container(keyedBy: AnyCodingKey.self)
        if let unknown = all.allKeys.first(where: { CodingKeys(stringValue: $0.stringValue) == nil }) {
            throw DecodingError.dataCorruptedError(forKey: unknown, in: all, debugDescription: "unknown configuration key \(unknown.stringValue)")
        }
        let c = try decoder.container(keyedBy: CodingKeys.self)
        func value<T: Decodable>(_ key: CodingKeys, _ fallback: T) throws -> T {
            try c.decodeIfPresent(T.self, forKey: key) ?? fallback
        }
        if try value(.requireMDLSignerEKU, false), try value(.acceptMDLSignerWithoutEKU, false) {
            throw DecodingError.dataCorruptedError(forKey: .requireMDLSignerEKU, in: c,
                                                   debugDescription: "require_mdl_signer_eku and accept_mdl_signer_without_eku can't both be set")
        }
        let keyID = try c.decodeIfPresent(String.self, forKey: .readerKeyID)
        let chain = try c.decodeIfPresent(String.self, forKey: .readerChain)
        self.init(
            issuers: IssuerTrust(
                roots: try value(.issuerRoots, ""),
                rootsByDocType: try value(.issuerRootsByDocType, [:]),
                anyIssuerForAnyType: try value(.anyIssuerForAnyType, false),
                acceptMDLSignerWithoutEKU: try value(.acceptMDLSignerWithoutEKU, false)),
            readerAuthentication: keyID == nil && chain == nil ? nil : ReaderAuthentication(keyID: keyID ?? "", chain: chain ?? ""),
            maxClockSkewSeconds: try c.decodeIfPresent(Int.self, forKey: .maxClockSkewSeconds),
            revocation: try Revocation(decodingFrom: c),
            status: try StatusLists(decodingFrom: c),
            statusCheck: try c.decodeIfPresent(StatusCheck.self, forKey: .statusCheck),
            development: try Development.decode(c))
    }

    /// Encodes the configuration as its flat JSON: every option's key,
    /// those of nil options left out.
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(issuers.roots, forKey: .issuerRoots)
        try c.encode(issuers.rootsByDocType, forKey: .issuerRootsByDocType)
        try c.encode(issuers.anyIssuerForAnyType, forKey: .anyIssuerForAnyType)
        try c.encode(issuers.acceptMDLSignerWithoutEKU, forKey: .acceptMDLSignerWithoutEKU)
        try c.encodeIfPresent(readerAuthentication?.keyID, forKey: .readerKeyID)
        try c.encodeIfPresent(readerAuthentication?.chain, forKey: .readerChain)
        try c.encodeIfPresent(maxClockSkewSeconds, forKey: .maxClockSkewSeconds)
        try revocation.encode(into: &c)
        try status.encode(into: &c)
        try c.encodeIfPresent(statusCheck, forKey: .statusCheck)
        try Development.encode(development, into: &c)
    }
}

/// An ISO/IEC 18013-5 mdoc reader: a verifier asking for an mdoc in
/// person over BLE. It needs no `Wallet`. The key store holds the
/// reader's key, `ProximityReaderConfiguration.readerAuthentication.keyID`; none for a
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
        try OID4VC.checkDevelopment(configuration.development != nil)
        let json = try StatusCacheKey.configuration(try JSONEncoder().encode(configuration), cacheDir: configuration.status.cacheDir)
        adapter = keys
        handle = try OID4VC.call { MobileNewProximityReader(json, keys, $0) }!
    }

    /// Reads the holder's `qrCode` and starts a session asking for
    /// `docType`'s `elements` (namespace → identifiers): it scans for the
    /// holder, or advertises for it, as the holder's QR code offers. A QR
    /// code it can't use is `WalletError` `.invalidInput`.
    public func start(qrCode: String, docType: String, elements: [String: [String]],
                      timeouts: ProximityTimeouts = ProximityTimeouts()) throws -> ProximityReaderSession {
        try start(qrCode: qrCode, documents: [DocumentRequest(docType: docType, elements: elements)], timeouts: timeouts)
    }

    /// One document a reader asks for: its `docType`, and its `elements`
    /// (namespace → identifiers).
    public struct DocumentRequest: Sendable, Encodable {
        public let docType: String
        public let elements: [String: [String]]

        /// A document request.
        public init(docType: String, elements: [String: [String]]) {
            self.docType = docType
            self.elements = elements
        }

        enum CodingKeys: String, CodingKey {
            case docType = "doctype", elements
        }
    }

    /// `start(qrCode:docType:elements:timeouts:)` asking for several
    /// `documents` at once, each of a different type, at most eight. The
    /// holder may answer any of them: `ProximityReaderSession.documents`
    /// has each one it did, so check each one needed came back.
    public func start(qrCode: String, documents: [DocumentRequest],
                      timeouts: ProximityTimeouts = ProximityTimeouts()) throws -> ProximityReaderSession {
        try start(qrCode: qrCode, documents: documents, timeouts: timeouts) { e in
            if e.bleMode == "central_client" {
                GattServerTransport(serviceUUID: e.uuid, characteristics: .centralClient, ident: e.ident)
            } else {
                GattClientTransport(serviceUUID: e.uuid, characteristics: .peripheralServer)
            }
        }
    }

    /// Replaces the Certificate Revocation Lists the configuration's
    /// `revocation.roles` are checked against with `pem`'s `X509 CRL`
    /// blocks, for sessions already started too. CRLs expire at their
    /// nextUpdate: fetch fresh ones and call this before then. Text holding
    /// anything else, or a CA's list older than the one held, throws
    /// `invalidInput` and keeps the lists as they were; empty text removes
    /// them all.
    public func setCRLs(_ pem: String) throws {
        let reader = handle
        try OID4VC.wrap { try reader.setCRLs(pem) }
    }

    /// Fetches the configuration's CRL distribution points and keeps each
    /// current list its CA signed that isn't older than the one held, for
    /// sessions already started too, as `Wallet.refreshCRLs()`.
    public func refreshCRLs() async throws -> CRLRefreshResult {
        let reader = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { reader.refreshCRLs(op, error: $0) } }
        return try CRLRefreshResult.from(json: json)
    }

    func start(qrCode: String, docType: String, elements: [String: [String]], timeouts: ProximityTimeouts,
               transport: (ReaderEngagement) -> any ProximityTransport) throws -> ProximityReaderSession {
        try start(qrCode: qrCode, documents: [DocumentRequest(docType: docType, elements: elements)], timeouts: timeouts, transport: transport)
    }

    func start(qrCode: String, documents: [DocumentRequest], timeouts: ProximityTimeouts,
               transport: (ReaderEngagement) -> any ProximityTransport) throws -> ProximityReaderSession {
        let reader = handle
        let session = try OID4VC.wrap { try reader.start(qrCode) }
        return try ProximityReaderSession(session, documents: documents, timeouts: timeouts, transport: transport)
    }
}

/// A reader session's engagement.
struct ReaderEngagement: Decodable {
    let serviceUUID: String
    let bleMode: String
    let ident: Data
    let signed: Bool
    /// The configuration's `statusCheck` is `.check`: the session checks
    /// a verified document's status before reporting it.
    let checkStatus: Bool?

    var uuid: UUID { UUID(uuidString: serviceUUID) ?? UUID() }

    enum CodingKeys: String, CodingKey {
        case serviceUUID = "service_uuid", bleMode = "ble_mode", ident, signed, checkStatus = "check_status"
    }
}

/// One reader session: follow `states` to `.verified` or another final state.
public final class ProximityReaderSession: @unchecked Sendable {
    /// How long a reader passing over a device waits for another to
    /// advertise the holder's service UUID: a holder advertises
    /// continuously, many times a second, until a reader connects.
    static let passOverFindSeconds: TimeInterval = 5

    /// Where the session is: follow `states`.
    public enum State: Sendable {
        /// Looking for the holder's device, or waiting for it to connect.
        case connecting
        /// Connected: the request is sent, and the holder is deciding.
        case waitingForResponse
        /// The mdoc verified, and, when the configuration checks status,
        /// its status is `.valid` or `.noStatus` (`VerifiedMdoc.status`).
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
    private let documentRequests: [ProximityReader.DocumentRequest]
    private let broadcast = StateBroadcast<State>(.connecting)
    private var task: Task<Void, Never>?
    private let verifiedDocuments = Locked<[VerifiedMdoc]>(initialState: [])

    /// Every verified mdoc, in the response's order, once the session is
    /// `.verified` (whose mdoc is the first): for a request of several
    /// documents, the ones the holder answered. Empty before.
    public var documents: [VerifiedMdoc] { verifiedDocuments.withLock { $0 } }

    /// Whether requests carry reader authentication.
    public let signed: Bool
    /// Whether the session checks a verified document's revocation status
    /// before reporting it `.verified`
    /// (`ProximityReaderConfiguration.statusCheck`).
    public let checksStatus: Bool
    /// The BLE mode this session uses, of those the holder offered:
    /// central client mode when it offered both.
    public let mode: ProximityBLEMode

    /// The current state.
    public var state: State { broadcast.value }
    /// The current state, then each change.
    public var states: AsyncStream<State> { broadcast.stream() }

    init(_ handle: MobileProximityReaderSession, documents: [ProximityReader.DocumentRequest], timeouts: ProximityTimeouts,
         transport: (ReaderEngagement) -> any ProximityTransport) throws {
        let e = try decode(ReaderEngagement.self, handle.engagement())
        self.handle = handle
        self.documentRequests = documents
        self.timeouts = timeouts
        self.signed = e.signed
        self.checksStatus = e.checkStatus ?? false
        guard let mode = ProximityBLEMode(rawValue: e.bleMode) else {
            throw WalletError(code: .internalError, message: "an unknown BLE mode")
        }
        self.mode = mode
        self.transport = transport(e)
        task = Task.detached { [self] in await run() }
    }

    private func run() async {
        do {
            // The time to find the holder's device: to connect, and to pass
            // over devices whose answers aren't the holder's (`exchange`).
            let deadline = ProcessInfo.processInfo.systemUptime + max(timeouts.connectSeconds, 0)
            do {
                try await withTimeout(timeouts.connectSeconds) { try await self.transport.connect() }
            } catch is ProximityTimeout {
                throw ProximityError(.timedOut, "the holder's device wasn't found")
            }
            // The reader speaks first: as GATT server (central client
            // mode), to the first device that started the session.
            transport.commit()
            let s = handle
            let json: String
            if documentRequests.count == 1 {
                let docType = documentRequests[0].docType
                let elementsJSON = String(decoding: try JSONEncoder().encode(documentRequests[0].elements), as: UTF8.self)
                json = try await OID4VC.offMain { try OID4VC.call { s.request(docType, elementsJSON: elementsJSON, error: $0) } }
            } else {
                let requestsJSON = String(decoding: try JSONEncoder().encode(documentRequests), as: UTF8.self)
                json = try await OID4VC.offMain { try OID4VC.call { s.requestDocuments(requestsJSON, error: $0) } }
            }
            let event = try await exchange(try decode(SendJSON.self, json).send, deadline: deadline)
            if let send = event.send { try? await transport.send(send) }
            if event.event == "verified", let v = event.verified {
                finish(await settled((event.documents ?? [v]).map(\.mdoc)))
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

    /// Sends `establishment` and returns Go's event for the answer. In
    /// mdoc peripheral server mode the reader connects to whichever device
    /// advertises the holder's service UUID, which the holder's adverts
    /// carry in the clear, so the device answering needn't be the holder:
    /// one whose answer Go rejects (`TryHandleMessage`: it doesn't decrypt,
    /// or is a bare status, which isn't encrypted), or whose link is lost
    /// before it answers, is passed over, and the same request goes to the
    /// next device advertising the UUID, until `deadline`. The holder takes
    /// it once. Passing over, the reader waits `passOverFindSeconds` for
    /// another device to advertise the UUID, not the whole time left: a
    /// holder that hasn't connected still advertises, so when none does,
    /// the holder has gone, having declined. An impostor can't hurry it
    /// so: the holder it got ahead of goes on advertising. When no other
    /// device is found, the outcome is the last rejected answer, a
    /// "rejected" event, whose reason the caller reports as an "ended"
    /// one's, or, with none, the lost link.
    private func exchange(_ establishment: Data, deadline: TimeInterval) async throws -> ReaderEventJSON {
        let passesOver = mode == .peripheralServer
        var rejected: ReaderEventJSON?
        while true {
            let answer: Data
            do {
                try await transport.send(establishment)
                broadcast.update(.waitingForResponse) { if case .connecting = $0 { true } else { false } }
                answer = try await withTimeout(timeouts.idleSeconds) { try await self.transport.receive() }
            } catch is ProximityTimeout {
                throw ProximityError(.timedOut, "the holder didn't respond in time")
            } catch let e as ProximityTransportError where passesOver && !e.bluetoothUnavailable {
                if try await passOver(deadline: deadline) { continue }
                if let rejected { return rejected }
                throw e
            }
            let s = handle
            let json = passesOver ? s.tryHandleMessage(answer) : s.handleMessage(answer)
            let event = try decode(ReaderEventJSON.self, json)
            guard event.event == "rejected" else { return event }
            rejected = event
            guard try await passOver(deadline: deadline) else { return event }
        }
    }

    /// Passes over the device that answered, or lost its link, and
    /// connects to the next one advertising the holder's service UUID
    /// before `deadline`: true once connected, false when none is found
    /// within `passOverFindSeconds`, or in time.
    private func passOver(deadline: TimeInterval) async throws -> Bool {
        if cancelling.withLock({ $0 }) { throw CancellationError() }
        transport.reject()
        let left = deadline - ProcessInfo.processInfo.systemUptime
        guard left > 0 else { return false }
        do {
            try await withTimeout(left) { try await self.transport.connect(findWithin: Self.passOverFindSeconds) }
            return true
        } catch let e as ProximityTransportError where e.bluetoothUnavailable {
            throw e
        } catch is ProximityTimeout, is ProximityTransportError {
            return false
        }
    }

    /// The final state for `mdoc`, which verified: `.verified`, unless the
    /// configuration checks status and it isn't `.valid` or `.noStatus`
    /// (`WalletError` `.documentNotValid`, its `protocolError` the status
    /// as the list says it), or the check failed. The connection is
    /// closed first: the status list is fetched over the network.
    private func settled(_ mdocs: [VerifiedMdoc]) async -> State {
        guard checksStatus else {
            verifiedDocuments.withLock { $0 = mdocs }
            return .verified(mdocs[0])
        }
        transport.close()
        do {
            let s = handle
            let json = try await OID4VC.cancellable { op in try OID4VC.call { s.checkStatus(op, error: $0) } }
            let checkedStatus = try decode(StatusJSON.self, json)
            let text = checkedStatus.status
            let status = MdocStatus(text)
            guard status == .valid || status == .noStatus else {
                return .failed(WalletError(code: .documentNotValid, protocolError: text, message: "the document's revocation status is \(text)"))
            }
            // Each document's own status; one alone has the combined one.
            let each = mdocs.enumerated().map { i, mdoc in
                var checked = mdoc
                let statuses = checkedStatus.statuses ?? []
                checked.status = i < statuses.count ? MdocStatus(statuses[i]) : status
                return checked
            }
            verifiedDocuments.withLock { $0 = each }
            return .verified(each[0])
        } catch is CancellationError {
            return .cancelled
        } catch let e as WalletError {
            return .failed(e)
        } catch {
            return .failed(WalletError(code: .internalError, message: "\(error)"))
        }
    }

    /// Ends the session now, from any state.
    public func cancel() {
        guard !state.isFinal else { return }
        cancelling.withLock { $0 = true }
        Task.detached { [self] in
            _ = try? await withTimeout(2) { await self.terminate() }
            finish(.cancelled)
        }
    }

    /// Set by cancel: the holder disconnecting on its termination
    /// doesn't end the session as a failure.
    private let cancelling = Locked(initialState: false)

    private func terminate() async {
        guard let message = try? decode(SendJSON.self, handle.terminate()).send else { return }
        if case .waitingForResponse = state { try? await transport.send(message) }
    }

    private func finish(_ final: State) {
        if cancelling.withLock({ $0 }) { guard case .cancelled = final else { return } }
        guard broadcast.update(final, if: { !$0.isFinal }) else { return }
        transport.close()
    }

    /// Checks the revocation status of the mdoc the session verified:
    /// fetches the Token Status List its MSO names, over https from a
    /// public address, and verifies it's signed under the certificate the
    /// MSO names or else under the CA that signed the document signer
    /// (ISO/IEC 18013-5 §12.3.6). Rely on the document only when this is
    /// `.valid` or `.noStatus`. Call it once the session is `.verified`, after
    /// the Bluetooth connection has closed; before, it throws `WalletError`
    /// `.wrongStep`. A failed fetch is `.network`, a list that doesn't
    /// verify `.protocol`; cancelling the calling Task cancels it. The list
    /// covers many documents, so fetching it doesn't tell its publisher
    /// which one was presented.
    public func checkStatus() async throws -> MdocStatus {
        let s = handle
        let json = try await OID4VC.cancellable { op in try OID4VC.call { s.checkStatus(op, error: $0) } }
        return MdocStatus(try decode(StatusJSON.self, json).status)
    }

    struct StatusJSON: Decodable {
        let status: String
        let statuses: [String]?
    }
}

/// A verified mdoc's revocation status, as
/// `ProximityReaderSession.checkStatus()` found it.
public enum MdocStatus: Equatable, Sendable {
    /// Neither revoked nor suspended.
    case valid
    /// Revoked for good (the list's `invalid`).
    case revoked
    /// Suspended, for now.
    case suspended
    /// A status the issuer's list defines itself, as "0x" and its value.
    case other(String)
    /// The MSO names no revocation list.
    case noStatus
    /// The MSO's status names no mechanism the reader knows, and no list
    /// says otherwise than valid: the status isn't known. Before
    /// OID4VCWallet 0.22.0, also an MSO naming an identifier list (ISO/IEC
    /// 18013-5 §12.3.6.4), which is now checked.
    case unknown

    init(_ text: String) {
        switch text {
        case "valid": self = .valid
        case "invalid": self = .revoked
        case "suspended": self = .suspended
        case "none": self = .noStatus
        case "unknown": self = .unknown
        default: self = .other(text)
        }
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
    /// The document signer certificate's subject common name, for display:
    /// any document signer under a trusted IACA can choose it, so decide
    /// on `issuerChain`.
    public let issuer: String
    /// The common name of the IACA it chains to, for display.
    public let trustAnchor: String
    /// When the mdoc's signed data (its MSO) became valid.
    public let validFrom: Date
    /// When it expires.
    public let validUntil: Date
    /// "signature" or "mac".
    public let deviceAuth: String
    /// The MSO's status list reference, unchecked: call
    /// `ProximityReaderSession.checkStatus()` before relying on the
    /// document.
    public let statusList: StatusListReference?
    /// The MSO's identifier list reference (ISO/IEC 18013-5 §12.3.6.4),
    /// unchecked, beside or instead of `statusList`: either may revoke
    /// the document, and `ProximityReaderSession.checkStatus()` checks
    /// both.
    public let identifierList: IdentifierListReference?
    /// The document signer's verified certificate path, leaf first,
    /// ending at the IACA in `ProximityReaderConfiguration.issuers.roots`
    /// it chains to: decide which issuers to accept on it.
    public let issuerChain: [SecCertificate]
    /// Its revocation status as the session checked it, `.valid` or
    /// `.noStatus`, when the configuration's `statusCheck` is `.check`;
    /// nil when it's `.decline`.
    public internal(set) var status: MdocStatus? = nil

    /// Where the mdoc's status is published: a Token Status List, and its index
    /// in it.
    public struct StatusListReference: Sendable {
        /// The status list's URL.
        public let uri: String
        /// The mdoc's index in the list.
        public let index: Int
    }

    /// Where the mdoc's revocation is published: an identifier list, and
    /// the mdoc's identifier, which the list names if it's revoked.
    public struct IdentifierListReference: Sendable {
        /// The identifier list's URL.
        public let uri: String
        /// The mdoc's identifier, as base64.
        public let id: String
    }
}

struct ReaderEventJSON: Decodable {
    let event: String
    let verified: VerifiedJSON?
    let documents: [VerifiedJSON]?
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
    let issuerChain: [Data]?

    /// `idx` is left out when 0, and an identifier list has none; a
    /// status list's carries the identifier list the MSO names too.
    struct Status: Decodable {
        let type: String?; let uri: String; let idx: Int?; let id: String?
        let identifierList: IdentifierList?

        struct IdentifierList: Decodable { let uri: String; let id: String }

        enum CodingKeys: String, CodingKey {
            case type, uri, idx, id
            case identifierList = "identifier_list"
        }
    }

    enum CodingKeys: String, CodingKey {
        case doctype, claims, issuer, status
        case deviceSignedClaims = "device_signed_claims", trustAnchor = "trust_anchor"
        case validFrom = "valid_from", validUntil = "valid_until", deviceAuth = "device_auth"
        case issuerChain = "issuer_chain"
    }

    var mdoc: VerifiedMdoc {
        let list = status.flatMap { $0.type == nil || $0.type == "status_list" ? $0 : nil }
        let identifiers = status.flatMap { s -> VerifiedMdoc.IdentifierListReference? in
            if s.type == "identifier_list", let id = s.id { return .init(uri: s.uri, id: id) }
            return s.identifierList.map { .init(uri: $0.uri, id: $0.id) }
        }
        return VerifiedMdoc(doctype: doctype, claims: claims, deviceSignedClaims: deviceSignedClaims, issuer: issuer,
                            trustAnchor: trustAnchor, validFrom: validFrom, validUntil: validUntil, deviceAuth: deviceAuth,
                            statusList: list.map { VerifiedMdoc.StatusListReference(uri: $0.uri, index: $0.idx ?? 0) },
                            identifierList: identifiers,
                            issuerChain: (issuerChain ?? []).compactMap { SecCertificateCreateWithData(nil, $0 as CFData) })
    }
}
