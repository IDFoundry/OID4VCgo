import CoreBluetooth
import Foundation

/// The GATT server's side of a session (CBPeripheralManager): advertises
/// `serviceUUID` and serves `characteristics`. The holder in mdoc
/// peripheral server mode, or the reader in mdoc central client mode
/// (serving `ident`). The app's Info.plist needs
/// NSBluetoothAlwaysUsageDescription.
///
/// Any device nearby can start a session (State 0x01), since the service
/// UUID is in the clear in adverts. Each one that does is a candidate,
/// and `receive` returns each candidate's first message, while it keeps
/// advertising, until `commit` picks the device whose message Go
/// accepted; `reject` drops one Go rejected. Only then does it stop
/// advertising and ignore the others.
///
/// iOS doesn't tell a peripheral about disconnections: the central
/// unsubscribing from Server2Client is taken as the other side ending.
final class GattServerTransport: NSObject, ProximityTransport, CBPeripheralManagerDelegate, @unchecked Sendable {
    /// How many devices may start a session at once before one is
    /// committed to: a new one displaces the oldest still silent.
    static let maxCandidates = 8

    /// A device that started a session, before one was committed to.
    private struct Candidate {
        let central: CBCentral
        var reassembler = BleChunks.Reassembler()
        /// Whether its first message was queued: it sends no more before
        /// a reply, so later ones are dropped.
        var delivered = false
    }

    /// A candidate's first message.
    private struct FirstMessage: Sendable {
        let central: UUID
        let message: Data
    }

    private let serviceUUID: CBUUID
    private let characteristics: GattCharacteristics
    private let ident: Data?
    private let queue = DispatchQueue(label: "dev.idfoundry.oid4vcwallet.gatt-server")

    // Touched only on `queue`.
    private var manager: CBPeripheralManager?
    private var state: CBMutableCharacteristic?
    private var server2Client: CBMutableCharacteristic?
    /// The device committed to (`commit`): the reader.
    private var peer: CBCentral?
    private var reassembler = BleChunks.Reassembler()
    /// Devices that started a session (State 0x01) before one was
    /// committed to, oldest first: any of them may be the reader.
    private var candidates: [Candidate] = []
    /// The candidate whose first message `receive` returned last.
    private var pending: UUID?
    /// Devices dropped (`reject`, or a malformed chunk): never again.
    private var refused = Set<UUID>()
    private var readyToUpdate: Pending<Void>?
    private var closed = false
    /// What ended the session, the first time: no chunk is sent after it.
    private var failure: ProximityTransportError?

    private let poweredOn = Signal()
    private let serviceAdded = Signal()
    private let advertising = Signal()
    private let started = Signal()
    /// The committed peer's messages.
    private let incoming = MessageQueue()
    /// Each candidate's first message, until one is committed to.
    private let firsts = BoundedQueue<FirstMessage>(capacity: 2 * maxCandidates)
    private let sending = AsyncMutex()

    init(serviceUUID: UUID, characteristics: GattCharacteristics, ident: Data? = nil) {
        self.serviceUUID = CBUUID(nsuuid: serviceUUID)
        self.characteristics = characteristics
        self.ident = ident
        super.init()
    }

    func connect() async throws {
        queue.sync { manager = CBPeripheralManager(delegate: self, queue: queue) }
        try await poweredOn.wait()
        queue.sync {
            guard let manager else { return }
            manager.add(service())
        }
        try await serviceAdded.wait()
        queue.sync {
            manager?.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUUID]])
        }
        try await advertising.wait()
        try await started.wait()
    }

    /// The service of §8.3.3.1.1.4's Table 11.
    private func service() -> CBMutableService {
        let service = CBMutableService(type: serviceUUID, primary: true)
        let st = CBMutableCharacteristic(type: characteristics.state, properties: [.notify, .writeWithoutResponse], value: nil, permissions: [.writeable])
        let c2s = CBMutableCharacteristic(type: characteristics.client2Server, properties: [.writeWithoutResponse], value: nil, permissions: [.writeable])
        let s2c = CBMutableCharacteristic(type: characteristics.server2Client, properties: [.notify], value: nil, permissions: [])
        var all = [st, c2s, s2c]
        if let identUUID = characteristics.ident, let ident {
            // A static value: CoreBluetooth answers reads itself.
            all.append(CBMutableCharacteristic(type: identUUID, properties: [.read], value: ident, permissions: [.readable]))
        }
        service.characteristics = all
        state = st
        server2Client = s2c
        return service
    }

    func send(_ message: Data) async throws {
        try await sending.locked {
            let size: Int = try queue.sync {
                guard let peer else { throw ProximityTransportError("no device connected") }
                return min(BleChunks.maxCharacteristicSize, peer.maximumUpdateValueLength)
            }
            for chunk in BleChunks.split(message, size: size) {
                try await update(chunk)
            }
        }
    }

    /// Notifies `value` on Server2Client, waiting while the queue is full.
    private func update(_ value: Data) async throws {
        while true {
            let wait: Pending<Void>? = try queue.sync {
                guard !closed, let manager, let peer, let server2Client else { throw ProximityTransportError("the session ended") }
                // A reader that unsubscribed or ended the session gets no
                // more chunks: updateValue could still take one while the
                // queue has room, and the response would seem sent.
                if let failure { throw failure }
                if manager.updateValue(value, for: server2Client, onSubscribedCentrals: [peer]) { return nil }
                let p = Pending<Void>()
                readyToUpdate = p
                return p
            }
            guard let wait else { return }
            do {
                try await withTimeout(5) { try await wait.wait() }
            } catch is ProximityTimeout {
                // The transport's own error, as its callers expect: the
                // queue never drained, so the reader has gone.
                throw ProximityTransportError("a notification couldn't be queued")
            }
        }
    }

    func receive() async throws -> Data {
        if queue.sync(execute: { peer != nil }) { return try await incoming.receive() }
        let first = try await firsts.receive()
        queue.sync { pending = first.central }
        return first.message
    }

    func reject() {
        queue.sync {
            guard peer == nil, let id = pending else { return }
            pending = nil
            drop(id, refuse: true)
        }
    }

    func commit() {
        queue.sync {
            guard peer == nil else { return }
            // The device whose message Go accepted; before any (a reader
            // that speaks first), the first to start a session.
            let chosen = pending.map { id in candidates.first { $0.central.identifier == id } } ?? candidates.first
            guard let chosen else {
                fail(ProximityTransportError("the other device disconnected", peerEnded: true))
                return
            }
            // One reader per session: stop being found, and ignore the
            // others from now on.
            peer = chosen.central
            candidates = []
            pending = nil
            manager?.stopAdvertising()
        }
    }

    /// Forgets candidate `id`, and with `refuse`, ignores it from now on:
    /// on `queue`.
    private func drop(_ id: UUID, refuse: Bool) {
        candidates.removeAll { $0.central.identifier == id }
        if refuse { refused.insert(id) }
    }

    func close() {
        queue.sync {
            guard !closed else { return }
            closed = true
            if let manager {
                if let state, let peer {
                    // Best effort: the other side may be gone already.
                    _ = manager.updateValue(GattCharacteristics.end, for: state, onSubscribedCentrals: [peer])
                }
                manager.stopAdvertising()
                manager.removeAllServices()
                manager.delegate = nil
            }
            readyToUpdate?.resolve(.failure(ProximityTransportError("the session ended")))
        }
        let ended = ProximityTransportError("the session ended", peerEnded: true)
        incoming.end(ended)
        firsts.end(ended)
        started.fail(ended)
        poweredOn.fail(ended)
    }

    /// Ends the session with error: on `queue`. The first error is the
    /// one a later send throws.
    private func fail(_ error: ProximityTransportError) {
        if failure == nil { failure = error }
        incoming.end(error)
        firsts.end(error)
        started.fail(error)
        // A send waiting for room in the queue: fail it now rather than
        // at its timeout. Its chunk was never queued.
        readyToUpdate?.resolve(.failure(error))
        readyToUpdate = nil
    }

    // MARK: CBPeripheralManagerDelegate, on `queue`

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            poweredOn.signal()
        case .unauthorized:
            let e = ProximityTransportError("Bluetooth isn't allowed for this app", bluetoothUnavailable: true)
            poweredOn.fail(e)
            fail(e)
        case .poweredOff, .unsupported:
            let e = ProximityTransportError("Bluetooth is off", bluetoothUnavailable: true)
            poweredOn.fail(e)
            fail(e)
        default:
            break
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: (any Error)?) {
        if let error {
            serviceAdded.fail(ProximityTransportError("adding the GATT service failed: \(error.localizedDescription)"))
        } else {
            serviceAdded.signal()
        }
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: (any Error)?) {
        if let error {
            advertising.fail(ProximityTransportError("BLE advertising failed: \(error.localizedDescription)"))
        } else {
            advertising.signal()
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        // A candidate is a device that starts a session (a State write
        // of 0x01), not one that subscribes: any device nearby can
        // subscribe.
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard characteristic.uuid == characteristics.server2Client else { return }
        if let peer {
            guard central.identifier == peer.identifier else { return }
            fail(ProximityTransportError("the other device disconnected", peerEnded: true))
        } else {
            drop(central.identifier, refuse: false)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            guard let value = request.value else { continue }
            if let peer {
                if request.central.identifier == peer.identifier { peerWrote(value, to: request.characteristic.uuid) }
            } else {
                candidateWrote(value, to: request.characteristic.uuid, from: request.central)
            }
        }
        // Writes without response need no answer; any other gets success.
        if let first = requests.first { peripheral.respond(to: first, withResult: .success) }
    }

    /// The committed peer wrote `value`: on `queue`.
    private func peerWrote(_ value: Data, to characteristic: CBUUID) {
        switch characteristic {
        case characteristics.state:
            if value == GattCharacteristics.end {
                fail(ProximityTransportError("the other device ended the session", peerEnded: true))
            }
        case characteristics.client2Server:
            do {
                if let message = try reassembler.add(value), !incoming.push(message) {
                    fail(ProximityTransportError("too many unread messages from the other device"))
                }
            } catch {
                fail(ProximityTransportError("a malformed chunk: \(error)"))
            }
        default:
            break
        }
    }

    /// `central` wrote `value` before a peer was committed to: on
    /// `queue`. A State write of 0x01 makes it a candidate, and its first
    /// whole message goes to `receive`. A malformed chunk refuses it, and
    /// 0x02 drops it, ending nothing: it may not be the reader.
    private func candidateWrote(_ value: Data, to characteristic: CBUUID, from central: CBCentral) {
        let id = central.identifier
        guard !refused.contains(id) else { return }
        switch characteristic {
        case characteristics.state where value == GattCharacteristics.start:
            addCandidate(central)
            started.signal()
        case characteristics.state where value == GattCharacteristics.end:
            drop(id, refuse: false)
        case characteristics.client2Server:
            candidateChunk(value, from: id)
        default:
            break
        }
    }

    /// Makes `central` a candidate: on `queue`. With `maxCandidates`
    /// already, the oldest that has sent no message yet makes way, so
    /// devices that start sessions and stay silent can't keep the reader
    /// out.
    private func addCandidate(_ central: CBCentral) {
        guard !candidates.contains(where: { $0.central.identifier == central.identifier }) else { return }
        if candidates.count >= Self.maxCandidates {
            guard let silent = candidates.firstIndex(where: { !$0.delivered }) else { return }
            candidates.remove(at: silent)
        }
        candidates.append(Candidate(central: central))
    }

    /// Adds a candidate's chunk, queuing its first whole message: on
    /// `queue`.
    private func candidateChunk(_ value: Data, from id: UUID) {
        guard let i = candidates.firstIndex(where: { $0.central.identifier == id }), !candidates[i].delivered else { return }
        do {
            guard let message = try candidates[i].reassembler.add(value) else { return }
            candidates[i].delivered = true
            if !firsts.push(FirstMessage(central: id, message: message)) { drop(id, refuse: true) }
        } catch {
            drop(id, refuse: true)
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        let p = readyToUpdate
        readyToUpdate = nil
        p?.resolve(.success(()))
    }
}

/// A mutual exclusion lock for async code: one `locked` body at a time.
final class AsyncMutex: @unchecked Sendable {
    private let lock = NSLock()
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func locked<T: Sendable>(_ body: () async throws -> T) async throws -> T {
        await acquire()
        defer { release() }
        return try await body()
    }

    private func acquire() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock()
            if held {
                waiters.append(c)
                lock.unlock()
            } else {
                held = true
                lock.unlock()
                c.resume()
            }
        }
    }

    private func release() {
        lock.lock()
        if waiters.isEmpty {
            held = false
            lock.unlock()
        } else {
            let next = waiters.removeFirst()
            lock.unlock()
            next.resume()
        }
    }
}
