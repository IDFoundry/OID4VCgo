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
/// advertising and ignore the others. `BleCandidates` keeps the list.
///
/// iOS doesn't tell a peripheral about disconnections: the central
/// unsubscribing from Server2Client is taken as the other side ending.
final class GattServerTransport: NSObject, ProximityTransport, CBPeripheralManagerDelegate, @unchecked Sendable {
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
    /// committed to: any of them may be the reader.
    private var candidates = BleCandidates<UUID>()
    /// The centrals listed in `candidates`, to commit to one.
    private var centrals: [UUID: CBCentral] = [:]
    /// The candidate whose first message `receive` returned last.
    private var pending: UUID?
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
    private let firsts = BoundedQueue<FirstMessage>(capacity: BleCandidates<UUID>.maxFirstMessages)
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
            guard let chosen = candidates.chosen(pending: pending).flatMap({ centrals[$0] }) else {
                fail(ProximityTransportError("the other device disconnected", peerEnded: true))
                return
            }
            // One reader per session: stop being found, and ignore the
            // others from now on.
            peer = chosen
            candidates.removeAll()
            centrals = [:]
            pending = nil
            manager?.stopAdvertising()
        }
    }

    /// Forgets candidate `id`, and with `refuse`, ignores it from now on:
    /// on `queue`.
    private func drop(_ id: UUID, refuse: Bool) {
        if refuse { candidates.refuse(id) } else { candidates.end(id) }
        if !candidates.contains(id) { centrals[id] = nil }
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
        guard !candidates.isRefused(id) else { return }
        switch characteristic {
        case characteristics.state where value == GattCharacteristics.start:
            if candidates.start(id) {
                // Keep only the listed ones: a newcomer may have displaced one.
                centrals = centrals.filter { candidates.contains($0.key) }
                centrals[id] = central
            }
            started.signal()
        case characteristics.state where value == GattCharacteristics.end:
            drop(id, refuse: false)
        case characteristics.client2Server:
            candidateChunk(value, from: id)
        default:
            break
        }
    }

    /// Adds a candidate's chunk, queuing its first whole message: on
    /// `queue`. With the queue full, that message is refused, not the
    /// ones before it.
    private func candidateChunk(_ value: Data, from id: UUID) {
        candidates.chunk(value, from: id, queueingOn: firsts) { FirstMessage(central: id, message: $0) }
        // It may have been refused, or have displaced others.
        if centrals.count > candidates.count { centrals = centrals.filter { candidates.contains($0.key) } }
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
