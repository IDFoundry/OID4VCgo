import CoreBluetooth
import Foundation

/// The GATT server's side of a session (CBPeripheralManager): advertises
/// `serviceUUID`, serves `characteristics`, and takes the first central
/// that subscribes. The holder in mdoc peripheral server mode, or the
/// reader in mdoc central client mode (serving `ident`). The app's
/// Info.plist needs NSBluetoothAlwaysUsageDescription.
///
/// iOS doesn't tell a peripheral about disconnections: the central
/// unsubscribing from Server2Client is taken as the other side ending.
final class GattServerTransport: NSObject, ProximityTransport, CBPeripheralManagerDelegate, @unchecked Sendable {
    private let serviceUUID: CBUUID
    private let characteristics: GattCharacteristics
    private let ident: Data?
    private let queue = DispatchQueue(label: "dev.idfoundry.oid4vcwallet.gatt-server")

    // Touched only on `queue`.
    private var manager: CBPeripheralManager?
    private var state: CBMutableCharacteristic?
    private var server2Client: CBMutableCharacteristic?
    private var peer: CBCentral?
    private var reassembler = BleChunks.Reassembler()
    private var readyToUpdate: Pending<Void>?
    private var sessionStarted = false
    private var closed = false

    private let poweredOn = Signal()
    private let serviceAdded = Signal()
    private let advertising = Signal()
    private let started = Signal()
    private let incoming = MessageQueue()
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
                if manager.updateValue(value, for: server2Client, onSubscribedCentrals: [peer]) { return nil }
                let p = Pending<Void>()
                readyToUpdate = p
                return p
            }
            guard let wait else { return }
            try await withTimeout(.seconds(5)) { try await wait.wait() }
        }
    }

    func receive() async throws -> Data { try await incoming.receive() }

    func close() {
        queue.sync {
            guard !closed else { return }
            closed = true
            if let manager {
                if sessionStarted, let state, let peer {
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
        started.fail(ended)
        poweredOn.fail(ended)
    }

    private func fail(_ error: ProximityTransportError) {
        incoming.end(error)
        started.fail(error)
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
        if peer == nil {
            peer = central
            // One reader per session: stop being found.
            peripheral.stopAdvertising()
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        guard central.identifier == peer?.identifier, characteristic.uuid == characteristics.server2Client else { return }
        fail(ProximityTransportError("the other device disconnected", peerEnded: true))
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            if peer == nil { peer = request.central; peripheral.stopAdvertising() }
            guard request.central.identifier == peer?.identifier, let value = request.value else { continue }
            switch request.characteristic.uuid {
            case characteristics.state:
                if value == GattCharacteristics.start {
                    sessionStarted = true
                    started.signal()
                } else if value == GattCharacteristics.end {
                    fail(ProximityTransportError("the other device ended the session", peerEnded: true))
                }
            case characteristics.client2Server:
                do {
                    if let message = try reassembler.add(value) { incoming.push(message) }
                } catch {
                    fail(ProximityTransportError("a malformed chunk: \(error)"))
                }
            default:
                break
            }
        }
        // Writes without response need no answer; any other gets success.
        if let first = requests.first { peripheral.respond(to: first, withResult: .success) }
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
