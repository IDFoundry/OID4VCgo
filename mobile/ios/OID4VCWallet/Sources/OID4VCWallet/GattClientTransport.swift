import CoreBluetooth
import Foundation
import os

/// The GATT client's side of a session (CBCentralManager): scans for
/// `serviceUUID`, connects, subscribes and starts the session. The
/// reader in mdoc peripheral server mode, and the holder in mdoc central
/// client mode, where it first reads the reader's Ident characteristic
/// and fails unless it's `ident` (§8.3.3.1.1.4). The app's Info.plist
/// needs NSBluetoothAlwaysUsageDescription.
final class GattClientTransport: NSObject, ProximityTransport, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {
    private let serviceUUID: CBUUID
    private let characteristics: GattCharacteristics
    private let ident: Data?
    private let queue = DispatchQueue(label: "dev.idfoundry.oid4vcwallet.gatt-client")
    private let log = Logger(subsystem: "dev.idfoundry.oid4vcwallet", category: "proximity")

    // Touched only on `queue`.
    private var manager: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var state: CBCharacteristic?
    private var client2Server: CBCharacteristic?
    private var server2Client: CBCharacteristic?
    private var reassembler = BleChunks.Reassembler()
    private var found: Pending<Void>?
    private var discovered: CBPeripheral?
    private var connected: Pending<Void>?
    private var operation: Pending<Void>?
    private var readyToWrite: Pending<Void>?
    private var identRead: Pending<Data>?
    private var identCharacteristic: CBCharacteristic?
    private var sessionStarted = false
    private var closed = false
    /// Devices whose Ident wasn't this session's reader's: never again.
    private var ignored = Set<UUID>()

    private let poweredOn = Signal()
    private let incoming = MessageQueue()
    private let sending = AsyncMutex()

    init(serviceUUID: UUID, characteristics: GattCharacteristics, ident: Data? = nil) {
        self.serviceUUID = CBUUID(nsuuid: serviceUUID)
        self.characteristics = characteristics
        self.ident = ident
        super.init()
    }

    func connect() async throws {
        queue.sync { manager = CBCentralManager(delegate: self, queue: queue) }
        try await poweredOn.wait()
        let attempts = 3
        var lastError: (any Error)?
        var attempt = 1
        while attempt <= attempts {
            try await scan()
            do {
                try await connectToDiscovered()
                try await start()
                return
            } catch let error as ProximityTransportError {
                // A closed session's "the session ended": never rescan.
                if queue.sync(execute: { closed }) { throw error }
                lastError = error
                let wrongReader = error.wrongReader
                queue.sync {
                    if let peripheral {
                        if wrongReader { ignored.insert(peripheral.identifier) }
                        manager?.cancelPeripheralConnection(peripheral)
                    }
                    peripheral = nil
                }
                if wrongReader {
                    // Another session's reader: keep looking for this
                    // one's, until the caller's connect timeout.
                    log.info("ignoring a device that isn't this session's reader")
                    continue
                }
                log.info("connecting failed (attempt \(attempt) of \(attempts)): \(error.message, privacy: .public)")
                attempt += 1
            }
        }
        throw lastError ?? ProximityTransportError("couldn't connect to the other device")
    }

    /// Scans until a peripheral advertising `serviceUUID` is found.
    private func scan() async throws {
        let p = Pending<Void>()
        try queue.sync {
            guard !closed else { throw ProximityTransportError("the session ended") }
            discovered = nil
            found = p
            manager?.scanForPeripherals(withServices: [serviceUUID])
        }
        defer { queue.sync { manager?.stopScan() } }
        try await p.wait()
    }

    /// Connects to the peripheral `scan` found.
    private func connectToDiscovered() async throws {
        let p = Pending<Void>()
        try queue.sync {
            guard !closed else { throw ProximityTransportError("the session ended") }
            guard let device = discovered else { throw ProximityTransportError("nothing found") }
            peripheral = device
            device.delegate = self
            connected = p
            manager?.connect(device)
        }
        try await withTimeout(.seconds(10)) { try await p.wait() }
    }

    /// Finds the service and its characteristics, subscribes, and writes
    /// 0x01 to State.
    private func start() async throws {
        try await perform { $0.discoverServices([self.serviceUUID]) }
        try await perform { p in
            guard let service = p.services?.first(where: { $0.uuid == self.serviceUUID }) else {
                throw ProximityTransportError("the other device lacks the mdoc service")
            }
            var wanted = [self.characteristics.state, self.characteristics.client2Server, self.characteristics.server2Client]
            if self.ident != nil, let id = self.characteristics.ident { wanted.append(id) }
            p.discoverCharacteristics(wanted, for: service)
        }
        try queue.sync {
            let chars = peripheral?.services?.first(where: { $0.uuid == serviceUUID })?.characteristics ?? []
            state = chars.first { $0.uuid == characteristics.state }
            client2Server = chars.first { $0.uuid == characteristics.client2Server }
            server2Client = chars.first { $0.uuid == characteristics.server2Client }
            if state == nil || client2Server == nil || server2Client == nil {
                throw ProximityTransportError("the mdoc service lacks a characteristic")
            }
            identCharacteristic = chars.first { $0.uuid == characteristics.ident }
        }
        if let ident { try await checkIdent(ident) }
        try await perform { p in p.setNotifyValue(true, for: self.server2Client!) }
        try await perform { p in p.setNotifyValue(true, for: self.state!) }
        try await write(GattCharacteristics.start, to: { self.state })
        queue.sync { sessionStarted = true }
    }

    /// Reads the reader's Ident: a device advertising the service UUID
    /// that isn't this session's reader fails the session.
    private func checkIdent(_ want: Data) async throws {
        let p = Pending<Data>()
        try queue.sync {
            guard !closed, let peripheral else { throw ProximityTransportError("the session ended") }
            guard let c = identCharacteristic else { throw ProximityTransportError("the reader's service lacks Ident") }
            identRead = p
            peripheral.readValue(for: c)
        }
        let got = try await withTimeout(.seconds(5)) { try await p.wait() }
        guard got == want else {
            throw ProximityTransportError("the device found isn't this session's reader (its Ident differs)", wrongReader: true)
        }
    }

    /// Starts one GATT operation on the peripheral and waits for its
    /// callback.
    private func perform(_ start: @escaping (CBPeripheral) throws -> Void) async throws {
        let p = Pending<Void>()
        try queue.sync {
            guard !closed, let peripheral else { throw ProximityTransportError("the session ended") }
            operation = p
            try start(peripheral)
        }
        try await withTimeout(.seconds(5)) { try await p.wait() }
    }

    /// Writes `value` without response, waiting while the queue is full.
    private func write(_ value: Data, to characteristic: @escaping () -> CBCharacteristic?) async throws {
        while true {
            let wait: Pending<Void>? = try queue.sync {
                guard !closed, let peripheral, let c = characteristic() else { throw ProximityTransportError("the session ended") }
                if peripheral.canSendWriteWithoutResponse {
                    peripheral.writeValue(value, for: c, type: .withoutResponse)
                    return nil
                }
                let p = Pending<Void>()
                readyToWrite = p
                return p
            }
            guard let wait else { return }
            try await withTimeout(.seconds(5)) { try await wait.wait() }
        }
    }

    func send(_ message: Data) async throws {
        try await sending.locked {
            let size: Int = try queue.sync {
                guard let peripheral else { throw ProximityTransportError("not connected") }
                return min(BleChunks.maxCharacteristicSize, peripheral.maximumWriteValueLength(for: .withoutResponse))
            }
            for chunk in BleChunks.split(message, size: size) {
                try await write(chunk, to: { self.client2Server })
            }
        }
    }

    func receive() async throws -> Data { try await incoming.receive() }

    func close() {
        queue.sync {
            guard !closed else { return }
            closed = true
            if let peripheral {
                if sessionStarted, let state, peripheral.state == .connected {
                    // Best effort, without waiting.
                    peripheral.writeValue(GattCharacteristics.end, for: state, type: .withoutResponse)
                }
                manager?.cancelPeripheralConnection(peripheral)
            }
            manager?.stopScan()
            let ended = ProximityTransportError("the session ended")
            found?.resolve(.failure(ended))
            connected?.resolve(.failure(ended))
            operation?.resolve(.failure(ended))
            readyToWrite?.resolve(.failure(ended))
            identRead?.resolve(.failure(ended))
        }
        let ended = ProximityTransportError("the session ended", peerEnded: true)
        incoming.end(ended)
        poweredOn.fail(ended)
    }

    private func fail(_ error: ProximityTransportError) {
        incoming.end(error)
        connected?.resolve(.failure(error))
        operation?.resolve(.failure(error))
    }

    // MARK: CBCentralManagerDelegate, on `queue`

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            poweredOn.signal()
        case .unauthorized:
            poweredOn.fail(ProximityTransportError("Bluetooth isn't allowed for this app", bluetoothUnavailable: true))
        case .poweredOff, .unsupported:
            let e = ProximityTransportError("Bluetooth is off", bluetoothUnavailable: true)
            poweredOn.fail(e)
            fail(e)
        default:
            break
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi: NSNumber) {
        guard let p = found, !ignored.contains(peripheral.identifier) else { return }
        found = nil
        discovered = peripheral
        p.resolve(.success(()))
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connected?.resolve(.success(()))
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: (any Error)?) {
        connected?.resolve(.failure(ProximityTransportError("connecting failed: \(error?.localizedDescription ?? "")")))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: (any Error)?) {
        guard peripheral.identifier == self.peripheral?.identifier else { return }
        fail(ProximityTransportError("the other device disconnected", peerEnded: sessionStarted))
    }

    // MARK: CBPeripheralDelegate, on `queue`

    private func finishOperation(_ error: (any Error)?, _ what: String) {
        let p = operation
        operation = nil
        if let error {
            p?.resolve(.failure(ProximityTransportError("\(what) failed: \(error.localizedDescription)")))
        } else {
            p?.resolve(.success(()))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        finishOperation(error, "discovering services")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: (any Error)?) {
        finishOperation(error, "discovering characteristics")
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: (any Error)?) {
        finishOperation(error, "subscribing")
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        let p = readyToWrite
        readyToWrite = nil
        p?.resolve(.success(()))
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        if characteristic.uuid == characteristics.ident, let p = identRead {
            identRead = nil
            if let value = characteristic.value, error == nil {
                p.resolve(.success(value))
            } else {
                p.resolve(.failure(ProximityTransportError("couldn't read the reader's Ident")))
            }
            return
        }
        guard error == nil, let value = characteristic.value else { return }
        switch characteristic.uuid {
        case characteristics.state:
            if value == GattCharacteristics.end {
                fail(ProximityTransportError("the other device ended the session", peerEnded: true))
            }
        case characteristics.server2Client:
            do {
                if let message = try reassembler.add(value) { incoming.push(message) }
            } catch {
                fail(ProximityTransportError("a malformed chunk: \(error)"))
            }
        default:
            break
        }
    }
}
