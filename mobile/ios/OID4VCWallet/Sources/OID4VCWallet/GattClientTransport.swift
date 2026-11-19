import CoreBluetooth
import Foundation
import os

/// The GATT client's side of a session (CBCentralManager): scans for
/// `serviceUUID`, connects, subscribes and starts the session. The
/// reader in mdoc peripheral server mode, and the holder in mdoc central
/// client mode, where it first reads the reader's Ident characteristic
/// (§8.3.3.1.1.4): a device whose Ident was read and isn't `ident`, or
/// that has none, is disconnected and passed over for a while
/// (`IgnoredDevices`), and the scan goes on. Any other failure, an Ident
/// read that fails or isn't answered included, is one failed attempt.
///
/// Neither the service UUID nor the Ident keeps out a device that never
/// saw the engagement: the UUID is in the clear in adverts, and anyone
/// can read the reader's Ident and serve it. Only Go can tell the peer
/// apart, once its message decrypts: `reject` passes over a device whose
/// message it rejected, and the next `connect`, or `receive`, connects
/// to another.
/// The app's Info.plist needs NSBluetoothAlwaysUsageDescription.
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
    /// The pending Ident read's value, nil when it failed.
    private var identRead: Pending<Data?>?
    private var identCharacteristic: CBCharacteristic?
    private var sessionStarted = false
    private var closed = false
    /// `reject` passed over the device: `receive` connects to another first.
    private var passedOver = false
    /// Devices whose Ident wasn't this session's reader's, or that had
    /// none: passed over for a while.
    private var ignored = IgnoredDevices<UUID>()

    private let poweredOn = Signal()
    /// This connection attempt's messages. Touched only on `queue`: a
    /// failed attempt ends its queue for good, so each attempt starts a
    /// new one.
    private var incoming = MessageQueue()
    private let sending = AsyncMutex()

    init(serviceUUID: UUID, characteristics: GattCharacteristics, ident: Data? = nil) {
        self.serviceUUID = CBUUID(nsuuid: serviceUUID)
        self.characteristics = characteristics
        self.ident = ident
        super.init()
    }

    /// Scans, connects and starts the session; after `reject`, with the
    /// next device advertising the service.
    func connect() async throws {
        try await connect(finding: nil)
    }

    /// `connect`, giving up when a scan finds no device advertising the
    /// service within `findWithin` seconds: the reader's holder, passed
    /// over a device, either still advertises, not having connected, or
    /// has gone. Each scan has the whole time, so a failed attempt's
    /// retry finds the same device again.
    func connect(findWithin: TimeInterval) async throws {
        try await connect(finding: findWithin)
    }

    private func connect(finding findWithin: TimeInterval?) async throws {
        queue.sync {
            if manager == nil { manager = CBCentralManager(delegate: self, queue: queue) }
        }
        try await poweredOn.wait()
        let attempts = 3
        var lastError: (any Error)?
        var attempt = 1
        while attempt <= attempts {
            // A device that failed before (disconnecting mid-setup,
            // leaving half a message) mustn't spoil this attempt.
            queue.sync {
                incoming = MessageQueue()
                reassembler = BleChunks.Reassembler()
            }
            try await scan(findWithin: findWithin)
            do {
                do {
                    try await connectToDiscovered()
                    try await start()
                    queue.sync { passedOver = false }
                } catch is ProximityTimeout {
                    // A device that stops answering mid-setup, its Ident
                    // read included: one failed attempt, as any other.
                    // A stall says nothing about which device it is, so
                    // it mustn't pass over the reader.
                    throw ProximityTransportError("the other device stopped answering")
                }
                return
            } catch let error as ProximityTransportError {
                // A closed session's "the session ended": never rescan.
                if queue.sync(execute: { closed }) { throw error }
                lastError = error
                let wrongReader = error.wrongReader
                queue.sync {
                    if let peripheral {
                        if wrongReader { ignored.ignore(peripheral.identifier) }
                        manager?.cancelPeripheralConnection(peripheral)
                    }
                    peripheral = nil
                }
                if wrongReader {
                    // Another session's reader: keep looking for this
                    // one's, until the caller's connect timeout.
                    log.info("passing over a device that isn't this session's reader")
                    continue
                }
                log.info("connecting failed (attempt \(attempt) of \(attempts)): \(error.message, privacy: .public)")
                attempt += 1
            }
        }
        throw lastError ?? ProximityTransportError("couldn't connect to the other device")
    }

    /// Scans until a peripheral advertising `serviceUUID` is found, or,
    /// with `findWithin`, throws once none is found in that time.
    private func scan(findWithin: TimeInterval?) async throws {
        let p = Pending<Void>()
        try queue.sync {
            guard !closed else { throw ProximityTransportError("the session ended") }
            discovered = nil
            found = p
            manager?.scanForPeripherals(withServices: [serviceUUID])
        }
        defer {
            queue.sync {
                manager?.stopScan()
                if found === p { found = nil }
            }
        }
        guard let findWithin else { return try await p.wait() }
        do {
            try await withTimeout(findWithin) { try await p.wait() }
        } catch is ProximityTimeout {
            throw ProximityTransportError("no other device advertises the service")
        }
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
        try await withTimeout(10) { try await p.wait() }
    }

    /// Finds the service and its characteristics, subscribes, and writes
    /// 0x01 to State.
    private func start() async throws {
        try await perform { $0.discoverServices([self.serviceUUID]) }
        try await perform { p in
            guard let service = p.services?.first(where: { $0.uuid == self.serviceUUID }) else {
                throw ProximityTransportError("the other device lacks the mdoc service", wrongReader: self.ident != nil)
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
                throw ProximityTransportError("the mdoc service lacks a characteristic", wrongReader: ident != nil)
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
    /// whose Ident differs, or that has no Ident to read, is refused
    /// (`wrongReader`), and passed over for a while; a read that fails is
    /// a failed attempt (`checkReaderIdent`).
    private func checkIdent(_ want: Data) async throws {
        let p = Pending<Data?>()
        try queue.sync {
            guard !closed, let peripheral else { throw ProximityTransportError("the session ended") }
            guard let c = identCharacteristic else { throw ProximityTransportError("the reader's service lacks Ident", wrongReader: true) }
            identRead = p
            peripheral.readValue(for: c)
        }
        let got = try await withTimeout(5) { try await p.wait() }
        try checkReaderIdent(got, want: want)
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
        try await withTimeout(5) { try await p.wait() }
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
            do {
                try await withTimeout(5) { try await wait.wait() }
            } catch is ProximityTimeout {
                // The transport's own error, as its callers expect: the
                // queue never drained, so the other device has gone.
                throw ProximityTransportError("a write couldn't be queued")
            }
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

    func receive() async throws -> Data {
        if queue.sync(execute: { passedOver }) { try await connect() }
        let messages = queue.sync { incoming }
        return try await messages.receive()
    }

    /// The device whose message `receive` returned last isn't this
    /// session's peer (Go rejected its message), or, for a reader, lost
    /// its link before answering: disconnect, and pass over it for a
    /// while (`IgnoredDevices`). The next `connect`, or `receive`,
    /// scans for and connects to another device advertising the service,
    /// within the caller's own time for it, as the GATT server transport
    /// goes on listening for others.
    func reject() {
        let rejected: MessageQueue? = queue.sync {
            guard !closed else { return nil }
            if let peripheral {
                ignored.ignore(peripheral.identifier)
                manager?.cancelPeripheralConnection(peripheral)
            }
            peripheral = nil
            state = nil
            client2Server = nil
            server2Client = nil
            identCharacteristic = nil
            sessionStarted = false
            passedOver = true
            return incoming
        }
        rejected?.end(ProximityTransportError("the device was passed over"))
    }

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
        queue.sync { incoming }.end(ended)
        poweredOn.fail(ended)
    }

    /// Ends this attempt with error: on `queue`.
    private func fail(_ error: ProximityTransportError) {
        incoming.end(error)
        connected?.resolve(.failure(error))
        operation?.resolve(.failure(error))
        // A device that disconnects during the Ident read or a write:
        // fail them now rather than at their timeouts.
        identRead?.resolve(.failure(error))
        readyToWrite?.resolve(.failure(error))
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

    /// Whether `p` is this attempt's device: a callback about another,
    /// one an earlier attempt gave up on, is ignored.
    private func isCurrent(_ p: CBPeripheral) -> Bool { p.identifier == peripheral?.identifier }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard isCurrent(peripheral) else { return }
        connected?.resolve(.success(()))
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: (any Error)?) {
        guard isCurrent(peripheral) else { return }
        connected?.resolve(.failure(ProximityTransportError("connecting failed: \(error?.localizedDescription ?? "")")))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: (any Error)?) {
        guard isCurrent(peripheral) else { return }
        fail(ProximityTransportError("the other device disconnected", peerEnded: sessionStarted))
    }

    // MARK: CBPeripheralDelegate, on `queue`

    private func finishOperation(_ peripheral: CBPeripheral, _ error: (any Error)?, _ what: String) {
        guard isCurrent(peripheral) else { return }
        let p = operation
        operation = nil
        if let error {
            p?.resolve(.failure(ProximityTransportError("\(what) failed: \(error.localizedDescription)")))
        } else {
            p?.resolve(.success(()))
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        finishOperation(peripheral, error, "discovering services")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: (any Error)?) {
        finishOperation(peripheral, error, "discovering characteristics")
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: (any Error)?) {
        finishOperation(peripheral, error, "subscribing")
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        guard isCurrent(peripheral) else { return }
        let p = readyToWrite
        readyToWrite = nil
        p?.resolve(.success(()))
    }

    /// Delivers the pending Ident read's result.
    private func identValue(_ value: Data?, _ error: (any Error)?) {
        guard let p = identRead else { return }
        identRead = nil
        p.resolve(.success(error == nil ? value : nil))
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: (any Error)?) {
        guard isCurrent(peripheral) else { return }
        if characteristic.uuid == characteristics.ident {
            identValue(characteristic.value, error)
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
}
