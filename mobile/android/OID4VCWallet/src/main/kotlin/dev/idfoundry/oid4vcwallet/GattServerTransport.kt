package dev.idfoundry.oid4vcwallet

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.util.UUID

/**
 * The GATT server's side of a session: advertises [serviceUUID] and
 * serves [characteristics]. The holder in mdoc peripheral server mode,
 * or the reader in mdoc central client mode (serving [ident]).
 * Bluetooth permissions are the caller's to have checked.
 *
 * Any device nearby can start a session (State 0x01), since the service
 * UUID is in the clear in adverts. Each one that does is a candidate,
 * and [receive] returns each candidate's first message, while it keeps
 * advertising, until [commit] picks the device whose message Go
 * accepted; [reject] drops one Go rejected. Only then does it stop
 * advertising and disconnect the others.
 */
@SuppressLint("MissingPermission")
internal class GattServerTransport(
    private val context: Context,
    private val serviceUUID: UUID,
    private val characteristics: GattCharacteristics,
    private val ident: ByteArray? = null,
) : ProximityTransport {
    private val manager = context.getSystemService(BluetoothManager::class.java)
        ?: throw ProximityTransportException("this device has no Bluetooth", bluetoothUnavailable = true)

    private var server: BluetoothGattServer? = null
    private lateinit var state: BluetoothGattCharacteristic
    private lateinit var server2Client: BluetoothGattCharacteristic

    private val serviceAdded = CompletableDeferred<Unit>()
    private val advertising = CompletableDeferred<Unit>()
    private val started = CompletableDeferred<Unit>()
    /** The committed peer's messages. */
    private val incoming = Channel<ByteArray>(INCOMING_MESSAGE_CAPACITY)
    /** Each candidate's first message, until one is committed to. */
    private val firsts = Channel<Pair<BluetoothDevice, ByteArray>>(2 * MAX_CANDIDATES)
    private val notified = Channel<Int>(Channel.CONFLATED)
    private val sending = Mutex()
    private val reassembler = BleChunks.Reassembler()

    /** A device that started a session, before one was committed to. */
    private class Candidate {
        val reassembler = BleChunks.Reassembler()
        /** Whether its first message was queued: it sends no more before a reply. */
        var delivered = false
    }

    /** Devices that started a session, oldest first; under this object's lock. */
    private val candidates = LinkedHashMap<BluetoothDevice, Candidate>()
    /** The candidate whose first message [receive] returned last; under the lock. */
    private var pending: BluetoothDevice? = null
    /** Devices dropped ([reject], or a malformed chunk): never again; under the lock. */
    private val refused = HashSet<BluetoothDevice>()

    /** The device committed to ([commit]): the reader. */
    @Volatile private var peer: BluetoothDevice? = null
    /** Each connected device's MTU, until one becomes the peer. */
    private val mtus = java.util.concurrent.ConcurrentHashMap<BluetoothDevice, Int>()
    @Volatile private var mtu = BleChunks.DEFAULT_MTU
    @Volatile private var closed = false
    /** Why the session failed, once it has. */
    @Volatile private var failure: ProximityTransportException? = null
    private val bluetoothOff = BluetoothOffWatch { fail(it) }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
            advertising.complete(Unit)
        }

        override fun onStartFailure(errorCode: Int) {
            advertising.completeExceptionally(ProximityTransportException("BLE advertising failed ($errorCode)"))
        }
    }

    private val callback = object : BluetoothGattServerCallback() {
        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            if (status == BluetoothGatt.GATT_SUCCESS) {
                serviceAdded.complete(Unit)
            } else {
                serviceAdded.completeExceptionally(ProximityTransportException("adding the GATT service failed ($status)"))
            }
        }

        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            Log.d(TAG, "connection state $newState (status $status)")
            when (newState) {
                // A candidate is a device that starts a session (a State
                // write of 0x01), not one that connects: any device
                // nearby can connect (Android reports other apps' LE
                // connections here too). Once committed, or refused, a
                // device is let go.
                BluetoothProfile.STATE_CONNECTED -> if (unwanted(device)) {
                    server?.cancelConnection(device)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    mtus.remove(device)
                    if (device == peer) fail(disconnectionFailure(manager)) else synchronized(this@GattServerTransport) { candidates.remove(device) }
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            mtus[device] = mtu
            if (device == peer) this@GattServerTransport.mtu = mtu
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice, requestId: Int, descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
        ) {
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
        }

        override fun onCharacteristicReadRequest(device: BluetoothDevice, requestId: Int, offset: Int, characteristic: BluetoothGattCharacteristic) {
            val value = if (characteristic.uuid == characteristics.ident && ident != null) ident else null
            if (value == null || offset > value.size) {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_READ_NOT_PERMITTED, offset, null)
            } else {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value.copyOfRange(offset, value.size))
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int, characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean, offset: Int, value: ByteArray?,
        ) {
            if (responseNeeded) server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            if (value == null) return
            val p = peer
            if (p == null) {
                candidateWrote(device, characteristic.uuid, value)
            } else if (device == p) {
                peerWrote(characteristic.uuid, value)
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            notified.trySend(status)
        }
    }

    /** Whether [device] is to be let go: another once one is committed to, or one refused. */
    private fun unwanted(device: BluetoothDevice): Boolean {
        val p = peer
        return if (p != null) device != p else synchronized(this) { device in refused }
    }

    /** The committed peer wrote [value] to [uuid]. */
    private fun peerWrote(uuid: UUID, value: ByteArray) {
        when (uuid) {
            characteristics.state -> if (value.contentEquals(byteArrayOf(GattCharacteristics.STATE_END))) {
                fail(ProximityTransportException("the other device ended the session", peerEnded = true))
            }
            characteristics.client2Server -> try {
                reassembler.add(value)?.let { message ->
                    val sent = incoming.trySend(message)
                    if (sent.isFailure && !sent.isClosed) fail(ProximityTransportException(TOO_MANY_MESSAGES))
                }
            } catch (e: IOException) {
                fail(ProximityTransportException("a malformed chunk: ${e.message}", cause = e))
            }
        }
    }

    /**
     * [device] wrote [value] to [uuid] before a peer was committed to. A
     * State write of 0x01 makes it a candidate, and its first whole
     * message goes to [receive]. A malformed chunk refuses it, and 0x02
     * drops it, ending nothing: it may not be the reader.
     */
    private fun candidateWrote(device: BluetoothDevice, uuid: UUID, value: ByteArray) {
        val start = value.contentEquals(byteArrayOf(GattCharacteristics.STATE_START))
        val end = value.contentEquals(byteArrayOf(GattCharacteristics.STATE_END))
        synchronized(this) {
            if (device in refused) return
            when {
                uuid == characteristics.state && start -> addCandidate(device)
                uuid == characteristics.state && end -> candidates.remove(device)
                uuid == characteristics.client2Server -> candidateChunk(device, value)
            }
        }
        if (uuid == characteristics.state && start) started.complete(Unit)
    }

    /**
     * Makes [device] a candidate, under the lock. With [MAX_CANDIDATES]
     * already, the oldest that has sent no message yet makes way, so
     * devices that start sessions and stay silent can't keep the reader
     * out.
     */
    private fun addCandidate(device: BluetoothDevice) {
        if (device in candidates) return
        if (candidates.size >= MAX_CANDIDATES) {
            val silent = candidates.entries.firstOrNull { !it.value.delivered }?.key ?: return
            candidates.remove(silent)
        }
        candidates[device] = Candidate()
    }

    /** Adds a candidate's chunk, queuing its first whole message, under the lock. */
    private fun candidateChunk(device: BluetoothDevice, value: ByteArray) {
        val c = candidates[device]?.takeIf { !it.delivered } ?: return
        val message = try {
            c.reassembler.add(value) ?: return
        } catch (e: IOException) {
            refuse(device)
            return
        }
        c.delivered = true
        if (firsts.trySend(device to message).isFailure) refuse(device)
    }

    /** Forgets [device] for good, letting it go, under the lock. */
    private fun refuse(device: BluetoothDevice) {
        candidates.remove(device)
        refused += device
        runCatching { server?.cancelConnection(device) }
    }

    override suspend fun connect() {
        // Watching first: Bluetooth turning off just after the check
        // below is caught too.
        bluetoothOff.start(context)
        val adapter = manager.adapter?.takeIf { it.isEnabled }
            ?: throw unavailable(ProximityTransportException(BLUETOOTH_OFF, bluetoothUnavailable = true))
        val advertiser = adapter.bluetoothLeAdvertiser
            ?: throw unavailable(ProximityTransportException("this device can't advertise over BLE", bluetoothUnavailable = true))
        synchronized(this) {
            if (closed) throw ProximityTransportException("the session ended")
            val s = manager.openGattServer(context, callback) ?: throw ProximityTransportException("couldn't open a GATT server")
            server = s
            if (!s.addService(service())) throw ProximityTransportException("couldn't add the GATT service")
        }
        serviceAdded.await()
        synchronized(this) {
            if (closed) throw ProximityTransportException("the session ended")
            advertiser.startAdvertising(
            AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(true)
                .setTimeout(0)
                .build(),
            AdvertiseData.Builder().addServiceUuid(ParcelUuid(serviceUUID)).setIncludeDeviceName(false).build(),
            advertiseCallback,
        )
        }
        advertising.await()
        started.await()
    }

    /** The service of §8.3.3.1.1.4's Table 11. */
    private fun service(): BluetoothGattService {
        val service = BluetoothGattService(serviceUUID, BluetoothGattService.SERVICE_TYPE_PRIMARY)
        fun notifying(uuid: UUID, extra: Int): BluetoothGattCharacteristic =
            BluetoothGattCharacteristic(
                uuid,
                BluetoothGattCharacteristic.PROPERTY_NOTIFY or extra,
                if (extra != 0) BluetoothGattCharacteristic.PERMISSION_WRITE else 0,
            ).apply {
                addDescriptor(
                    BluetoothGattDescriptor(
                        GattCharacteristics.clientConfiguration,
                        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
                    ),
                )
            }
        state = notifying(characteristics.state, BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE)
        server2Client = notifying(characteristics.server2Client, 0)
        service.addCharacteristic(state)
        service.addCharacteristic(
            BluetoothGattCharacteristic(
                characteristics.client2Server,
                BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
                BluetoothGattCharacteristic.PERMISSION_WRITE,
            ),
        )
        service.addCharacteristic(server2Client)
        characteristics.ident?.let {
            service.addCharacteristic(
                BluetoothGattCharacteristic(it, BluetoothGattCharacteristic.PROPERTY_READ, BluetoothGattCharacteristic.PERMISSION_READ),
            )
        }
        return service
    }

    override suspend fun send(message: ByteArray): Unit = sending.withLock {
        for (chunk in BleChunks.split(message, BleChunks.characteristicSize(mtu))) notify(server2Client, chunk)
    }

    /**
     * Notifies [value] on [characteristic] and waits until it's sent. A
     * session that has failed sends nothing more, and a notification the
     * stack doesn't confirm in time ends the session: the reader has
     * gone without a disconnection being reported.
     */
    private suspend fun notify(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        failure?.let { throw it }
        val device = peer ?: throw ProximityTransportException("no device connected")
        val s = server ?: throw ProximityTransportException("the session ended")
        while (notified.tryReceive().isSuccess) Unit // a stale one
        val queued = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            s.notifyCharacteristicChanged(device, characteristic, false, value) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = value
            @Suppress("DEPRECATION")
            s.notifyCharacteristicChanged(device, characteristic, false)
        }
        if (!queued) throw ProximityTransportException("a notification couldn't be sent")
        // Not withTimeout: its TimeoutCancellationException is a
        // cancellation, which a caller takes as its own and lets pass.
        val status = withTimeoutOrNull(NOTIFICATION_TIMEOUT_MS) { notified.receive() } ?: throw unconfirmed()
        if (status != BluetoothGatt.GATT_SUCCESS) throw ProximityTransportException("a notification failed ($status)")
    }

    override suspend fun receive(): ByteArray =
        try {
            if (peer != null) {
                incoming.receive()
            } else {
                val (device, message) = firsts.receive()
                synchronized(this) { pending = device }
                message
            }
        } catch (e: ProximityTransportException) {
            throw e
        } catch (e: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            throw ProximityTransportException("the session ended", peerEnded = true, cause = e)
        }

    @Synchronized override fun reject() {
        if (peer != null) return
        val device = pending ?: return
        pending = null
        refuse(device)
    }

    override fun commit() {
        val others = synchronized(this) {
            if (peer != null) return
            // The device whose message Go accepted; before any (a reader
            // that speaks first), the first to start a session.
            val chosen = pending?.takeIf { it in candidates } ?: candidates.keys.firstOrNull().takeIf { pending == null }
            if (chosen == null) {
                fail(ProximityTransportException("the other device disconnected", peerEnded = true))
                return
            }
            // One reader per session: stop being found, and let the
            // others go.
            peer = chosen
            mtus[chosen]?.let { mtu = it }
            val others = candidates.keys.filter { it != chosen }
            candidates.clear()
            pending = null
            others
        }
        stopAdvertising()
        others.forEach { runCatching { server?.cancelConnection(it) } }
    }

    /**
     * Why a notification wasn't confirmed in time, with the session
     * ended for it: what ended the session meanwhile, else Bluetooth
     * being off, else the reader having stopped answering.
     */
    private fun unconfirmed(): ProximityTransportException {
        failure?.let { return it }
        if (closed) return ProximityTransportException("the session ended")
        val e = disconnectionFailure(manager).takeIf { it.bluetoothUnavailable }
            ?: ProximityTransportException("a notification wasn't confirmed")
        fail(e)
        return failure ?: e
    }

    /**
     * Ends the session with [e], once: [connect] and [receive] throw it,
     * and so does [send] before its next chunk. Bluetooth turning off
     * also ends the wait for a chunk's confirmation, so a response being
     * sent then fails as that rather than as a lost connection.
     */
    private fun fail(e: ProximityTransportException) {
        synchronized(this) {
            if (closed || failure != null) return
            failure = e
        }
        incoming.close(e)
        firsts.close(e)
        if (e.bluetoothUnavailable) notified.close(e)
        serviceAdded.completeExceptionally(e)
        advertising.completeExceptionally(e)
        started.completeExceptionally(e)
    }

    /** [e], with the watch stopped: a [connect] that fails before it starts leaves nothing registered. */
    private fun unavailable(e: ProximityTransportException): ProximityTransportException {
        bluetoothOff.stop()
        return e
    }

    private fun stopAdvertising() {
        runCatching { manager.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
    }

    @Synchronized override fun close() {
        if (closed) return
        closed = true
        bluetoothOff.stop()
        stopAdvertising()
        val s = server
        val device = peer
        if (s != null && device != null) {
            // Best effort: the other side may be gone already.
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    s.notifyCharacteristicChanged(device, state, false, byteArrayOf(GattCharacteristics.STATE_END))
                } else {
                    @Suppress("DEPRECATION")
                    state.value = byteArrayOf(GattCharacteristics.STATE_END)
                    @Suppress("DEPRECATION")
                    s.notifyCharacteristicChanged(device, state, false)
                }
            }
            runCatching { s.cancelConnection(device) }
        }
        runCatching { s?.close() }
        incoming.close()
        firsts.close()
        serviceAdded.cancel()
        advertising.cancel()
        started.cancel()
    }

    private companion object {
        const val TAG = "OID4VCProximity"
        /** How many devices may start a session at once before one is committed to: a new one displaces the oldest still silent. */
        const val MAX_CANDIDATES = 8
        const val NOTIFICATION_TIMEOUT_MS = 5_000L
    }
}
