package dev.idfoundry.oid4vcwallet

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.util.UUID

/**
 * The GATT client's side of a session: scans for [serviceUUID],
 * connects, subscribes and starts the session. The reader in mdoc
 * peripheral server mode. Bluetooth permissions are the caller's to
 * have checked.
 *
 * Android's own failures are worked around as Multipaz does: a scan
 * that reports nothing for [SCAN_RESTART_MS] is restarted (Android
 * silently stops reporting to an app it thinks scans too often), and a
 * connection that fails — GATT error 133 among others — is retried up
 * to [CONNECT_ATTEMPTS] times.
 */
@SuppressLint("MissingPermission")
internal class GattClientTransport(
    private val context: Context,
    private val serviceUUID: UUID,
    private val characteristics: GattCharacteristics,
) : ProximityTransport {
    private val manager = context.getSystemService(BluetoothManager::class.java)
        ?: throw ProximityTransportException("this device has no Bluetooth")

    private var gatt: BluetoothGatt? = null
    private var state: BluetoothGattCharacteristic? = null
    private var client2Server: BluetoothGattCharacteristic? = null

    /** The pending GATT operation's result, one at a time. */
    private val results = Channel<Int>(Channel.CONFLATED)
    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
    private val sending = Mutex()
    private val reassembler = BleChunks.Reassembler()

    @Volatile private var connection: CompletableDeferred<Int>? = null
    @Volatile private var mtu = BleChunks.DEFAULT_MTU
    @Volatile private var sessionStarted = false
    @Volatile private var closed = false

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            Log.d(TAG, "connection state $newState (status $status)")
            val pending = connection
            when {
                newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS -> pending?.complete(status)
                newState == BluetoothProfile.STATE_DISCONNECTED -> {
                    if (pending != null && !pending.isCompleted) {
                        pending.complete(if (status == BluetoothGatt.GATT_SUCCESS) BluetoothGatt.GATT_FAILURE else status)
                    } else {
                        fail(ProximityTransportException("the other device disconnected", peerEnded = true))
                    }
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            if (status == BluetoothGatt.GATT_SUCCESS) this@GattClientTransport.mtu = mtu
            results.trySend(status)
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            results.trySend(status)
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            results.trySend(status)
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            results.trySend(status)
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, value: ByteArray) {
            changed(characteristic.uuid, value)
        }

        @Deprecated("Before Android 13")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) changed(characteristic.uuid, characteristic.value ?: return)
        }
    }

    private fun changed(uuid: UUID, value: ByteArray) {
        when (uuid) {
            characteristics.state -> if (value.contentEquals(byteArrayOf(GattCharacteristics.STATE_END))) {
                fail(ProximityTransportException("the other device ended the session", peerEnded = true))
            }
            characteristics.server2Client -> try {
                reassembler.add(value)?.let { incoming.trySend(it) }
            } catch (e: IOException) {
                fail(ProximityTransportException("a malformed chunk: ${e.message}", cause = e))
            }
        }
    }

    override suspend fun connect() {
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) throw ProximityTransportException("Bluetooth is off")
        var lastStatus = 0
        repeat(CONNECT_ATTEMPTS) { attempt ->
            val device = scan()
            val status = attemptConnection(device)
            if (status == BluetoothGatt.GATT_SUCCESS) {
                start()
                return
            }
            lastStatus = status
            Log.i(TAG, "connecting failed with status $status (attempt ${attempt + 1} of $CONNECT_ATTEMPTS)")
            gatt?.close()
            gatt = null
            delay(RETRY_DELAY_MS)
        }
        throw ProximityTransportException("couldn't connect to the other device (status $lastStatus)")
    }

    /** Scans until a device advertising [serviceUUID] is found. */
    private suspend fun scan(): BluetoothDevice {
        val scanner = manager.adapter?.bluetoothLeScanner ?: throw ProximityTransportException("Bluetooth is off")
        while (true) {
            val found = CompletableDeferred<BluetoothDevice>()
            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    found.complete(result.device)
                }

                override fun onScanFailed(errorCode: Int) {
                    found.completeExceptionally(ProximityTransportException("BLE scanning failed ($errorCode)"))
                }
            }
            scanner.startScan(
                listOf(ScanFilter.Builder().setServiceUuid(ParcelUuid(serviceUUID)).build()),
                ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                scanCallback,
            )
            try {
                withTimeoutOrNull(SCAN_RESTART_MS) { found.await() }?.let { return it }
                Log.i(TAG, "nothing found in ${SCAN_RESTART_MS / 1000} s: restarting the scan")
            } finally {
                runCatching { scanner.stopScan(scanCallback) }
            }
        }
    }

    /** Connects to [device], returning the GATT status. */
    private suspend fun attemptConnection(device: BluetoothDevice): Int {
        val pending = CompletableDeferred<Int>()
        connection = pending
        gatt = device.connectGatt(context, false, callback, BluetoothDevice.TRANSPORT_LE)
            ?: return BluetoothGatt.GATT_FAILURE
        return withTimeoutOrNull(CONNECT_TIMEOUT_MS) { pending.await() } ?: BluetoothGatt.GATT_FAILURE
    }

    /** Negotiates the MTU, finds the service, subscribes, and writes 0x01 to State. */
    private suspend fun start() {
        val g = gatt ?: throw ProximityTransportException("not connected")
        drain()
        if (g.requestMtu(REQUESTED_MTU)) {
            // An MTU exchange the other side never answers keeps the default.
            withTimeoutOrNull(OPERATION_TIMEOUT_MS) { results.receive() }
        }
        drain()
        if (!g.discoverServices()) throw ProximityTransportException("couldn't discover the other device's services")
        expectSuccess("discovering services")
        val service = g.getService(serviceUUID) ?: throw ProximityTransportException("the other device lacks the mdoc service")
        val st = service.getCharacteristic(characteristics.state)
        val c2s = service.getCharacteristic(characteristics.client2Server)
        val s2c = service.getCharacteristic(characteristics.server2Client)
        if (st == null || c2s == null || s2c == null) throw ProximityTransportException("the mdoc service lacks a characteristic")
        state = st
        client2Server = c2s
        subscribe(g, s2c)
        subscribe(g, st)
        write(st, byteArrayOf(GattCharacteristics.STATE_START))
        sessionStarted = true
    }

    private suspend fun subscribe(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
        if (!g.setCharacteristicNotification(characteristic, true)) throw ProximityTransportException("couldn't subscribe")
        val descriptor = characteristic.getDescriptor(GattCharacteristics.clientConfiguration)
            ?: throw ProximityTransportException("a characteristic lacks its configuration descriptor")
        drain()
        val queued = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            g.writeDescriptor(descriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            descriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            @Suppress("DEPRECATION")
            g.writeDescriptor(descriptor)
        }
        if (!queued) throw ProximityTransportException("couldn't subscribe")
        expectSuccess("subscribing")
    }

    /** Writes [value] to [characteristic], without response, and waits until it's sent. */
    private suspend fun write(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
        val g = gatt ?: throw ProximityTransportException("the session ended")
        drain()
        val type = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        val queued = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            g.writeCharacteristic(characteristic, value, type) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            characteristic.writeType = type
            @Suppress("DEPRECATION")
            characteristic.value = value
            @Suppress("DEPRECATION")
            g.writeCharacteristic(characteristic)
        }
        if (!queued) throw ProximityTransportException("a write couldn't be sent")
        expectSuccess("writing")
    }

    private fun drain() {
        while (results.tryReceive().isSuccess) Unit
    }

    private suspend fun expectSuccess(what: String) {
        val status = withTimeout(OPERATION_TIMEOUT_MS) { results.receive() }
        if (status != BluetoothGatt.GATT_SUCCESS) throw ProximityTransportException("$what failed ($status)")
    }

    override suspend fun send(message: ByteArray): Unit = sending.withLock {
        val c2s = client2Server ?: throw ProximityTransportException("the session hasn't started")
        for (chunk in BleChunks.split(message, BleChunks.characteristicSize(mtu))) write(c2s, chunk)
    }

    override suspend fun receive(): ByteArray =
        try {
            incoming.receive()
        } catch (e: ClosedReceiveChannelException) {
            throw ProximityTransportException("the session ended", peerEnded = true, cause = e)
        }

    private fun fail(e: ProximityTransportException) {
        incoming.close(e)
    }

    override fun close() {
        if (closed) return
        closed = true
        val g = gatt
        val st = state
        if (g != null && st != null && sessionStarted) {
            // Best effort, without waiting: the other side may be gone.
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    g.writeCharacteristic(st, byteArrayOf(GattCharacteristics.STATE_END), BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE)
                } else {
                    @Suppress("DEPRECATION")
                    st.value = byteArrayOf(GattCharacteristics.STATE_END)
                    @Suppress("DEPRECATION")
                    g.writeCharacteristic(st)
                }
            }
        }
        runCatching { g?.disconnect() }
        runCatching { g?.close() }
        incoming.close()
    }

    private companion object {
        const val TAG = "OID4VCProximity"
        const val SCAN_RESTART_MS = 10_000L
        const val CONNECT_ATTEMPTS = 10
        const val CONNECT_TIMEOUT_MS = 10_000L
        const val RETRY_DELAY_MS = 500L
        const val OPERATION_TIMEOUT_MS = 5_000L
        const val REQUESTED_MTU = 517
    }
}
