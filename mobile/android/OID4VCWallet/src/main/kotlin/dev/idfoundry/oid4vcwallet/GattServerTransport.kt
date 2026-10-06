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
import kotlinx.coroutines.withTimeout
import java.io.IOException
import java.util.UUID

/**
 * The GATT server's side of a session: advertises [serviceUUID], serves
 * [characteristics] and takes the first device that connects. The
 * holder in mdoc peripheral server mode, or the reader in mdoc central
 * client mode (serving [ident]). Bluetooth permissions are the caller's
 * to have checked.
 */
@SuppressLint("MissingPermission")
internal class GattServerTransport(
    private val context: Context,
    private val serviceUUID: UUID,
    private val characteristics: GattCharacteristics,
    private val ident: ByteArray? = null,
) : ProximityTransport {
    private val manager = context.getSystemService(BluetoothManager::class.java)
        ?: throw ProximityTransportException("this device has no Bluetooth")

    private var server: BluetoothGattServer? = null
    private lateinit var state: BluetoothGattCharacteristic
    private lateinit var server2Client: BluetoothGattCharacteristic

    private val serviceAdded = CompletableDeferred<Unit>()
    private val advertising = CompletableDeferred<Unit>()
    private val started = CompletableDeferred<Unit>()
    private val incoming = Channel<ByteArray>(Channel.UNLIMITED)
    private val notified = Channel<Int>(Channel.CONFLATED)
    private val sending = Mutex()
    private val reassembler = BleChunks.Reassembler()

    @Volatile private var peer: BluetoothDevice? = null
    @Volatile private var mtu = BleChunks.DEFAULT_MTU
    @Volatile private var closed = false
    @Volatile private var sessionStarted = false

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
                BluetoothProfile.STATE_CONNECTED -> {
                    if (peer == null) {
                        peer = device
                        // One reader per session: stop being found.
                        stopAdvertising()
                    } else if (peer != device) {
                        server?.cancelConnection(device)
                    }
                }
                BluetoothProfile.STATE_DISCONNECTED -> if (device == peer) {
                    fail(ProximityTransportException("the other device disconnected", peerEnded = true))
                }
            }
        }

        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
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
            if (device != peer || value == null) return
            when (characteristic.uuid) {
                characteristics.state -> when {
                    value.contentEquals(byteArrayOf(GattCharacteristics.STATE_START)) -> {
                        sessionStarted = true
                        started.complete(Unit)
                    }
                    value.contentEquals(byteArrayOf(GattCharacteristics.STATE_END)) ->
                        fail(ProximityTransportException("the other device ended the session", peerEnded = true))
                }
                characteristics.client2Server -> try {
                    reassembler.add(value)?.let { incoming.trySend(it) }
                } catch (e: IOException) {
                    fail(ProximityTransportException("a malformed chunk: ${e.message}", cause = e))
                }
            }
        }

        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            notified.trySend(status)
        }
    }

    override suspend fun connect() {
        val adapter = manager.adapter
        if (adapter == null || !adapter.isEnabled) throw ProximityTransportException("Bluetooth is off")
        val advertiser = adapter.bluetoothLeAdvertiser ?: throw ProximityTransportException("this device can't advertise over BLE")
        val s = manager.openGattServer(context, callback) ?: throw ProximityTransportException("couldn't open a GATT server")
        server = s
        s.addService(service())
        serviceAdded.await()
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

    /** Notifies [value] on [characteristic] and waits until it's sent. */
    private suspend fun notify(characteristic: BluetoothGattCharacteristic, value: ByteArray) {
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
        val status = withTimeout(NOTIFICATION_TIMEOUT_MS) { notified.receive() }
        if (status != BluetoothGatt.GATT_SUCCESS) throw ProximityTransportException("a notification failed ($status)")
    }

    override suspend fun receive(): ByteArray =
        try {
            incoming.receive()
        } catch (e: ProximityTransportException) {
            throw e
        } catch (e: kotlinx.coroutines.channels.ClosedReceiveChannelException) {
            throw ProximityTransportException("the session ended", peerEnded = true, cause = e)
        }

    private fun fail(e: ProximityTransportException) {
        incoming.close(e)
        started.completeExceptionally(e)
    }

    private fun stopAdvertising() {
        runCatching { manager.adapter?.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback) }
    }

    override fun close() {
        if (closed) return
        closed = true
        stopAdvertising()
        val s = server
        val device = peer
        if (s != null && device != null && sessionStarted) {
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
        started.cancel()
    }

    private companion object {
        const val TAG = "OID4VCProximity"
        const val NOTIFICATION_TIMEOUT_MS = 5_000L
    }
}
