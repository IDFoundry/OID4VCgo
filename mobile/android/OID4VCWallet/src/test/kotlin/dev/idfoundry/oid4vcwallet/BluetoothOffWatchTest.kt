package dev.idfoundry.oid4vcwallet

import android.bluetooth.BluetoothAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Bluetooth turning off ends a BLE transport, once, and as Bluetooth being unavailable. */
class BluetoothOffWatchTest {
    private val failures = mutableListOf<ProximityTransportException>()
    private val watch = BluetoothOffWatch { failures += it }

    @Test
    fun turningOffFailsOnce() {
        watch.onState(BluetoothAdapter.STATE_TURNING_OFF)
        val e = failures.single()
        assertTrue(e.bluetoothUnavailable)
        assertEquals(BLUETOOTH_OFF, e.message)
        // Off follows turning off: it's the same failure.
        watch.onState(BluetoothAdapter.STATE_OFF)
        assertEquals(1, failures.size)
    }

    @Test
    fun offAloneFails() {
        watch.onState(BluetoothAdapter.STATE_OFF)
        assertTrue(failures.single().bluetoothUnavailable)
    }

    @Test
    fun turningOnIsIgnored() {
        watch.onState(BluetoothAdapter.STATE_TURNING_ON)
        watch.onState(BluetoothAdapter.STATE_ON)
        watch.onState(BluetoothAdapter.ERROR) // an intent without the extra
        assertTrue(failures.isEmpty())
        watch.onState(BluetoothAdapter.STATE_TURNING_OFF)
        assertEquals(1, failures.size)
    }

    @Test
    fun nothingAfterStop() {
        watch.stop()
        watch.stop() // again: nothing
        watch.onState(BluetoothAdapter.STATE_TURNING_OFF)
        watch.onState(BluetoothAdapter.STATE_OFF)
        assertTrue(failures.isEmpty())
    }

    @Test
    fun reasonFromTheFlag() {
        val e = transportFailure(ProximityTransportException("the adapter went away", bluetoothUnavailable = true))
        assertEquals(ProximityException.Reason.BluetoothUnavailable, e.reason)
    }

    /** The flag alone decides: the message is for logs. */
    @Test
    fun reasonNotFromTheMessage() {
        for (message in listOf(BLUETOOTH_OFF, "the other device disconnected")) {
            assertEquals(message, ProximityException.Reason.ConnectionLost, transportFailure(ProximityTransportException(message)).reason)
        }
    }
}
