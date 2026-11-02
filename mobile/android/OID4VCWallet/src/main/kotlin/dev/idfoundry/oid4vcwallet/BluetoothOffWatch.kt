package dev.idfoundry.oid4vcwallet

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build

/**
 * Ends a BLE transport when Bluetooth turns off. A transport still
 * advertising or scanning has no link to lose, and some devices (an
 * Android 9 phone among them) report no disconnection when the adapter
 * goes down, so the adapter's own state is watched instead. [onOff] runs
 * once, on the first STATE_TURNING_OFF or STATE_OFF, unless [stop] came
 * first.
 */
internal class BluetoothOffWatch(private val onOff: (ProximityTransportException) -> Unit) {
    private var done = false
    private var receiver: BroadcastReceiver? = null
    private var registeredWith: Context? = null

    /** Handles the adapter's new state, one of BluetoothAdapter's STATE_ values. */
    fun onState(state: Int) {
        if (state != BluetoothAdapter.STATE_TURNING_OFF && state != BluetoothAdapter.STATE_OFF) return
        synchronized(this) {
            if (done) return
            done = true
        }
        onOff(ProximityTransportException(BLUETOOTH_OFF, bluetoothUnavailable = true))
    }

    /**
     * Watches the adapter until [stop], on [context]'s application
     * context, so a transport left unclosed can't leak an Activity.
     * Starting again, or after [stop], does nothing.
     */
    fun start(context: Context) {
        val app = context.applicationContext ?: context
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        synchronized(this) {
            if (done || receiver != null) return
            val r = object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    onState(intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR))
                }
            }
            // Not exported: the system's broadcasts still reach it.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                app.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                app.registerReceiver(r, filter)
            }
            receiver = r
            registeredWith = app
        }
    }

    /** Stops watching: [onOff] won't run from now on. Calling it again does nothing. */
    fun stop() {
        val (r, app) = synchronized(this) {
            done = true
            (receiver to registeredWith).also {
                receiver = null
                registeredWith = null
            }
        }
        if (r != null && app != null) runCatching { app.unregisterReceiver(r) }
    }
}

/**
 * The failure when the other device disconnects: Bluetooth being off
 * instead, if the adapter is no longer on, so that a disconnection
 * reported before the adapter's own broadcast still ends the session as
 * Bluetooth being off.
 */
@SuppressLint("MissingPermission")
internal fun disconnectionFailure(manager: BluetoothManager): ProximityTransportException =
    if (manager.adapter?.state == BluetoothAdapter.STATE_ON) {
        ProximityTransportException("the other device disconnected")
    } else {
        ProximityTransportException(BLUETOOTH_OFF, bluetoothUnavailable = true)
    }
