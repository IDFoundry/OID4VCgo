package dev.idfoundry.oid4vcwallet

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Tells a [FileCredentialStore] when the device locks, so that under
 * [FileCredentialStore.Protection.WHEN_UNLOCKED] it may hold the record
 * keys it has unwrapped, as it does under
 * [FileCredentialStore.Protection.AFTER_FIRST_UNLOCK], and drop them
 * when the device locks ([FileCredentialStore.Options.lockSignal]).
 * [of] is the device's own.
 */
public interface LockSignal {
    /**
     * Whether the device is unlocked now. The store uses no record key
     * it holds, and holds none it unwraps, while this is false.
     */
    public val isUnlocked: Boolean

    /**
     * Calls [onLock] each time the device may have locked, from now on:
     * early rather than late, as the screen turning off is. Returns false
     * when it can't, and the store then holds no record key. [onLock] may
     * run on any thread.
     */
    public fun watch(onLock: () -> Unit): Boolean

    /** The device's lock signal. */
    public companion object {
        /**
         * The device's: [KeyguardManager.isDeviceLocked], and the screen
         * turning off ([Intent.ACTION_SCREEN_OFF]), which comes before the
         * device locks. One per process, whatever [context] is given.
         */
        public fun of(context: Context): LockSignal = DeviceLockSignal.of(context)
    }
}

/** [LockSignal.of]: one receiver on the application context, for every store watching. */
internal class DeviceLockSignal private constructor(private val app: Context) : LockSignal {
    private val keyguard: KeyguardManager? = app.getSystemService(KeyguardManager::class.java)
    private val listeners = CopyOnWriteArrayList<() -> Unit>()
    private var receiver: BroadcastReceiver? = null

    override val isUnlocked: Boolean get() = keyguard?.isDeviceLocked == false

    override fun watch(onLock: () -> Unit): Boolean {
        if (keyguard == null) return false
        synchronized(this) {
            if (receiver == null) {
                val r = object : BroadcastReceiver() {
                    override fun onReceive(context: Context, intent: Intent) {
                        if (intent.action == Intent.ACTION_SCREEN_OFF) listeners.forEach { it() }
                    }
                }
                val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
                try {
                    // Not exported: the system's broadcasts still reach it.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        app.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED)
                    } else {
                        app.registerReceiver(r, filter)
                    }
                } catch (e: RuntimeException) {
                    return false
                }
                receiver = r
            }
            listeners += onLock
        }
        return true
    }

    internal companion object {
        @Volatile
        private var instance: DeviceLockSignal? = null

        fun of(context: Context): DeviceLockSignal =
            instance ?: synchronized(this) {
                instance ?: DeviceLockSignal(context.applicationContext ?: context).also { instance = it }
            }
    }
}
