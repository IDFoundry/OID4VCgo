package dev.idfoundry.oid4vcwallet

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import java.lang.ref.WeakReference
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
     * Whether the device is unlocked now. The store asks on each read: it
     * uses no record key it holds, and holds none it unwraps, while this
     * is false, and drops those it holds when it finds it false.
     */
    public val isUnlocked: Boolean

    /**
     * Calls [onLock] each time the device may have locked, from now on:
     * early rather than late, as the screen turning off is. Returns false
     * when it can't, and the store then holds no record key. [onLock] may
     * run on any thread. The store keeps [onLock] while it's alive, and
     * [onLock] holds the store weakly, so a signal may hold it either way;
     * [of]'s holds it weakly, and stops watching once no store does.
     */
    public fun watch(onLock: () -> Unit): Boolean

    /** The device's lock signal. */
    public companion object {
        /**
         * The device's. It counts the device unlocked only while
         * [KeyguardManager.isDeviceLocked] is false and the screen is on
         * ([PowerManager.isInteractive]), so a store holds no key it
         * unwraps while the screen is off: the device may lock any time
         * after, up to its "lock after screen timeout" delay, with no
         * broadcast of its own. It calls `onLock` when the screen turns
         * off ([Intent.ACTION_SCREEN_OFF]), and, every 10 s while any
         * store watches, whenever it finds the device locked or the
         * screen off: a lock no broadcast announces (lockdown, a work
         * profile's own challenge) or a broadcast missed drops the keys
         * within that time.
         *
         * Its limits: it runs only while the app's process does. Android
         * defers broadcasts to a cached app (from Android 14) and freezes
         * a cached app's process, timers and all, so keys a store held
         * when the app was cached stay in its memory until the process
         * runs again, when the first read or check drops them. No held
         * key is *used* while the device is locked: each read asks
         * [isUnlocked] first. An app that must hold no key in memory while
         * the device is locked gives its store no signal. One per process,
         * whatever [context] is given.
         */
        public fun of(context: Context): LockSignal = DeviceLockSignal.of(context)
    }
}

/**
 * The listeners a [DeviceLockSignal] calls, each held weakly: a store
 * keeps its own, so one no store keeps any more is dropped, rather than
 * kept for the process's life.
 */
internal class LockListeners {
    private val listeners = CopyOnWriteArrayList<WeakReference<() -> Unit>>()

    fun add(onLock: () -> Unit) {
        listeners += WeakReference(onLock)
    }

    /** Calls every listener still kept, dropping the rest, and returns how many were called. */
    fun fire(): Int {
        var called = 0
        for (ref in listeners) {
            val onLock = ref.get()
            if (onLock == null) {
                listeners.remove(ref)
                continue
            }
            runCatching(onLock)
            called++
        }
        return called
    }

    /** Drops the listeners no longer kept, and returns how many are. */
    fun prune(): Int {
        listeners.removeAll { it.get() == null }
        return listeners.size
    }
}

/**
 * [LockSignal.isUnlocked] from [KeyguardManager.isDeviceLocked] ([locked])
 * and [PowerManager.isInteractive] ([interactive]): unlocked only when the
 * device says it isn't locked and the screen isn't off. Null is unknown,
 * for want of the service: the keyguard's is needed, the screen's isn't.
 */
internal fun deviceUnlocked(locked: Boolean?, interactive: Boolean?): Boolean = locked == false && interactive != false

/**
 * [LockSignal.of]: one receiver on the application context, and one poll
 * on the main looper, for every store watching, both stopped once none is.
 */
internal class DeviceLockSignal private constructor(private val app: Context) : LockSignal {
    private val keyguard: KeyguardManager? = app.getSystemService(KeyguardManager::class.java)
    private val power: PowerManager? = app.getSystemService(PowerManager::class.java)
    private val listeners = LockListeners()
    private val handler by lazy { Handler(Looper.getMainLooper()) }
    private val poll = Runnable { check() }
    private var receiver: BroadcastReceiver? = null

    override val isUnlocked: Boolean
        get() = deviceUnlocked(keyguard?.isDeviceLocked, runCatching { power?.isInteractive }.getOrNull())

    override fun watch(onLock: () -> Unit): Boolean {
        if (keyguard == null) return false
        synchronized(this) {
            if (receiver == null) {
                val r = object : BroadcastReceiver() {
                    override fun onReceive(context: Context, intent: Intent) {
                        if (intent.action == Intent.ACTION_SCREEN_OFF) listeners.fire()
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
                handler.postDelayed(poll, POLL_MILLIS)
            }
            listeners.add(onLock)
        }
        return true
    }

    /**
     * The poll: calls the listeners when the device is locked or the
     * screen off, which a missed or deferred broadcast, or a lock with
     * none, would otherwise leave keys held through; then polls again,
     * or, once no store watches, stops, receiver and all.
     */
    private fun check() {
        if (!isUnlocked) listeners.fire()
        val stopped = synchronized(this) {
            if (listeners.prune() > 0) {
                handler.postDelayed(poll, POLL_MILLIS)
                null
            } else {
                receiver.also { receiver = null }
            }
        }
        stopped?.let { runCatching { app.unregisterReceiver(it) } }
    }

    internal companion object {
        /** How often the signal checks the device's lock while a store watches. */
        const val POLL_MILLIS = 10_000L

        @Volatile
        private var instance: DeviceLockSignal? = null

        fun of(context: Context): DeviceLockSignal =
            instance ?: synchronized(this) {
                instance ?: DeviceLockSignal(context.applicationContext ?: context).also { instance = it }
            }
    }
}
