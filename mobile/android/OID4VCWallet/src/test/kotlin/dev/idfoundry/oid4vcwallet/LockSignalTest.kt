package dev.idfoundry.oid4vcwallet

import java.lang.ref.WeakReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The device's lock signal counts the device unlocked only while the screen
 * is on too, and holds the stores' listeners weakly, so a store gone is no
 * longer called, nor kept.
 */
class LockSignalTest {
    @Test
    fun unlockedOnlyWithTheScreenOn() {
        assertTrue(deviceUnlocked(locked = false, interactive = true))
        // The screen off: the device may lock any moment, with no broadcast.
        assertFalse(deviceUnlocked(locked = false, interactive = false))
        assertFalse(deviceUnlocked(locked = true, interactive = true))
        assertFalse(deviceUnlocked(locked = true, interactive = false))
        // No keyguard, no unlock; no power service, the keyguard alone.
        assertFalse(deviceUnlocked(locked = null, interactive = true))
        assertTrue(deviceUnlocked(locked = false, interactive = null))
    }

    @Test
    fun firesEveryListenerKept() {
        val listeners = LockListeners()
        var a = 0
        var b = 0
        val onA = { a++; Unit }
        val onB: () -> Unit = { throw IllegalStateException("one failing doesn't stop the rest") }
        val onC = { b++; Unit }
        // Kept, as stores keep theirs.
        val keep = listOf(onA, onB, onC)
        keep.forEach(listeners::add)
        assertEquals(3, listeners.fire())
        assertEquals(3, listeners.fire())
        assertEquals(2, a)
        assertEquals(2, b)
        assertEquals(keep.size, listeners.prune())
    }

    @Test
    fun listenerNoLongerKeptIsDropped() {
        val listeners = LockListeners()
        listeners.add(kept)
        val probe = addUnkept(listeners)
        repeat(50) {
            if (probe.get() == null) return@repeat
            System.gc()
            Thread.sleep(10)
        }
        assumeTrue("the collector didn't collect the listener", probe.get() == null)
        assertEquals(1, listeners.prune())
        assertEquals(1, listeners.fire())
    }

    /** Kept by the test, as a store keeps its own. */
    private val kept: () -> Unit = object : () -> Unit {
        override fun invoke() {}
    }

    /** Adds a listener nothing else keeps, and returns a weak reference to it. */
    private fun addUnkept(listeners: LockListeners): WeakReference<() -> Unit> {
        val onLock: () -> Unit = object : () -> Unit {
            override fun invoke() {}
        }
        listeners.add(onLock)
        return WeakReference(onLock)
    }
}
