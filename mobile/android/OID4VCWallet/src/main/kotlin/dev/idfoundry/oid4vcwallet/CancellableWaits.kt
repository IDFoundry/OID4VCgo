package dev.idfoundry.oid4vcwallet

import kotlinx.coroutines.Job
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlin.coroutines.coroutineContext

/**
 * Waits on Go's thread that another thread can cancel by a key: a
 * holder's authentication by its key's ID, a Wallet Provider call by
 * the issuance's instance key. Go calls back on its own thread, which
 * waits; when the call waiting on it is cancelled, Go tells the wallet's
 * CallbackCanceller, which cancels the wait here, so a prompt it shows
 * is dismissed (as [BiometricPromptAuthenticator]'s is, on its
 * coroutine's cancellation) and the callback returns.
 */
internal class CancellableWaits {
    private val waits = HashMap<String, MutableSet<Job>>()

    /**
     * Runs [body] on this thread, which waits for it, until it returns
     * or [cancel] is called with [key]: then it throws the
     * CancellationException.
     */
    fun <T> await(key: String, body: suspend () -> T): T = runBlocking {
        val job = coroutineContext.job
        synchronized(waits) { waits.getOrPut(key) { mutableSetOf() }.add(job) }
        try {
            body()
        } finally {
            synchronized(waits) {
                waits[key]?.let { jobs ->
                    jobs.remove(job)
                    if (jobs.isEmpty()) waits.remove(key)
                }
            }
        }
    }

    /** Cancels every wait for [key] in progress; none is fine. */
    fun cancel(key: String) {
        val jobs = synchronized(waits) { waits[key]?.toList() } ?: return
        jobs.forEach { it.cancel() }
    }

    /** How many waits are in progress, for tests. */
    internal val size: Int get() = synchronized(waits) { waits.values.sumOf { it.size } }
}
