package oid4vcgo.interop.eudi

import kotlinx.coroutines.runBlocking
import kotlin.system.exitProcess

/**
 * Runs the issuance cases of one issuer profile against
 * cmd/conformance-issuer, printing an ok or FAIL line per check, and
 * exits non-zero if any failed. run-issuer.sh starts the issuer in the
 * profile's configuration first.
 *
 *   main <driver.json> <base|key-attestation|deferred|dpop-nonces|production|production-scaled>
 */
fun main(args: Array<String>) {
    require(args.size == 2) { "usage: <driver.json> <profile>" }
    val wallet = Wallet(DriverConfig.load(args[0]))
    val run = Run(wallet)
    runBlocking {
        when (args[1]) {
            "base" -> baseCases(run)
            "key-attestation" -> keyAttestationCases(run)
            "deferred" -> deferredCases(run)
            "dpop-nonces" -> dpopNonceCases(run)
            "production" -> productionCases(run)
            "production-scaled" -> productionCases(run, scaled = true)
            else -> error("unknown profile ${args[1]}")
        }
    }
    wallet.http.close()
    exitProcess(if (run.failed) 1 else 0)
}

/** The ok/FAIL report of a run. */
class Run(
    val wallet: Wallet,
) {
    var failed = false
        private set

    /** The two-instance profile's split, which every case is checked against. */
    var split: Split? = null

    fun ok(what: String) = println("  ok    $what")

    /** A deviation of the wallet the README documents, observed again: noted, not failed. */
    fun known(what: String) = println("  known $what")

    fun bad(what: String) {
        println("  FAIL  $what")
        failed = true
    }

    fun expect(
        condition: Boolean,
        what: String,
        detail: () -> String = { "" },
    ) = if (condition) ok(what) else bad(what + detail().let { if (it.isEmpty()) "" else " ($it)" })

    /** Runs one case: a failure it throws fails the case, and is shown. */
    suspend fun case(
        name: String,
        block: suspend Wallet.() -> Unit,
    ) {
        println("== $name")
        wallet.recorder.clear()
        try {
            wallet.block()
            split?.let { checkSplit(it) }
        } catch (t: Throwable) {
            bad("${t::class.simpleName}: ${describe(t)}")
            System.err.println("case \"$name\" failed:")
            t.printStackTrace()
        }
    }

    /** Runs one control: [block] must throw, and [refused] says whether it threw for the right reason. */
    suspend fun control(
        name: String,
        what: String,
        refused: (Throwable) -> Boolean,
        block: suspend Wallet.() -> Unit,
    ) {
        println("== control: $name")
        wallet.recorder.clear()
        val thrown =
            try {
                wallet.block()
                null
            } catch (t: Throwable) {
                t
            }
        when {
            thrown == null -> bad("$what: it went through")
            refused(thrown) -> ok("$what: ${describe(thrown)}")
            else -> {
                bad("$what, for the expected reason: ${thrown::class.simpleName}: ${describe(thrown)}")
                thrown.printStackTrace()
            }
        }
        split?.let { checkSplit(it) }
    }
}

fun describe(t: Throwable): String {
    val chain = generateSequence(t) { it.cause }.take(4).toList()
    return chain.joinToString(" <- ") { (it.message ?: it.toString()).take(240) }
}
