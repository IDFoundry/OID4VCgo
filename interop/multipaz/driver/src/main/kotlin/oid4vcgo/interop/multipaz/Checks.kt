package oid4vcgo.interop.multipaz

/**
 * Prints each case's line, "ok" or "FAIL", and counts the failures.
 */
abstract class Checks {
    protected var failed = 0

    /** Why a control was refused, for its ok line. */
    protected var reason: String? = null

    protected fun ok(what: String) = println("  ok    $what")
    protected fun bad(what: String) {
        println("  FAIL  $what")
        failed++
    }

    /** Runs a case: [block] returns null if it went as expected, or what went wrong. */
    protected inline fun check(what: String, block: () -> String?) {
        reason = null
        val problem = try {
            block()
        } catch (e: Exception) {
            "${e::class.simpleName}: ${e.message}"
        }
        if (problem == null) ok(what + (reason?.let { " ($it)" } ?: "")) else bad("$what: $problem")
    }

    /** null if [r] failed with an error containing [want], or what it did instead. */
    protected fun refusal(r: Reply, want: String): String? = refusal(r.error, r.toString(), want)

    /** null if [error] contains [want], or what happened instead ([answer] when there was no error). */
    protected fun refusal(error: String?, answer: String, want: String): String? = when {
        error == null -> "accepted: $answer"
        !error.contains(want) -> "refused, but not for its ${want.ifEmpty { "reason" }}: $error"
        else -> {
            reason = error.take(160)
            null
        }
    }
}
