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

    /**
     * Runs a case Multipaz is known to get wrong (README.md, "What it
     * found"): [block] returns null while it still does, noted rather
     * than failed, or what changed, which fails, so the finding is
     * revisited.
     */
    protected inline fun known(what: String, block: () -> String?) {
        reason = null
        val problem = try {
            block()
        } catch (e: Exception) {
            "${e::class.simpleName}: ${e.message}"
        }
        if (problem == null) println("  known $what" + (reason?.let { " ($it)" } ?: "")) else bad("$what: $problem")
    }

    /**
     * null if [got], what Multipaz sent of [name], is [want], what it
     * sends today, or what changed: OID4VCgo is lenient about it
     * (SPECIFICATIONS.md, "Known leniencies"), so a change would pass
     * unnoticed otherwise.
     */
    protected fun observed(name: String, got: String?, want: String): String? = when (got) {
        null -> "nothing observed of $name"
        want -> {
            reason = "$name: $got"
            null
        }
        else -> "$name was \"$want\", now \"$got\": Multipaz changed what it sends; update README.md's \"What it found\" and Observed"
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
