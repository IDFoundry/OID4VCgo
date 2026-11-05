package dev.idfoundry.oid4vcwallet

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.time.Instant

/**
 * Where [Wallet.refreshCRLs] or [ProximityReader.refreshCRLs] fetches a
 * CA's Certificate Revocation List from, bound to that CA: a list [url]
 * serves is kept only when this CA signed it.
 */
@Serializable
public data class CRLDistributionPoint(
    /** An `http` or `https` URL: the distribution point the CA's certificates name. `http` is usual, since a CRL is signed. */
    @SerialName("url") val url: String,
    /** The CA's certificate, PEM. */
    @SerialName("issuer") val issuer: String,
)

/** What a CRL refresh did: each distribution point's outcome, the lists now held, and when to refresh again. */
@Serializable
public data class CRLRefreshResult(
    /** One per configured distribution point, in configuration order. */
    @SerialName("results") val results: List<Point>,
    /**
     * Every list now held, as PEM `X509 CRL` blocks: persist it, and pass
     * it back as the configuration's `crls` at the next launch, so checks
     * work before the first refresh and an older list is still refused
     * after a restart.
     */
    @SerialName("crls") val crls: String,
    /**
     * When to refresh again: halfway to the earliest list's nextUpdate, at
     * most an hour away, or after a backoff growing with each failure, both
     * a little randomised so devices don't fetch together. Refresh at a
     * foreground only once it has passed; WorkManager may run the work
     * later.
     */
    @SerialName("next_refresh") @Serializable(InstantSerializer::class) val nextRefresh: Instant,
) {
    /** One distribution point's outcome. */
    @Serializable
    public data class Point(
        /** The distribution point, its password (if any) redacted. */
        @SerialName("url") val url: String,
        /** What the fetch did. */
        @SerialName("outcome") val outcome: Outcome,
        /** Why it failed, as `[code] message`, for logs; null unless [outcome] is [Outcome.FAILED]. */
        @SerialName("error") val error: String? = null,
    )

    /** A distribution point's outcome. */
    @Serializable
    public enum class Outcome {
        /** A newer list now replaces the one held for its CA, for every check from now on. */
        @SerialName("updated") UPDATED,

        /** The list served is the one held already. */
        @SerialName("unchanged") UNCHANGED,

        /**
         * Nothing was kept: the point couldn't be reached, answered with an
         * error, or served a list that's refused (another CA's, not current,
         * or older than the one held). The list held stays.
         */
        @SerialName("failed") FAILED,
    }

    /** Whether any distribution point failed. */
    public val anyFailed: Boolean get() = results.any { it.outcome == Outcome.FAILED }

    internal companion object {
        /** Decodes the Go side's JSON. */
        fun of(text: String): CRLRefreshResult = decode(text)
    }
}
