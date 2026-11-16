package dev.idfoundry.oid4vcwallet

import kotlinx.serialization.SerializationException

/**
 * How status and identifier lists are read and kept: [Wallet.checkStatus]'s, in a
 * [WalletConfiguration], and a reader session's status check, in a
 * [ProximityReaderConfiguration].
 */
public data class StatusLists(
    /** The largest status list read, in bytes; 0 means 1 MiB. Raise it for issuers whose lists are larger. */
    val maxBytes: Int = 0,
    /** The largest mdoc identifier list read, in bytes; 0 means 4 MiB. */
    val identifierListMaxBytes: Int = 0,
    /**
     * How long a status or identifier list fetched is used before it's revalidated, in
     * seconds: 0 means 5 minutes, at most a day, and never past the list's own `ttl` or
     * `exp`. Longer means fewer requests, and a revocation seen that much later.
     */
    val cacheMaxAgeSeconds: Long = 0,
    /**
     * Where the lists verified are kept across launches: a launch then asks each list's
     * server whether the list it kept is current, a `304 Not Modified` rather than the
     * list, and never uses one the server hasn't confirmed. The lists are authenticated
     * with a key the library makes, wrapped by an Android Keystore key, so one anyone else
     * wrote to the directory is dropped. Null, the default, keeps them in
     * `oid4vcwallet-status-lists` in the app's `context.cacheDir` (found from `java.io.tmpdir`,
     * and used only when that is the app's own cache directory), or in memory only when it
     * isn't, or that key can't be had; an absolute path, the app's own, keeps them there;
     * empty keeps them in memory only. The directory isn't encrypted beyond the app's
     * storage: it shows whoever can read it which status lists are checked (their URIs, so
     * the issuers of the credentials, not which entries), the lists themselves, and when
     * each was last checked.
     */
    val cacheDir: String? = null,
)

/**
 * A development configuration: set (non-null) on a [WalletConfiguration] or a
 * [ProximityReaderConfiguration], it relaxes what production requires, as each one's
 * `development` says. Never ship an app with it set.
 */
public data class Development(
    /**
     * PEM certificates HTTPS requests trust besides the system's: a development service's
     * own CA (Go reads only Android's system CA files, so a CA installed on the device
     * doesn't reach it). A [Wallet]'s requests trust them, and [Wallet.refreshCRLs]'s
     * fetches too, from OID4VCWallet 0.27.0; a [ProximityReader]'s
     * [ProximityReader.refreshCRLs] `https` fetches do, for a development CA's distribution
     * points served under its own TLS certificate.
     */
    val roots: String = "",
) {
    internal companion object {
        /**
         * The development configuration flat JSON's `development` and `development_roots`
         * name: null for production. Roots without `development` were refused by Go
         * (`development_roots needs development`), and are refused here too.
         */
        fun decoded(development: Boolean, roots: String): Development? = when {
            development -> Development(roots)
            roots.isNotEmpty() -> throw SerializationException("development_roots needs development")
            else -> null
        }
    }
}
