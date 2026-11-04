package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.content.Intent
import dev.idfoundry.oid4vcwallet.CRLDistributionPoint
import dev.idfoundry.oid4vcwallet.ProximityReaderConfiguration
import dev.idfoundry.oid4vcwallet.WalletConfiguration
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * What the demo wallet talks to: the wallet's configuration and the
 * Wallet Provider's URL — the JSON mobile/cmd/testservices serves at
 * /config, or run-passport-vdc.sh builds for the passport-vdc demo. It
 * comes from the launch intent's `config` extra, or from
 * `demo-config.json` in the app's external files directory (`adb push`),
 * and is remembered for later launches.
 */
@Serializable
data class DemoConfiguration(
    val wallet: WalletConfiguration,
    /**
     * The Wallet Provider, for issuers that ask for attestations; null
     * for a wallet that receives only from issuers that don't.
     */
    @SerialName("provider_url") val providerURL: String? = null,
    /** The reader mode's identity, when the services give one. */
    val reader: Reader? = null,
) {
    /**
     * A demo reader: the IACAs it accepts, and its key (PKCS #8 PEM) and
     * certificate chain (PEM, leaf first). A demo shortcut: a real
     * reader's key is made on its device and never leaves it.
     */
    @Serializable
    data class Reader(
        @SerialName("issuer_roots") val issuerRoots: String,
        @SerialName("reader_chain") val readerChain: String,
        @SerialName("reader_key") val readerKey: String,
        /**
         * The roles checked against the IACAs' Certificate Revocation
         * Lists, when the services publish them (the passport-vdc demo
         * does), and where `refreshCRLs` fetches them, as
         * [ProximityReaderConfiguration]'s. Without them the reader
         * declines checking revocation.
         */
        @SerialName("revocation") val revocation: List<ProximityReaderConfiguration.RevocationRole>? = null,
        @SerialName("crl_distribution_points") val crlDistributionPoints: List<CRLDistributionPoint>? = null,
        @SerialName("crl_distribution_points_from_roots") val crlDistributionPointsFromRoots: Boolean = false,
        @SerialName("crl_require_https") val crlRequireHTTPS: Boolean = false,
        /** A development reader, which may fetch CRLs from a loopback address (adb reverse). */
        @SerialName("development") val development: Boolean = false,
    )

    companion object {
        private const val PREFS = "demo"
        private const val KEY = "demo-configuration"

        /**
         * The Certificate Revocation Lists the app last fetched
         * (`refreshCRLs`'s `crls`), PEM, in the app's preferences: the
         * wallet's and the reader's. Passed back as the configuration's
         * `crls` at each launch, so checks work before the next refresh,
         * and a list older than these is still refused.
         */
        const val CRLS = "demo-crls"
        const val READER_CRLS = "demo-reader-crls"
        // Strict: a misspelled wallet option is refused, not silently
        // dropped before the wallet could refuse it.
        private val json = Json

        fun load(context: Context, intent: Intent?): DemoConfiguration? {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val pushed = context.getExternalFilesDir(null)?.let { File(it, "demo-config.json") }
            val given = intent?.getStringExtra("config") ?: pushed?.takeIf { it.isFile }?.readText()?.also { pushed.delete() }
            if (given != null) {
                runCatching { json.decodeFromString(serializer(), given) }.getOrNull()?.let {
                    val edit = prefs.edit().putString(KEY, given)
                    // Another configuration (new trust anchors, say) starts
                    // without the revocation lists fetched under the last one.
                    if (prefs.getString(KEY, null) != given) edit.remove(CRLS).remove(READER_CRLS)
                    edit.apply()
                    return it
                }
            }
            val saved = prefs.getString(KEY, null) ?: return null
            return runCatching { json.decodeFromString(serializer(), saved) }.getOrNull()
        }
    }
}
