package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
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
 * or, built in with `-Pdemo.config` (build-shareable.sh), from the APK's
 * own assets/demo-config.json, and is remembered for later launches.
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
        /**
         * A development reader, which may fetch CRLs from a loopback
         * address (adb reverse), trusting the wallet's development CA
         * (`development_roots`) for https ones.
         */
        @SerialName("development") val development: Boolean = false,
    )

    companion object {
        private const val PREFS = "demo"
        private const val KEY = "demo-configuration"
        /** The bundled configuration last applied, so a newer APK's applies once. */
        private const val BUNDLED = "demo-bundled-configuration"
        private const val ASSET = "demo-config.json"

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

        /**
         * The configuration [intent] or a pushed demo-config.json gives,
         * or the one remembered. The pushed file is read in a debuggable
         * build only: below Android 10 (API 29) any app holding
         * `WRITE_EXTERNAL_STORAGE` can write the external files
         * directory, and so replace a release build's trust roots.
         * Without either, a configuration bundled in the APK (part of
         * the signed package, so any build reads it) is applied once:
         * at the first launch, and again only when a newer APK bundles
         * another.
         */
        fun load(context: Context, intent: Intent?): DemoConfiguration? {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val debuggable = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
            val pushed = context.getExternalFilesDir(null)?.takeIf { debuggable }?.let { File(it, "demo-config.json") }
            val bundled = runCatching { context.assets.open(ASSET).bufferedReader().use { it.readText() } }.getOrNull()
            val given = intent?.getStringExtra("config")
                ?: pushed?.takeIf { it.isFile }?.readText()?.also { pushed.delete() }
                ?: bundled?.takeIf { it != prefs.getString(BUNDLED, null) }?.also { prefs.edit().putString(BUNDLED, it).apply() }
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
