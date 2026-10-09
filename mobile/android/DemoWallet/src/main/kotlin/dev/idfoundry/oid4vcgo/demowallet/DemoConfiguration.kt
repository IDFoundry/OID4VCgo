package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.content.Intent
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
    )

    companion object {
        private const val PREFS = "demo"
        private const val KEY = "demo-configuration"
        private val json = Json { ignoreUnknownKeys = true }

        fun load(context: Context, intent: Intent?): DemoConfiguration? {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val pushed = context.getExternalFilesDir(null)?.let { File(it, "demo-config.json") }
            val given = intent?.getStringExtra("config") ?: pushed?.takeIf { it.isFile }?.readText()?.also { pushed.delete() }
            if (given != null) {
                runCatching { json.decodeFromString(serializer(), given) }.getOrNull()?.let {
                    prefs.edit().putString(KEY, given).apply()
                    return it
                }
            }
            val saved = prefs.getString(KEY, null) ?: return null
            return runCatching { json.decodeFromString(serializer(), saved) }.getOrNull()
        }
    }
}
