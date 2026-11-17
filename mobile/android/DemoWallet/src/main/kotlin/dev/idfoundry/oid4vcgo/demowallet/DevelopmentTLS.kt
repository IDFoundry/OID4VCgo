package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

/**
 * One more CA to trust, for development only: the self-signed
 * certificate of mobile/cmd/testservices or the passport-vdc demo,
 * placed as `dev-ca.pem` in the app's internal files directory (the run
 * scripts copy it there with `run-as`, which only a debuggable build
 * allows). The wallet's own requests trust it through the
 * configuration's `development_roots`, and the demo's Wallet Provider
 * client through [socketFactory]; nothing else in the process does.
 * A configuration without `development`, or a build that isn't
 * debuggable, never trusts it.
 */
object DevelopmentTLS {
    private const val FILE = "dev-ca.pem"

    /** The configuration, trusting the CA too when it's for development in a debuggable build. */
    fun install(context: Context, config: DemoConfiguration): DemoConfiguration {
        val development = config.wallet.development ?: return config
        if (!debuggable(context)) return config
        val kept = File(context.filesDir, FILE)
        if (!kept.isFile) return config
        return config.copy(wallet = config.wallet.copy(development = development.copy(roots = kept.readText())))
    }

    /**
     * A socket factory trusting the system's CAs and the configuration's
     * development roots, for the demo's Wallet Provider client alone;
     * null, for the system's default, without them or outside a
     * debuggable build.
     */
    fun socketFactory(context: Context, config: DemoConfiguration): SSLSocketFactory? {
        if (!debuggable(context)) return null
        val pem = config.wallet.development?.roots?.takeIf { it.isNotBlank() } ?: return null
        val extra = CertificateFactory.getInstance("X.509").generateCertificates(pem.byteInputStream()).map { it as X509Certificate }
        return withExtra(extra).socketFactory
    }

    private fun debuggable(context: Context): Boolean =
        context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    /**
     * The system's CAs and [extra], under the platform's own trust
     * manager: the same checks, with one more anchor.
     */
    private fun withExtra(extra: List<X509Certificate>): SSLContext {
        val system = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            for (alias in system.aliases()) setCertificateEntry(alias, system.getCertificate(alias))
            extra.forEachIndexed { i, c -> setCertificateEntry("dev-$i", c) }
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
        // TLS 1.3 is API 29's.
        val protocol = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) "TLSv1.3" else "TLSv1.2"
        return SSLContext.getInstance(protocol).apply { init(null, trust.trustManagers, null) }
    }
}
