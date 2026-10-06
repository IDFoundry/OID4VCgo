package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * One more CA to trust, for development only: the self-signed
 * certificate of mobile/cmd/testservices, pushed as `dev-ca.pem` to the
 * app's external files directory. The wallet's own requests trust it
 * through the configuration's `development_roots`, the Wallet Provider's
 * through a trust manager adding it to the system's. A configuration
 * without `development` never trusts it.
 */
object DevelopmentTLS {
    /** The configuration, trusting the pushed CA too when it's for development. */
    fun install(context: Context, config: DemoConfiguration): DemoConfiguration {
        if (!config.wallet.development) return config
        val kept = File(context.filesDir, "dev-ca.pem")
        context.getExternalFilesDir(null)?.let { File(it, "dev-ca.pem") }?.takeIf { it.isFile }?.let {
            it.copyTo(kept, overwrite = true)
            it.delete()
        }
        if (!kept.isFile) return config
        val pem = kept.readText()
        val extra = CertificateFactory.getInstance("X.509").generateCertificates(pem.byteInputStream()).map { it as X509Certificate }
        HttpsURLConnection.setDefaultSSLSocketFactory(withExtra(extra).socketFactory)
        return config.copy(wallet = config.wallet.copy(developmentRoots = pem))
    }

    private fun withExtra(extra: List<X509Certificate>): SSLContext {
        val system = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(null as KeyStore?) }
            .trustManagers.filterIsInstance<X509TrustManager>().first()
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            extra.forEachIndexed { i, c -> setCertificateEntry("dev-$i", c) }
        }
        val dev = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            .trustManagers.filterIsInstance<X509TrustManager>().first()
        val both = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = system.checkClientTrusted(chain, authType)
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                try {
                    system.checkServerTrusted(chain, authType)
                } catch (e: java.security.cert.CertificateException) {
                    dev.checkServerTrusted(chain, authType)
                }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = system.acceptedIssuers + dev.acceptedIssuers
        }
        return SSLContext.getInstance("TLS").apply { init(null, arrayOf(both), null) }
    }
}
