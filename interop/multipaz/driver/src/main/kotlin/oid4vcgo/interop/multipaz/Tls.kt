package oid4vcgo.interop.multipaz

import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.HttpClientEngineFactory
import io.ktor.client.engine.java.Java
import io.ktor.client.engine.java.JavaHttpConfig
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * The TLS the peer's certificates set up: every HTTPS party in the run
 * (cmd/conformance-verifier, the driver's Verifier) serves the peer's
 * localhost certificate, under its TLS CA.
 */
class Tls(dir: File) {
    private val certificates = CertificateFactory.getInstance("X.509")

    /** Trusts the peer's TLS CA, and nothing else. */
    val client: SSLContext = trusting(File(dir, "go-tls-ca.pem").readText())

    /** The peer's localhost certificate and key, as "tls", with no password. */
    val keyStore: KeyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
        load(null, null)
        val der = pem(File(dir, "tls-key.pem").readText())
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))
        setKeyEntry("tls", key, CharArray(0), arrayOf(certificate(File(dir, "tls-cert.pem").readText())))
    }

    /** Serves the peer's localhost certificate. */
    val server: SSLContext = SSLContext.getInstance("TLSv1.3").apply {
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keyStore, CharArray(0)) }
        init(keys.keyManagers, null, null)
    }

    /** A context trusting [caPEM], and nothing else. */
    fun trusting(caPEM: String): SSLContext = SSLContext.getInstance("TLSv1.3").apply {
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null, null) }
        store.setCertificateEntry("ca", certificate(caPEM))
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        init(null, trust.trustManagers, null)
    }

    /** A client that follows no redirect, so a test can read one. */
    val http: HttpClient = HttpClient.newBuilder()
        .sslContext(client)
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(Duration.ofSeconds(10))
        .build()

    /** Ktor's Java engine over [client], for Multipaz's own requests. */
    val ktor = ktorOver(client)

    /** Ktor's Java engine trusting [caPEM]. */
    fun ktorTrusting(caPEM: String) = ktorOver(trusting(caPEM))

    private fun ktorOver(context: SSLContext) = object : HttpClientEngineFactory<JavaHttpConfig> {
        override fun create(block: JavaHttpConfig.() -> Unit): HttpClientEngine = Java.create {
            block()
            config { sslContext(context) }
        }
    }

    fun get(url: String): HttpResponse<String> =
        http.send(HttpRequest.newBuilder(URI(url)).GET().build(), HttpResponse.BodyHandlers.ofString())

    fun post(url: String, json: String): HttpResponse<String> =
        http.send(
            HttpRequest.newBuilder(URI(url)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)).build(),
            HttpResponse.BodyHandlers.ofString(),
        )

    private fun certificate(pem: String) =
        certificates.generateCertificate(pem.byteInputStream()) as X509Certificate

    private fun pem(text: String): ByteArray =
        Base64.getMimeDecoder().decode(text.lines().filterNot { it.startsWith("-----") }.joinToString(""))
}
