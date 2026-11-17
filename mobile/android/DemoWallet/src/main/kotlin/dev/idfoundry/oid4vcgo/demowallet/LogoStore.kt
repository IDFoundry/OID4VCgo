package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import dev.idfoundry.oid4vcwallet.CredentialSummary
import dev.idfoundry.oid4vcwallet.Logo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLDecoder
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocketFactory

/**
 * Credential logos, kept on the device when their credential is
 * accepted: showing one fetches nothing, so the issuer doesn't learn
 * when, or how often, the holder looks at the credential.
 */
object LogoStore {
    /** The largest logo kept. */
    private const val MAX_BYTES = 512 * 1024

    private val images = ConcurrentHashMap<String, Bitmap>()

    private fun directory(context: Context) = File(context.filesDir, "logos")

    /**
     * The logo's image, if it's a `data:` image or was kept when its
     * credential was accepted; nothing is fetched.
     */
    fun image(context: Context, logo: Logo?): Bitmap? {
        logo ?: return null
        images[logo.uri]?.let { return it }
        val data = if (logo.uri.startsWith("data:")) {
            decodeDataURL(logo.uri)
        } else {
            file(context, logo.uri).takeIf { it.isFile }?.let { runCatching { it.readBytes() }.getOrNull() }
        }
        val image = data?.let { BitmapFactory.decodeByteArray(it, 0, it.size) } ?: return null
        images[logo.uri] = image
        return image
    }

    /**
     * Fetches and keeps the https logos of [credentials] not kept yet:
     * once, as they're accepted. A logo that fails to load is left out.
     * [socketFactory], if set, is the TLS trust ([DevelopmentTLS]).
     */
    suspend fun fetch(context: Context, credentials: List<CredentialSummary>, socketFactory: SSLSocketFactory?) = withContext(Dispatchers.IO) {
        val uris = credentials.flatMap { listOf(it.display?.logo?.uri, it.display?.issuerLogo?.uri) }.filterNotNull().toSet()
        for (uri in uris) {
            if (!uri.startsWith("https:")) continue
            val file = file(context, uri)
            if (file.exists()) continue
            val data = try {
                download(uri, socketFactory)
            } catch (e: IOException) {
                Log.w("DemoWallet", "fetching a credential logo: $e")
                null
            } ?: continue
            if (BitmapFactory.decodeByteArray(data, 0, data.size) == null) continue
            file.parentFile?.mkdirs()
            val partial = File(file.parentFile, file.name + ".tmp")
            runCatching {
                partial.writeBytes(data)
                if (!partial.renameTo(file)) partial.delete()
            }
        }
    }

    /** [uri]'s body, at most [MAX_BYTES], with no cache. */
    private fun download(uri: String, socketFactory: SSLSocketFactory?): ByteArray? {
        val connection = URI(uri).toURL().openConnection() as HttpURLConnection
        try {
            if (socketFactory != null && connection is HttpsURLConnection) connection.sslSocketFactory = socketFactory
            connection.useCaches = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 15_000
            if (connection.responseCode != 200) return null
            if (connection.contentLengthLong > MAX_BYTES) return null
            val out = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_BYTES) return null
                }
            }
            return out.toByteArray()
        } finally {
            connection.disconnect()
        }
    }

    /** Where the logo at [uri] is kept: named by its SHA-256. */
    private fun file(context: Context, uri: String): File {
        val name = MessageDigest.getInstance("SHA-256").digest(uri.toByteArray()).joinToString("") { "%02x".format(it) }
        return File(directory(context), name)
    }

    /** A `data:` URL's bytes: base64 or percent-encoded. */
    private fun decodeDataURL(uri: String): ByteArray? {
        val comma = uri.indexOf(',').takeIf { it >= 0 } ?: return null
        val header = uri.substring(0, comma)
        val payload = uri.substring(comma + 1)
        return runCatching {
            if (header.endsWith(";base64")) Base64.getDecoder().decode(payload) else URLDecoder.decode(payload, "UTF-8").toByteArray()
        }.getOrNull()
    }
}
