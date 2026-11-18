package dev.idfoundry.oid4vcgo.demowallet

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import dev.idfoundry.oid4vcwallet.CredentialSummary
import dev.idfoundry.oid4vcwallet.Logo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URI
import java.net.URISyntaxException
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
 *
 * A logo is the issuer's choice of image, so it's handled as hostile:
 * one larger than [MAX_BYTES], or than [BoundedImages.MAX_DIMENSION]
 * pixels a side, is refused, and each is decoded off the main thread at
 * the size it's shown, never at its own: a small file can decode to a
 * bitmap of hundreds of megabytes.
 */
object LogoStore {
    /** The largest logo kept. */
    private const val MAX_BYTES = 512 * 1024

    /** The size a logo is checked at before it's kept, in pixels. */
    private const val CHECK_SIZE = 128

    private val images = ConcurrentHashMap<String, Bitmap>()

    private fun directory(context: Context) = File(context.filesDir, "logos")

    /** The logo's image if it has been decoded already. */
    fun cached(logo: Logo?): Bitmap? = logo?.let { images[it.uri] }

    /**
     * The logo's image, at most about [sizePx] pixels a side, if it's a
     * `data:` image or was kept when its credential was accepted;
     * nothing is fetched. Decoded off the main thread.
     */
    suspend fun image(context: Context, logo: Logo?, sizePx: Int): Bitmap? {
        logo ?: return null
        images[logo.uri]?.let { return it }
        return withContext(Dispatchers.IO) {
            val data = if (logo.uri.startsWith("data:")) {
                decodeDataURL(logo.uri)
            } else {
                file(context, logo.uri).takeIf { it.isFile }?.let { runCatching { it.readBytes() }.getOrNull() }
            }
            data?.let { BoundedImages.decode(it, sizePx) }?.also { images[logo.uri] = it }
        }
    }

    /**
     * Fetches and keeps the https logos of [credentials] not kept yet:
     * once, as they're accepted. A logo that fails to load is left out.
     * [socketFactory], if set, is the TLS trust ([DevelopmentTLS]).
     * Outside [development], a logo whose host answers a loopback,
     * private or link-local address is refused, as is a redirect.
     */
    suspend fun fetch(context: Context, credentials: List<CredentialSummary>, socketFactory: SSLSocketFactory?, development: Boolean) =
        withContext(Dispatchers.IO) {
            val uris = credentials.flatMap { listOf(it.display?.logo?.uri, it.display?.issuerLogo?.uri) }.filterNotNull().toSet()
            for (uri in uris) {
                if (uri.startsWith("https:")) keep(file(context, uri), uri, socketFactory, development)
            }
        }

    /** Fetches the logo at [uri] into [file] unless it's kept already. */
    private fun keep(file: File, uri: String, socketFactory: SSLSocketFactory?, development: Boolean) {
        if (file.exists()) return
        val data = try {
            download(uri, socketFactory, development)
        } catch (e: IOException) {
            Log.w("DemoWallet", "fetching a credential logo: $e")
            null
        } catch (e: URISyntaxException) {
            Log.w("DemoWallet", "fetching a credential logo: $e")
            null
        } catch (e: IllegalArgumentException) {
            Log.w("DemoWallet", "fetching a credential logo: $e")
            null
        }
        if (data == null || BoundedImages.decode(data, CHECK_SIZE) == null) return
        file.parentFile?.mkdirs()
        val partial = File(file.parentFile, file.name + ".tmp")
        runCatching {
            partial.writeBytes(data)
            if (!partial.renameTo(file) && !partial.delete()) {
                Log.w("DemoWallet", "couldn't remove a partial credential logo")
            }
        }
    }

    /**
     * [uri]'s body, at most [MAX_BYTES], with no cache; null for a
     * redirect, or outside [development] for a host answering a local
     * address. The host is checked before the connection, which
     * resolves it again: a DNS answer changing in between isn't caught.
     */
    private fun download(uri: String, socketFactory: SSLSocketFactory?, development: Boolean): ByteArray? {
        val url = URI(uri).toURL()
        if (!development && InetAddress.getAllByName(url.host).any(::isLocal)) {
            Log.w("DemoWallet", "refused a credential logo on a local address")
            return null
        }
        val connection = url.openConnection() as HttpURLConnection
        try {
            if (socketFactory != null && connection is HttpsURLConnection) connection.sslSocketFactory = socketFactory
            connection.instanceFollowRedirects = false
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

    /**
     * Whether [address] is one only the device or its own network
     * reaches: loopback, unspecified, link-local, private (10/8,
     * 172.16/12, 192.168/16, 100.64/10, fc00::/7) or multicast.
     */
    private fun isLocal(address: InetAddress): Boolean {
        if (address.isLoopbackAddress || address.isAnyLocalAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress
        ) return true
        val b = address.address
        return when (b.size) {
            4 -> b[0].toInt() == 100 && (b[1].toInt() and 0xC0) == 64
            16 -> (b[0].toInt() and 0xFE) == 0xFC
            else -> false
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
