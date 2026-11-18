package dev.idfoundry.oid4vcgo.demowallet

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * Images an issuer chose — a credential's logo, a holder's portrait —
 * decoded as hostile: a small file can declare a size that decodes to
 * a bitmap of hundreds of megabytes. Each is refused past
 * [MAX_DIMENSION] pixels a side, read from its header before any pixel
 * is decoded, and sampled down as it's decoded to about the size it's
 * shown.
 */
object BoundedImages {
    /** The widest or tallest image decoded, in pixels. */
    const val MAX_DIMENSION = 4096

    /**
     * The power-of-two sample size that decodes a [width] × [height]
     * image to no less than [sizePx] on its longer side, or null for an
     * image refused: one whose size couldn't be read, or with a side
     * past [MAX_DIMENSION].
     */
    fun sampleSize(width: Int, height: Int, sizePx: Int): Int? {
        if (width <= 0 || height <= 0 || width > MAX_DIMENSION || height > MAX_DIMENSION) return null
        val target = sizePx.coerceAtLeast(1)
        var sample = 1
        while (maxOf(width, height) / (sample * 2) >= target) sample *= 2
        return sample
    }

    /** Whether [data]'s header names an image [decode] would decode. Reads no pixels. */
    fun accepts(data: ByteArray): Boolean = bounds(data).let { (w, h) -> sampleSize(w, h, 1) != null }

    /**
     * [data] decoded at most about [sizePx] pixels a side: its bounds
     * read first, refused past [MAX_DIMENSION], then sampled down as
     * it's decoded. Call it off the main thread.
     */
    fun decode(data: ByteArray, sizePx: Int): Bitmap? {
        val (w, h) = bounds(data)
        val sample = sampleSize(w, h, sizePx) ?: return null
        return BitmapFactory.decodeByteArray(data, 0, data.size, BitmapFactory.Options().apply { inSampleSize = sample })
    }

    private fun bounds(data: ByteArray): Pair<Int, Int> {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(data, 0, data.size, bounds)
        return bounds.outWidth to bounds.outHeight
    }
}

/**
 * An image claim's bytes — an mdoc's portrait, an SD-JWT VC's picture —
 * whose header [BoundedImages] accepted. Its pixels are decoded only by
 * [ClaimImage], off the main thread, at the size shown.
 */
class EncodedImage(val bytes: ByteArray) {
    /** Its SHA-256: what its decoded thumbnails are cached by. */
    val key: String by lazy { MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) } }
}

/**
 * Claim images decoded at the sizes they're shown, kept in memory: the
 * home screen shows each holder's portrait on every launch, and decodes
 * it once.
 */
object ClaimImages {
    private val cache = object : LruCache<String, Bitmap>(8 * 1024 * 1024) {
        override fun sizeOf(key: String, value: Bitmap) = value.byteCount
    }

    fun cached(image: EncodedImage, sizePx: Int): Bitmap? = cache.get("${image.key}@$sizePx")

    /** [image] at most about [sizePx] pixels a side, decoded off the main thread. */
    suspend fun bitmap(image: EncodedImage, sizePx: Int): Bitmap? =
        cached(image, sizePx) ?: withContext(Dispatchers.Default) { BoundedImages.decode(image.bytes, sizePx) }
            ?.also { cache.put("${image.key}@$sizePx", it) }
}

/**
 * An image claim, [width] × [height]: decoded off the main thread at
 * that size, its space kept empty until it is, or if it can't be.
 */
@Composable
fun ClaimImage(
    image: EncodedImage,
    width: Dp,
    height: Dp,
    modifier: Modifier = Modifier,
    contentScale: ContentScale = ContentScale.Fit,
    contentDescription: String? = null,
) {
    val sizePx = with(LocalDensity.current) { maxOf(width, height).roundToPx() }
    val bitmap by produceState(ClaimImages.cached(image, sizePx), image.key, sizePx) {
        value = ClaimImages.bitmap(image, sizePx)
    }
    val shown = bitmap
    if (shown != null) {
        Image(shown.asImageBitmap(), contentDescription, modifier.size(width, height), contentScale = contentScale)
    } else {
        // Not [modifier]: its tag names a shown image.
        Box(Modifier.size(width, height))
    }
}
