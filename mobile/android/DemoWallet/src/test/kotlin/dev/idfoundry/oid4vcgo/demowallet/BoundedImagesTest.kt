package dev.idfoundry.oid4vcgo.demowallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedImagesTest {
    /** A small file can declare a huge size: refused from its bounds, before any pixel is decoded. */
    @Test
    fun refusesSidesPastTheMaximum() {
        assertNull(BoundedImages.sampleSize(20_000, 20_000, 150))
        assertNull(BoundedImages.sampleSize(BoundedImages.MAX_DIMENSION + 1, 10, 150))
        assertNull(BoundedImages.sampleSize(10, BoundedImages.MAX_DIMENSION + 1, 150))
    }

    @Test
    fun refusesUnreadableSizes() {
        // BitmapFactory reports -1 for data that isn't an image.
        assertNull(BoundedImages.sampleSize(-1, -1, 150))
        assertNull(BoundedImages.sampleSize(0, 100, 150))
    }

    /** Sampled down by powers of two, never below the size shown. */
    @Test
    fun samplesDownToTheSizeShown() {
        assertEquals(1, BoundedImages.sampleSize(150, 200, 480))
        assertEquals(4, BoundedImages.sampleSize(1536, 2048, 480))
        assertEquals(8, BoundedImages.sampleSize(BoundedImages.MAX_DIMENSION, BoundedImages.MAX_DIMENSION, 480))
        // The longer side, decoded, is still at least the size shown.
        val sample = BoundedImages.sampleSize(3000, 4000, 150)!!
        assertTrue(4000 / sample >= 150 && 4000 / (sample * 2) < 150)
    }

    @Test
    fun aZeroSizeStillEnds() {
        assertEquals(4096, BoundedImages.sampleSize(4096, 4096, 0))
    }
}
