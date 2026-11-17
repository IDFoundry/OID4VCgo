package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint

/** A key agreement peer's point must be on P-256: KeyFactory doesn't check it. */
class OnCurveTest {
    private val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        .generateKeyPair().public as ECPublicKey
    private val params = key.params
    private val p = (params.curve.field as ECFieldFp).p

    @Test
    fun aGeneratedKeyIsOnTheCurve() {
        assertTrue(onCurve(key.w, params))
    }

    @Test
    fun pointsOffTheCurveAreRefused() {
        val w = key.w
        assertFalse("y + 1", onCurve(ECPoint(w.affineX, w.affineY.add(BigInteger.ONE).mod(p)), params))
        assertFalse("x + p", onCurve(ECPoint(w.affineX.add(p), w.affineY), params))
        assertFalse("y + p", onCurve(ECPoint(w.affineX, w.affineY.add(p)), params))
        assertFalse("(0, 0)", onCurve(ECPoint(BigInteger.ZERO, BigInteger.ZERO), params))
        assertFalse("infinity", onCurve(ECPoint.POINT_INFINITY, params))
    }
}
