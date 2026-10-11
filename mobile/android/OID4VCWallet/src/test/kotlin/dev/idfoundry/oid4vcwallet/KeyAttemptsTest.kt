package dev.idfoundry.oid4vcwallet

import dev.idfoundry.oid4vcwallet.AndroidKeystoreKeyStore.StrongBox
import org.junit.Assert.assertEquals
import org.junit.Test

/** The order AndroidKeystoreKeyStore tries key generations in. */
class KeyAttemptsTest {
    private val both = listOf("NONE", "SHA-256")
    private val none = listOf("NONE")

    @Test
    fun strongBoxBeforeKeyAgreement() {
        // A holder key StrongBox can't make for both is made there to
        // sign before the TEE is tried.
        assertEquals(
            listOf(
                KeyAttempt(true, true, both), KeyAttempt(true, true, none),
                KeyAttempt(true, false, both), KeyAttempt(true, false, none),
                KeyAttempt(false, true, both), KeyAttempt(false, true, none),
                KeyAttempt(false, false, both), KeyAttempt(false, false, none),
            ),
            keyAttempts(StrongBox.PREFERRED, agree = true, apiLevel = 36),
        )
    }

    @Test
    fun storagesAsAllowed() {
        assertEquals(listOf(true), keyAttempts(StrongBox.REQUIRED, agree = false, apiLevel = 36).map { it.strongBox }.distinct())
        assertEquals(listOf(false), keyAttempts(StrongBox.OFF, agree = true, apiLevel = 36).map { it.strongBox }.distinct())
        // Below API 28 there's no StrongBox to ask for.
        assertEquals(listOf(null), keyAttempts(StrongBox.PREFERRED, agree = false, apiLevel = 26).map { it.strongBox }.distinct())
    }

    @Test
    fun keyAgreementOnlyFromAPI31() {
        assertEquals(listOf(false), keyAttempts(StrongBox.PREFERRED, agree = true, apiLevel = 30).map { it.agree }.distinct())
        assertEquals(listOf(false), keyAttempts(StrongBox.PREFERRED, agree = false, apiLevel = 36).map { it.agree }.distinct())
    }

    @Test
    fun signingKeysAsBefore() {
        assertEquals(
            listOf(KeyAttempt(true, false, both), KeyAttempt(true, false, none), KeyAttempt(false, false, both), KeyAttempt(false, false, none)),
            keyAttempts(StrongBox.PREFERRED, agree = false, apiLevel = 36),
        )
    }
}
