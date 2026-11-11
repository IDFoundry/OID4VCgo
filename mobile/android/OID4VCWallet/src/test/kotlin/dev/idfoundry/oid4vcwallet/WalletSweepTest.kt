package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** Which key stores Wallet.sweepOrphanedKeys refuses to sweep. */
class WalletSweepTest {
    @Test
    fun refusesPrefixesOverlappingTheRegistrationKeys() {
        val registration = HttpWalletProvider.REGISTRATION_KEY_ALIAS_PREFIX
        for (prefix in listOf("", registration, registration + "other.", "org.idfoundry.oid4vcgo.", "org.idfoundry.", "o")) {
            assertNotNull("prefix $prefix accepted", Wallet.walletSweepRefusal(prefix))
        }
    }

    @Test
    fun acceptsTheWalletsOwnPrefixes() {
        for (prefix in listOf(AndroidKeystoreKeyStore.Options().aliasPrefix, "com.example.wallet.keys.", "org.idfoundry.oid4vcgo.key.test.")) {
            assertNull("prefix $prefix refused", Wallet.walletSweepRefusal(prefix))
        }
    }
}
