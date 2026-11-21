package dev.idfoundry.oid4vcwallet

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.UUID

/** Which key stores the sweeps refuse to sweep, and which keys a store lists and sweeps. */
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

    /**
     * A registration key sweep refuses a store whose prefix is, covers or
     * falls under a wallet key store's; with no wallet built, it can't
     * tell.
     */
    @Test
    fun registrationSweepRefusesPrefixesOverlappingAWallets() {
        val wallets = setOf("com.example.wallet.keys.", AndroidKeystoreKeyStore.Options().aliasPrefix)
        for (prefix in listOf("com.example.wallet.keys.", "com.example.wallet.", "com.example.wallet.keys.wp.", "org.idfoundry.", "")) {
            assertNotNull("prefix $prefix accepted", HttpWalletProvider.registrationSweepRefusal(prefix, wallets))
        }
        for (prefix in listOf(HttpWalletProvider.REGISTRATION_KEY_ALIAS_PREFIX, "com.example.wallet.wp.", "com.example.wallet.keysx")) {
            assertNull("prefix $prefix refused", HttpWalletProvider.registrationSweepRefusal(prefix, wallets))
        }
        assertNull(HttpWalletProvider.registrationSweepRefusal(AndroidKeystoreKeyStore.Options().aliasPrefix, emptySet()))
    }

    /**
     * A store lists only the aliases it makes, its prefix and a UUID: not
     * a key under a longer prefix, with a separator or without, nor any
     * other alias under its own.
     */
    @Test
    fun aStoreListsOnlyTheKeysItMakes() {
        val prefix = AndroidKeystoreKeyStore.Options().aliasPrefix
        val id = UUID.randomUUID().toString()
        val theirs = UUID.randomUUID().toString()
        val longer = listOf("b.", "b-", "b")
        val aliases = listOf(prefix + id, prefix + id.uppercase(), prefix + id + "x", prefix + "secret", "com.example.keys.$theirs") +
            longer.map { prefix + it + theirs }
        assertEquals(listOf(id), storeKeyIDs(aliases, prefix))
        for (p in longer) assertEquals(p, listOf(theirs), storeKeyIDs(aliases, prefix + p))
    }
}
