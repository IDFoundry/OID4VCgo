package dev.idfoundry.oid4vcgo.demowallet

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class PendingAuthorizationTest {
    private val forged = "dev.idfoundry.oid4vcgo.demowallet:/callback?state=x&code=y"
    private val genuine = "dev.idfoundry.oid4vcgo.demowallet:/callback?state=s&code=c&iss=https%3A%2F%2Fas.example"

    /** Any app can send a link on the callback scheme: in an Auth Tab only the tab's result completes the authorization. */
    @Test
    fun anAuthTabIgnoresLinks() = runBlocking {
        val pending = PendingAuthorization(inAuthTab = true)
        pending.link(forged)
        assertFalse("a link completed an Auth Tab's authorization", pending.isCompleted)
        pending.tabResult(genuine)
        val redirect = pending.await()
        assertEquals(genuine, redirect.uri)
        assertFalse(redirect.fromLink)
    }

    @Test
    fun aClosedAuthTabCancels() = runBlocking {
        val pending = PendingAuthorization(inAuthTab = true)
        pending.tabResult(null)
        try {
            pending.await()
            fail("a closed Auth Tab gave a redirect")
        } catch (_: WalletModel.AuthorizationCancelled) {
            // Expected: a closed Auth Tab cancels the authorization.
        }
    }

    /** A Custom Tab's redirect can only arrive as a link: the first is taken, marked as one, and later ones ignored. */
    @Test
    fun aCustomTabTakesTheFirstLink() = runBlocking {
        val pending = PendingAuthorization(inAuthTab = false)
        pending.tabResult(genuine)
        assertFalse("a Custom Tab took an Auth Tab result", pending.isCompleted)
        pending.link(forged)
        pending.link(genuine)
        val redirect = pending.await()
        assertEquals(forged, redirect.uri)
        assertTrue(redirect.fromLink)
    }
}
