package dev.idfoundry.oid4vcgo.demowallet

import kotlinx.coroutines.CompletableDeferred

/** The issuer's redirect back, and whether it arrived as a link: one any app on the device can send. */
class AuthorizationRedirect(val uri: String, val fromLink: Boolean)

/**
 * An authorization at the issuer's pages, waiting for its redirect.
 *
 * In an Auth Tab the redirect comes back as the tab's activity result,
 * which only the browser that ran it gives: a link on the callback
 * scheme, which any app on the device can send, is then ignored.
 *
 * A Custom Tab's redirect can only come back as such a link, so the
 * first one is taken. walletflow refuses one whose `state` isn't this
 * authorization's (the app can't compare it itself: the authorization
 * URL carries only the pushed request's `request_uri`), and
 * [WalletModel] then keeps the offer open to try again rather than
 * ending it.
 */
class PendingAuthorization(val inAuthTab: Boolean) {
    private val redirect = CompletableDeferred<AuthorizationRedirect>()

    val isCompleted: Boolean get() = redirect.isCompleted

    suspend fun await(): AuthorizationRedirect = redirect.await()

    /**
     * A link on the callback scheme arrived while this authorization is
     * waiting: taken only outside an Auth Tab. Either way it's this
     * authorization's, never a relaunch's to resume.
     */
    fun link(uri: String) {
        if (!inAuthTab) redirect.complete(AuthorizationRedirect(uri, fromLink = true))
    }

    /** The Auth Tab's result: its redirect, or null when the holder closed it. */
    fun tabResult(uri: String?) {
        if (!inAuthTab) return
        if (uri != null) redirect.complete(AuthorizationRedirect(uri, fromLink = false)) else cancel()
    }

    /** The holder closed the issuer's page: the offer stays. */
    fun cancel() {
        redirect.completeExceptionally(WalletModel.AuthorizationCancelled())
    }
}
