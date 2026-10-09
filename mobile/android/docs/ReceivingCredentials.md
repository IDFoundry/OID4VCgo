# Receiving credentials

Receive the credentials a Credential Offer offers, with either grant,
and look after them once they're held.

An issuer offers credentials with an `openid-credential-offer://` link,
as a QR code or a link the holder opens. Declare that scheme in an
intent filter so links open the app, and hand the link to
`Wallet.startIssuance`. It resolves the offer and the issuer's metadata,
and returns an `Issuance` whose `offer` you show the holder: who is
offering what.

The offer names one of two grants:

- **Authorization code:** the holder signs in at the issuer's pages, in
  a browser, which redirects back to the wallet's redirect URI.
- **Pre-authorized code:** the issuer has already authenticated the
  holder, and may ask for a PIN it sent them separately (`offer.txCode`).

Either way, `requestCredentials()` then requests, checks and stores the
credentials, and `close()` ends the issuance.

## Receive an offer

```kotlin
import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import dev.idfoundry.oid4vcwallet.CredentialSummary
import dev.idfoundry.oid4vcwallet.DeferredCredential
import dev.idfoundry.oid4vcwallet.DeferredStatus
import dev.idfoundry.oid4vcwallet.Issuance
import dev.idfoundry.oid4vcwallet.Offer
import dev.idfoundry.oid4vcwallet.Wallet
import dev.idfoundry.oid4vcwallet.WalletException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay

/**
 * Receives the credentials an offer link offers. `askPIN` asks the
 * holder for the PIN the issuer sent, or returns null if they cancel;
 * `signIn` opens the issuer's page and returns the redirect back.
 */
suspend fun receive(
    offerLink: String,
    wallet: Wallet,
    askPIN: suspend (Offer.TxCode?) -> String?,
    signIn: suspend (String) -> String,
): Issuance.Result? {
    val issuance = wallet.startIssuance(offerLink)
    try {
        when (issuance.offer.grant) {
            Offer.Grant.PRE_AUTHORIZED_CODE -> while (true) {
                val pin = askPIN(issuance.offer.txCode) ?: return null
                try {
                    issuance.redeemPreAuthorizedCode(pin)
                    break
                } catch (e: WalletException) {
                    if (!e.isRetryable) throw e // A wrong PIN (invalid_grant) is retryable: ask again.
                }
            }
            Offer.Grant.AUTHORIZATION_CODE -> {
                val url = issuance.beginAuthorization()
                issuance.completeAuthorization(signIn(url))
            }
        }
        return issuance.requestCredentials()
    } finally {
        issuance.close()
    }
}
```

`Issuance.Result` lists what arrived, what the issuer deferred, and what
failed: one credential the issuer refused doesn't hold up the rest.

## Open the issuer's page

Open the authorization URL in an Auth Tab where the browser has them,
with the redirect URI's scheme as its callback scheme, and an ephemeral
session, which keeps the issuer's cookies out of the browser's. Where
the browser has no Auth Tabs, open a Custom Tab: its redirect reaches
the app through the intent filter, as a new intent.

```kotlin
/** Opens issuers' authorization pages from `activity`, and returns their redirects. */
class IssuerSignIn(private val activity: ComponentActivity, private val callbackScheme: String) {
    private var pending: CompletableDeferred<String>? = null
    private val authTab: ActivityResultLauncher<Intent> =
        AuthTabIntent.registerActivityResultLauncher(activity) { result ->
            val uri = result.resultUri
            if (result.resultCode == AuthTabIntent.RESULT_OK && uri != null) {
                pending?.complete(uri.toString())
            } else {
                pending?.completeExceptionally(IllegalStateException("the holder closed the issuer's page"))
            }
        }

    /** The redirect back; it throws when the holder closes the page. */
    suspend fun open(url: String): String {
        val redirect = CompletableDeferred<String>()
        pending = redirect
        try {
            val browser = CustomTabsClient.getPackageName(activity, null)
            if (browser != null && CustomTabsClient.isAuthTabSupported(activity, browser)) {
                AuthTabIntent.Builder().setEphemeralBrowsingEnabled(true).build()
                    .launch(authTab, Uri.parse(url), callbackScheme)
            } else {
                CustomTabsIntent.Builder().setEphemeralBrowsingEnabled(true).build().launchUrl(activity, Uri.parse(url))
            }
            return redirect.await()
        } finally {
            pending = null
        }
    }

    /** Call from the activity's onNewIntent: a Custom Tab's redirect arrives there. Returns whether it was one. */
    fun redirected(intent: Intent): Boolean {
        val uri = intent.data ?: return false
        if (uri.scheme != callbackScheme) return false
        return pending?.complete(uri.toString()) ?: false
    }
}
```

If the holder closes the page, the offer stays open: `beginAuthorization()`
can begin again. A redirect is used up by `completeAuthorization`
whatever happens, so after a failure there, begin again rather than
retrying it.

## Resume after the process is killed

Android can end the app's process while the holder is at the issuer's
pages. The authorization in progress is kept in the credential store,
so when the redirect arrives at a relaunched app — a redirect
`IssuerSignIn.redirected` didn't take — `Wallet.resumeIssuance` completes
it and returns an issuance ready for `requestCredentials()`.

```kotlin
/** Completes an authorization the app's process was killed during, from the redirect that relaunched it. */
suspend fun resume(redirect: String, wallet: Wallet): Issuance.Result {
    val issuance = wallet.resumeIssuance(redirect)
    try {
        return issuance.requestCredentials()
    } finally {
        issuance.close()
    }
}
```

A redirect that matches no authorization in progress throws a
`WalletException` with code `notFound`.

## Wait for a deferred credential

An issuer may issue a credential later, after a review, say. It's kept
in the credential store until it's issued, denied or abandoned, so it
survives the app quitting. `Wallet.deferredCredentials()` lists them
without network requests; poll each at the interval the issuer asks for.

```kotlin
/** Polls a deferred credential until the issuer settles it: the credential, or a `credentialDenied` error. */
suspend fun waitFor(deferred: DeferredCredential, wallet: Wallet): CredentialSummary {
    var interval = deferred.intervalSeconds
    while (true) {
        delay((maxOf(interval, 5.0) * 1000).toLong())
        when (val status = wallet.pollDeferred(deferred.id)) {
            is DeferredStatus.Issued -> return status.credential
            is DeferredStatus.Pending -> interval = status.intervalSeconds
        }
    }
}
```

`Wallet.abandonDeferred` gives one up, deleting its keys: once its
access token has expired, say.

## Look after held credentials

- `Wallet.credentials()` lists them, and `Wallet.credential(id)` returns
  one with its claims, for display. A summary's `display` carries the
  issuer's names, logos and colours, in the holder's language
  (`WalletConfiguration.locales`).
- `Wallet.checkStatus(id)` checks revocation against the issuer's
  status list, which covers many credentials, so the issuer can't tell
  which one is checked.
- Each credential arrives as a batch of copies, each bound to its own
  key (`WalletConfiguration.batchSize`), so presentations can't be
  linked by the credential. When a summary's `copiesLeft` reaches zero,
  `Wallet.refreshCredential(id)` replaces them without the holder, if
  the issuance kept a refresh token (`WalletConfiguration.requestRefresh`).
  Otherwise it throws `reissueRequired`: receive the credential again.
- `Wallet.deleteCredential(id)` deletes a credential and its keys,
  revoking its refresh token at the issuer.
