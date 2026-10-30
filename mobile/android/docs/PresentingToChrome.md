# Presenting to Chrome

Answer a web page's OpenID4VP request over the Digital Credentials API,
as a Credential Manager provider.

> **Status:** this has run end to end in Chrome on the Android emulator
> (API 37, with Google Play), not yet on a device. The check that the
> request really comes through Credential Manager from the browser it
> names is still open: until it's settled, treat the reported origin as
> what the platform says, not as proven. Watch OID4VCgo's
> [MOBILE.md](https://github.com/IDFoundry/OID4VCgo/blob/main/mobile/MOBILE.md)
> for both.

A page in Chrome can ask for a credential with the W3C Digital
Credentials API, using OpenID4VP (OpenID4VP 1.0 Appendix A). Android's
Credential Manager shows the holder the matching credentials from the
wallets that registered them, and launches the chosen wallet's provider
activity with the request. The wallet answers through
`Wallet.startDCAPIPresentation`; the response goes back through
Credential Manager to the page, encrypted to it, with no network
request from the wallet.

Chrome sends OpenID4VP, mdocs included: `org-iso-mdoc` is Safari's
route on iOS. `DigitalCredentials.request` prefers OpenID4VP when a page
offers both, and an `org-iso-mdoc` request can only be answered for a
web origin.

`DigitalCredentials` does Credential Manager's part. It needs Google
Play services on the device, and brings in the `androidx.credentials`
and `androidx.credentials.registry` libraries, which are still alpha.

## Register the credentials

Credential Manager matches a page's request against what each wallet
registered. `DigitalCredentials.register` registers every presentable
credential (unexpired, with its key on the device), SD-JWT VCs and
mdocs, with their claims, replacing what was registered before. Call it
whenever the credentials change: after an issuance, a deletion or a
restore. The registry's default matcher is Google's OpenID4VP one, so
the app writes none.

```kotlin
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.util.Log
import dev.idfoundry.oid4vcwallet.DigitalCredentials
import dev.idfoundry.oid4vcwallet.Presentation
import dev.idfoundry.oid4vcwallet.Wallet
import dev.idfoundry.oid4vcwallet.WalletException

/** Registers the wallet's credentials: call it whenever they change. */
suspend fun registerForChrome(context: Context, wallet: Wallet) {
    try {
        val registered = DigitalCredentials.register(context, wallet)
        Log.i("Wallet", "registered $registered credential(s)")
    } catch (e: Exception) {
        // No Google Play services, say: Chrome won't offer the wallet.
        Log.w("Wallet", "registering with Credential Manager: $e")
    }
}
```

Nothing is presented by registering: the holder still agrees in the
app. The claims' values are registered too, so the matcher can answer a
query that asks for a value and the system's chooser can show it. They
are then held by the system's registry before any consent; set
`RegistrationOptions(claimValues = false)` to register the claims'
names only. `RegistrationOptions` also sets the registry's ID and each
credential's icon in the chooser.

## Answer in the provider activity

Declare an exported activity for Credential Manager to launch:

```xml
<activity android:name=".GetCredentialActivity" android:exported="true">
    <intent-filter>
        <action android:name="androidx.credentials.registry.provider.action.GET_CREDENTIAL" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```

Being exported, any app on the device can start it, with an intent it
fills in itself: the request, the calling app's package name and
certificate, and the page's origin are all extras. So
`DigitalCredentials.request` takes the activity, and answers only when
Credential Manager started it: an app signed with the platform's key,
or Google Play services (by its signing certificate, which
`credentialManagerApps` can replace). Anything else gets null, so a
relayed request can't borrow a page's origin.

In it, `DigitalCredentials.request` reads the request and the caller's
origin. That is a browser's origin for the page when the browser is on
the privileged-browsers list you give it (Credential Manager's JSON
allowlist; the demo carries Chrome's entries from Google's list), or
else the calling app's own, `android:apk-key-hash:` and its signing
certificate's SHA-256. It returns null when the caller's origin can't
be established, and for a request in no protocol the wallet answers.

```kotlin
/**
 * Answers the request a provider activity was started with: `activity`
 * is the provider activity, and `askTheHolder` shows the holder the
 * page's origin, the Verifier and what sharing would disclose, and
 * returns whether they agree. Returns the intent to set as the
 * activity's result.
 */
suspend fun answerFromChrome(
    activity: Activity,
    wallet: Wallet,
    privilegedBrowsers: String,
    askTheHolder: suspend (origin: String, Presentation, List<Presentation.Disclosure>) -> Boolean,
): Intent {
    val request = DigitalCredentials.request(activity, privilegedBrowsers) ?: return DigitalCredentials.failure()
    // org-iso-mdoc is Safari's route: Chrome asks over OpenID4VP.
    if (request.isMdoc) return DigitalCredentials.failure()
    val presentation = try {
        request.startPresentation(wallet)
    } catch (e: WalletException) {
        // untrustedVerifier, or requestRefused: the wallet refused the
        // request, and the page gets the failure.
        return DigitalCredentials.failure(e.message ?: "the wallet refused the request")
    }
    if (!presentation.isAnswerable) return presentation.decline().dcapiResponse
        ?.let { DigitalCredentials.response(request, it) } ?: DigitalCredentials.failure()
    // The holder agrees to exactly this selection, and it's what is sent.
    val (selection, disclosures) = try {
        val chosen = presentation.defaultSelection()
        chosen to presentation.preview(chosen)
    } catch (e: WalletException) {
        // Nothing can be shown: decline, so the page isn't left waiting.
        return presentation.decline().dcapiResponse
            ?.let { DigitalCredentials.response(request, it) } ?: DigitalCredentials.failure()
    }
    val presented = if (askTheHolder(request.origin, presentation, disclosures)) {
        presentation.respond(selection)
    } else {
        presentation.decline()
    }
    return presented.dcapiResponse?.let { DigitalCredentials.response(request, it) } ?: DigitalCredentials.failure()
}
```

The activity sets the returned intent with `setResult(RESULT_OK, …)` and
finishes.

Show the holder what `preview` returned for the selection you then
`respond` with: if the holder changes the selection on the consent
screen, preview the new one, show that, and respond with it. Never
respond with a selection the holder didn't see. Show `request.origin`
alongside the Verifier: for an unsigned request it's the only identity
there is.

When `startPresentation` throws `requestRefused`, the wallet refused an
authentic request it must not answer — `transaction_data` it doesn't
support, say — and has already told the Verifier, as OpenID4VP requires:
return a failure to the page, and tell the holder the request wasn't
answered. Over the DC API there's no redirect to open:
`Wallet.takeRefusalRedirect` is for requests from links.

`request.selectedCredentialID` is the credential the holder picked in
the system's chooser: start the consent screen from it. The demo's
`GetCredentialActivity` does all this with a consent screen. Launched by
Credential Manager rather than the holder, the activity should skip the
app's launch work: a key sweep then would delete the keys of an
issuance the app has in progress.

## Trust

- A signed request is checked against `WalletConfiguration.verifierRoots`,
  and its `expected_origins` must include the origin: another site
  can't replay it.
- An unsigned request has only its origin for identity: show it on the
  consent screen, and a signed request's alongside the Verifier's name.
  `WalletConfiguration.requireSignedDCAPIRequests` refuses those before
  the holder sees them; HAIP requires wallets to support them, so set it
  only where every Verifier must be a known one.
- Each presentation is recorded as shown to the page's origin, for
  linkability, as for a link's Verifier.
