# Presenting from a link

Answer a Verifier's OpenID4VP request: show who is asking and what, let
the holder choose, and present exactly that.

A Verifier asks with an `openid4vp://` link, as a QR code or a link on
its page. Declare that scheme in an intent filter so links open the
app, and hand the link to `Wallet.startPresentation`. It fetches the
Verifier's signed request, checks its certificate against
`WalletConfiguration.verifiers.roots`, and finds the credentials that can
answer it. A request from a Verifier the wallet doesn't trust throws a
`WalletException` with code `untrustedVerifier` before anything is
shown.

The `Presentation` it returns says:

- who is asking: `verifier`, its name, and its `registration` when a
  registrar the wallet trusts (`WalletConfiguration.verifiers.registrarRoots`)
  registered it, with its purpose and the claims it's registered to ask
  for;
- what it asks for: `queries`, each with the held credentials that can
  answer it, and `credentialSets`, the request's alternatives.

## Present

```kotlin
import dev.idfoundry.oid4vcwallet.Presentation
import dev.idfoundry.oid4vcwallet.Wallet
import dev.idfoundry.oid4vcwallet.WalletException

/**
 * Answers a request link: `confirm` shows the holder who is asking and
 * what sharing would disclose, and returns whether they agree. Returns
 * where to send the browser, when the Verifier asks.
 */
suspend fun present(
    requestLink: String,
    wallet: Wallet,
    confirm: suspend (Presentation, List<Presentation.Disclosure>) -> Boolean,
): String? {
    val presentation = try {
        wallet.startPresentation(requestLink)
    } catch (e: WalletException) {
        // A refused request: the Verifier was told, and may say where to
        // take the holder next (OpenID4VP §8.2). Ask the holder before
        // opening one that isn't https.
        if (e.code == WalletException.Code.requestRefused) return e.refusalRedirect
        throw e
    }
    if (!presentation.isAnswerable) return presentation.decline().redirectURI
    val (selection, disclosures) = try {
        val chosen = presentation.defaultSelection()
        chosen to presentation.preview(chosen)
    } catch (e: WalletException) {
        // Nothing can be shown: decline, so the Verifier isn't left waiting.
        runCatching { presentation.decline() }
        throw e
    }
    if (!confirm(presentation, disclosures)) return presentation.decline().redirectURI
    // The holder key signs now: the fingerprint or screen lock, if the key store asks.
    return presentation.respond(selection).redirectURI
}
```

`defaultSelection()` picks the first credential that answers each
query, and the first answerable option of each credential set. To let
the holder choose, build a `Selection` — query ID to credential IDs —
from each query's `credentials` instead: a query that takes one
credential gets exactly one. The wallet presents exactly the selection,
after checking it answers the request (`invalidSelection` otherwise),
and `preview` says what it would disclose without signing or sending
anything: show that before the holder agrees.

Open `Presented.redirectURI`, when the Verifier sends one, in the
browser the request came from: it's how a same-device flow returns to
the Verifier's page. The library refuses http, schemes that run code
or read local data (`javascript:`, `data:`, `file:`, and Android's
`intent:`, `content:` and `android-app:`), and schemes that open a
system app rather than the Verifier's page or app (`market:`, `tel:`,
`sms:`, `mailto:`, `geo:` and their like), but lets through a scheme
the Verifier's own app may have registered: open an https URL in the
browser, any other only
through an `ACTION_VIEW` intent, never in a WebView, and never one in
the wallet's own schemes (`openid4vp`, `openid-credential-offer`, its
redirect URI's), which would start another flow in the wallet. Where
you know the schemes of your Verifiers' apps, name them in
`presentation.verifierRedirectSchemes`, or `listOf("https")` for none:
a redirect with any other scheme is then refused too, and `respond` or
`decline` throws `WalletException.Code.protocol`, the presentation
answered.

## When the wallet refuses a request

A request the wallet must not answer — one with `transaction_data` it
doesn't support, or a parameter OpenID4VP forbids — makes
`startPresentation` throw `WalletException.Code.requestRefused`, its
`protocolError` the error code the wallet sent the Verifier, such as
`invalid_transaction_data`. Nothing is shown to the holder, and nothing
is presented. The Verifier may answer the refusal with a redirect: the
exception's `refusalRedirect` is it, and you open it in the browser the
request came from, as a `redirectURI`, so the holder isn't left
stranded. The holder has done no more than open the link, so ask them
before opening one that isn't `https`: it opens another app, which can
look like the wallet's next step. It's that call's own, so
presentations started at once each get their Verifier's;
`Wallet.takeRefusalRedirect()` returns the latest refusal's, of
whichever call, once. Tell the holder the request wasn't answered.

## Show what's being asked beyond a registration

For a Verifier with a verified registration, each query's
`unregistered` lists the claims it asks for beyond what it's registered
to request, and `unregisteredAll` whether it names no claims at all.
The library flags such a query in full, though OpenID4VP 1.0 §6.4.1
reads it as asking for no selectively disclosable claims, so a
presentation for it discloses only what the credential always shows.
Nothing is refused for them: show them, and let the holder decide.

## Keep presentations unlinkable

Each presentation uses a copy of the credential, bound to its own key,
so two Verifiers can't link the holder's presentations by the
credential. `WalletConfiguration.presentation.copyPolicy` chooses which copy:

- `PER_PRESENTATION`, the default: a copy no Verifier has seen, every
  time.
- `PER_VERIFIER`: the copy a Verifier has seen before, so it can
  recognize a returning holder, and an unused one for a new Verifier.

Once every copy is used, one is reused. A candidate's `linkableHere`
says whether presenting it now would hand this Verifier a copy another
has seen: warn the holder, and refresh the credential
(`Wallet.refreshCredential`) when its `copiesLeft` reaches zero.

## When delivery is uncertain

If sending the response fails in a way that leaves it unknown whether
the Verifier received it, `respond` throws `deliveryUnknown` and doesn't
send it again: the holder should check with the Verifier before sharing
again.
