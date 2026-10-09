# Presenting from a link

Answer a Verifier's OpenID4VP request: show who is asking and what, let
the holder choose, and present exactly that.

A Verifier asks with an `openid4vp://` link, as a QR code or a link on
its page. Declare that scheme in an intent filter so links open the
app, and hand the link to `Wallet.startPresentation`. It fetches the
Verifier's signed request, checks its certificate against
`WalletConfiguration.verifierRoots`, and finds the credentials that can
answer it. A request from a Verifier the wallet doesn't trust throws a
`WalletException` with code `untrustedVerifier` before anything is
shown.

The `Presentation` it returns says:

- who is asking: `verifier`, its name, and its `registration` when a
  registrar the wallet trusts (`WalletConfiguration.registrarRoots`)
  registered it, with its purpose and the claims it's registered to ask
  for;
- what it asks for: `queries`, each with the held credentials that can
  answer it, and `credentialSets`, the request's alternatives.

## Present

```kotlin
import dev.idfoundry.oid4vcwallet.Presentation
import dev.idfoundry.oid4vcwallet.Wallet

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
    val presentation = wallet.startPresentation(requestLink)
    if (!presentation.isAnswerable) return presentation.decline().redirectURI
    val selection = presentation.defaultSelection()
    val disclosures = presentation.preview(selection)
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
the Verifier's page.

## Show what's being asked beyond a registration

For a Verifier with a verified registration, each query's
`unregistered` lists the claims it asks for beyond what it's registered
to request, and `unregisteredAll` whether it asks for every claim.
Nothing is refused for them: show them, and let the holder decide.

## Keep presentations unlinkable

Each presentation uses a copy of the credential, bound to its own key,
so two Verifiers can't link the holder's presentations by the
credential. `WalletConfiguration.copyPolicy` chooses which copy:

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
