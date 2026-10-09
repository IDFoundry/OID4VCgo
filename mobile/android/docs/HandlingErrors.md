# Handling errors

Tell the holder what went wrong, retry what may succeed, and log what
helps without personal data.

Every failure from the wallet is a `WalletException`:

- `code`: what kind of failure, stable across releases;
- `protocolError`: the issuer's, Authorization Server's or Verifier's
  own OAuth error code, when it gave one, such as `invalid_grant` for a
  wrong PIN;
- `isRetryable`: whether trying the same step again may succeed;
- `description`: a sentence fit to show the holder;
- `message`: detail for logs. It never carries personal data, a remote
  party's own description, or a URL's path or query, so it's safe to
  log.

In-person sessions add `ProximityException` for Bluetooth failures:
Bluetooth off or unavailable, a missing permission, a timeout, or a
lost connection.

```kotlin
import dev.idfoundry.oid4vcwallet.ProximityException
import dev.idfoundry.oid4vcwallet.WalletException

/** What to show the holder for an error, and whether to offer to try again. */
fun describe(error: Throwable): Pair<String, Boolean> = when (error) {
    is WalletException -> error.description to error.isRetryable
    is ProximityException -> error.description to (error.reason == ProximityException.Reason.TimedOut ||
        error.reason == ProximityException.Reason.ConnectionLost)
    else -> "Something went wrong." to false
}
```

## The codes

| Code | Meaning | What to do |
|---|---|---|
| `network`, `unavailable` | A service couldn't be reached, or was unavailable | Offer to try again |
| `protocol` | A service refused the request; `protocolError` says why | Retry when `isRetryable` (a wrong PIN, a stale nonce) |
| `authorizationDenied` | The Authorization Server refused the authorization: the holder declined, say | Start again from the offer |
| `credentialDenied` | The issuer refused a deferred credential | Tell the holder |
| `untrustedVerifier` | The Verifier or reader isn't one the wallet trusts: nothing was shown | Tell the holder |
| `noMatchingCredential` | No held credential answers the request | Decline |
| `invalidSelection` | The selection doesn't answer the request | Choose again |
| `deliveryUnknown` | A response may or may not have reached the Verifier: it isn't sent again | Ask the holder to check with the Verifier |
| `reissueRequired` | A credential can't be refreshed | Receive it again from the issuer |
| `notFound` | No such credential, deferred credential or authorization | Refresh the list |
| `wrongStep` | The session isn't at that step | A bug in the app's flow |
| `cancelled` | The call was cancelled (a cancelled coroutine ends with its own `CancellationException` instead) | Nothing |
| `invalidInput` | A link, PIN or configuration isn't valid | Tell the holder, or fix the configuration |
| `platform` | The key store, credential store or Wallet Provider failed | Check the app's implementation |
| `internal` | Unexpected | Log it |

## Cancel

Every call that waits on the network or the holder is a `suspend`
function: cancel its coroutine, as the holder leaves the screen, say,
and the call returns promptly, throwing `CancellationException`.
