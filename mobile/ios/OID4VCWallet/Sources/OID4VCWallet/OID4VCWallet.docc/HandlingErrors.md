# Handling errors

Tell the holder what went wrong, retry what may succeed, and log what
helps without personal data.

## Overview

Every failure from the wallet is a ``WalletError``:

- ``WalletError/code``: what kind of failure, stable across releases;
- ``WalletError/protocolError``: the issuer's, Authorization Server's or
  Verifier's own OAuth error code, when it gave one, such as
  `invalid_grant` for a wrong PIN;
- ``WalletError/isRetryable``: whether trying the same step again may
  succeed;
- `localizedDescription`: a sentence fit to show the holder;
- ``WalletError/message``: detail for logs. It never carries personal
  data, a remote party's own description, or a URL's path or query, so
  it's safe to log.

In-person sessions add ``ProximityError`` for Bluetooth failures:
Bluetooth off or not allowed, a timeout, or a lost connection.

```swift
import Foundation
import OID4VCWallet

/// What to show the holder for an error, and whether to offer to try
/// again.
func describe(_ error: Error) -> (message: String, canRetry: Bool) {
    switch error {
    case let error as WalletError:
        return (error.localizedDescription, error.isRetryable)
    case let error as ProximityError:
        return (error.localizedDescription, error.reason != .bluetoothUnavailable)
    default:
        return (error.localizedDescription, false)
    }
}
```

### The codes

| Code | Meaning | What to do |
|---|---|---|
| ``WalletError/Code/network``, ``WalletError/Code/unavailable`` | A service couldn't be reached, or was unavailable | Offer to try again |
| ``WalletError/Code/protocolError`` | A service refused the request; ``WalletError/protocolError`` says why | Retry when ``WalletError/isRetryable`` (a wrong PIN, a stale nonce) |
| ``WalletError/Code/authorizationDenied`` | The holder or the issuer refused the authorization | Start again from the offer |
| ``WalletError/Code/credentialDenied`` | The issuer refused to issue a credential | Tell the holder |
| ``WalletError/Code/untrustedVerifier`` | The Verifier or reader isn't one the wallet trusts: nothing was shown | Tell the holder |
| ``WalletError/Code/noMatchingCredential`` | No held credential answers the request | Decline |
| ``WalletError/Code/invalidSelection`` | The selection doesn't answer the request | Choose again |
| ``WalletError/Code/deliveryUnknown`` | A response may or may not have reached the Verifier: it isn't sent again | Ask the holder to check with the Verifier |
| ``WalletError/Code/reissueRequired`` | A credential can't be refreshed | Receive it again from the issuer |
| ``WalletError/Code/notFound`` | No such credential, deferred credential or authorization | Refresh the list |
| ``WalletError/Code/wrongStep`` | The session isn't at that step | A bug in the app's flow |
| ``WalletError/Code/cancelled`` | The calling task was cancelled | Nothing |
| ``WalletError/Code/invalidInput`` | A link, PIN or configuration isn't valid | Tell the holder, or fix the configuration |
| ``WalletError/Code/platform`` | The key store, credential store or Wallet Provider failed | Check the app's implementation |
| ``WalletError/Code/internalError`` | Unexpected | Log it |

### Cancel

Every call that waits on the network or the holder runs in the calling
task: cancel the task, as the holder leaves the screen, say, and the
call returns ``WalletError/Code/cancelled`` promptly.
