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
  succeed. Not with input the step used up: a redirect given to
  ``Issuance/completeAuthorization(redirect:)`` is spent whatever
  happened, so begin the authorization again;
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
| ``WalletError/Code/credentialDenied`` | The issuer refused a deferred credential | Tell the holder |
| ``WalletError/Code/untrustedVerifier`` | The Verifier or reader isn't one the wallet trusts: nothing was shown | Tell the holder |
| ``WalletError/Code/requestRefused`` | The wallet refused a Verifier's request it must not answer (`transaction_data` it doesn't support, say) and told the Verifier; ``WalletError/protocolError`` is the code it sent. Nothing was shown | Open ``Wallet/takeRefusalRedirect()`` if it returns a URL; tell the holder the request wasn't answered |
| ``WalletError/Code/tlsPin`` | A pinned host's certificate matched none of its ``WalletConfiguration/tlsPins``: an interception, or keys changed beyond the pins. Nothing was sent | Don't retry; tell the holder to try another network, or ship new pins |
| ``WalletError/Code/documentNotValid`` | A ``ProximityReader`` checking status (`statusCheck: .check`) verified a document whose revocation status isn't valid; ``WalletError/protocolError`` is the status (`invalid`, `suspended`, `unknown`, or `0x` and a value) | Don't accept the document, and show its `localizedDescription` |
| ``WalletError/Code/noMatchingCredential`` | No held credential answers the request | Decline |
| ``WalletError/Code/invalidSelection`` | The selection doesn't answer the request | Choose again |
| ``WalletError/Code/deliveryUnknown`` | A response may or may not have reached the Verifier: it isn't sent again | Ask the holder to check with the Verifier |
| ``WalletError/Code/reissueRequired`` | A credential can't be refreshed | Receive it again from the issuer |
| ``WalletError/Code/profileViolation`` | Under the `.haip` issuance profile, the issuer doesn't follow HAIP 1.0 | Tell the holder: the wallet doesn't receive from this issuer |
| ``WalletError/Code/clientAuthUnsupported`` | The issuer needs a Wallet Attestation the wallet can't give: no `WalletProvider` or `clientID` | Tell the holder, or configure a provider |
| ``WalletError/Code/proofUnsupported`` | The wallet can't hold the credential, or the issuer needs a proof it can't give (a key attestation needs a `WalletProvider`, and a `clientID` for an issuance that redeems a pre-authorized code without client authentication) | Tell the holder |
| ``WalletError/Code/notFound`` | No such credential, deferred credential or authorization | Refresh the list |
| ``WalletError/Code/wrongStep`` | The session isn't at that step | A bug in the app's flow |
| ``WalletError/Code/cancelled`` | The calling task was cancelled, or the holder dismissed Face ID or the passcode for a holder key | Nothing |
| ``WalletError/Code/invalidInput`` | A link, PIN or configuration isn't valid | Tell the holder, or fix the configuration |
| ``WalletError/Code/platform`` | The key store, credential store or Wallet Provider failed. When the provider refused (``WalletProviderRefusedError``), ``WalletError/protocolError`` is its error code: `instance_not_active` (suspended), `instance_revoked`, `invalid_signed_request`, … | Show its `localizedDescription`; without a `protocolError`, check the app's implementation |
| ``WalletError/Code/internalError`` | Unexpected | Log it |

### Revoked certificates and out-of-date revocation lists

Where a trust role is checked against Certificate Revocation Lists
(`revocation`), a refusal for a revoked certificate has
``WalletError/isCertificateRevoked`` set, and one for want of a current
list from the certificate's CA ``WalletError/isNoCurrentCRL``, whatever
the ``WalletError/code`` (``WalletError/Code/protocolError`` for a
credential or a document a ``ProximityReader`` verified,
``WalletError/Code/untrustedVerifier`` for a Verifier): tell the holder
which, and for the second refresh the lists (``Wallet/refreshCRLs()``)
and try again. A held credential's status says the same:
``CredentialStatus/reason`` is ``CredentialStatus/Reason/issuerCertificateRevoked``
or ``CredentialStatus/Reason/noCurrentCRL``.

### Cancel

Every call that waits on the network or the holder runs in the calling
task: cancel the task, as the holder leaves the screen, say, and the
call returns ``WalletError/Code/cancelled`` promptly. A Face ID or
passcode sheet a holder key is showing meanwhile is dismissed:
``KeychainKeyStore`` invalidates the signature's `LAContext`. A
``KeyStore`` of your own dismisses its prompt in
``KeyStore/cancelKeyUse(id:)``; one that doesn't implement it holds the
call until the holder answers. A presentation cancelled so sends
nothing, and can be answered again. A ``WalletProvider`` call in
progress has its task cancelled too.
