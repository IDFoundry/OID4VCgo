# OID4VCgo mobile ABI

The API the Go `mobile` package exposes through gomobile: version
**4** (`ABIVersion`). The Swift package `ios/OID4VCWallet` wraps it in
typed Swift (`Wallet`, `Issuance`, `Presentation`, `WalletError`); this
document is the contract underneath, for the Swift wrapper, a future
Kotlin one, or an app calling the framework directly.

The version changes whenever a function, object, JSON result, record
format or error code below changes incompatibly.

## Conventions

- **Types:** strings, bools, integers, `[]byte` (`Data`), the objects
  below, and the callback interfaces the app implements.
- **JSON:** every JSON result is an object with `"abi"`, the version it
  was written for. Times are RFC 3339.
- **Errors:** a failing call's error text is `[code] message`, or
  `[code:detail] message` when the issuer, Authorization Server or
  Verifier answered with an OAuth error code of its own (`detail`: for
  example `invalid_grant`, which a wrong PIN gets). The code and detail
  are stable; the message is for logs. A callback's error comes back to
  the app as `platform`, carrying its message. (Version 1 had no
  detail.)
- **Threads:** every call blocks. Call from a background thread, never
  the main thread; callbacks run on the calling thread.
- **Cancellation:** a call that waits on the network takes an
  `Operation` (`NewOperation(timeoutMillis)`, 0 for no timeout); `Cancel`
  it from any thread, and the call returns `cancelled`. Its timeout,
  like a request's own, returns `network`.

## Error codes

| Code | Meaning |
|---|---|
| `invalid_input` | an argument or the configuration is malformed |
| `platform` | a callback into the app failed (its message follows) |
| `network` | a request couldn't be made, got no answer, or timed out; retryable |
| `unavailable` | the service answered with HTTP 5xx or 429; retryable later |
| `cancelled` | the Operation was cancelled |
| `not_found` | no key, credential or deferred credential with that ID |
| `wrong_step` | a session method called out of turn, or after Close |
| `authorization_denied` | the Authorization Server refused, e.g. the holder declined |
| `credential_denied` | the issuer refused a deferred credential |
| `no_matching_credential` | nothing held answers the Verifier's request |
| `protocol` | an issuer, Authorization Server or Verifier answered with an error, or with something the wallet refuses |
| `internal` | a bug |

An error's message is fit for an app's logs. It never carries a remote
party's own description (`error_description`, an error body), a URL's
path or query (which can carry a pre-authorized code, a `request_uri` or
a `response_code`), credential claims, or control characters. It's at
most 300 characters. The remote party's OAuth error code is the
`detail`.

## Callbacks the app implements

A callback that can fail returns `[]byte` or nothing besides its error:
Swift imports those as `throws`. `KeyStore.CreateKey` returns a string,
so Swift sees it with an `NSError` out-parameter instead.

### KeyStore

P-256 keys that never leave the platform (the Secure Enclave on iOS).

| Method | |
|---|---|
| `CreateKey(purpose) → id` | `purpose` is `instance`, `dpop` or `holder` |
| `PublicKey(id) → []byte` | uncompressed X9.63 point; empty if there's no such key |
| `Sign(id, digest) → []byte` | ECDSA over a SHA-256 digest, ASN.1 DER |
| `DeleteKey(id)` | no error if absent |
| `Durable() → bool` | whether keys survive the app quitting (the Keychain): receiving credentials without `development` needs it |

Instance and DPoP keys sign protocol messages silently; holder keys sign
only when presenting, and may require user presence. `CheckKeyStore`
exercises an implementation as the wallet will.

### CredentialStore

Opaque records kept by ID, under the platform's data protection.

| Method | |
|---|---|
| `Put(id, record)` | replaces any record with that ID |
| `Get(id) → []byte` | empty if there's none |
| `List() → []byte` | a JSON array of every record |
| `Delete(id)` | no error if absent |

A record is JSON the app needn't read: `id`, `credential_issuer`,
`configuration_id`, `format`, `vct`, `doctype`, `credential`,
`holder_key_id`, `received_at`, and `claims` (absent from a record
written before claims were kept).

The store also keeps each **pending deferred credential**, under the ID
`deferred-<id>`, as a record with `"kind": "deferred"`. The record holds
what polling it after a relaunch needs: the issuer, the configuration,
the transaction ID, the access token and its expiry, the DPoP and holder
key IDs, the interval, and when it was deferred. The access token is
bound to the DPoP key, which never leaves the KeyStore. A store keeps
these records like any other; `List` returns them too, and Go tells them
apart.

It keeps each **authorization in progress** too, under the ID
`authorization-<SHA-256 of its state>`, as a record with `"kind":
"authorization"`: FAPIgo's session record (with the PKCE verifier), the
resolved offer, the authorization server, and the instance and DPoP key
IDs. `ResumeIssuance` completes it from the redirect after a relaunch.

`Durable()` says whether records survive the app quitting. Receiving
credentials without `development` needs a durable `CredentialStore` and
`KeyStore`.

The Swift package's `FileCredentialStore` keeps records as files with
complete data protection, excluded from backups. It's durable.

### WalletProvider

The Wallet Provider's backend (HAIP 1.0 §4.4.1, §4.5.1). Keys are public
JWKs; the results are compact JWTs.

| Method | |
|---|---|
| `WalletAttestation(clientID, instanceKeyJWK) → []byte` | binds the instance key to the wallet's client ID |
| `KeyAttestation(keysJWK, nonce) → []byte` | `keysJWK` is a JSON array of JWKs; the attestation carries the issuer's nonce |

## Wallet

`NewWallet(configJSON, keys, credentials, provider)`:

```json
{"client_id": "…", "redirect_uri": "…",
 "issuer_roots": "<PEM>", "verifier_roots": "<PEM>",
 "development": false}
```

`client_id`, `redirect_uri`, `issuer_roots` and a provider are needed to
receive credentials; `verifier_roots` to present them. `development`
allows services on loopback addresses.

| Method | Result |
|---|---|
| `Credentials()` | `{"credentials": [summary]}` |
| `HolderKeyIDs()` | `{"key_ids": [...]}`: the keys the wallet still needs: the credentials' holder keys, and each pending deferred credential's holder and DPoP keys. Any other key in the KeyStore, at launch before any issuance, is an orphan to delete |
| `Deferred()` | `{"deferred": [pending]}`: the credentials issuers have deferred and not yet settled, oldest first, including ones from before the app last quit. No network calls |
| `PollDeferred(op, deferredID)` | `{"status": "pending" \| "issued", "credential": summary, "interval_seconds"}`; a refusal is `credential_denied`, and is then no longer pending. The first poll after a relaunch fetches the issuer's metadata |
| `AbandonDeferred(deferredID)` | deletes a pending one and its keys, for example after its access token has expired |
| `Credential(id)` | summary with `"claims"`: an SD-JWT VC's claims, or an mdoc's namespace → element → value, byte strings in base64 |
| `DeleteCredential(id)` | deletes it and its holder key |
| `StartIssuance(op, offerURI)` | an `Issuance` |
| `ResumeIssuance(op, redirect)` | an `Issuance` ready for `RequestCredentials`: completes the authorization in progress that the redirect's `state` names, after the app was killed during the browser step. One that matches nothing, has already been used, or has expired is `not_found` |
| `StartPresentation(op, requestLink)` | a `Presentation` |

A credential **summary** is `{"id", "credential_issuer",
"configuration_id", "format", "vct", "doctype", "received_at",
"holder_key_present"}`. `holder_key_present` is false when the key store
no longer holds the credential's key, for example after a restore to
another device, so it can't be presented. It's set by `Credentials` and
`Credential`.

## Issuance

Steps, in order: `Offer`; then `BeginAuthorization` and
`CompleteAuthorization` (`grant` `authorization_code`), or
`RedeemPreAuthorizedCode` (`grant` `pre-authorized_code`); then
`RequestCredentials`; `Close`. A deferred credential is polled from the
`Wallet` (`PollDeferred`): it outlives `Close`, and the app quitting.

| Method | Result |
|---|---|
| `Offer()` | `{"credential_issuer", "issuer_name", "grant", "tx_code": {"input_mode", "length", "description"}, "credentials": [{"configuration_id", "format", "vct", "doctype", "name"}]}` |
| `BeginAuthorization(op)` | the authorization URL, to open in `ASWebAuthenticationSession` |
| `CompleteAuthorization(op, redirect)` | the redirect back to `redirect_uri`, whole or just its query |
| `RedeemPreAuthorizedCode(op, txCode)` | the PIN, `""` if `tx_code` is absent; a wrong one is `protocol` and can be retried |
| `RequestCredentials(op)` | `{"credentials": [summary], "deferred": [pending]}` |
| `Close()` | deletes the issuance's instance key, and its DPoP key unless a pending deferred credential still polls with it |

A **pending** deferred credential is `{"id", "credential_issuer",
"configuration_id", "interval_seconds", "deferred_at",
"access_token_expires_at"}`. `access_token_expires_at` is present only
when the issuer gave the token a lifetime; once it has passed, polls
fail and the credential can only be abandoned.

ABI version 3 moved `PollDeferred` from the `Issuance` to the `Wallet`,
and added `Deferred` and `AbandonDeferred`.

## Presentation

Steps: `Verifier` and `Candidates`; `Preview` the holder's choice; then
`Respond` or `Decline`, once.

| Method | Result |
|---|---|
| `Verifier()` | `{"client_id", "name", "response_uri"}` |
| `Candidates()` | `{"queries": [{"query_id", "credentials": [summary]}]}`, empty when nothing held answers |
| `Preview(idsJSON)` | `{"disclosures": [{"query_id", "credential_id", "claims": [path]}]}` |
| `Respond(op, idsJSON)` | `{"query_ids", "redirect_uri"}` |
| `Decline(op)` | `{"query_ids": [], "redirect_uri"}` |

`idsJSON` is a JSON array of credential IDs from `Candidates`, or `""`
to let the request's query choose. A claim **path** is a JSON array of
keys, indexes, and `null` for every element. Holder keys sign during
`Respond`, so a key store requiring user presence prompts then. When
`redirect_uri` is set, open it in the browser.

## Other functions

| Function | |
|---|---|
| `ParseRequestLink(link)` | `{"client_id", "request_uri", "request_uri_method"}` |
| `CheckKeyStore(store)` | `{"checked": [purposes]}` |
| `IsTestBuild()` | whether the framework is the `mobiletest` build: an app should refuse to run on one |

## Test build

Built with `-tags mobiletest` (into `build/test/`, apart from the
release build in `build/release/`), the framework adds `StartTestEnv`:
an in-process HAIP issuer, Wallet Provider and Verifier, for the Swift
package's end-to-end tests. `IsTestBuild` is true in it. An app never
ships that build.

## Swift

The Swift package (`ios/OID4VCWallet`) doesn't expose these gomobile
shapes: an app implements its own `KeyStore`, `CredentialStore` and
`WalletProvider` protocols — throwing, non-optional, the provider
`async` — which it adapts, and `WalletError` carries `code`,
`protocolError`, `isRetryable` and a user-facing
`localizedDescription`.
