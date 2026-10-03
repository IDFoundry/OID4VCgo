# OID4VCgo mobile ABI

The API the Go `mobile` package exposes through gomobile: version
**7** (`ABIVersion`). The Swift package `ios/OID4VCWallet` wraps it in
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
| `delivery_unknown` | sending a presentation failed in a way that leaves it unknown whether the Verifier received it; it isn't sent again, which could present twice |
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
`holder_key_id`, `received_at`, `claims`, `display`, `valid_until`,
`status_list` and `status`, and `copies` (each copy's `credential`,
`holder_key_id` and `presented`). A record written before a field was
kept lacks it.

The store also keeps each **pending deferred credential**, under the ID
`deferred-<id>`, as a record with `"kind": "deferred"`. The record holds
what polling it after a relaunch needs: the issuer, the configuration,
the transaction ID, the access token and its expiry, the DPoP key ID
and every copy's holder key ID, the interval, and when it was
deferred. The access token is
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

These may wait on the network. A cancelled call returns without waiting
for them. An error whose message starts with `[network]` is a network
failure, reported as `network` (retryable); any other is `platform`.
The Swift package's adapter marks a `URLError` this way.

## Wallet

`NewWallet(configJSON, keys, credentials, provider)`:

```json
{"client_id": "…", "redirect_uri": "…",
 "issuer_roots": "<PEM>", "verifier_roots": "<PEM>",
 "development": false, "locales": ["en-AU", "en"], "batch_size": 0}
```

`client_id`, `redirect_uri`, `issuer_roots` and a provider are needed to
receive credentials; `verifier_roots` to present them. `development`
allows services on loopback addresses. `locales` are the holder's
preferred languages (BCP 47, most preferred first) for issuers' display
metadata. Without them, the issuer's entry without a locale is used,
else its first. `batch_size` is how many copies of each credential to
request when an issuer offers batches: 0 means 5, and it's capped at
the issuer's `batch_size`.

| Method | Result |
|---|---|
| `Credentials()` | `{"credentials": [summary]}` |
| `HolderKeyIDs()` | `{"key_ids": [...]}`: the keys the wallet still needs: the credentials' holder keys, and each pending deferred credential's holder and DPoP keys. Any other key in the KeyStore, at launch before any issuance, is an orphan to delete |
| `Deferred()` | `{"deferred": [pending]}`: the credentials issuers have deferred and not yet settled, oldest first, including ones from before the app last quit. No network calls |
| `PollDeferred(op, deferredID)` | `{"status": "pending" \| "issued", "credential": summary, "interval_seconds"}`; a refusal is `credential_denied`, and is then no longer pending. The first poll after a relaunch fetches the issuer's metadata |
| `AbandonDeferred(deferredID)` | deletes a pending one and its keys, for example after its access token has expired |
| `Credential(id)` | summary with `"claims"`: an SD-JWT VC's claims, or an mdoc's namespace → element → value, byte strings in base64 |
| `DeleteCredential(id)` | deletes it and its holder key |
| `CheckStatus(op, credentialID)` | the summary, with `"status"` checked now. It fetches the issuer's status list and checks the list's signature against `issuer_roots`. The list covers many credentials, so fetching it doesn't tell the issuer which one is checked. A credential without a status list is returned as it is |
| `StartIssuance(op, offerURI)` | an `Issuance` |
| `ResumeIssuance(op, redirect)` | an `Issuance` ready for `RequestCredentials`: completes the authorization in progress that the redirect's `state` names, after the app was killed during the browser step. One that matches nothing, has already been used, or has expired is `not_found` |
| `StartPresentation(op, requestLink)` | a `Presentation` |

A credential **summary** is `{"id", "credential_issuer",
"configuration_id", "format", "vct", "doctype", "received_at",
"holder_key_present", "display", "valid_until", "status"}`.

- `holder_key_present` is false when the key store no longer holds the
  credential's key, for example after a restore to another device, so
  it can't be presented. It's set by `Credentials` and `Credential`.
- `display` is how to show the credential, from the issuer's metadata
  when it was received, in `locales`' language: `{"issuer_name",
  "issuer_logo", "name", "description", "logo", "background_color",
  "text_color"}`. A logo is `{"uri", "alt_text"}`, and only an https URL
  or a `data:` image is passed on.
- `valid_until` is when the credential expires.
- `copies` is how many copies the wallet holds, each bound to its own
  key, and `copies_left` how many no Verifier has seen. A presentation
  uses one of those, so presentations can't be linked by the
  credential. Once none is left, a copy is reused.
- `status` is its revocation status as last checked: `{"value": "valid"
  | "invalid" | "suspended" | "0x…", "checked_at"}`.

Each of those three is absent when unknown.

## Issuance

Steps, in order: `Offer`; then `BeginAuthorization` and
`CompleteAuthorization` (`grant` `authorization_code`), or
`RedeemPreAuthorizedCode` (`grant` `pre-authorized_code`); then
`RequestCredentials`; `Close`. A deferred credential is polled from the
`Wallet` (`PollDeferred`): it outlives `Close`, and the app quitting.

| Method | Result |
|---|---|
| `Offer()` | `{"credential_issuer", "issuer_name", "issuer_logo", "grant", "tx_code": {"input_mode", "length", "description"}, "credentials": [{"configuration_id", "format", "vct", "doctype", "name", "description", "logo", "background_color", "text_color"}]}`, with display metadata as in a summary |
| `BeginAuthorization(op)` | the authorization URL, to open in `ASWebAuthenticationSession` |
| `CompleteAuthorization(op, redirect)` | the redirect back to `redirect_uri`, whole or just its query. It's used up whatever happens: after a failure, start again with `BeginAuthorization` |
| `RedeemPreAuthorizedCode(op, txCode)` | the PIN, `""` if `tx_code` is absent; a wrong one is `protocol` and can be retried |
| `RequestCredentials(op)` | `{"credentials": [summary], "deferred": [pending], "failed": [{"configuration_id", "code", "detail"}]}`. A failed one was refused for good, or failed the wallet's checks, and doesn't hold up the rest; only when nothing was obtained is a refusal an error |
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
| `Respond(op, idsJSON)` | `{"query_ids", "redirect_uri"}`. A failure in transit, or a Verifier's server error, is `delivery_unknown`, and the presentation is then answered |
| `Decline(op)` | `{"query_ids": [], "redirect_uri"}`. The refusal stands from the first call. If sending it failed in transit, call `Decline` again to send the same refusal |

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
