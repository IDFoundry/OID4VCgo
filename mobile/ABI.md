# OID4VCgo mobile ABI

The API the Go `mobile` package exposes through gomobile: version
**13** (`ABIVersion`). The Swift package `ios/OID4VCWallet` wraps it in
typed Swift (`Wallet`, `Issuance`, `Presentation`, `WalletError`), and
the Kotlin library `android/OID4VCWallet` in Kotlin (the same types,
with suspend functions, `WalletException` and `StateFlow`s); this
document is the contract underneath, for those wrappers or an app
calling the framework directly.

Version 13 adds `CompareAndSwap` to the `CredentialStore` the app
implements (see CredentialStore), which the wallet now changes every
record through, so that processes sharing one store (an app and its
extension) never both use one credential copy, complete one
authorization or redeem one refresh token. A version-12 store has no
such call, and the wrappers refuse a framework of another version. It
also adds the `unavailable` error's `refresh_in_progress` detail, and
the records' `reservation`, `redemption` and `redemption_expires_at`
fields.

Some additions came within version 12 without bumping it: they add
calls and optional JSON fields, so an older wrapper is unaffected, but
an app can't tell from `ABIVersion` whether a library has them. The
DC API's `StartMdocPresentation` and `MdocCandidates` arrived in
OID4VCWallet 0.7.0 (Swift); `StartDCAPIPresentation`, proximity
(`StartProximityPresentation`, `NewProximityReader`) and
`require_signed_dcapi_requests` came after it, then `tls_pins` and the
`tls_pin` code, later the KeyAgreement (`SetKeyAgreement`,
`CheckKeyAgreement`, `proximity_device_auth`), and then certificate
revocation (`crls`, `revocation`, `SetCRLs` on a Wallet and a
ProximityReader, later `crl_issuers` and a Wallet's
`no_revocation_check`), and later `accept_mdl_signer_without_eku`
on a Wallet and a ProximityReader. An older wrapper shows a
code it doesn't know as it is. Check a library's release notes for the
calls it has.

Some error classifications changed within version 12 too. A call the
configuration lacks what it needs for — `issuer_roots` or
`redirect_uri` to receive credentials, `verifier_roots` to present, a
provider and `client_id` under `"issuance_profile": "haip"` — was
`protocol` and is now `invalid_input` with the detail
`not_configured` (`DetailNotConfigured`), its message naming the
configuration key. A `redirect_uri` in a form no issuance can
authenticate with is `invalid_input` at `NewWallet` rather than
`protocol` at each issuance (see Wallet). Outside `development`, a
configuration that sets a trust role's roots without naming the role
in `revocation` or `no_revocation_check` is `invalid_input` at
`NewWallet`, where it used to check that role for nothing (see
Wallet).

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
  example `invalid_grant`, which a wrong PIN gets), or with one of the
  wallet's own (`request_refused`'s, and `invalid_input`'s
  `not_configured`). The code and detail are stable; the message is for
  logs. A callback's error comes back to the app as `platform`,
  carrying its message. (Version 1 had no detail.)
- **Threads:** every call blocks. Call from a background thread, never
  the main thread; callbacks run on the calling thread.
- **Cancellation:** a call that waits on the network takes an
  `Operation` (`NewOperation(timeoutMillis)`, 0 for no timeout); `Cancel`
  it from any thread, and the call returns `cancelled`. Its timeout,
  like a request's own, returns `network`.

## Error codes

| Code | Meaning |
|---|---|
| `invalid_input` | an argument or the configuration is malformed, or, with the detail `not_configured`, the configuration lacks what the call needs (`verifier_roots` to present, say): the message names the key |
| `platform` | a callback into the app failed (its message follows) |
| `network` | a request couldn't be made, got no answer, or timed out; retryable |
| `unavailable` | the service answered with HTTP 5xx or 429; or, with the detail `refresh_in_progress` (ABI 13), another process sharing the CredentialStore is refreshing with the same refresh grant; retryable later |
| `cancelled` | the Operation was cancelled |
| `not_found` | no key, credential or deferred credential with that ID |
| `wrong_step` | a session method called out of turn, or after Close |
| `authorization_denied` | the Authorization Server refused, e.g. the holder declined |
| `credential_denied` | the issuer refused a deferred credential |
| `no_matching_credential` | nothing held answers the Verifier's request |
| `reissue_required` | a credential can't be refreshed: no refresh token was kept, or the Authorization Server no longer accepts it |
| `untrusted_verifier` | the Verifier's request is signed with a certificate that doesn't chain to `verifier_roots`: it's refused unread |
| `invalid_selection` | a presentation's selection doesn't answer the request as it asks, or, at `Respond`, what the holder was shown no longer holds (a copy another Verifier has seen would now be presented, or a selected credential was refreshed since): nothing was sent |
| `delivery_unknown` | sending a presentation failed in a way that leaves it unknown whether the Verifier received it; it isn't sent again, which could present twice |
| `tls_pin` | a host in `tls_pins` presented a certificate matching none of its pins; nothing was sent to it |
| `profile_violation` | under `"issuance_profile": "haip"`, the issuer doesn't follow HAIP 1.0: it's refused |
| `client_auth_unsupported` | the offer's Authorization Server takes no client authentication the wallet can give: a Wallet Attestation needs a provider and `client_id` |
| `proof_unsupported` | the wallet can't hold an offered credential, or the issuer takes no proof it can give: one bound to no key (which the wallet doesn't receive) or by a method other than `jwk`/`cose_key`, both refused before the holder sees the offer; or, when the credentials are requested, no proof type signed with ES256, or a key attestation without a provider |
| `request_refused` | the wallet refused an authentic presentation request it must not answer (`transaction_data` it doesn't support, or a parameter OpenID4VP forbids), and sent the Verifier the error OpenID4VP requires: the detail is that error code, such as `invalid_transaction_data`. For a DC API request, the start call's error is what goes back to the platform. For a redirect request, `TakeRefusalRedirect` returns the `redirect_uri` the Verifier answered with, to open |
| `protocol` | an issuer, Authorization Server or Verifier answered with an error, or with something the wallet refuses |
| `internal` | a bug |

An error's message is fit for an app's logs. It never carries a remote
party's own description (`error_description`, an error body), a URL's
path or query (which can carry a pre-authorized code, a `request_uri` or
a `response_code`), credential claims, control characters, line or
paragraph separators, or invisible format characters. It's at most 300
characters. The remote party's OAuth error code is the
`detail`.

## Callbacks the app implements

A callback that can fail returns `[]byte` or nothing besides its error:
Swift imports those as `throws`. `KeyStore.CreateKey` returns a string,
so Swift sees it with an `NSError` out-parameter instead.

### KeyStore

P-256 keys that never leave the platform: the Secure Enclave on iOS,
Android Keystore (StrongBox, else the TEE) on Android.

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

A `CreateKey` error whose message starts with `[network]` is reported as
`network` (retryable), as a `WalletProvider`'s is; any other is
`platform`. The Kotlin library's adapter asks the app's `WalletProvider`
for an attestation challenge before it creates a key, and marks an
`IOException` from it this way. That challenge, and the key's
attestation chain, stay on the Kotlin side: the ABI's calls are
unchanged.

### KeyAgreement

Optional: ECDH with holder keys inside the platform key store, so an
in-person response can authenticate with deviceMac (ISO/IEC 18013-5
§9.1.3.5) instead of a signature. Give one with
`Wallet.SetKeyAgreement(ka)` and set `"proximity_device_auth":
"mac_preferred"`; it's separate from the KeyStore, which is unchanged.

| Method | |
|---|---|
| `Agree(id, peerPublicKey) → []byte` | ECDH between holder key `id` and `peerPublicKey` (uncompressed X9.63 P-256): the 32-byte shared secret |

A key that can't agree keys (Android Keystore keys need
`PURPOSE_AGREE_KEY`, API 31+) fails with a message starting with
`[no_key_agreement]`: the wallet then signs. On iOS, `KeychainKeyStore`
agrees keys with any holder key, in the Secure Enclave or not
(`SecKeyCopyKeyExchangeResult`), and asks for user presence as it
does to sign. Any other error fails the
response as `platform`. `CheckKeyAgreement(store, ka)` exercises one.

### CredentialStore

Opaque records kept by ID, under the platform's data protection.

| Method | |
|---|---|
| `Put(id, record)` | replaces any record with that ID |
| `Get(id) → []byte` | empty if there's none |
| `List() → []byte` | a JSON array of every record |
| `Delete(id)` | no error if absent |
| `CompareAndSwap(id, expected, record) → []byte` | atomically: replaces `id`'s record with `record`, or deletes it when `record` is empty, only if what's stored is byte for byte `expected` (empty: no record); returns what was stored before, either way (added in ABI 13) |
| `Durable() → bool` | whether records survive the app quitting (below) |

`CompareAndSwap` is the one call that must be atomic **across
processes**: between its read and its write, no `Put`, `Delete` or
other `CompareAndSwap` from any process sharing the store may write that
record. The wallet reads a record, changes it and swaps it in with
`CompareAndSwap`, reading again when another write got in first: that
is how it reserves a credential's copy for a presentation, consumes an
authorization (swapping in nothing), records a status or a refresh, and
claims a refresh grant while it redeems the token. `Put` and `Delete`
must hold the same exclusion, so a swap never overwrites a write made
after its read. A store shared with an extension (an app group on iOS)
needs a lock both processes take — a file lock — not one inside each.
Compare the record as stored, after decrypting it if the store encrypts
it: the wallet compares what `Get` returned. A store that doesn't
compare loses the guarantee: two processes may then present one copy
as unused, or redeem one refresh token twice.

A record is JSON the app needn't read: `id`, `credential_issuer`,
`configuration_id`, `format`, `vct`, `doctype`, `credential`,
`holder_key_id`, `received_at`, `claims`, `display`, `valid_until`,
`status_list`, `status_list_cwt`, `status`, `grant_id` and
`credential_identifier` (the dataset a refresh asks for again),
`copies_correlated` (the issuer gave two copies the same `jti`, `sub`,
status list or identifier list entry, disclosure digest, or validity timestamp not rounded
to the day; absent when not), and `copies` (each copy's `credential`, `holder_key_id`, `presented`,
`shown_to`, its own `status_list` and `valid_until`, and `reservation`,
the latest presentation that reserved it and may still undo that). A
record written before a field was kept lacks it.

The store also keeps each **pending deferred credential**, under the ID
`deferred-<id>`, as a record with `"kind": "deferred"`. The record holds
what polling it after a relaunch needs: the issuer, the configuration
and credential_identifier, the transaction ID, the access token and its expiry, the DPoP key ID
and every copy's holder key ID, the interval, when it was deferred,
and the grant it came from and the credential it replaces, if any. The access token is
bound to the DPoP key, which never leaves the KeyStore — unless the
record has `"token_type": "Bearer"` and no DPoP key: a Bearer token,
usable by whoever holds it, which is why the store must keep these
records under the platform's data protection (OpenID4VCI 1.0 §13.10). A store keeps
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
complete data protection, excluded from backups. The Kotlin library's
keeps each as a file in `noBackupFilesDir`, encrypted with AES-256-GCM
under an Android Keystore key that works only while the device is
unlocked. Both are durable, and both take an exclusive lock on a file
in their directory (`flock` on iOS, a `FileChannel` lock on Android) for
every write, so their `CompareAndSwap` is atomic across processes using
the directory — on iOS, an app and its extensions sharing an app
group's.

### WalletProvider

The Wallet Provider's backend (HAIP 1.0 §4.4.1, §4.5.1). Keys are public
JWKs; the results are compact JWTs. It's optional: without one, the
wallet gives neither attestation, and receives credentials only from
issuers that ask for neither (OpenID4VCI 1.0 allows both to be left
out). An issuer asking for one is then refused with
`client_auth_unsupported` or `proof_unsupported`.

| Method | |
|---|---|
| `WalletAttestation(clientID, instanceKeyJWK) → []byte` | binds the instance key to the wallet's client ID |
| `KeyAttestation(keysJWK, nonce) → []byte` | `keysJWK` is a JSON array of JWKs; the attestation carries the issuer's nonce |

These may wait on the network. A cancelled call returns without waiting
for them. An error whose message starts with `[network]` is a network
failure, reported as `network` (retryable); any other is `platform`.
The Swift package's adapter marks a `URLError` this way, and the Kotlin
library's an `IOException`.

## Wallet

`NewWallet(configJSON, keys, credentials, provider)`:

```json
{"client_id": "…", "redirect_uri": "…",
 "issuer_roots": "<PEM>", "verifier_roots": "<PEM>", "registrar_roots": "<PEM>",
 "mdoc_reader_roots": "<PEM>", "mdoc_reader_require_eku": false, "require_trusted_mdoc_reader": false,
 "verifier_require_eku": "", "registrar_require_eku": "", "issuer_require_eku": "", "issuer_metadata_require_eku": "",
 "mdoc_issuer_roots": "<PEM>", "mdoc_issuer_roots_by_doctype": {"org.iso.18013.5.1.mDL": "<PEM>"}, "mdoc_issuer_require_eku": "",
 "accept_mdl_signer_without_eku": false,
 "require_signed_dcapi_requests": false,
 "development": false, "development_roots": "<PEM>", "locales": ["en-AU", "en"], "batch_size": 0,
 "request_refresh": false, "copy_policy": "per_presentation", "issuance_profile": "openid4vci",
 "tls_pins": {"issuer.example": ["<base64 SHA-256 of an SPKI>"]}, "proximity_device_auth": "signature",
 "status_issuers": {"https://issuer.example": ["https://status.example"]},
 "require_issuer_name": false, "issuer_metadata_roots": "<PEM>", "require_signed_issuer_metadata": false,
 "require_issuer_metadata_name": false, "max_issuer_metadata_age_seconds": 0, "allow_foreign_iss": false,
 "crls": "<PEM X509 CRLs>", "revocation": ["issuer", "verifier"], "crl_issuers": "<PEM>",
 "no_revocation_check": ["status", "issuer_metadata", "registrar", "mdoc_reader"]}
```

`issuer_roots` is needed to receive credentials, and `verifier_roots` to
present them. `issuance_profile` is `"openid4vci"`, the default, or
`"haip"`. Under `"openid4vci"`, an issuance follows the issuer's and its
Authorization Server's metadata: a Wallet Attestation at the token
endpoint where the server takes one, and none for a pre-authorized code
where it allows that (`pre-authorized_grant_anonymous_access_supported`);
a key attestation where the issuer requires one
(`key_attestations_required`), and a jwt proof otherwise; a c_nonce where
the issuer has a nonce endpoint; a DPoP-bound access token, or a Bearer
one where the server issues that. `"haip"` also refuses an issuer that
doesn't follow HAIP 1.0 §4 (`profile_violation`), and needs a provider
and `client_id`. A Wallet Attestation needs a provider and `client_id`,
and the authorization code grant a `redirect_uri`: a wallet receiving
credentials only from pre-authorized codes redeemed with no client
authentication needs none of them. Outside `development`, a
`redirect_uri` must be the app's own URI scheme
(`com.example.wallet:/callback`) or loopback http to 127.0.0.1 or
[::1], or `NewWallet` is `invalid_input`: `ResumeIssuance` can't
complete an https one. In `development` too, a private-use scheme must
be a domain name in reverse order followed by a single slash,
`reverse.domain:/path` (RFC 8252 §7.1), and no `redirect_uri` may carry
a fragment or credentials: `myapp:/callback`,
`com.example.wallet://callback` and `com.example.wallet:callback` are
`invalid_input` at `NewWallet`. (Earlier within ABI 12 `NewWallet`
took them, and every issuance that authenticated then failed as
`protocol`.)
`registrar_roots`, if set, are the registrars whose registrations of
Verifiers the wallet checks (OpenID4VP `verifier_info`, OID4VCgo's
`registration` format); without them, registrations are ignored.
`mdoc_reader_roots`, if set, are the mdoc readers recognized when one
signs an `org-iso-mdoc` request (see MdocPresentation); without them,
every such request is shown by its origin. `verifier_require_eku`,
`registrar_require_eku`, `issuer_require_eku` and
`issuer_metadata_require_eku`, dotted object identifiers, recognize only
certificates under `verifier_roots`, `registrar_roots`, `issuer_roots`
and `issuer_metadata_roots` whose extended key usage extension lists
that OID: the one an ecosystem marks its Verifiers', registrars',
issuers' or issuer-metadata signers' certificates with (OpenID4VP and
HAIP define none). `anyExtendedKeyUsage` (2.5.29.37.0) is refused as
one. Outside `development`, two roles whose roots may vouch for the same
certificates each need theirs (`mdoc_reader_require_eku` for
`mdoc_reader_roots`, whose EKU is 1.0.18013.5.1.6), and the two must
differ: otherwise an issuer's signing certificate would be taken for a
trusted Verifier, a Verifier's for an issuer, or a Verifier's second
certificate for a registrar, and `NewWallet` fails with
`invalid_input`. Roots may vouch for the same certificates when they
share a certificate, a key under the same subject, or a certification
path, and whenever either holds an intermediate (a certificate not
signed by its own key), since where it chains to can't be told. All
four were added within ABI version 12: `issuer_require_eku` and
`issuer_metadata_require_eku` later, as the check grew to cover every
role.

`mdoc_issuer_roots`, `mdoc_issuer_roots_by_doctype` and
`mdoc_issuer_require_eku` give mdocs (`mso_mdoc`) their own issuer
trust, for a wallet receiving both formats, whose SD-JWT VC issuers and
document signers carry different extended key usages and may come from
different trust lists. `mdoc_issuer_roots` (PEM), if set, are the IACAs
a received mdoc must chain to in place of `issuer_roots`, so an
`issuer_roots` anchor alone can't sign an mDL. `mdoc_issuer_roots_by_doctype`
(an object of document type to PEM) are each document type's own: an
mdoc of a type it names must chain to them, not to `mdoc_issuer_roots`
or `issuer_roots`; a type named with an empty string is refused.
`mdoc_issuer_require_eku`, a dotted object identifier, recognizes only
document signer certificates with that extended key usage (the mDL's
is 1.0.18013.5.1.2), in place of `issuer_require_eku`. Unset, an mdoc
under `issuer_roots` gets `issuer_require_eku`, and one under the mdoc
roots ISO/IEC 18013-5's default document signer check, which requires
the mDL document signer extended key usage. With only
`issuer_roots` and none of these, both formats share them, as before.
`issuer_roots` is then optional for a wallet receiving only mdocs. In
the role check above, the issuers' roots of both formats are one role,
and aren't checked against each other; the mdoc ones are checked
against the other roles with `mdoc_issuer_require_eku`. Added within
ABI version 12.

`accept_mdl_signer_without_eku` (default false) also accepts a document
signer certificate with no extended key usage extension, which the
default check refuses, for issuers whose document signers have none.
Any end-entity certificate without one under the same IACAs, such as a
revocation list signer's, can then sign mdocs the wallet accepts. A
certificate with an extended key usage must still list the mDL
document signer's. It can't be set with `mdoc_issuer_require_eku`, or
with `issuer_require_eku` unless `mdoc_issuer_roots` is set: either
already decides which document signers are accepted, and the
combination is `invalid_input`. Added within ABI version 12.

`NewWallet`, and `NewProximityReader`, refuse a configuration with a key
they don't know, one that matches a key only in case, or anything after
the JSON object, so a misspelled option is never silently left at its
default.
`mdoc_reader_require_eku`
recognizes only reader certificates with the ISO/IEC 18013-5 reader
authentication extended key usage (1.0.18013.5.1.6), and
`require_trusted_mdoc_reader` refuses a request no recognized reader
signed, with `untrusted_verifier`; it needs `mdoc_reader_roots`.
`require_signed_dcapi_requests` refuses an unsigned OpenID4VP request
over the Digital Credentials API (`StartDCAPIPresentation`) with
`untrusted_verifier`: off by default, since HAIP requires a wallet to
support unsigned requests. The Kotlin library sets it
(`requireSignedDCAPIRequests`); the Swift package doesn't, since Safari
asks only with `org-iso-mdoc`.
`status_issuers` names, for each credential issuer (an SD-JWT VC's
`iss`), the Status Issuers that may sign its status lists on its behalf,
each recognized by a certificate under `issuer_roots` naming it (a URI,
or a DNS name for a `dns:` identifier). Without it, `CheckStatus`
accepts only a status list the credential's issuer signed itself, with
the credential's own key or a certificate naming its `iss`, so another
issuer under the same roots can't decide its status. An mdoc's status
list is bound as ISO/IEC 18013-5 §12.3.6 says instead (under the
certificate its MSO's status names, or else the CA that signed its
document signer), and `status_issuers` doesn't apply to it. Added
within ABI version 12.
`require_issuer_name` refuses a received SD-JWT VC whose `iss` its
signing certificate doesn't name; SD-JWT VC doesn't require them to
correspond, so set it where `issuer_roots` certify several issuers.
A received, deferred or refreshed SD-JWT VC whose `iss` isn't the
`credential_issuer` it was requested from is refused, so an issuer
can't hand over another's credential, issued for the holder's keys, as
its own; one without `iss` names nothing to check. `allow_foreign_iss`
receives it: OpenID4VCI §14.4 lets a credential name its issuer
differently, so set it only for issuers that do, where `issuer_roots`
certify them alone. Added within ABI version 12.
`issuer_metadata_roots` are the trust anchors for signed Credential
Issuer Metadata (OpenID4VCI §12.2.3, HAIP 1.0 §4.1): with them, signed
metadata is asked for and verified. `require_signed_issuer_metadata`
refuses an issuer whose metadata isn't signed under them, before the
holder signs in or enters a transaction code;
`require_issuer_metadata_name` refuses signed metadata whose
certificate doesn't name the issuer; and
`max_issuer_metadata_age_seconds` refuses metadata signed longer ago.
The two requirements need `issuer_metadata_roots`. Added within ABI
version 12.
`development`
relaxes what production requires, for a wallet talking to services on a
development machine. Never ship an app with it set, nor set it just to
use memory stores: it also drops the network protections. It lets
issuers, Authorization Servers, Verifiers and status lists be on
loopback addresses, over http there too; makes every request through an
ordinary HTTP client, which reaches private network addresses and
follows redirects, instead of the hardened one (with or without
`development_roots`); and skips the checks made in production: durable stores and
keys, the random source, roles' roots sharing no trust anchor, the
private-use or loopback `redirect_uri` rule, and FAPIgo's own client
checks. `development_roots`, only with
`development`, are CAs the wallet's HTTPS requests trust besides the
system's: a development service's own, where the platform's trust store
can't be given it — Go on Android reads only the system's CA files. `locales` are the holder's
preferred languages (BCP 47, most preferred first) for issuers' display
metadata. Without them, the issuer's entry without a locale is used,
else its first. `batch_size` is how many copies of each credential to
request when an issuer offers batches: 0 means 5, and it's capped at
the issuer's `batch_size`. `request_refresh` asks Authorization Servers,
in the authorization code grant, for a refresh token (the
`offline_access` scope), so `RefreshCredential` can later replace a
credential's copies without the holder (OpenID4VCI 1.0 §13.5). The
server must allow the wallet that scope, or the authorization fails. In
the pre-authorized code grant there's no scope to ask with: a refresh
token the server issues anyway is kept.
The refresh token is kept in the CredentialStore, as a record of
`"kind": "grant"`, with the wallet instance key ID, the key every
refresh must authenticate with again — or, for a grant that
authenticated no client (`"client_auth": "none"`), the `dpop_key_id`
its refresh token is bound to, whether its access tokens are DPoP or
Bearer (`"token_type": "Bearer"`). A record without `client_auth` is a
Wallet Attestation's. While a refresh redeems the token, the record
holds its claim (`redemption`, until `redemption_expires_at`, two
minutes on): a refresh from another process sharing the store then
fails as `unavailable`, with the detail `refresh_in_progress`, rather
than redeem the token twice. `copy_policy` is which copy of a
credential a presentation uses (OpenID4VCI 1.0: "a unique Credential
per presentation or per Verifier"). With `"per_presentation"`, the
default, every presentation uses a copy no Verifier has seen, so not
even one Verifier can link two presentations. With `"per_verifier"`, a
Verifier is shown the copy it has seen before, and only a new Verifier
an unused one: Verifiers can't link presentations to each other, but
one can recognise a returning holder, and copies last longer. Each copy
records the Verifiers it was shown to as hashes of their client_ids,
never the client_ids. Once every copy has been presented, a copy only
the same Verifier has seen is reused, if there is one, else the one
shown to the fewest Verifiers.

`tls_pins` pins hosts' certificates for the wallet's HTTPS requests:
host → base64 SHA-256 digests of a certificate's SubjectPublicKeyInfo
(`walletflow.TLSPins`). A request to a pinned host fails with `tls_pin`,
before anything is sent, unless a certificate in a chain that verified
has one of its pins: pins add to certificate verification, never
replace it. A host is a name, matched without case, or `*.` and a name,
matching any name one label below it. An IP address can't be pinned,
since a handshake to one names no host. A malformed host or pin, or a
host without pins, is `invalid_input`. The pins cover the requests Go
makes, in development too; an app's own requests, such as to its Wallet
Provider, are the app's to pin.

`revocation` names the trust roles whose certificate chains must pass a
check against Certificate Revocation Lists (RFC 5280), and `crls` holds
those lists as PEM `X509 CRL` blocks. The roles are `issuer` (a
received, deferred or refreshed credential's signer, under
`issuer_roots` and the mdoc roots alike), `issuer_metadata` (the signer
of signed issuer metadata), `registrar`, `mdoc_reader` (org-iso-mdoc and
in-person readers), `verifier` (a Verifier's request-signing
certificate, under `verifier_roots`) and `status` (a status list's
signer, in `CheckStatus`). `no_revocation_check` names the roles that
decline checking revocation, an explicit choice for where something
else stands in for it (certificates too short-lived to be worth
revoking, say). Outside `development`, each role whose roots are set —
`issuer` and `status` for `issuer_roots`, `mdoc_issuer_roots` or
`mdoc_issuer_roots_by_doctype`, `issuer_metadata` for
`issuer_metadata_roots`, `registrar` for `registrar_roots`,
`mdoc_reader` for `mdoc_reader_roots` and `verifier` for
`verifier_roots` — must be named in one of the two, or `NewWallet` is
`invalid_input`, its message naming the roots' key; a role named in
both is `invalid_input` too. In `development`, a role in neither checks
no revocation. `no_revocation_check`, and the refusal, were added within
ABI 12: before them, a role not named checked no revocation in
production too. A role named in `revocation` accepts a certificate only through a verified path on which
each certificate below the trust anchor has a current CRL (its
nextUpdate not passed) from its issuer that doesn't list it; the trust
anchor itself isn't checked, unless it's a certificate in the
roots that isn't self-signed (a Verifier's leaf in `verifier_roots`,
say, or an intermediate CA), which is checked against a CRL from the
CA that issued it. That
CA isn't on the path, so its certificate, to verify the CRL with, comes
from `crl_issuers` (PEM CA certificates, used for nothing else: they
aren't trust anchors). Checking an intermediate CA in the roots was
added within ABI 12: before it, one was never checked, so a path
ending at it passed whatever its own CA's CRL said. A certificate a
list names is refused, and so, failing closed, is one whose issuer has
no current list, or a pinned one whose CA isn't in `crl_issuers` — with lists for issuers but not
for Verifiers, name `issuer` alone. `crl_issuers` holding anything but
CA certificates is `invalid_input`; it was added within ABI 12, and
before it a pinned certificate that isn't self-signed was always
refused under its role. A refused credential is `protocol`, a
refused Verifier `untrusted_verifier`, a refused registrar's
registration unverified and a refused reader unrecognized, as for a
certificate outside their roots. A role may be named with no `crls`
yet: it refuses everything until `SetCRLs` supplies lists. An unknown
or repeated role, or `crls` holding anything but CRLs (a certificate,
text outside the PEM blocks, a list that doesn't parse, more than 64),
is `invalid_input`. Lists expire at their nextUpdate: fetch fresh ones
from the CAs' distribution points and pass them to `SetCRLs` before
then. Added within ABI version 12.

| Method | Result |
|---|---|
| `Credentials()` | `{"credentials": [summary]}` |
| `HolderKeyIDs()` | `{"key_ids": [...]}`: the keys the wallet still needs: the credentials' holder keys, each pending deferred credential's holder and DPoP keys, and each refresh grant's wallet instance key. A refresh grant no credential uses is forgotten, with its key. Any other key in the KeyStore, at launch before any issuance or refresh, is an orphan to delete |
| `Deferred()` | `{"deferred": [pending]}`: the credentials issuers have deferred and not yet settled, oldest first, including ones from before the app last quit. No network calls |
| `PollDeferred(op, deferredID)` | `{"status": "pending" \| "issued", "credential": summary, "interval_seconds"}`; a refusal is `credential_denied`, and is then no longer pending. The first poll after a relaunch fetches the issuer's metadata. One that ends without a credential stored releases its refresh grant once nothing else uses it, revoking the refresh token, best effort |
| `AbandonDeferred(deferredID)` | deletes a pending one and its keys, for example after its access token has expired, and its refresh grant once nothing else uses it, revoking the refresh token at the Authorization Server, best effort: a network request |
| `Credential(id)` | summary with `"claims"`: an SD-JWT VC's claims, or an mdoc's namespace → element → value, byte strings in base64 |
| `DeleteCredential(id)` | deletes it and its holder keys, and its refresh grant with the grant's instance key once no other credential uses it. The refresh token is first revoked at the Authorization Server (RFC 7009), best effort, when it has a revocation endpoint: a network request, so call it off the main thread |
| `RefreshCredential(op, credentialID)` | `{"credential": summary, "deferred": pending or null}`: replaces a `refreshable` credential's copies with a fresh batch, each bound to a new attested key, under the same ID, without the holder. If the issuer defers it, the credential is returned as it was, with the deferred one to poll, which settles as a new credential. One that can't be refreshed (no refresh token was kept, the Authorization Server no longer accepts it, or its grant issued several datasets of its configuration and the wallet can't ask for the one it holds again) is `reissue_required`: receive it again from a new offer |
| `CheckStatus(op, credentialID)` | the summary, with `"status"` checked now. It fetches the issuer's status list and checks the list's signature against `issuer_roots` (an mdoc's, against the mdoc roots it was received under). The list covers many credentials, so fetching it doesn't tell the issuer which one is checked. A credential without a status list is returned as it is, as is an expired one: it isn't valid whatever its status, so its status list isn't fetched (draft-ietf-oauth-status-list §8.3) |
| `StartIssuance(op, offerURI)` | an `Issuance` |
| `ResumeIssuance(op, redirect)` | an `Issuance` ready for `RequestCredentials`: completes the authorization in progress that the redirect's `state` names, after the app was killed during the browser step. One that matches nothing, has already been used, or has expired is `not_found` |
| `StartPresentation(op, requestLink)` | a `Presentation`. The `request_uri` is fetched by GET, or, for a link with `request_uri_method=post`, by POST with a fresh `wallet_nonce` and the wallet's metadata (OpenID4VP 1.0 §5.10), the Request Object then having to carry that `wallet_nonce` |
| `TakeRefusalRedirect()` | once, the `redirect_uri` the Verifier answered the latest `request_refused` with, `""` for none: open it (OpenID4VP §8.2). Added within ABI 12 |
| `SetCRLs(pem)` | replaces the lists the `revocation` roles check against, for every check from then on, with `pem`'s `X509 CRL` blocks. Anything but CRLs is `invalid_input`, and the lists are left as they were; `""` removes them all, so every role named then refuses. No network calls. Added within ABI 12 |

A credential **summary** is `{"id", "credential_issuer",
"configuration_id", "format", "vct", "doctype", "received_at",
"holder_key_present", "display", "valid_until", "status", "copies",
"copies_left", "linkable", "refreshable"}`, and on a
presentation's candidates `"shown_to_verifier"` and `"linkable_here"`.

- `holder_key_present` is false when the key store no longer holds the
  credential's key, for example after a restore to another device, so
  it can't be presented. It's set by `Credentials` and `Credential`.
- `display` is how to show the credential, from the issuer's metadata
  when it was received, in `locales`' language: `{"issuer_name",
  "issuer_logo", "name", "description", "logo", "background_color",
  "text_color"}`. A logo is `{"uri", "alt_text"}`, and only an https URL
  of a public host name (no IP address, single label, or name under
  `localhost`, `local`, `home.arpa`, `internal` or `lan`) or a `data:`
  image is passed on.
- `valid_until` is when the credential expires.
- `copies` is how many copies the wallet holds, each bound to its own
  key, and `copies_left` how many no Verifier has seen. A presentation
  uses one of those, so presentations can't be linked by the
  credential. Once none is left, a copy is reused.
- `linkable` is whether a copy has been presented to more than one
  Verifier, so those Verifiers could link the holder's presentations —
  or, when the issuer gave its copies the same `jti`, `sub` or status
  list entry, whether copies have between them. Refreshing gives it
  copies no Verifier has seen.
- `shown_to_verifier` and `linkable_here` are set only on a
  presentation's candidates (`Queries`): whether the Verifier asking has
  been shown this credential before, and whether presenting it now would
  hand it a copy another Verifier has seen (or, copies correlated as
  above, any copy another has seen).
- `refreshable` is whether its issuance kept a refresh token
  (`request_refresh`), so `RefreshCredential` can replace its copies.
  The Authorization Server may still refuse it (`reissue_required`).
- `status` is its revocation status as last checked: `{"value": "valid"
  | "invalid" | "suspended" | "0x…" | "unknown", "checked_at"}`.
  `unknown` is an mdoc whose MSO names an identifier list (ISO/IEC
  18013-5 §12.3.6.4), which the wallet can't check, and no status list
  on which it's anything but valid (added within ABI 12: before, such an
  mdoc was returned with no `status`).

`display`, `valid_until` and `status` are absent when unknown.

## Issuance

Steps, in order: `Offer`; then `BeginAuthorization` and
`CompleteAuthorization` (`grant` `authorization_code`), or
`RedeemPreAuthorizedCode` (`grant` `pre-authorized_code`); then
`RequestCredentials`; `Close`. A deferred credential is polled from the
`Wallet` (`PollDeferred`): it outlives `Close`, and the app quitting.

| Method | Result |
|---|---|
| `Offer()` | `{"credential_issuer", "issuer_name", "issuer_logo", "grant", "tx_code": {"input_mode", "length", "description"}, "credentials": [{"configuration_id", "format", "vct", "doctype", "name", "description", "logo", "background_color", "text_color"}]}`, with display metadata as in a summary |
| `BeginAuthorization(op)` | the authorization URL, to open in `ASWebAuthenticationSession` (iOS) or an Auth Tab, falling back to a Custom Tab (Android) |
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

Steps: `Verifier` and `Queries`; choose a selection (or start from
`DefaultSelection`); `Preview` it; then `Respond` or `Decline`, once.

| Method | Result |
|---|---|
| `Verifier()` | `{"client_id", "name", "response_uri", "registration": {"status", "name", "purpose", "privacy_policy", "registrar", "claims", "credentials", "expires"}}`: the registration is the Verifier's, from its request's `verifier_info`, checked against `registrar_roots` — `status` `"verified"` (with the rest: `claims` are the claims paths it's registered to request from any type of credential, and `credentials`, added within ABI version 12, those it's registered to request from given types: `[{"vct_values" or "doctype_value", "claims"}]`), `"invalid"` (it didn't verify, so isn't relied on), or `"none"` (none, or no `registrar_roots`) |
| `Queries()` | `{"queries": [{"query_id", "multiple", "credentials": [summary], "unregistered": [path], "unregistered_all"}], "credential_sets": [{"options": [[query ID]], "required"}]}`: the request's credential queries in its order, each with the credentials that can answer it (none when nothing can), and its sets of alternatives (none: every query must be answered). For a Verifier with a verified registration, `unregistered` are the claims paths a query asks for beyond it, then those its credentials would disclose along with them beyond it (the rest of an array disclosed as one, say), and `unregistered_all` whether it asks for every claim; nothing is refused for them — the holder decides |
| `DefaultSelection()` | `{"selection": {query ID: [credential ID]}}`: what the wallet would choose itself, the first answerable option of each set and each query's first credential, even when it takes several (`multiple`): the holder adds the others. `no_matching_credential` when the request can't be answered |
| `Preview(selectionJSON)` | `{"disclosures": [{"query_id", "credential_id", "claims": [path], "always_disclosed": [path], "retained": [path]}]}`: `always_disclosed` are the SD-JWT VC claims the Verifier receives beyond `claims`: those its issuer didn't make selectively disclosable, and what shares a Disclosure with a claim: the plaintext members of a disclosed object or array element a claim sits within, and the other elements of an array disclosed as one, each as a leaf (an index counts the credential's elements); show them with `claims` (added within ABI 12). `retained` are the claims the Verifier says it will keep (an mdoc query's `intent_to_retain`, OpenID4VP Appendix B.2.4): show that with them (added within ABI 12, later) |
| `Respond(op, selectionJSON)` | `{"query_ids", "redirect_uri"}`. A failure in transit, or a Verifier's server error, is `delivery_unknown`, and the presentation is then answered |
| `Decline(op)` | `{"query_ids": [], "redirect_uri"}`. The refusal stands from the first call. If sending it failed in transit, call `Decline` again to send the same refusal |

`selectionJSON` is a JSON object of query ID to an array of credential
IDs: the app's choice, from `Queries`, by whatever policy it applies.
The wallet presents exactly it, after checking it answers the request,
and returns `invalid_selection` otherwise: an unknown query or
credential, a credential that doesn't answer its query, more than one
for a query whose `multiple` is false (OpenID4VP 1.0 §6.1), a required
credential set with no option fully selected, two alternative options
of one set selected, or a query selected outside any fully selected
option (§6.4.2). Each credential's next
unused copy is presented. A claim **path** is a JSON array of keys,
indexes, and `null` for every element. Holder keys sign during
`Respond`, so a key store requiring user presence prompts then. When
`redirect_uri` is set, open it in the browser.

ABI version 12 added `registrar_roots`, the Verifier's `registration`,
and each query's `unregistered` and `unregistered_all`. Within it,
`issuance_profile`, an optional provider, `profile_violation`,
`client_auth_unsupported` and `proof_unsupported`, the grant record's
`client_auth`, `dpop_key_id` and `token_type`, and the deferred
record's `token_type` came later: each is new, and an older wrapper
shows a new code as a generic failure. An older wrapper sends no
`issuance_profile`, so its wallet follows the default, `"openid4vci"`:
it now receives from issuers outside HAIP 1.0, and redeems a
pre-authorized code anonymously where the Authorization Server allows
it. Set `"haip"` to keep refusing them.

ABI version 11 added `untrusted_verifier`.

ABI version 10 added `copy_policy`, each copy's Verifier record, and the
summary's `linkable`, `shown_to_verifier` and `linkable_here`.

ABI version 9 added `RefreshCredential`, `request_refresh`, the
summary's `refreshable` and `reissue_required`.

ABI version 8 replaced `Candidates` with `Queries` and the credential ID
arrays of `Preview` and `Respond` with a selection, and added
`DefaultSelection` and `invalid_selection`.

### Over the Digital Credentials API

`Wallet.StartDCAPIPresentation(op, protocol, requestData, origin)` takes
an OpenID4VP request delivered through the Digital Credentials API
(OpenID4VP 1.0 Appendix A) as the platform hands it over — on Android,
Credential Manager's protocol (`openid4vp-v1-unsigned`,
`openid4vp-v1-signed` or `openid4vp-v1-multisigned`) and its data — and
the calling page's or app's origin as the platform reports it. It
returns a `Presentation`, answered with the same steps, except:

- `Verifier()` has `"origin"`, and no `response_uri`. An unsigned
  request names no Verifier but its origin (no `client_id` or `name`):
  show that. A signed one's must chain to `verifier_roots`.
- `Respond` and `Decline` send nothing. Each returns, in
  `"dcapi_response"`, the response's data — a JSON object as text,
  `{"response": <the encrypted response>}` — for the platform to hand
  back to the page; `Decline`'s is OpenID4VP Appendix A.4's
  `{"error": "access_denied"}`, not encrypted.
- Presentations are bound to `"origin:" + origin`. A copy presented
  counts as shown to that origin for an unsigned request, and for a
  signed one to its `client_id` at that origin, so two Verifiers whose
  requests come from one page are two Verifiers
  (`shown_to_verifier`, `linkable_here`). A copy recorded as shown to
  the origin alone, over a signed request by an earlier release,
  counts as another Verifier's: it's `linkable_here`, not
  `shown_to_verifier`.
- A request that can't be parsed, or comes with no origin, is
  `invalid_input`: what the platform handed over, not a service's
  refusal. `StartMdocPresentation`'s is too. (Before OID4VCWallet 0.9.0
  both were `protocol`.)

`StartDCAPIPresentation` and these fields were added within ABI version
12, without changing anything there.

## MdocPresentation

An mdoc asked for over the Digital Credentials API as `org-iso-mdoc`
(ISO/IEC TS 18013-7 Annex C): what iOS hands a document provider
extension. `Wallet.StartMdocPresentation(op, requestData, origin)`
takes the request's data and the requesting page's origin as the
platform reports them (on iOS, `IdentityDocumentWebPresentmentRawRequest.requestData`
and `ISO18013MobileDocumentRequestContext.requestingWebsiteOrigin`,
serialized as `scheme://host[:port]`, with no trailing slash: the
session transcript binds it byte for byte). Steps: `Request`, then
`Respond` once; to decline, cancel the platform's request — nothing is
sent to the reader.

| Method | Result |
|---|---|
| `Request()` | `{"origin", "reader", "documents": [{"doctype", "elements": [{"namespace", "identifier", "retain"}], "credentials": [summary]}]}`: `reader` is the subject common name of the reader that signed the request when its certificate chains to `mdoc_reader_roots`, without control, line separator or invisible format characters, else `""` — show `origin` then. `reader_certificate`, with `reader`, is that reader's certificate, base64 DER: compare it, not the name, with a reader the app checked itself. Each document is the request's, with the held mdocs of its doctype (none when nothing can answer); `retain` is whether the reader says it will keep the value. Each summary has `shown_to_verifier` and `linkable_here`, for this origin |
| `Wallet.MdocCandidates(origin)` | `{"credentials": [summary]}`: the held mdocs, each with `shown_to_verifier` and `linkable_here` for `origin` — for a consent screen shown before iOS releases the request itself |
| `Respond(op, document, credentialID, elementsJSON)` | `{"response", "linkable"}`: `response` is the base64 `EncryptedResponse` to hand back to the platform (on iOS, `ISO18013MobileDocumentResponse(responseData:)`); `linkable` whether the copy presented had been seen by another Verifier |

`elementsJSON` is a JSON array of `[namespace, identifier]` pairs, each
one the document requested (`invalid_selection` otherwise), and
`document` an index into `documents`. The credential's next unused copy
is presented, recorded as shown to `"origin:" + origin`. Its holder key
signs during `Respond`. A malformed request is `protocol`.

`mdoc_reader_roots`, `mdoc_reader_require_eku`,
`require_trusted_mdoc_reader`, `MdocCandidates`, MdocPresentation and
`development_roots`, `tls_pins` and `tls_pin` were added within ABI version 12: they add to it without changing anything there.

## ProximityPresentation

### NFC engagement additions

The following calls are additive within ABI 12. They provide Go
handover messages, and (in the next table) the APDU protocols carrying
them; they do not register an Android NFC service or perform NFC I/O. They have not yet
been published in a release.

| Call | Contract |
|---|---|
| `Wallet.StartNFCProximityPresentationWithModes(modesJSON)` | Static NFC handover to BLE; modes use the existing JSON string array |
| `Wallet.StartNFCNegotiatedProximityPresentationWithModes(modesJSON)` | Prepare negotiated handover; finish it before starting the selected BLE transport |
| `Wallet.StartNFCDataProximityPresentation(maxCommand, maxResponse)` | Static NFC-only engagement; APDU data-field limits 1–65535 and 1–65536, excluding headers/status |
| `Wallet.StartNFCNegotiatedDataProximityPresentation(maxCommand, maxResponse)` | Negotiated NFC-only engagement; complete Hr/Hs before retrieval |
| `ProximityPresentation.HandoverSelect()` | Copy of NDEF Hs without NLEN; nil for QR or before negotiated selection |
| `ProximityPresentation.HandleHandoverRequest(hr)` | Complete NDEF Hr to Hs; freezes the accepted selection; repeated identical Hr is idempotent before establishment |
| `NewNFCHandoverRequest(modesJSON)` | Reader's Hr for supported mdoc BLE modes; retain exact returned bytes |
| `NewNFCHandoverRequestWithNFCData(modesJSON, maxCommand, maxResponse)` | Offer BLE plus classic NFC; retain exact Hr |
| `ProximityReader.StartFromHandover(hs)` | Start a reader from a static NDEF Hs |
| `ProximityReader.StartFromNegotiatedHandover(hs, hr)` | Start from the exact negotiated NDEF messages |
| `ProximityReader.StartFromNFCDataHandover(hs)` | Classic NFC-only reader with the same authentication and issuer policy |
| `ProximityReader.StartFromNegotiatedNFCDataHandover(hs, hr)` | Validate negotiated NFC carrier limits against Hr; bind both exact messages |
| `ParseNfcDataParameters(hs)` | Validate an NFC-only Hs; return `{"abi", "max_command", "max_response"}` |

For NFC, `Engagement().qr_code` is empty. Static roles share one UUID;
negotiated `Engagement` describes the chosen mode after Hr processing.
Reader signing, issuer roots, per-document trust policy and clock skew
remain those of `NewProximityReader`. Consent and response methods are
the existing presentation methods. Malformed handover input is
`invalid_input`; calls after the wallet presentation has progressed are
`wrong_step`. The platform owns lifecycle and radio cleanup; Go does
message staging and TNEP. For NFC-only holders, `ble_modes` is an empty array,
`service_uuid` and `ble_mode` are empty, and no BLE radio is needed.
Reader `Engagement`'s BLE fields are meaningful only for BLE sessions;
the native adapter retains the selected NFC data parameters separately.
Whole encrypted messages still go through `HandleMessage`/`Request`/
`Respond`; Go's `NFCHolder` and `NFCExchange` add and remove DO53 and
chain APDUs.

#### NFC APDUs (additive, ABI 12)

Every byte exchanged over NFC is built and parsed in Go
(`proximity/nfcapdu`). Native code moves APDUs and keeps threads, timers
and cancellation.

| Call | Contract |
|---|---|
| `ProximityPresentation.NFCHolder(negotiated, nfcData)` | The mdoc's NFC tag for this presentation: static (`HandoverSelect`) or TNEP (`HandleHandoverRequest`) handover, and NFC data retrieval when `nfcData`; limits must fit short APDUs. `invalid_input` otherwise |
| `NFCHolder.Process(apdu)` | One command APDU to an `NFCStep`: `Response`; `HandoverRead` (commit NFC-to-BLE now); `DataSelected`; `HasMessage`/`Message` (a session message: `Response` is nil and the answer goes through `Respond`); `Delivered` (the reader read the whole answer) |
| `NFCHolder.Respond(message)` | Answer the pending message: the `NFCStep` whose `Response` is the final ENVELOPE's response (GET RESPONSE fetches the rest). `wrong_step` with no message pending |
| `NFCHolder.RefuseMessage()` | Drop a message the session couldn't take; returns the `6985` response |
| `NFCHolder.Deactivate(handoverCommitted, qrSelected)` | Field loss: `NFCDeactivation.Cancel` (a negotiated Hs was answered but not read: end the presentation) and `DataClosed` (NFC data retrieval ended) |
| `NFCHolder.Close()` | End NFC data retrieval |
| `ClassifyNFCCommand(apdu)` | `NFCCommandOther`, `NFCCommandSelectNDEF`, `NFCCommandSelectData`, `NFCCommandSelectDataNoFCI` or `NFCCommandSelectOther`, for QR/NFC arbitration |
| `NewNFCHandoverRead(maxTransceive, hr)` | Reader: an `NFCExchange` reading the Hs, negotiating with `hr` when the tag offers TNEP (refused when `hr` is nil). `Negotiated()` afterwards |
| `NewNFCTransact(maxTransceive, maxCommand, maxResponse, message)` | Reader: an `NFCExchange` sending one session message to the NFC data application and reading the answer |
| `NFCExchange.Done()`, `Command()`, `WaitMillis()`, `Next(response)`, `Result()`, `Close()` | Until `Done`: wait `WaitMillis` (TNEP's waiting time; native code sleeps, so cancellation can interrupt it), send `Command`, pass the response to `Next`. Then `Result` is the Hs or the answer (`invalid_input` on a protocol failure). `Close` an abandoned exchange |
| `NFCSelectDataApplication()`, `CheckNFCDataApplicationSelected(response)` | Reader: select the NFC data application and check its response |

### QR and BLE presentation

An ISO/IEC 18013-5 in-person presentation, from the holder's side: the
holder shows a QR code, a reader scans it and connects over BLE, and
the reader asks for an mdoc. The app owns the BLE transport: in mdoc
peripheral server mode it advertises the service UUID and is the GATT
server; in mdoc central client mode it scans for the reader's service
UUID and connects as GATT client. Either way it reassembles each
message from its chunks and hands it to `HandleMessage`. Go does the
rest. `Wallet.StartProximityPresentation()` starts a session in
peripheral server mode; `Wallet.StartProximityPresentationWithModes(modesJSON)`
in the modes a JSON array lists, `"peripheral_server"`,
`"central_client"` or both (`invalid_input` otherwise). Offering both,
the app advertises and scans until the reader connects one way; a
reader offered both should choose central client mode (§8.3.3.1.1). Steps: `Engagement`, then `HandleMessage` for each
message, then `Respond` or `Terminate` on the `request` event. One
request per session. Every method is safe to call from any thread.

| Method | Result |
|---|---|
| `Engagement()` | `{"qr_code", "service_uuid", "ble_mode", "ble_modes", "ident"}`: the QR code's text (`mdoc:` and the DeviceEngagement), and in `ble_modes` each mode offered, `{"mode", "service_uuid"}`, each with its own UUID. In `peripheral_server` mode, advertise `service_uuid` and be the GATT server. In `central_client` mode, scan for `service_uuid`, connect as GATT client, and disconnect from a reader whose Ident characteristic isn't `ident` (base64, present only with that mode). `service_uuid` and `ble_mode` are `ble_modes`' first: peripheral server mode's, when offered |
| `HandleMessage(op, message)` | `{"event", "send", "reason", "error"}`. If `send` is present, it's the base64 message to send the reader. `event` is `request` (show `Request`), `ended` (send `send`, then disconnect) or `none`. `reason`, for `ended`, is `reader_ended` (the reader ended the session first) or `error`. `error` is then the failing call's text: `protocol` for a bad message, `untrusted_verifier` for a reader `require_trusted_mdoc_reader` refuses |
| `Request()` | `{"reader": {"status", "name", "claimed_name", "chain", "error"}, "documents": [{"doctype", "elements": [{"namespace", "identifier", "retain"}], "credentials": [summary]}]}`, in the request's order. `reader.status` is `trusted` (its certificate chains to `mdoc_reader_roots` and passes `mdoc_reader_require_eku`), `untrusted` (signed by a certificate that doesn't), `unauthenticated` (not signed) or `invalid` (a signature that doesn't verify for this session). `name` is the reader's name, set only when `trusted`; for another signed request, `claimed_name` is the name its certificate gives itself, which anyone can claim, so never show it as the reader's. Both are the certificate's subject common name without control, line separator or invisible format characters (bidirectional ones among them). (Within ABI 12, `name` was the common name whatever the status, until this was found to let an untrusted reader pass for a trusted one in an app that didn't check `status`.) `chain` is the certificates, leaf first, as base64 DER, and `certificates` their fields, for an app that can't parse them (iOS): `{"subject", "issuer", "not_before", "not_after", "serial", "subject_alt_names", "extended_key_usages", "key_usages", "is_ca", "signature_algorithm", "extensions", "sha256"}`. `error` says why the reader isn't `trusted`. Each summary has `shown_to_verifier` (this reader, known by its certificate, was shown it before; never for an unsigned one) and `linkable_here` |
| `Respond(op, document, credentialID, elementsJSON)` | `{"send", "linkable"}`: send `send`, the encrypted DeviceResponse, which ends the session, then disconnect. `linkable` is whether the copy presented had been seen by another Verifier. On an error, nothing is sent and the session goes on |
| `Terminate()` | `{"send"}`: the holder declined, cancelled or timed out. Send `send` (status 20) if a reader is connected, then disconnect. Nothing is disclosed |

`elementsJSON` and `document` are as in MdocPresentation. The
credential's next unused copy is presented, recorded as shown to the
reader by its certificate, or to a reader of that session alone when it
didn't sign. The holder key signs during `Respond` — or, with
`"proximity_device_auth": "mac_preferred"` and a KeyAgreement that can
agree with it, agrees a key with the reader's ephemeral key for
deviceMac. The reader can check a MAC but can't prove to anyone else that
the holder's device took part; the issuer-signed elements it receives
stay as provable as with a signature. An mDL must release
its mandatory elements to an unauthenticated reader (ISO/IEC 18013-5
§7.2.1), so `require_trusted_mdoc_reader` suits other documents.

The app enforces the timeouts. ISO/IEC 18013-5 recommends allowing at
least 30 seconds from engagement to the request (§8.2.3), and ending a
session after at least 300 seconds of inactivity (§9.1.1.4). The
transport's own rules (chunking, the State characteristic, not
reconnecting after a disconnect) are in `proximity/README.md`.

ProximityPresentation was added within ABI version 12, and later within
it `StartProximityPresentationWithModes`, `ble_modes` and `ident`.

## ProximityReader

The reader's side of an ISO/IEC 18013-5 in-person presentation: a
verifier asking for an mdoc over BLE. It doesn't need a `Wallet`.
`NewProximityReader(configJSON, keys)` configures a reader, and `keys`
may be nil for a reader that doesn't sign. Its `Start(qrCode)` begins a
`ProximityReaderSession` for the holder's QR code. A QR code the reader
can't use is `invalid_input`.

The configuration is `{"issuer_roots", "issuer_roots_by_doctype",
"reader_key_id", "reader_chain", "max_clock_skew_seconds",
"require_mdl_signer_eku", "accept_mdl_signer_without_eku", "crls",
"revocation", "crl_issuers"}`:
- `issuer_roots` (PEM) are the IACAs whose mdocs are accepted, of any
  document type `issuer_roots_by_doctype` doesn't name.
- `issuer_roots_by_doctype` (an object of document type to PEM) are each
  document type's own IACAs: a document of a type it names must chain to
  them, not to `issuer_roots`, so an issuer trusted for one document type
  can't sign another. With it, `issuer_roots` is optional, and then only
  the types it names are accepted. Additive within ABI 12.
- With `reader_key_id` (a P-256 key in `keys`) and `reader_chain` (PEM,
  leaf first, the leaf certifying that key), each request is signed
  (reader authentication, §9.1.4), so the holder sees who is asking.
  The leaf should carry the mdoc reader authentication extended key
  usage (1.0.18013.5.1.6).
- `max_clock_skew_seconds` (at most 3600) tolerates an issuer's clock
  that far off.
- `require_mdl_signer_eku` accepts only document signers with the mDL
  document signer extended key usage. The default check requires it
  too, so a document signer certificate without one is refused either
  way.
- `accept_mdl_signer_without_eku` also accepts a document signer
  certificate with no extended key usage extension, as a Wallet's; it
  can't be set with `require_mdl_signer_eku` (`invalid_input`). Added
  within ABI version 12.
- `crls` (PEM `X509 CRL` blocks) and `revocation` (roles: `issuer`, the
  document signer's chain, so a document whose signer or an IACA
  intermediate is revoked doesn't verify; `status`, a status list
  signer's in `CheckStatus`) work as a Wallet's: a role named fails
  closed for a CA without a current list, `SetCRLs(pem)` replaces the
  lists for sessions started before or after, and anything but CRLs is
  `invalid_input`. An MSO's status list chaining to the certificate its
  status names needs that certificate's list too. `crl_issuers` are
  the CAs of certificates pinned in the roots, as a Wallet's. Additive
  within ABI 12. A reader has no `development` setting, and no
  `no_revocation_check`: a role it doesn't name checks no revocation.

| Method | Result |
|---|---|
| `Engagement()` | `{"service_uuid", "ble_mode", "ident", "signed"}`. `ble_mode` is the BLE mode the reader uses, from those the holder offers, preferring `central_client` (§8.3.3.1.1). In `peripheral_server` mode the holder advertises `service_uuid`, and the reader scans, connects and is the GATT client. In `central_client` mode the reader advertises `service_uuid` and is the GATT server, serving `ident` (base64) on the Ident characteristic. `signed` is whether the request will carry reader authentication |
| `Request(docType, elementsJSON)` | `{"send"}`: send the base64 SessionEstablishment once connected. `elementsJSON` is `{namespace: [identifiers]}`. A reader key requiring user presence prompts now. Once per session (`wrong_step` otherwise) |
| `HandleMessage(message)` | `{"event", "verified", "send", "reason", "error"}` for the holder's answer. The session is then over: send `send` if present, write `0x02` to State, and disconnect. `event` is `verified` or `ended`. `reason`, for `ended`, is `declined` (status 20, which isn't authenticated) or `error`, with `error` the failing call's text (`protocol` for a response that doesn't verify) |
| `Terminate()` | `{"send"}`: the reader cancelled or timed out. Send `send` (status 20) if connected, then disconnect |
| `CheckStatus(op)` | `{"status"}`: the revocation status of the mdoc `HandleMessage` verified, fetched from the network (see below). `wrong_step` before a verified mdoc |

`verified` is `{"doctype", "claims", "device_signed_claims", "issuer",
"trust_anchor", "valid_from", "valid_until", "device_auth", "status",
"issuer_chain"}`. It means the issuer's chain reaches `issuer_roots`
(with §9.3.3's country checks), and the digests, validity and device
authentication over this session all verified. The disclosed elements
are only ones the request asked for. `claims` is `{namespace:
{identifier: value}}` with values as a wallet's claims (byte strings as
base64, dates as their text). The holder may withhold elements, so check
that each one needed is there. `device_auth` is `signature` or `mac`.
`issuer_chain` is the document signer's verified certificate path, leaf
first, ending at the root in `issuer_roots` it chained to, as base64
DER: decide which issuers to accept on it. `issuer` and `trust_anchor`
are its first and last certificates' common names, which any document
signer under a trusted root can choose, so they're for display only.
`status`, when present, is the MSO's revocation reference, which
`HandleMessage` doesn't check: call `CheckStatus` before relying on the
document. It's `{"type": "status_list", "uri", "idx"}` or `{"type":
"identifier_list", "uri", "id"}` (`id` as base64), with `certificate`
(base64 DER), the list signer's trust anchor, when the MSO names one,
or `{"type": "unknown", "uri": ""}` for an MSO status naming neither (a
mechanism the reader doesn't know, or a misspelt one), which may still
revoke the document. `type` and the identifier list were added within
ABI version 12; before, an identifier list gave no `status`. `unknown`
was added within ABI version 12 too; before, such a status gave none.

```json
{"abi": 12, "event": "verified", "verified": {
  "doctype": "org.iso.18013.5.1.mDL",
  "claims": {"org.iso.18013.5.1": {"family_name": "Doe"}},
  "issuer": "Example DS", "trust_anchor": "Example IACA",
  "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2027-10-01T00:00:00Z",
  "device_auth": "signature",
  "status": {"type": "status_list", "uri": "https://issuer.example/status/1", "idx": 412},
  "issuer_chain": ["MIIB…", "MIIC…"]}}
```

`CheckStatus(op)` fetches the Token Status List `status` names, as a
CWT, over https from public addresses only, and verifies it as ISO/IEC
18013-5 §12.3.6 requires: signed under `status`'s `certificate` when
there is one, or else under the CA that signed the document signer,
chaining to the same root in `issuer_roots` as the document, not to
another IACA the reader trusts. It returns `{"abi", "status"}`, where
`status` is `valid`, `invalid` (revoked), `suspended`, another status
the list defines (`0x` and its value), `none` (the MSO names no
revocation list) or `unknown` (an identifier list, §12.3.6.3, which this
reader can't check, and no status list or one on which the document is
valid; within ABI 12, an MSO naming both was reported by its status
list alone; or a status naming no mechanism the reader knows, which
within ABI 12 was reported as `none`). Rely on the document only on `valid` or `none`. A
failed fetch is `network`, a list that doesn't verify `protocol`, and
cancelling `op` makes it `cancelled`. The list covers many documents, so
fetching it doesn't tell its publisher which one was presented; it can
be called after the BLE session has ended.

```json
{"abi": 12, "status": "valid"}
```

ProximityReader was added within ABI version 12, and later within it
`issuer_chain` and `CheckStatus`.

## Other functions

| Function | |
|---|---|
| `ParseRequestLink(link)` | `{"client_id", "request_uri", "request_uri_method"}` |
| `CheckKeyStore(store)` | `{"checked": [purposes]}` |
| `CheckKeyAgreement(store, ka)` | `{"key_agreement"}`: `supported`, or `unsupported` for a holder key that can't agree keys |
| `IsTestBuild()` | whether the framework is the `mobiletest` build: an app should refuse to run on one |

## Test build

Built with `-tags mobiletest` (into `build/test/`, apart from the
release build in `build/release/`), the framework adds `StartTestEnv`
and `StartBatchTestEnv`: an in-process HAIP issuer, Wallet Provider and
Verifier, for the Swift and Kotlin libraries' end-to-end tests. A
`TestEnv` makes offers, approves or denies authorizations and deferred
credentials (`Approve`, `Decide`), revokes (`Revoke`, `RevokeGrants`),
and plays a Verifier: `Request`, `RegisteredRequest` and
`RequestResult` for a link, `DCAPIRequest` and `DCAPIResult` over the
Digital Credentials API. `CertDirectories` reports `SSL_CERT_DIR` as Go
sees it, for the Android tests. Its `ProximityReader(keys)` creates a key in
`keys` and issues it a reader authentication certificate from a new test
CA ("Test Reader"), returning `{"reader_config", "mdoc_reader_roots"}`:
a `NewProximityReader` configuration and the CA to recognize the reader
by. `IssuerCRL(revokeSigner)` returns a PEM CRL from the issuer's CA,
current for an hour, listing the credentials' signing certificate when
`revokeSigner` is set, for testing `revocation`. `IsTestBuild` is true
in it. An app never ships that build.

## Swift

The Swift package (`ios/OID4VCWallet`) doesn't expose these gomobile
shapes: an app implements its own `KeyStore`, `CredentialStore` and
`WalletProvider` protocols — throwing, non-optional, the provider
`async` — which it adapts, and `WalletError` carries `code`,
`protocolError`, `isRetryable` and a user-facing
`localizedDescription`.

## Kotlin

The Kotlin library (`android/OID4VCWallet`) does the same: an app
implements its `KeyStore`, `CredentialStore` and `WalletProvider`
interfaces (the provider's calls `suspend`), or uses
`AndroidKeystoreKeyStore` and `FileCredentialStore`. Calls that can
wait on the network or the holder are `suspend` functions run on
`Dispatchers.IO` and cancelled with their coroutine, and failures are `WalletException`s with the same `code`,
`protocolError` and `isRetryable`. In-person sessions add
`ProximityException` for Bluetooth failures, and need the runtime
permissions `ProximityPermissions` lists.

## Combined engagement (additive, ABI 12)

`Wallet.StartCombinedProximityPresentation(modesJSON string, negotiated,
nfcData, omitQR bool) (*ProximityPresentation, error)` creates independent QR
and NFC offers with one wallet consent state machine. Modes use the existing
nonempty JSON array (`peripheral_server`, `central_client`). Classic NFC data
uses command/response maxima 255/256. `omitQR` suppresses QR and BLE construction
when the native application lacks Bluetooth permission for a data-only NFC path.

New methods on `ProximityPresentation`:

| Method | Meaning |
| --- | --- |
| `IsCombined() bool` | Native code must explicitly select an offer before messages. |
| `SelectEngagement(nfc bool) error` | Atomically claim NFC (`true`) or QR (`false`); close the losing Go session. Wrong/closed steps return `wrong_step`. |
| `SelectedEngagement() string` | Empty until selected; then `qr`, `nfc_ble`, or `nfc_data`. |

For a combined presentation, initial `Engagement()` supplies QR transport
metadata (or empty QR/BLE fields if omitted). After NFC selection it supplies
the NFC carrier metadata. `HandoverSelect()` always addresses the NFC offer;
`HandleHandoverRequest()` prepares the independent NFC offer before selection
and is rejected once QR wins. It does not withdraw QR or switch its metadata.
Commit NFC-to-BLE after the complete Hs read; commit NFC data on its data AID
SELECT after handover. Repeated winning claims
are idempotent while waiting for a request. Losing claims and claims after
termination cannot replace keys or transcripts. `Terminate()` closes both offers.
Existing JSON shapes and all existing call signatures are unchanged.

Android adds `Wallet.startCombinedPresentation(context, timeouts, modes, nfc)`
and `NfcEngagementOptions(negotiated, nfcData)`. The returned
`CombinedPresentation` exposes QR text, the existing state flow, respond,
decline, cancel, selected-engagement flow, foreground preference and awaited
close. See `android/docs/PresentingInPerson.md` for resume/pause/exit calls.
