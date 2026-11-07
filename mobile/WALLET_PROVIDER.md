# Wallet Provider protocol, version 1

The HTTP protocol between a wallet app and a Wallet Provider built
with `walletprovider` (`Provider.Handler`), version **1**. The Go
`walletprovider.Client`, the Kotlin library's `HttpWalletProvider`
(with `android-key` evidence) and the Swift library's
`HttpWalletProvider` (with `apple-app-attest`) speak it; this document is the contract for a native client in Swift
or Kotlin, or any other. The version is in the
path: a change a version-1 client can't read gets a new one, `/v2/`.

A wallet uses it to register an *instance* (HAIP 1.0's Wallet
Instance: one installation of the app on one device), then to get the
two attestations HAIP 1.0 has a Credential Issuer rely on:

- a **Wallet Attestation** (HAIP 1.0 §4.4.1, OID4VCI 1.0 Appendix E),
  JWT `typ` `oauth-client-attestation+jwt`, which authenticates the
  instance as an OAuth client: its `sub` is the client ID, its
  `cnf.jwk` an *instance key*;
- a **Key Attestation** (HAIP 1.0 §4.5.1, OID4VCI 1.0 Appendix D), JWT
  `typ` `key-attestation+jwt`, which vouches for holder keys a
  credential is to be bound to: its `attested_keys`, with
  `key_storage` and `user_authentication` where the provider's policy
  claims them, and the issuer's `c_nonce` as `nonce`.

The protocol has two kinds of wallet key, never the same key:

- The **registration key**, one per instance, made when the app is
  installed and kept for its life. It's registered with the provider
  (`POST /v1/instances`) and signs every later request to it. No
  attestation names it: it's the provider's alone.
- An **instance key**, one per issuance: a fresh key for each
  Credential Issuer (or each issuance), which a Wallet Attestation's
  `cnf` names and whose holder signs the Client Attestation PoP.
  HAIP 1.0 §4.4.1 forbids reusing a Wallet Attestation across
  Credential Issuers, and draft-ietf-oauth-attestation-based-client-auth-07
  §11.1 asks for different instance keys per Authorization Server, so
  issuers can't link one issuance to another. Platform evidence
  vouches for an instance key the first time a Wallet Attestation is
  asked for it; the provider records it against the instance, and
  later Wallet Attestations for it (when one expires mid-issuance)
  need no evidence.

Each instance key has its own entry in one of the provider's Token
Status Lists, which the provider serves under `/v1/status/`: every
Wallet Attestation for the key, and every Key Attestation issued for
the same issuance, carries a `status` claim naming it. The lists
belong to periods (by default a week): an instance key used in a later
period than its entry's gets a new entry on that period's lists, so a
later attestation for the same key may name a different entry. Issuers see only
per-issuance keys and status entries, and the shared client ID. The
provider knows which instance keys belong to which instance, so
suspending or revoking the instance — the installation — sets the
status of all of them, withdrawing every attestation it was issued.

The provider attests nothing without platform evidence, in development
as in production: a registration, a Wallet Attestation for an instance
key it hasn't recorded, or a Key Attestation request with none is
refused.

## Conventions

The paths are relative to where the provider mounts the protocol (its
*base URL*, an absolute `https` URL): `POST {base}/v1/challenge`, and
so on.

- **Requests** are `POST` with `Content-Type: application/json`, at
  most 256 KiB (`MaxRequestBytes`). Bodies are decoded strictly: a
  member the request doesn't define, a member given twice, a member
  whose name matches only case-insensitively, text that isn't UTF-8,
  or anything after the object is refused (`400 invalid_request`).
- **Responses** are `application/json` with `Cache-Control: no-store`,
  but for the status lists under `/v1/status/`.
- **Binary values** (evidence data) are base64url without padding.
- **Times** (`expires_at`) are seconds since the Unix epoch.
- **Keys** (`registration_key`, `instance_key`, `keys`) are public
  JWKs (RFC 7517): EC P-256 or OKP Ed25519. A JWK carrying a private
  member (`d`) is refused.
- **Challenges** are 32 random bytes, base64url without padding (43
  characters), issued for one purpose, used once, and valid for the
  provider's challenge TTL (by default 5 minutes, at most 15). A
  challenge is used up by the request that names it, accepted or not,
  so a refused request is retried with a new one — except a signed
  request that doesn't verify, which leaves the `request` challenge it
  names unused.
- **Instance IDs** are opaque strings (today 16 random bytes,
  base64url).
- A client must not follow redirects: an answer other than the one
  documented is a failure.

## Errors

A refusal is a JSON object:

```json
{"error": "evidence_rejected", "error_description": "The evidence didn't verify."}
```

`error` is one of the codes below; `error_description` is fixed text
for it, never the provider's internal error (which goes to its log).
Clients decide on `error` and the status code, never the description.

| Status | `error` | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | The body is malformed, or a value in it is invalid (an unknown purpose, a key listed twice, more keys than the policy allows, more evidence than keys). |
| 413 | `invalid_request` | The body is larger than 256 KiB. |
| 415 | `invalid_request` | The body isn't `application/json`. |
| 400 | `invalid_challenge` | The challenge is unknown, used, expired, or for another purpose. Get a new one. |
| 400 | `evidence_required` | No evidence was sent: at registration, for a Key Attestation, or with a Wallet Attestation request for an instance key the provider hasn't recorded yet, or no longer has (see the provider's retention, below). |
| 400 | `unsupported_evidence` | The provider takes no evidence of that `kind`. |
| 403 | `evidence_rejected` | The evidence didn't verify, or doesn't cover the keys or challenge it should. |
| 403 | `policy_refused` | The evidence verified, but the provider's policy refuses it (platform, app version, boot state, security level) — or, for a registered instance, no longer accepts what its registration evidence proved, or the security level its instance key was recorded at, since the policy is applied again at every attestation. |
| 409 | `instance_key_registered` | The key is already another's: a registration key that's already registered or is an instance key, or an instance key that's another instance's or is this instance's registration key. Make a new key. |
| 400 | `unknown_instance_key` | A Key Attestation request's `instance_key` isn't one a Wallet Attestation recorded for this instance, or the provider has deleted its record (retention). |
| 400 | `unknown_client` | The provider doesn't attest that client ID. |
| 401 | `invalid_signed_request` | The signed request didn't verify (see below). It carries `WWW-Authenticate: Wallet-Provider-Request`. |
| 403 | `instance_not_active` | The instance is suspended. |
| 403 | `instance_revoked` | The instance is revoked, for good: register a new one. |
| 403 | `no_key_attested` | None of the holder keys could be attested. |
| 500 | `server_error` | The provider couldn't answer. |

A path or method the protocol doesn't define gets the HTTP server's own
`404` or `405`, which may not be JSON. Rate limiting is the
deployment's: expect `429` (or other statuses) from what fronts the
provider.

## Platform evidence

Evidence is `{"kind": ..., "data": ...}`, `data` base64url without
padding. The provider accepts the kinds it's configured with.

### `android-key`: Android Key Attestation

One key's attestation certificate chain, its DER certificates
concatenated, leaf first, as `KeyStore.getCertificateChain` returns
them (each certificate's `getEncoded()`, appended in order). The key is
generated in Android Keystore with `setAttestationChallenge` set to the
challenge's **decoded 32 bytes**, not its base64url text. The
provider checks the chain to Google's hardware attestation roots and
their revocation list, the challenge, the security levels, the root of
trust and the app (`walletprovider/androidkey`). Keys attested with an
app's own attestation key (`setAttestKeyAlias`) are refused.

- At registration, the evidence is the **registration key's** chain,
  over a `registration` challenge.
- For an instance key's first Wallet Attestation, the evidence is the
  **instance key's** chain, over an `instance` challenge.
- For a Key Attestation, the evidence is one chain **per holder key**,
  each over the same `holder` challenge.

Evidence after registration must come from the same platform and app
as the registration evidence, and is held to the provider's policy as
that was.

### `apple-app-attest`: Apple App Attest

App Attest attests the **app**, not the wallet's keys: its key, made
by `DCAppAttestService`, lives in the Secure Enclave and signs only
App Attest's own assertions. The wallet's registration, instance and
holder keys are bound in through the **client data** each
attestation or assertion is made over. What the provider learns is
that a genuine copy of the app, on a genuine Apple device, asked for
those keys; nothing proves where the keys themselves are. The provider
reports them at security level `secure-enclave` with binding
`app-assertion`, and a Key Attestation claims `key_storage` for them
only where the provider's policy says so for that binding
(`walletprovider.KeyStorageRule`). Make them Secure Enclave keys all
the same.

The evidence's `data` is the bytes `DCAppAttestService` returned,
unchanged, base64url without padding: an **attestation object** at
registration, an **assertion** after it. The provider checks them as
Apple's "Validating apps that connect to your server" describes
(`walletprovider/appattest`): the certificates to the Apple App
Attestation Root CA, the nonce, the key ID, the App ID (team ID and
bundle ID, `ABCDE12345.com.example.wallet`), the environment, the
assertion's signature and its counter.

#### The App Attest key

Each instance has one App Attest key, made at registration with
`generateKey()` and kept, by its key ID, with the registration key for
the instance's life: every assertion after registration is made with
it. App Attest keys aren't backed up or moved to another device, so an
app restored from a backup, or reinstalled, has lost it: register a new
instance (and registration key). Where `DCAppAttestService.isSupported`
is false (the Simulator, some older devices) there's no App Attest
key, and the app can't register.

If `attestKey` fails with `DCError.serverUnavailable`, try again later
with the same key; on any other error, make a new key. An app built
for development (the `com.apple.developer.devicecheck.appattest-environment`
entitlement set to `development`) makes development-environment keys,
which only a provider configured for them accepts
(`appattest.Verifier.AllowDevelopment`); a released app's are
production's.

#### Client data

Every attestation and assertion is made over a `clientDataHash`, the
SHA-256 of the client data: UTF-8 text of lines, **each ending in
`\n`** (LF), the last one included:

```
OID4VCgo-WalletProvider-AppAttest/1
<purpose>
<challenge>
<thumbprint of the first key>
<thumbprint of the next key>
...
```

- `purpose` is the challenge's: `registration`, `instance` or
  `holder`.
- `challenge` is the challenge exactly as `POST /v1/challenge`
  returned it (base64url without padding), not its decoded bytes.
- Each thumbprint is a key's RFC 7638 JWK SHA-256 thumbprint,
  base64url without padding (for a P-256 key, the SHA-256 of
  `{"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"}`), one line per key,
  in the order the request lists the keys.

| Request | Purpose | Keys | Evidence |
| --- | --- | --- | --- |
| `POST /v1/instances` | `registration` | `registration_key` | `attestKey(keyId, clientDataHash)` of the new App Attest key |
| `POST /v1/wallet-attestation`, a new instance key | `instance` | `instance_key` | `generateAssertion(keyId, clientDataHash)` |
| `POST /v1/key-attestation` | `holder` | every key of `keys`, in order | **one** `generateAssertion(keyId, clientDataHash)` for all of them: `evidence` holds exactly one entry |

The challenge is the one in the body (`challenge`), never the signed
request's `request` challenge.

Test vectors. The keys are the P-256 keys whose private scalars are
the bytes `0x01` to `0x20`, and the same bytes with the last one
`0x21`:

| Key | `x` | `y` | Thumbprint |
| --- | --- | --- | --- |
| 1 | `UVw9brnjlrkE0_7Kf1T9zQzB6Ze_N13KUVrQpsO0A18` | `RTa-OlDzGPv5pUdZAqIhUCvvDVfgjFOyzApW8X2fk1Q` | `6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM` |
| 2 | `rM8BBu-Fj6LZGTMTRoBaeLWLutC4ROXHiSh5FGGH3SY` | `Zq2ngbt_ERNyJRqJEGIfY03xKKxI44H9bvkGBzH2lKQ` | `6rpgUp9sT-ItA87f0SCoStuYFvCFUFrnT9HqUF0sY_8` |

With the challenge `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` (the
bytes `0x00` to `0x1f`):

- `registration`, key 1: the client data is
  `"OID4VCgo-WalletProvider-AppAttest/1\nregistration\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM\n"`,
  and its `clientDataHash` (hex)
  `659141d12dbf4b9421adb6a080d4245a01ead653218a6289376baa869a8f477f`;
- `holder`, keys 1 and 2: the client data is
  `"OID4VCgo-WalletProvider-AppAttest/1\nholder\nAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n6UoWwDCkLjV0J-pQG8c0THxbVhBcpR0AZDift1Yl5DM\n6rpgUp9sT-ItA87f0SCoStuYFvCFUFrnT9HqUF0sY_8\n"`,
  and its `clientDataHash`
  `3ba79d8b12988b5db62d590f308d273093573803711f21315bb2b3e504b1b38c`.

#### The counter

App Attest counts the assertions a key makes, and each one carries the
count. The provider keeps the last count it accepted for the instance
and refuses an assertion whose count doesn't exceed it, so an
assertion is accepted once (`evidence_rejected`, or `no_key_attested`
for a Key Attestation). Make one assertion at a time and send it
before making the next: an assertion made after another but sent
first leaves the earlier one refused. An assertion that never reached
the provider costs nothing: the next one's count is still larger.

Evidence after registration must come from the same app, and is held
to the provider's policy as the registration was. Unlike
`android-key`, an assertion can be made for a key that already
exists: when the provider has deleted an instance key's record
(retention), the wallet can send a fresh `instance` challenge and
assertion for the same key.

## Signed requests

Requests after registration (`/v1/wallet-attestation`,
`/v1/key-attestation`) are signed with the registration key — never an
instance key — so an instance ID alone grants nothing. The request
carries one header,

```
Wallet-Provider-Request: <compact JWS>
```

at most 4 KiB, a JWT with the header

```json
{"alg": "ES256", "typ": "wallet-provider-request+jwt"}
```

(`EdDSA` for an Ed25519 registration key), and the claims

| Claim | Value |
| --- | --- |
| `sub` | The instance ID. |
| `method` | The request's method: `POST`. |
| `path` | The request's path as sent, escaped, including any prefix the base URL has (`/wp/v1/key-attestation`). |
| `body_sha256` | The SHA-256 of the exact body bytes sent, base64url without padding. |
| `challenge` | A challenge issued for `request`. |
| `iat` | The time it's signed, seconds since the epoch: at most a minute ahead of the provider's clock, and no older than the challenge TTL. |

Sign the body bytes you send: re-encoding the JSON after signing
changes the hash. Each signed request needs a fresh `request`
challenge, which the request uses up, so it's accepted once.

The provider verifies the signature, method, path, body hash and `iat`
before anything else. Every way a signed request can fail that check —
malformed or stale, signed by another key, for another path or body,
naming an unknown instance, or naming a challenge that is unknown or
used — gets the same `401 invalid_signed_request`, so a client can't
tell an unknown instance from a wrong key, and such a request leaves
the challenge it names unused. Only a request that verifies learns
that its instance is suspended (`instance_not_active`) or revoked
(`instance_revoked`).

## Endpoints

### `POST /v1/challenge`

```json
{"purpose": "registration"}
```

`purpose` is `registration` (to bind registration evidence to),
`instance` (to bind a new instance key's evidence to), `holder` (to
bind Key Attestation evidence to) or `request` (to sign a request
with). The answer, `200`:

```json
{"challenge": "q1x...", "purpose": "registration", "expires_at": 1767225600}
```

Not signed. A client checks `purpose` is the one it asked for.

### `POST /v1/instances`

Registers an instance.

```json
{
  "challenge": "<a registration challenge>",
  "registration_key": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "evidence": {"kind": "android-key", "data": "MIIC..."}
}
```

The evidence must vouch for `registration_key` over `challenge`. The
answer, `201`:

```json
{"instance_id": "bW6PhcY_vgNH4Q1qR53wEg"}
```

Not signed (the evidence proves the key). Keep the instance ID with
the registration key; registering the same key again is `409
instance_key_registered`. Registering takes no status list entry: each
instance key gets its own.

### `POST /v1/wallet-attestation`

Signed. Asks for a Wallet Attestation for a client and an instance
key:

```json
{
  "client_id": "my-wallet",
  "instance_key": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "challenge": "<an instance challenge>",
  "evidence": {"kind": "android-key", "data": "MIIC..."}
}
```

- The first time the instance asks for `instance_key`, `challenge` and
  `evidence` are required: the evidence must vouch for the key over
  the challenge (an `instance` challenge), from the instance's
  platform and app, at a security level the provider's policy
  accepts. The provider then records the key for the instance, with a
  status list entry of its own; without them the answer is `400
  evidence_required`.
- Once the key is recorded, `challenge` and `evidence` may be left
  out, and are ignored if sent: not verified, and the challenge not
  used up. The Wallet Attestation carries the same status entry as
  before, unless a new period has started since: then a new entry,
  which the provider gives the key.
- The provider deletes the record of an instance key unused for its
  retention (90 days after the start of the week it was last used in,
  by default; `Config.InstanceKeyRetention`). Asked for it after that,
  it answers `400 evidence_required`, as for a new key: the key needs
  `challenge` and `evidence` again, and gets a new status entry. Evidence
  that binds the challenge into the key's own attestation, as Android
  Key Attestation does, can't be made for a key that already exists:
  such a wallet makes a new instance key, and a credential whose
  refresh needs the old one must be received again.
- An `instance_key` that's another instance's, or this instance's
  registration key, is `409 instance_key_registered`.

The answer, `200`:

```json
{"wallet_attestation": "eyJ..."}
```

Its `sub` is `client_id` and its `cnf.jwk` `instance_key`; a client
checks both before using it. Its signature and `x5c` are for the
Credential Issuer to verify. It's valid for the provider's Wallet
Attestation TTL (by default an hour, at most 24): ask again, with the
same instance key, when it expires during an issuance.

### `POST /v1/key-attestation`

Signed. Asks for a Key Attestation over holder keys:

```json
{
  "instance_key": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "challenge": "<a holder challenge>",
  "keys": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}],
  "evidence": [{"kind": "android-key", "data": "MIIC..."}],
  "nonce": "<the Credential Issuer's c_nonce>"
}
```

`instance_key` is the instance key of the issuance the holder keys are
for: one a Wallet Attestation recorded for this instance (else `400
unknown_instance_key`). The Key Attestation's `status` is that key's
entry (in a new period, its new one, as for a Wallet Attestation), so
it's withdrawn with the issuance's Wallet Attestations.
`keys` are the holder keys, each once, at most the provider's limit
(by default 10). `evidence` vouches for them over `challenge`: one per
key for `android-key`, at most one per key; one assertion for all of
them for `apple-app-attest`. `nonce`, optional, is the
issuer's `c_nonce`, carried as the attestation's `nonce`. The
challenge in the body (`holder`) and the one in the signed request
(`request`) are two different challenges. The answer, `200`:

```json
{"key_attestation": "eyJ...", "expires_at": 1767232800}
```

Its `attested_keys` are the keys the provider attested, which may be
fewer than were sent (a key whose evidence failed, or at a security
level the policy refuses, is left out); a client uses only those, and
checks each was one it sent, and that `nonce` is the one it sent.
`key_storage` and `user_authentication` are claimed only where the
evidence proved them. It's valid until `expires_at` (the provider's
Key Attestation TTL, by default two hours, at most 24).

### `GET /v1/status/{start}/{n}`

One of the provider's Token Status Lists
(draft-ietf-oauth-status-list-14): list `n` (0 to 63) of the period
starting at `start` (seconds since the Unix epoch), as a JWT
(`application/statuslist+jwt`) or a CWT
(`application/statuslist+cwt`) as the `Accept` header asks, with
`Cache-Control` from its TTL. The provider serves a period's lists
through the two periods after it, and only those it has handed an
entry out of: any other is `404`. Not signed, and not for wallets: the
Credential Issuer fetches it from every attestation's `status` claim.

## A wallet's sequence

1. Once, at installation: `POST /v1/challenge` `{"purpose":
   "registration"}`; generate the registration key in the platform
   keystore with the challenge's bytes as its attestation challenge
   (Android), or generate it and an App Attest key and attest the App
   Attest key over the client data (iOS), and `POST /v1/instances`
   with the key and its evidence. Keep the instance ID with the
   registration key (and, on iOS, the App Attest key ID).
2. For each issuance (each Credential Issuer): `POST /v1/challenge`
   `{"purpose": "instance"}`; generate a fresh instance key over it
   (Android), or generate it and make an assertion over the client
   data (iOS);
   `POST /v1/challenge` `{"purpose": "request"}`; then a signed `POST
   /v1/wallet-attestation` with the instance key and its evidence. Use
   the attestation as the Client Attestation JWT, with a Client
   Attestation PoP signed by the instance key. If it expires before
   the issuance ends, ask again for the same instance key, without
   evidence.
3. When the issuer asks for key attestation: `POST /v1/challenge`
   `{"purpose": "holder"}`; generate the holder keys over it
   (Android), or generate them and make one assertion over the client
   data (iOS); `POST
   /v1/challenge` `{"purpose": "request"}`; a signed `POST
   /v1/key-attestation` with the issuance's instance key, the holder
   keys, their evidence and the issuer's `c_nonce`.
4. Once the issuance is over, the instance key may be deleted: never
   use it with another issuer.
5. On `instance_revoked`, discard the instance, its registration key
   and its instance keys, and register again from step 1. On
   `instance_not_active`, stop and tell the user; the provider may
   resume it.
