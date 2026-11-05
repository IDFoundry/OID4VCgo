# Wallet Provider protocol, version 1

The HTTP protocol between a wallet app and a Wallet Provider built
with `walletprovider` (`Provider.Handler`), version **1**. The Go
`walletprovider.Client` speaks it; this document is the contract for a
native client in Swift or Kotlin, or any other. The version is in the
path: a change a version-1 client can't read gets a new one, `/v2/`.

A wallet uses it to register an *instance* (one installation of the
app on one device, identified by its *instance key*), then to get the
two attestations HAIP 1.0 has a Credential Issuer rely on:

- a **Wallet Attestation** (HAIP 1.0 §4.4.1, OID4VCI 1.0 Appendix E),
  JWT `typ` `oauth-client-attestation+jwt`, which authenticates the
  instance as an OAuth client: its `sub` is the client ID, its
  `cnf.jwk` the instance key;
- a **Key Attestation** (HAIP 1.0 §4.5.1, OID4VCI 1.0 Appendix D), JWT
  `typ` `key-attestation+jwt`, which vouches for holder keys a
  credential is to be bound to: its `attested_keys`, with
  `key_storage` and `user_authentication` where the provider's policy
  claims them, and the issuer's `c_nonce` as `nonce`.

Every attestation carries a `status` claim naming the instance's entry
in the provider's Token Status List, which the provider serves at
`/v1/status`; suspending or revoking the instance withdraws them all.

The provider attests nothing without platform evidence, in development
as in production: a registration or Key Attestation request with none
is refused.

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
  but for `/v1/status`.
- **Binary values** (evidence data) are base64url without padding.
- **Times** (`expires_at`) are seconds since the Unix epoch.
- **Keys** (`instance_key`, `keys`) are public JWKs (RFC 7517): EC
  P-256 or OKP Ed25519. A JWK carrying a private member (`d`) is
  refused.
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
| 400 | `evidence_required` | No evidence was sent. |
| 400 | `unsupported_evidence` | The provider takes no evidence of that `kind`. |
| 403 | `evidence_rejected` | The evidence didn't verify, or doesn't cover the keys or challenge it should. |
| 403 | `policy_refused` | The evidence verified, but the provider's policy refuses it (platform, app version, boot state, security level) — or, for a registered instance, no longer accepts what its registration evidence proved, since the policy is applied again at every attestation. |
| 409 | `instance_key_registered` | The instance key is already registered: each instance key registers one instance. |
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

- At registration, the evidence is the **instance key's** chain, over
  an `instance` challenge.
- For a Key Attestation, the evidence is one chain **per holder key**,
  each over the same `holder` challenge.

### Apple App Attest

Phase 2 of the Wallet Provider adds App Attest evidence; its `kind`
and format will be documented here.

## Signed requests

Requests after registration (`/v1/wallet-attestation`,
`/v1/key-attestation`) are signed with the instance key, so an
instance ID alone grants nothing. The request carries one header,

```
Wallet-Provider-Request: <compact JWS>
```

at most 4 KiB, a JWT with the header

```json
{"alg": "ES256", "typ": "wallet-provider-request+jwt"}
```

(`EdDSA` for an Ed25519 instance key), and the claims

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
{"purpose": "instance"}
```

`purpose` is `instance` (to register), `holder` (to bind Key
Attestation evidence to) or `request` (to sign a request with). The
answer, `200`:

```json
{"challenge": "q1x...", "purpose": "instance", "expires_at": 1767225600}
```

Not signed. A client checks `purpose` is the one it asked for.

### `POST /v1/instances`

Registers an instance.

```json
{
  "challenge": "<an instance challenge>",
  "instance_key": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."},
  "evidence": {"kind": "android-key", "data": "MIIC..."}
}
```

The evidence must vouch for `instance_key` over `challenge`. The
answer, `201`:

```json
{"instance_id": "bW6PhcY_vgNH4Q1qR53wEg"}
```

Not signed (the evidence proves the key). Keep the instance ID with
the instance key; registering the same key again is `409
instance_key_registered`.

### `POST /v1/wallet-attestation`

Signed. Asks for a Wallet Attestation for a client:

```json
{"client_id": "my-wallet"}
```

The answer, `200`:

```json
{"wallet_attestation": "eyJ..."}
```

Its `sub` is `client_id` and its `cnf.jwk` the instance key; a client
checks both before using it. Its signature and `x5c` are for the
Credential Issuer to verify. It's valid for the provider's Wallet
Attestation TTL (by default an hour, at most 24): ask again when it
expires.

### `POST /v1/key-attestation`

Signed. Asks for a Key Attestation over holder keys:

```json
{
  "challenge": "<a holder challenge>",
  "keys": [{"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}],
  "evidence": [{"kind": "android-key", "data": "MIIC..."}],
  "nonce": "<the Credential Issuer's c_nonce>"
}
```

`keys` are the holder keys, each once, at most the provider's limit
(by default 10). `evidence` vouches for them over `challenge`: one per
key for `android-key`, at most one per key. `nonce`, optional, is the
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

### `GET /v1/status`

The provider's Token Status List (draft-ietf-oauth-status-list-14), as
a JWT (`application/statuslist+jwt`) or a CWT
(`application/statuslist+cwt`) as the `Accept` header asks, with
`Cache-Control` from its TTL. Not signed, and not for wallets: the
Credential Issuer fetches it from every attestation's `status` claim.

## A wallet's sequence

1. `POST /v1/challenge` `{"purpose": "instance"}`.
2. Generate the instance key in the platform keystore with the
   challenge's bytes as its attestation challenge, and `POST
   /v1/instances` with the key and its evidence. Keep the instance ID.
3. For each Credential Issuer: `POST /v1/challenge` `{"purpose":
   "request"}`, then a signed `POST /v1/wallet-attestation`. Use the
   attestation as the Client Attestation JWT, with a Client
   Attestation PoP signed by the instance key.
4. When an issuer asks for key attestation: `POST /v1/challenge`
   `{"purpose": "holder"}`; generate the holder keys over it; `POST
   /v1/challenge` `{"purpose": "request"}`; a signed `POST
   /v1/key-attestation` with the keys, their evidence and the issuer's
   `c_nonce`.
5. On `instance_revoked`, discard the instance and its key, and
   register again from step 1. On `instance_not_active`, stop and tell
   the user; the provider may resume it.
