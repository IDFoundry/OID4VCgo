# walt.id interop

Interop with [walt.id](https://walt.id)'s Community Stack v2, the
OpenID4VCI 1.0 and OpenID4VP 1.0 services of
[walt-id/waltid-identity](https://github.com/walt-id/waltid-identity):
Issuer2, Verifier2 and Wallet2, run locally from their published images
(`waltid/issuer-api2`, `waltid/verifier-api2`, `waltid/wallet-api2`).
[`run.sh`](run.sh) runs every direction against them, from
[`.github/workflows/waltid-interop.yml`](../../.github/workflows/waltid-interop.yml).

## Cases

| Direction | Case | Expected |
|---|---|---|
| OID4VCgo's wallet ← Issuer2 | SD-JWT VC PID, by pre-authorized code | issued, and passes the wallet's checks |
| | mdoc PID | issued, and passes the wallet's checks |
| | mDL | issued, and passes the wallet's checks |
| | The wallet trusts an unrelated issuer CA | the wallet refuses the credential |
| OID4VCgo's wallet → Verifier2 | SD-JWT VC PID, signed `x509_hash` request, response encrypted (`direct_post.jwt`) | Verifier2 accepts it |
| | mDL, the same | Verifier2 accepts it |
| | SD-JWT VC PID, relayed: the response encrypted to a key of the wallet transport's own, then again to Verifier2's, unchanged | Verifier2 accepts it |
| | That, the Key Binding JWT's `nonce` another | Verifier2 refuses it (VP policy `nonce-check`) |
| | That, the Key Binding JWT's `aud` another `x509_hash` | Verifier2 refuses it (VP policy `audience-check`) |
| | That, a disclosure's value changed (its digest no longer the Issuer's) | Verifier2 refuses it (`Invalid disclosures`), as `503 temporarily_unavailable` (finding 7) |
| | That, the Issuer-signed JWT signed again under a self-signed certificate | a note, not a case: Verifier2 accepts it (finding 3); the run fails if that changes |
| | The request unsigned, naming its `x509_hash` client | the wallet refuses |
| | The wallet trusts an unrelated Verifier CA | the wallet refuses |
| Wallet2 ← OID4VCgo's issuer | SD-JWT VC PID: Wallet Attestation and PoP, DPoP, pre-authorized code | issued |
| | mdoc PID, the same | issued |
| | The Wallet Attestation from an attester the issuer doesn't trust | the issuer refuses (`invalid_client`) |
| | SD-JWT VC PID, the issuer's `dpop-nonces` profile | issued: the Token and Credential Endpoints each ask for a DPoP nonce, and Wallet2 retries with it |
| | SD-JWT VC PID, its `deferred` profile | deferred (202), then issued from the Deferred Credential Endpoint when Wallet2 resumes the handle |
| | SD-JWT VC PID, its `key-attestation` profile | a note, not a case: Wallet2 stops before its Credential Request (see "What isn't covered") |
| OID4VCgo's issuer → OID4VCgo's wallet → Verifier2 | SD-JWT VC PID and mdoc PID, the session's VC policies `signature` and `credential-status` (IETF, VALID) | Verifier2 fetches the issuer's Token Status List, its `credential-status` policy passes, and it accepts the PID |
| | Each, revoked by the issuer (its `POST /status`) after it was issued, before the wallet presents it | Verifier2 refuses it, by `credential-status` (`Status validation failed: expected one of [0], but got 1`), the session `FAILED` |
| Wallet2 → OID4VCgo's verifier | That SD-JWT VC PID, `x509_hash`, `direct_post.jwt`, `request_uri_method` none, `get` and `post` | verified |
| | That mdoc PID | verified, only the requested elements disclosed |
| | The verifier's Access Certificate under an unrelated CA | Wallet2 refuses (`X509TrustAnchorMismatch`) |
| | The verifier trusts an unrelated issuer CA | the verifier refuses the credential |

Each control is checked for its reason, not just for a failure:
OID4VCgo's own error for its refusals (an untrusted chain, a request
object that isn't signed), walt.id's error for Wallet2's
(`X509TrustAnchorMismatch`), and for Verifier2's the error it answers
the wallet's response with (`invalid_request`, naming the VP policy
that failed) and the session's status (`FAILED`); a failure of the
run itself (setup, TLS) isn't a refusal. Wallet2 reports only the
issuer's `invalid_client`,
not its description, so the untrusted attester control also checks
that the stand-in attester signed with its other key: the cases before
it, which pass, differ in that alone.

OID4VCgo's side is `walletflow` ([`scripts/wallet`](scripts/wallet)),
`cmd/conformance-verifier` and `cmd/conformance-issuer`, the latter two
configured as in [`../eudi`](../eudi/README.md): the issuer is the EUDI
issuer run's ([`setup-issuer`](../eudi/scripts/setup-issuer)), under
HAIP. Wallet2 receives from it in the base profile, then, each from a
fresh Wallet2 wallet, in three more of
[`../eudi/run-issuer.sh`](../eudi/run-issuer.sh)'s profiles, the issuer
restarted with its config changed as there: `dpop-nonces`
(`dpop_nonces`), `deferred` (`deferred`) and `key-attestation`
(`key_attestation.jwt_proof_requires_key_attestation`).

### Status lists

`cmd/conformance-issuer` publishes its Token Status List as an issuer
does (`status_lists`: a `statuslist.Allocator` hands each credential
its index and keeps its status, and a `statuslist.Publisher` signs the
list on each fetch, the SD-JWT VC's by its issuer key with `x5c`, the
mdoc's by its Document Signer with `x5chain`), and Verifier2's
`credential-status` policy fetches it, verifies its signature, binds
its signer to the credential's (the same `x5c`/`x5chain` leaf), checks
its claims and reads the entry. That instance of the issuer is a
second one, named `localhost`, as OID4VCgo's wallet's development
fetcher needs, its lists published as `https://waltid.test:…`
(`status_lists.base_url`), which Verifier2 reaches through
[`scripts/serve`](scripts/serve)'s tap, which logs who fetched which
form. Each control has the issuer revoke the credentials the wallet
received (the wallet's `-revoke`, the issuer's `POST /status`,
`Allocator.SetStatus`) before it presents one: it differs from the case
before it in that status alone. The positive cases are graded by the
session, which Verifier2 may decide after the wallet stopped waiting for
its answer (its first status check took 17 s on an emulated image).

Verifier2 asks for both forms at once (`Accept:
application/statuslist+jwt, application/statuslist+cwt, …`), and the
issuer's Publisher serves the CWT on a tie, so Verifier2 reads the
SD-JWT VC's list as a CWT too, and verifies it. Its status reader
caches a list only for an HTTP `max-age`, which the issuer's tokens,
with no `ttl`, don't set.

## What walt.id sends

Where SPECIFICATIONS.md's "Known leniencies" let OID4VCgo accept less
than a specification asks, the run records what walt.id sends and
asserts it as 1.2.1 sends it, so that a change is noticed. Wallet2's
requests to OID4VCgo's issuer go through a tap in
[`scripts/serve`](scripts/serve), which logs each Client Attestation
PoP's `iss` and claims and each DPoP proof's header; the wallet's
transport ([`scripts/wallet`](scripts/wallet)) records what Issuer2 and
Verifier2 send it.

| From | What | Seen with 1.2.1 |
|---|---|---|
| Wallet2 | Client Attestation PoP (draft-07 §5.2 requires `iss`) | `iss` the `client_id`; claims `aud`, `exp`, `iat`, `iss`, `jti` |
| Wallet2 | DPoP proof | `typ` `dpop+jwt`, `ES256`, its `jwk` without `alg` (RFC 9449 asks for none); a `nonce` only once asked for one |
| Issuer2 | Token Response `token_type` | `DPoP` |
| Issuer2 | `credential_request_encryption` (§12.2.4 requires a `kid` on each key) | none: Issuer2 doesn't take encrypted Credential Requests, so there's no key to check |
| Verifier2 | response encryption JWK (OpenID4VP 1.0 §8.3 requires `alg`) | one key, `alg` `ECDH-ES`, `kid` `response-encryption-…` |

None of these is a deviation: walt.id sends each as the specification
asks.

## How it's set up

- **Configs.** Each service runs with its tag's `docker-compose/<service>/config`,
  fetched by commit and SHA-256, with [`scripts/setup`](scripts/setup)'s
  blocks appended (HOCON reads a later setting as replacing an earlier
  one): Issuer2 signs with a key under the run's CA, at an HTTPS base
  URL, redeeming the pre-authorized code anonymously; Verifier2 is an
  `x509_hash` client under the run's CA; Wallet2 trusts the run's CA for
  `x509_hash` clients (and, through a truststore, for TLS), keeps its
  wallets in memory, needs no login, and asks the stand-in Wallet
  Provider for its Wallet Attestations.
- **Names.** Issuer2 and Verifier2, which only OID4VCgo's wallet calls,
  are `localhost`, behind [`scripts/serve`](scripts/serve)'s TLS
  proxies: in development, OID4VCgo's fetcher reaches loopback for a
  loopback name alone. What Wallet2 calls from its container is
  `waltid.test`, which the container maps to the runner
  (`host-gateway`): OID4VCgo's issuer, its verifiers and the attester,
  bound to the Docker bridge's gateway on Linux and to loopback on
  macOS.
- **The Wallet Provider.** Wallet2 posts its instance key to an attester
  and takes back a Client Attestation JWT
  (`{"walletInstanceAttestation": ...}`); it doesn't pass the
  `client_id`, so the stand-in ([`scripts/serve`](scripts/serve)) signs
  for the one OID4VCgo's issuer registers, with its attester key and
  `x5c`, and Wallet2 is told that `client_id` when it redeems the offer.
- **Negative presentations.** OID4VCgo's wallet builds its
  presentation as always; its transport ([`scripts/wallet`](scripts/wallet)'s
  `-tamper`, `tamper.go`) changes it on its way to Verifier2, as an
  attacker relaying it would, nothing of it in the library. The
  response is encrypted to Verifier2, so the transport replaces the
  request object's `client_metadata.jwks` with a key of its own
  (keeping the `kid`) and signs the request again with Verifier2's
  key and `x5c` (setup's `verifier2-key.pem`); it then decrypts the
  wallet's response, makes its one change (signing the Key Binding JWT
  again with the wallet's own holder key, its `sd_hash` recomputed),
  and encrypts it again to Verifier2's key. An SD-JWT VC's Key Binding
  JWT doesn't cover the encryption key, so the relayed case, which
  changes nothing else, is accepted, and each control differs from it
  in its one change.
- **Sessions.** Verifier2 signs its request and asks for an encrypted
  response only when the session says so (`signed_request`,
  `encrypted_response`); otherwise it serves an unsigned request object
  (`application/json`) naming its `x509_hash` client, which OID4VCgo's
  wallet refuses: the control above.

## Findings

Seen running walt.id 1.2.1; none reported upstream.

1. **Issuer2 serves its signing keys.** `GET /issuer2/profiles`, which
   takes no authentication, returns every profile, issuer private key
   (`d`) included. The configs ship test keys, but a deployment's own
   keys are served the same way.
2. **Verifier2 serves unsigned requests for an `x509_hash` client by
   default.** A session without `signed_request` names the `x509_hash`
   Client Identifier but serves the request object as plain JSON, which
   no Wallet can authenticate; a Wallet must refuse it (OpenID4VP 1.0
   §5.9.3).
3. **Verifier2 doesn't check the issuer by default.** Its default
   credential policy checks the signature against the credential's own
   `x5c`, not that the chain reaches a trust anchor: it accepted
   credentials from the run's CA, which it was never told about, and,
   the run shows, a PID whose Issuer-signed JWT the wallet's transport
   signed again with a fresh key under a self-signed certificate (the
   session `SUCCESSFUL`, the response answered 200). Its other
   policies (`allowed-issuer`, an ETSI trust list, a VICAL) don't take
   X.509 roots, so the run tests Verifier2's handling of OID4VCgo's
   wallet's presentation, not its issuer trust; the self-signed case is
   a note, and fails the run if Verifier2 starts refusing it.

Observations, not deviations:

4. **Issuer2's EU PID profile discloses everything.** Only `birthdate`
   is selectively disclosable: the address, personal administrative
   number, phone number and portrait are in every presentation of it,
   whatever a Verifier asks for. Which claims are selectively
   disclosable is the issuer's choice; this is the profile's
   configuration, not the protocol.
5. **Issuer2's metadata names no client authentication.** By default it
   says the pre-authorized code isn't redeemable anonymously
   (`pre-authorized_grant_anonymous_access_supported: false`) but names
   no `token_endpoint_auth_methods_supported`, so OID4VCgo's wallet
   refuses before redeeming it; the run enables `preauth-anonymous`.
   A default configuration a deployment changes, not a protocol
   fault.
6. **Wallet2 has no attester of its own.** It posts its instance key
   to whatever Wallet Provider `attestationConfig.attesterUrl` names,
   by default the EUDI reference implementation's
   (`wallet-provider.eudiw.dev`, in its tag's `wallet-service.conf`),
   and passes on the Client Attestation JWT it gets back. The run
   points it at its own stand-in ([`scripts/serve`](scripts/serve)),
   which signs with the attester key and `x5c` that
   [`../eudi/scripts/setup-issuer`](../eudi/scripts/setup-issuer) makes
   for OID4VCgo's issuer, and sets the `iss` the issuer expects
   (draft-ietf-oauth-attestation-based-client-auth-07 §5.1). So every
   Wallet Attestation in the run is OID4VCgo's stand-in's, not walt.id's
   or EUDI's.

Found by the negative presentations:

7. **Verifier2 refuses a disclosure the Issuer didn't sign as a
   dependency being unavailable.** Given an SD-JWT VC presentation one
   of whose disclosures has another value, so that its digest isn't in
   the Issuer-signed JWT, Verifier2 refuses it (RFC 9901 §7.1), but
   answers the response with `503` `temporarily_unavailable`,
   "Verification could not be completed because a dependency was
   unavailable: Invalid disclosures: …", where its other refusals of a
   presentation are `400` `invalid_request`. `temporarily_unavailable`
   tells the Wallet the failure is transient (RFC 6749 §4.1.2.1: the
   server is "unable to handle the request due to a temporary
   overloading or maintenance"), and the presentation can never
   verify. The session is `FAILED`, so the refusal holds; the run
   asserts the answer as 1.2.1 gives it, so that a change is noticed.

## What isn't covered

- The authorization code flow, in either direction, and Issuer2's
  Wallet Attestation: Issuer2 runs with anonymous pre-authorized codes.
- Status lists of Issuer2's credentials, which carry none, and of the
  PIDs Wallet2 is issued: the base profile's issuer sets no
  `status_lists`, and OID4VCgo's verifiers here check none. Only
  Verifier2 checks status (above); a SUSPENDED status isn't exercised,
  the issuer's list taking 1 bit.
- Verifier2's issuer trust (finding 3), its DC API flows, and Wallet2's
  checks of the credentials it's issued.
- Wallet2 receiving from Issuer2: walt.id with itself.
- Wallet2 with key attestations: the issuer's `key-attestation` profile
  is a note, not a case. Wallet2's library adds a key attestation to a
  `jwt` proof only from a `KeyAttestationProvider` attached to the
  wallet (`waltid-openid4vc-wallet`'s `KeyAttestationProvider.kt`,
  `keyAttestationForProof`: "Issuer requires key attestation but no
  wallet-provider service is configured"), and at 1.2.1 nothing in the
  Wallet2 service (`waltid-services/waltid-wallet-api2`) attaches one:
  `attachKeyAttestationProvider` is called only by the demo apps and
  the ITB conformance runner. Before that, it refuses the REST API's
  keys, which aren't Crypto2 keys (`WalletCredentialIssuance.kt`,
  `resolveProofHolderBindings`: "Key attestation requires a Crypto2
  holder key"), which is the refusal the run sees, with no Credential
  Request sent. If a later Wallet2 is issued the credential, the run
  says so.

## Running it

```sh
interop/waltid/run.sh
WALTID_TAG=latest interop/waltid/run.sh
```

It needs Docker, Go, `jq`, `curl`, `openssl` and `keytool`, and exits 0
only if every case behaves as expected. `BASE_PORT` (21400) moves its
ports (`BASE_PORT`+1 to +34), `WORK` keeps the run's files, and
`COMPOSE_PROJECT_NAME` (`oid4vcgo-waltid`) prefixes the containers'
names.

## Moving the pins

The images are pinned by digest in `run.sh`, with the commit of their
tag, whose `docker-compose/` configs the run fetches by SHA-256. The
weekly run tests walt.id's `latest` images with the pinned configs. To
move the pins, read the release's changes and its `docker-compose/`,
then take the new digests and hashes:

```sh
docker buildx imagetools inspect waltid/issuer-api2:X.Y.Z
curl -sSfL https://raw.githubusercontent.com/walt-id/waltid-identity/COMMIT/docker-compose/PATH | openssl dgst -sha256
```
