# Credo interop

Interop with [Credo](https://github.com/openwallet-foundation/credo-ts)
(credo-ts), the TypeScript framework of the OpenWallet Foundation, as
an OpenID4VCI 1.0 Credential Issuer, an OpenID4VP 1.0 Verifier and a
holder (wallet) of both (`@credo-ts/openid4vc`, versions `'v1'`), run
from its published npm packages. [`run.sh`](run.sh) runs every case against it, from
[`.github/workflows/credo-interop.yml`](../../.github/workflows/credo-interop.yml).

## Cases

| Direction | Case | Expected |
|---|---|---|
| OID4VCgo's wallet ← Credo's issuer | SD-JWT VC PID, by pre-authorized code; DPoP and a Wallet Attestation required | issued, and passes the wallet's checks; the Token Response's `token_type` is `DPoP` |
| | mDL (`mso_mdoc`), the same | issued, and passes the wallet's checks |
| | SD-JWT VC PID, the offer with a numeric `tx_code` | issued |
| | That, the `tx_code`'s last digit another | Credo refuses the Token Request: `invalid_grant`, `Invalid 'tx_code' provided` |
| | The wallet trusts an unrelated issuer CA | the wallet refuses the credential: `is invalid: wallet: verify issued credential: issuer certificate: certchain: certificate chain does not verify against a trusted root: …` |
| | The Wallet Attestation from a Wallet Provider under a CA Credo doesn't trust | Credo refuses the Token Request: `invalid_client`, `Error verifying client attestation. client attestation jwt verification failed. No trusted certificate was found while validating the X.509 chain` |
| | The wallet's default profile, which redeems the code anonymously as Credo's metadata allows | a note, not a case: Credo refuses it (finding 1); the run fails if that changes |
| | SD-JWT VC PID whose `jwt` proof requires a Key Attestation (`key_attestations_required`, key storage `iso_18045_moderate`): the wallet's from OID4VCgo's Wallet Provider, in the proof's `key_attestation` header, the proof's key in its `jwk` header | issued; the Wallet Provider served the Key Attestation |
| | That, key storage `iso_18045_high` required | Credo refuses the Credential Request: `invalid_proof: Insufficient key_storage for key attestation …` |
| | That (`iso_18045_moderate`), the proof's key named by its index in `attested_keys` (`kid` `"0"`), `walletflow`'s default | a note, not a case: Credo refuses it (finding 7); the run fails if that changes |
| OID4VCgo's wallet → Credo's verifier | SD-JWT VC PID: DCQL, a signed `x509_hash` request, the response encrypted (`direct_post.jwt`) | Credo verifies it (`ResponseVerified`), only `family_name` and `birthdate` disclosed |
| | mDL, the same | Credo verifies it, only `family_name` disclosed |
| | SD-JWT VC PID, relayed: the response encrypted to a key of the wallet transport's own, then again to Credo's, unchanged | Credo verifies it |
| | That, the Key Binding JWT's `nonce` another | Credo refuses it: `400 invalid_request`, its session `Error`: `Verify Error: Invalid Nonce` |
| | That, the Key Binding JWT's `aud` another `x509_hash` | Credo refuses it: `… The key binding JWT does not contain the expected audience` |
| | That, a disclosure's value changed (its digest no longer the Issuer's) | Credo refuses it: `… Unreferenced disclosure(s) detected in SD-JWT` |
| | That, the Issuer-signed JWT signed again under a self-signed certificate | Credo refuses it: `… No trusted certificate was found while validating the X.509 chain` |
| | The request unsigned (Credo sends it by value, as a `redirect_uri` client) | the wallet refuses it: `wallet: parse authorization request link: request_uri is required` |
| | The wallet trusts an unrelated Verifier CA | the wallet refuses the request: `parse authorization request: untrusted verifier: wallet: verifier certificate: certchain: …` |
| Credo's holder ← OID4VCgo's issuer | SD-JWT VC PID, by pre-authorized code, from `cmd/conformance-issuer` under HAIP: a Wallet Attestation from OID4VCgo's Wallet Provider, DPoP | issued, and passes Credo's checks; the Token Response's `token_type` is `DPoP` |
| | mdoc PID, the same | issued, and passes Credo's checks |
| | SD-JWT VC PID, the offer with a `tx_code` | issued |
| | That, the `tx_code`'s last digit another | the issuer refuses the Token Request: `400`, `{"error":"invalid_grant","error_description":"tx_code does not match"}` |
| | The Wallet Attestation from a Wallet Provider under a CA the issuer doesn't trust | the issuer refuses the Token Request: `401`, `{"error":"invalid_client","error_description":"no matching attester key"}` |
| | Credo looking up the key of the Wallet Attestation's `cnf.jwk` by `kid` alone, as it does | a note, not a case: Credo can't sign the Client Attestation PoP (finding 6); the run fails if that changes |
| | The issuer's `dpop-nonces` profile | issued; the Token and Credential Endpoints each challenged with `use_dpop_nonce`, and Credo retried with the nonce |
| | The issuer's `deferred` profile | deferred (`202`), then issued from the Deferred Credential Endpoint as Credo polled it |
| | The issuer's `key-attestation` profile (its `jwt` proofs require a Key Attestation): SD-JWT VC and mdoc PIDs, the Key Attestation from OID4VCgo's Wallet Provider over the `c_nonce` | issued, the Key Attestation sent as the `attestation` proof type |
| | That, the Key Attestation without the `c_nonce`, which Credo then sends in a `jwt` proof's `key_attestation` header | the issuer refuses the Credential Request: `400 invalid_nonce`, `proof 0: its key_attestation's nonce isn't the proof's c_nonce` |
| Credo's holder → OID4VCgo's verifier | SD-JWT VC PID to `cmd/conformance-verifier` on its default engine: DCQL, a signed `x509_hash` request (`request_uri_method` `get`, then `post`), `direct_post.jwt` | verified (issuer, holder binding, status), only `family_name` and `given_name` disclosed |
| | SD-JWT VC PID through `verifier.Transactions` under production assurance | verified, its result released to the browser that began the request |
| | mdoc PID, the same | verified, only the requested elements disclosed |
| | An SD-JWT VC PID the issuer revoked after issuing it (`POST /status`, `INVALID`) | the verifier refuses it, answering `400 invalid_request`: `verifier: credential status: statuslist: the referenced token's status is INVALID (revoked)` |
| | The verifier's Access Certificate under a CA Credo doesn't trust | Credo refuses the request as it resolves it: `… No trusted certificate was found while validating the X.509 chain` |
| | The verifier trusting an unrelated issuer CA | the verifier refuses the credential, answering `400 invalid_request`: `reason: untrusted_issuer`, `verifier: resolve issuer key: certchain: …` |

Each control is checked for its reason, not just for a failure:
OID4VCgo's own error for its refusals, Credo's Token or Credential
Endpoint error for its issuer's, and for its Verifier's both its answer
to the wallet's response (`400 invalid_request`, "One or more
presentations failed verification.", the same for every refusal) and
its verification session's error, which names the check that failed.
Each negative presentation differs from the relayed case, which Credo
accepts, in its one change. Where OID4VCgo's issuer refuses Credo's
holder, Credo reports its error response whole; where its verifier
does, the verifier's result page says why (a status refusal has no
`verifier.Reason`, so its error does), and its answer to Credo is `400
invalid_request`. The untrusted attester's case differs from the first
in its Wallet Provider alone, and the revoked PID's from the next
presentation to the same verifier in its status alone. A failure of
the run itself (setup, TLS) is not a refusal.

Credo also says what it sends, which the run asserts so that a change
is noticed: its response encryption key, in each signed request's
`client_metadata`, is one key with `alg` `ECDH-ES` and a `kid`
(OpenID4VP 1.0 §8.3); and its holder's Client Attestation PoP carries
no `iss` (the pinned draft-07 §5.2 has one, later drafts don't;
SPECIFICATIONS.md, "Known leniencies"), which a tap in front of
OID4VCgo's issuer logs, with each DPoP proof.

## How it's set up

- **Credo** is [`driver/`](driver), a small TypeScript program on
  `@credo-ts/core`, `@credo-ts/openid4vc`, `@credo-ts/node` and
  `@credo-ts/askar` (Askar's in-memory store, through
  `@openwallet-foundation/askar-nodejs`): one agent that is the
  Credential Issuer, the Verifier and the holder, serving the first
  two's endpoints over HTTPS at `https://localhost:$BASE_PORT+1` (the
  issuer at `/oid4vci/credo`, the Verifier at `/oid4vp/credo`), and a
  control API on loopback HTTP that `run.sh` drives with curl: it
  creates offers and requests and reports their sessions' states and
  errors, and has the holder redeem an offer or answer a request,
  reporting the stage it reached and why it stopped
  ([`driver/src/control.ts`](driver/src/control.ts),
  [`driver/src/holder.ts`](driver/src/holder.ts)).
- **Keys and trust.** [`scripts/setup`](scripts/setup) makes the run's
  CA, which Credo's TLS certificate, its SD-JWT VC signer and its
  Verifier's Access Certificate chain to; an IACA and a Document Signer
  under it, which signs Credo's mdocs; and another CA, which nothing
  trusts, for the controls. Credo imports the keys into its key
  management. Its Verifier trusts the run's CA and the IACA for
  credentials, and its issuer trusts the Wallet Provider's CA for Wallet
  Attestations, each by its verification type
  ([`driver/src/agent.ts`](driver/src/agent.ts)), nothing else. As
  holder it trusts the credentials it receives by their chain to the
  run's CA (OID4VCgo's issuer's SD-JWT VC signer, which setup makes,
  naming the issuer as finding 3 needs) or to OID4VCgo's issuer's IACA,
  and requests by their Access Certificate's chain to the run's CA; it
  fetches over TLS trusting the run's CA as well as Node's roots
  (`NODE_EXTRA_CA_CERTS`).
- **The issuer** requires DPoP (`dpopRequired`) and a Wallet Attestation
  (`walletAttestationsRequired`) on every Token Request, as HAIP 1.0
  does, and offers `pid-sd-jwt` (`dc+sd-jwt`, `vct`
  `urn:eudi:pid:1`, its claims selectively disclosable) and `mdl-mdoc`
  (`mso_mdoc`, `org.iso.18013.5.1.mDL`), each with a `scope`, bound to
  the wallet's key by a `jwt` proof.
- **OID4VCgo's wallet** is `walletflow`, at development assurance,
  through [`../waltid/scripts/wallet`](../waltid/scripts/wallet), the
  walt.id run's: it receives under `walletflow.ProfileHAIP` (`-haip`),
  attested by OID4VCgo's Wallet Provider
  ([`../walletprovider`](../walletprovider), `walletprovider.Provider`
  over sealed SQLite stores, over its v1 protocol), and redeems a
  `tx_code` with `-tx-code`. Each presentation's credential is the one
  the same wallet received from Credo's issuer just before.
- **Negative presentations.** The wallet's transport changes its
  SD-JWT VC presentation on the way to Credo (the walt.id wallet's
  `-tamper`, [`tamper.go`](../waltid/scripts/wallet/tamper.go)), as an
  attacker relaying it would, nothing of it in the library: it replaces
  the request object's response encryption key with its own, signs the
  request again with the Verifier's key (setup's `verifier-key.pem`),
  decrypts the wallet's response, makes its one change, signs the Key
  Binding JWT again with the holder's key, and encrypts it again to
  Credo.
- **The issuer's Key Attestations.** Credo's `pid-sd-jwt-ka` and
  `pid-sd-jwt-ka-high` require one in the `jwt` proof
  (`key_attestations_required`), of key storage `iso_18045_moderate`
  and `iso_18045_high`; OID4VCgo's Wallet Provider attests
  `iso_18045_moderate`. The wallet names the proof's key in its `jwk`
  header (`-proof-key-by-jwk`, `walletflow.Config.ProofKeyByJWK`), as
  Credo takes it (finding 7).
- **OID4VCgo's issuer** is `cmd/conformance-issuer` in
  [`../eudi/run-issuer.sh`](../eudi/run-issuer.sh)'s profiles (its
  config from [`../eudi/scripts/setup-issuer`](../eudi/scripts/setup-issuer):
  HAIP, pre-authorized code offers from its offers listener, an SD-JWT
  VC and an mdoc PID), each credential with a Token Status List entry,
  at `https://localhost:$BASE_PORT+9` through a tap (the walt.id run's
  [`serve`](../waltid/scripts/serve)) that logs what Credo's holder
  sends it. Its client is the one the Wallet Providers attest, its
  Wallet Attestations and Key Attestations trusted by their chain to
  the trusted provider's CA.
- **Credo's holder's attestations** come from the same Wallet
  Providers, through each one's agent
  ([`../walletprovider`](../walletprovider)'s `agent`: one registered
  instance, as the Swift and Kotlin libraries' `HttpWalletProvider` is
  on a device): a Wallet Attestation for each issuance's instance key,
  and a Key Attestation over the holder key and the `c_nonce` where the
  issuer requires one. Credo signs only with a key its JWK's `kid`
  names, which neither attestation's JWKs carry (finding 6), so the
  driver answers Credo's key lookup by the JWK's thumbprint for the
  keys it made ([`driver/src/keylookup.ts`](driver/src/keylookup.ts)),
  as Credo would need to itself; one case runs without it.
- **OID4VCgo's verifiers** are `cmd/conformance-verifier`, each a
  signed `x509_hash` request under setup's `our-verifier` Access
  Certificate, `direct_post.jwt`, checking each credential's chain and
  its Token Status List entry, fetched from the issuer through the tap:
  the SD-JWT VC PID's on the default engine at development assurance,
  then, through `verifier.Transactions` under production assurance
  (its transactions in a sealed SQLite file), the SD-JWT VC PID's, the
  mdoc PID's, one whose Access Certificate is under the CA Credo
  doesn't trust, and one trusting another issuer CA. The run redeems
  each result as the browser that began the request.

## Findings

Seen running Credo 0.7.4; none reported upstream.

1. **Credo's metadata allows anonymous pre-authorized code redemption
   that its Token Endpoint refuses.** Its Authorization Server metadata
   always says `pre-authorized_grant_anonymous_access_supported: true`
   (`OpenId4VcIssuerService.getIssuerMetadata`), also when
   `walletAttestationsRequired` is set, and then its Token Endpoint
   refuses a Token Request without one: `invalid_client`, "Missing
   required client attestation parameters in access token request". A
   Wallet that takes the metadata at its word (OpenID4VCI 1.0 §12.3)
   and redeems the code anonymously, as `walletflow`'s default profile
   does where the server allows that, is refused. The run's wallet
   receives under `ProfileHAIP`, which attests itself at every Token
   Request; the default profile's refusal is a note, and fails the run
   if it changes.

Observations, not deviations:

2. **Credo's Credential Issuer Metadata carries pre-1.0 members.**
   Besides 1.0's `credential_configurations_supported`, it serves
   draft 11's `credentials_supported` (an array, `vc+sd-jwt` and
   `cryptographic_suites_supported`), and the Authorization Server's
   `token_endpoint` and `dpop_signing_alg_values_supported`, for wallets
   on older drafts (`issuerMetadataEndpoint.ts`). A 1.0 wallet ignores
   them; `walletflow` does.
3. **Credo binds an SD-JWT VC's `iss` to its signer's certificate.** It
   signs an x5c SD-JWT VC only if `iss` is a SAN URI of the leaf, or its
   host a SAN DNS name, and checks the same when it verifies one. That
   is Credo's policy, not the specification's; the run's signer
   certificate names the Credential Issuer Identifier.
4. **Credo sends an unsigned request only as a `redirect_uri` client, by
   value.** With no request signer it names the `redirect_uri` Client
   Identifier and puts the request in the link, so there is no unsigned
   `x509_hash` request to refuse; the control is that by-value request,
   which `walletflow`, taking requests only by reference, refuses as it
   parses the link.
5. **Credo's answer to a refused presentation names no reason.** Every
   refusal is `400 invalid_request`, "One or more presentations failed
   verification."; the reason is in the verification session's
   `errorMessage`, which the run reads through the driver.

Seen running Credo's holder, and its issuer's Key Attestations:

6. **Credo's holder can sign only with a key whose JWK carries its
   `kid`.** It signs through its key management by the JWK's `kid`
   (`Kms.PublicJwk.keyId`, which throws "Unable to determine keyId for
   jwk" without one), and finds no key by its public key. A Wallet
   Attestation's `cnf.jwk` and a Key Attestation's `attested_keys` are
   the Wallet Provider's copies of the wallet's public keys, and
   nothing requires them to carry the `kid` the wallet's key management
   gave them (RFC 7800 §3.2; OpenID4VCI 1.0 Appendix D.1); OID4VCgo's
   Wallet Provider's don't. So Credo's holder can't sign the Client
   Attestation PoP for such a Wallet Attestation, and sends no Token
   Request, nor use such a Key Attestation's keys. The run's driver
   looks such keys up by thumbprint; the case without that lookup is a
   note, and fails the run if it changes.
7. **Credo's issuer can't verify a key-attested `jwt` proof that names
   its key by index.** OpenID4VCI 1.0 Appendix F.1 has the proof's key
   identified by `kid`, `jwk` or `x5c`; with a `key_attestation`, ETSI
   TS 119 472-3 has the `kid` be the key's index in `attested_keys`,
   which is `walletflow`'s default (`kid` `"0"`). Credo's issuer
   resolves a `kid` only as a DID URL, so it finds no key for the
   proof: `invalid_proof`, "Unable to verify jws with unsupported jws
   signer method 'custom'". It verifies one whose key is in its `jwk`
   header (`walletflow.Config.ProofKeyByJWK`), which the run's key
   attestation case sends; the default's refusal is a note, and fails
   the run if it changes.

Observations, not deviations:

8. **Credo's holder carries the Token Endpoint's DPoP nonce to the
   Credential Endpoint.** Its first Credential Request's DPoP proof has
   the nonce the Authorization Server gave it, which a Credential
   Issuer with nonces of its own (RFC 9449 §9) challenges with
   `use_dpop_nonce` like a proof without one; Credo then retries with
   the Credential Issuer's.
9. **Credo's holder fetches a credential's status list as it receives
   it**, both the SD-JWT VC's and the mdoc's, which the tap tells from
   the verifiers' fetches by the User-Agent.

## What isn't covered

- The authorization code flow, PAR and PKCE, in either direction;
  batch issuance; Credential Request and Response encryption; deferred
  issuance from Credo's issuer.
- Credo's issuer's Key Attestations by the `attestation` proof type, and
  Key Attestation controls beyond the key storage level (an untrusted
  attester's, say): the wallet takes its Wallet Attestation and Key
  Attestations from the same provider, so an untrusted one is refused
  at the Token Endpoint first.
- A Key Attestation from Credo's holder in a `jwt` proof's
  `key_attestation` header, accepted: it sends one there only without
  the `c_nonce`, which OID4VCgo's issuer refuses (a control).
- Certificate revocation: the wallet checks none of Credo's certificates
  against a CRL (`-crl-set none`), and Credo checks none of the
  wallet's, nor OID4VCgo's issuer and verifiers Credo's holder's;
  status lists from Credo's issuer; revoked Wallet Attestations
  (OID4VCgo's issuer checks their status only in its production setup,
  which the run doesn't use).
- Negative mdoc presentations, and an mdoc revoked by its issuer: the
  transport changes SD-JWT VCs only, and the run revokes an SD-JWT VC.
- The Digital Credentials API, and `walletflow` at production assurance.

## Running it

```sh
interop/credo/run.sh
CREDO_VERSION=latest interop/credo/run.sh
```

It needs Go, Node 22 or later with npm, `jq`, `curl` and `openssl`, and
exits 0 only if every case behaves as expected. `BASE_PORT` (21600)
moves its ports (`BASE_PORT`+1 to +16: Credo's endpoints, its control
API, two Wallet Providers with their admin listeners and agents,
OID4VCgo's issuer with its tap and offers listener, and its five
verifiers), `WORK` keeps the run's files, and `CREDO_LOG_LEVEL` (`info`) sets Credo's logging
(`debug`, `info`, `warn`, `error`), into `credo.log`. The driver is
built in the work directory, so the checkout's `driver/` gets no
`node_modules`.

## Moving the pin

Credo is pinned by exact version in
[`driver/package.json`](driver/package.json), with every dependency
locked in [`driver/package-lock.json`](driver/package-lock.json), from
which `run.sh` installs with `npm ci --ignore-scripts`: no package's
install script runs. Askar's native library, which
`@openwallet-foundation/askar-nodejs`'s install script would fetch
from Askar's GitHub releases without a checksum, `run.sh` fetches
itself and checks against `askar_sha256`, by the release
askar-nodejs names (`binary.version` in its `package.json`) and the
platform. askar-nodejs's version is the one Credo's own repository
uses for that release. Dependabot doesn't update any of it. To move
it, read the release's changelog (`packages/openid4vc/CHANGELOG.md`
among them), change the four `@credo-ts/*` versions (and Askar's, if
the release moved it), then:

```sh
cd interop/credo/driver
rm -rf node_modules package-lock.json
npm install --ignore-scripts
npx tsc -p tsconfig.json
```

If the new askar-nodejs names another Askar release, add that
release's `library-linux-x86_64`, `library-linux-aarch64` and
`library-darwin-universal` archives' SHA-256 to `askar_sha256` in
`run.sh` (download each from
`https://github.com/openwallet-foundation/askar/releases/download/<release>/`
and hash it); `run.sh` refuses a release it has no checksum for. The
weekly run on Credo's newest release fails the same way, naming the
release, when one moves it.

and run `run.sh`. Credo's API changes between minor releases, so expect
the driver to need changes with it, and read again whether findings 1,
6 and 7 still hold: once Credo finds a key without its `kid`, drop
[`driver/src/keylookup.ts`](driver/src/keylookup.ts).

The weekly run tests Credo's newest release (`CREDO_VERSION=latest`)
with the pinned driver and the rest of the lock, and opens an
`interop-credo-latest` issue when it fails: a new release, or one the
driver no longer builds against.
