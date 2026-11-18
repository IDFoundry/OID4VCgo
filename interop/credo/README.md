# Credo interop

Interop with [Credo](https://github.com/openwallet-foundation/credo-ts)
(credo-ts), the TypeScript framework of the OpenWallet Foundation, as
an OpenID4VCI 1.0 Credential Issuer and an OpenID4VP 1.0 Verifier
(`@credo-ts/openid4vc`, versions `'v1'`), run from its published npm
packages. [`run.sh`](run.sh) runs every case against it, from
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
| OID4VCgo's wallet → Credo's verifier | SD-JWT VC PID: DCQL, a signed `x509_hash` request, the response encrypted (`direct_post.jwt`) | Credo verifies it (`ResponseVerified`), only `family_name` and `birthdate` disclosed |
| | mDL, the same | Credo verifies it, only `family_name` disclosed |
| | SD-JWT VC PID, relayed: the response encrypted to a key of the wallet transport's own, then again to Credo's, unchanged | Credo verifies it |
| | That, the Key Binding JWT's `nonce` another | Credo refuses it: `400 invalid_request`, its session `Error`: `Verify Error: Invalid Nonce` |
| | That, the Key Binding JWT's `aud` another `x509_hash` | Credo refuses it: `… The key binding JWT does not contain the expected audience` |
| | That, a disclosure's value changed (its digest no longer the Issuer's) | Credo refuses it: `… Unreferenced disclosure(s) detected in SD-JWT` |
| | That, the Issuer-signed JWT signed again under a self-signed certificate | Credo refuses it: `… No trusted certificate was found while validating the X.509 chain` |
| | The request unsigned (Credo sends it by value, as a `redirect_uri` client) | the wallet refuses it: `wallet: parse authorization request link: request_uri is required` |
| | The wallet trusts an unrelated Verifier CA | the wallet refuses the request: `parse authorization request: untrusted verifier: wallet: verifier certificate: certchain: …` |

Each control is checked for its reason, not just for a failure:
OID4VCgo's own error for its refusals, Credo's Token Endpoint error
for the issuer's, and for the Verifier's both its answer to the
wallet's response (`400 invalid_request`, "One or more presentations
failed verification.", the same for every refusal) and its
verification session's error, which names the check that failed. Each
negative presentation differs from the relayed case, which Credo
accepts, in its one change. A failure of the run itself (setup, TLS) is
not a refusal.

Credo also says what it sends, which the run asserts so that a change
is noticed: its response encryption key, in each signed request's
`client_metadata`, is one key with `alg` `ECDH-ES` and a `kid`
(OpenID4VP 1.0 §8.3).

## How it's set up

- **Credo** is [`driver/`](driver), a small TypeScript program on
  `@credo-ts/core`, `@credo-ts/openid4vc`, `@credo-ts/node` and
  `@credo-ts/askar` (Askar's in-memory store, through
  `@openwallet-foundation/askar-nodejs`): one agent that is both the
  Credential Issuer and the Verifier, serving their endpoints over
  HTTPS at `https://localhost:$BASE_PORT+1` (the issuer at
  `/oid4vci/credo`, the Verifier at `/oid4vp/credo`), and a control API
  on loopback HTTP that `run.sh` drives with curl: it creates offers and
  requests and reports their sessions' states and errors
  ([`driver/src/control.ts`](driver/src/control.ts)). A holder role,
  for the directions where OID4VCgo is the issuer and Verifier, would
  be a third set of routes there.
- **Keys and trust.** [`scripts/setup`](scripts/setup) makes the run's
  CA, which Credo's TLS certificate, its SD-JWT VC signer and its
  Verifier's Access Certificate chain to; an IACA and a Document Signer
  under it, which signs Credo's mdocs; and another CA, which nothing
  trusts, for the controls. Credo imports the keys into its key
  management. Its Verifier trusts the run's CA and the IACA for
  credentials, and its issuer trusts the Wallet Provider's CA for Wallet
  Attestations, each by its verification type
  ([`driver/src/agent.ts`](driver/src/agent.ts)), nothing else.
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

## What isn't covered

- Credo as holder: Credo's wallet receiving from `cmd/conformance-issuer`
  and presenting to `cmd/conformance-verifier`. The driver's control API
  and agent are where a holder role would go.
- The authorization code flow, PAR and PKCE; batch and deferred issuance;
  Credential Request and Response encryption.
- Key attestations: Credo's issuer here asks for plain `jwt` proofs (no
  `key_attestations_required`), so the wallet sends no Key Attestation.
- Certificate revocation: the wallet checks none of Credo's certificates
  against a CRL (`-crl-set none`), and Credo checks none of the
  wallet's; status lists, in either direction.
- Negative mdoc presentations: the transport changes SD-JWT VCs only.
- The Digital Credentials API, and `walletflow` at production assurance.

## Running it

```sh
interop/credo/run.sh
CREDO_VERSION=latest interop/credo/run.sh
```

It needs Go, Node 22 or later with npm, `jq`, `curl` and `openssl`, and
exits 0 only if every case behaves as expected. `BASE_PORT` (21600)
moves its ports (`BASE_PORT`+1 to +6: Credo's endpoints, its control
API, and two Wallet Providers with their admin listeners), `WORK` keeps
the run's files, and `CREDO_LOG_LEVEL` (`info`) sets Credo's logging
(`debug`, `info`, `warn`, `error`), into `credo.log`. The driver is
built in the work directory, so the checkout's `driver/` gets no
`node_modules`.

## Moving the pin

Credo is pinned by exact version in
[`driver/package.json`](driver/package.json), with every dependency
locked in [`driver/package-lock.json`](driver/package-lock.json), from
which `run.sh` installs with `npm ci`; Askar's native library comes
with `@openwallet-foundation/askar-nodejs`, whose version is the one
Credo's own repository uses for that release. Dependabot doesn't update
it. To move it, read the release's changelog
(`packages/openid4vc/CHANGELOG.md` among them), change the four
`@credo-ts/*` versions (and Askar's, if the release moved it), then:

```sh
cd interop/credo/driver
rm -rf node_modules package-lock.json
npm install
npx tsc -p tsconfig.json
```

and run `run.sh`. Credo's API changes between minor releases, so expect
the driver to need changes with it, and read again whether finding 1
still holds.

The weekly run tests Credo's newest release (`CREDO_VERSION=latest`)
with the pinned driver and the rest of the lock, and opens an
`interop-credo-latest` issue when it fails: a new release, or one the
driver no longer builds against.
