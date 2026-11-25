# EUDIPLO interop

Interop with [EUDIPLO](https://github.com/openwallet-foundation-labs/eudiplo),
the OpenWallet Foundation Labs' Credential Issuer and Verifier
middleware (TypeScript, NestJS; no wallet), run from its published image
(`ghcr.io/eudiplo/eudiplo`). [`run.sh`](run.sh) runs every case against
it, from [`.github/workflows/eudiplo-interop.yml`](../../.github/workflows/eudiplo-interop.yml),
in two directions: EUDIPLO's Verifier, presented to by OID4VCgo's
wallet; then ([`issuer.sh`](issuer.sh), which `run.sh` sources)
EUDIPLO's Credential Issuer, issuing to OID4VCgo's wallet.

EUDIPLO isn't a fully independent implementation of the protocols:
it builds on the same TypeScript libraries as Credo
([`../credo`](../credo/README.md)), `@openid4vc/openid4vp` and
`@openid4vc/oauth2` (10.1.0 pins 0.10.0 of each; Credo 0.7.4, 0.6.0),
`@openid4vc/openid4vci` (0.10.0; Credo, 0.6.0), `@sd-jwt/*` (0.25.0;
Credo, 0.21.1) and `@owf/mdoc` (0.10.0; Credo, 0.8.3). So some of its
refusals are those libraries' (its Key Binding JWT `nonce` refusal
reads `Verify Error: Invalid Nonce`, as Credo's does; neither verifies
a key-attested `jwt` proof naming its key by index, finding 3), and a
gap in them would show in both runs. What is EUDIPLO's own is around
them: its trust lists, its status checks and status lists, its
sessions, its authorization server, its Digital Credentials API and
Annex C endpoints.

EUDIPLO 10.1.0 implements OpenID4VP 1.0 (final), as its
[protocol reference](https://docs.eudiplo.dev/reference/protocols)
says, and as what it sends shows: `client_id` prefixes (`x509_hash:`),
`dcql_query`, `client_metadata.vp_formats_supported` with 1.0's member
names (`sd-jwt_alg_values`, `kb-jwt_alg_values`, `issuerauth_alg_values`,
`deviceauth_alg_values`), `encrypted_response_enc_values_supported`,
`aud` `https://self-issued.me/v2`, `response_mode` `direct_post.jwt`
and `dc_api.jwt`, `expected_origins` in a DC API request; and
`walletflow`, which takes 1.0 alone, answers each. Its issuer
implements OpenID4VCI 1.0 (final): offers by reference, the nonce
endpoint, `proofs` (`jwt` and `attestation`), batches
(`batch_credential_issuance`), credential request and response
encryption, the notification endpoint. Of the other specifications, it
names the SD-JWT VC and Token Status List drafts without a version,
OAuth 2.0 Attestation-Based Client Authentication for Wallet
Attestations, and ISO/IEC TS 18013-7 Annex C.

## Cases

| Direction | Case | Expected |
|---|---|---|
| OID4VCgo's issuer → OID4VCgo's wallet → EUDIPLO's Verifier | SD-JWT VC PID: a cross-device request (`request_uri`, GET), signed, `x509_hash`, DCQL, the response encrypted (`direct_post.jwt`) | EUDIPLO verifies it (session `completed`), its issuer matched by the trust list naming OID4VCgo's issuer's CA, only `family_name` and `birth_date` disclosed |
| | mdoc PID, the same | EUDIPLO verifies it, its issuer matched by the IACA, only `family_name` disclosed |
| | Each, its status list entry | EUDIPLO fetched the issuer's Token Status List, the SD-JWT VC's as a JWT, the mdoc's as a CWT |
| | The SD-JWT VC PID, revoked by the issuer (`POST /status`) after issuance | EUDIPLO refuses it: `400`, the session `failed`, `Presentation validation failed: Status is not valid` |
| | The mdoc PID, the same | EUDIPLO refuses it, as `trust_list_unavailable` (finding 1), its session log `Status for id '…' is not Valid (0), but is instead '1'` |
| | SD-JWT VC PID, relayed: the response encrypted to a key of the wallet transport's own, then again to EUDIPLO's, unchanged | EUDIPLO verifies it |
| | That, the Key Binding JWT's `nonce` another | EUDIPLO refuses it: `Presentation validation failed: Verify Error: Invalid Nonce` |
| | That, the Key Binding JWT's `aud` another `x509_hash` | EUDIPLO refuses it: `Presentation validation failed: Invalid key binding JWT audience` |
| | That, a disclosure's value changed (its digest no longer the Issuer's) | EUDIPLO refuses it: `Presentation validation failed: Unreferenced disclosure(s) detected in SD-JWT` |
| | That, the Issuer-signed JWT signed again under a self-signed certificate | EUDIPLO refuses it: `trust_chain_not_trusted`, "The credential issuer is not in the trusted list." |
| | A request whose trust list names only a CA that issued nothing | the wallet refuses it: no held credential under the `trusted_authorities` (`aki`) EUDIPLO sends |
| | The wallet trusts an unrelated Verifier CA | the wallet refuses the request: `untrusted verifier: wallet: verifier certificate: certchain: …` |
| | SD-JWT VC PID and mdoc PID over the Digital Credentials API (`openid4vp-v1-signed`, `dc_api.jwt`), the request bound to the page's origin | EUDIPLO verifies each, only the claims asked for disclosed |
| | mdoc PID over ISO/IEC TS 18013-7 Annex C (`org-iso-mdoc`), the DeviceRequest signed by EUDIPLO's Access Certificate (`readerAuth`) | the wallet recognizes the reader; EUDIPLO verifies it |
| | That, the wallet handed another origin than the page's, so its session transcript is another | EUDIPLO refuses it: `400`, `HPKE decryption failed` |
| | EUDIPLO's response encryption JWK, in `client_metadata.jwks` | as 10.1.0 sends it (below) |
| EUDIPLO's issuer → OID4VCgo's wallet | SD-JWT VC PID, a pre-authorized code with a `tx_code`; a Wallet Attestation from OID4VCgo's Wallet Provider and DPoP required | issued as a batch of 2, every Credential Request and Response encrypted, a `DPoP` token; the wallet checks its chain to EUDIPLO's CA and its holder binding; the session `completed` (the wallet's notification) |
| | mdoc PID, the same | the same, its chain to EUDIPLO's IACA |
| | The Wallet Attestation's status | EUDIPLO fetched the provider's status list |
| | SD-JWT VC PID under walletflow's HAIP profile (a Wallet Attestation at every Token Request; a `jwt` proof carrying a Key Attestation, its key in `jwk`) | issued |
| | SD-JWT VC PID from the tenant requiring request and response encryption (`encryption_required`) | issued, encrypted both ways |
| | A Key Attestation required (`key_storage` `iso_18045_moderate`): in a `jwt` proof's `key_attestation`, its key in `jwk`; as an `attestation` proof | issued: one credential for the one `jwt` proof, a batch of 2 for the attestation proof's two keys |
| | Each PID's Token Status List entry, checked by the wallet | VALID; the SD-JWT VC's list signed by EUDIPLO as a Status Issuer, the wallet told so |
| | Each PID, revoked by EUDIPLO (`POST /api/session/revoke`) after issuance | the wallet reads it INVALID (`status_list`) |
| | The SD-JWT VC's status list, the wallet not told EUDIPLO is a Status Issuer | the wallet refuses it: `token signer isn't the referenced token's issuer: … iss "…/issuers/oid4vcgo" isn't a URI of the signing certificate` |
| | A wrong `tx_code` | EUDIPLO refuses the Token Request: `invalid_grant: Invalid 'tx_code' provided` |
| | A Wallet Attestation from the other Wallet Provider instance, which EUDIPLO's trust list doesn't name | EUDIPLO refuses it: `invalid_client: Wallet provider certificate is not trusted - no matching entity in trust list` |
| | A Wallet Attestation whose instance the provider revoked once it attested it | EUDIPLO refuses it, by its status: `invalid_client: Wallet attestation is not valid: Invalid/Revoked` |
| | A Key Attestation below the required level (`iso_18045_high`) | EUDIPLO refuses the proof: `invalid_proof: The key attestation does not state an accepted key_storage value (accepted: iso_18045_high)` |
| | Each Credential Request's DPoP proof signed again, its `htu` the Notification Endpoint's | EUDIPLO refuses it: `Dpop jwt contains htu value '…/vci/notification', but expected htu value '…/vci/credential'` |
| | The wallet trusts another issuer CA | the wallet refuses the credential: `issuer certificate: certchain: certificate chain does not verify against a trusted root`; its notification fails the session (`credential_failure`) |
| | The authorization code flow (PAR, PKCE, DPoP) | a note: EUDIPLO's PAR refuses the request's `nonce` (finding 2) |
| | A key-attested `jwt` proof naming its key by its index (`kid` `0`, walletflow's default) | a note: EUDIPLO refuses it, `invalid_proof: Error verifying credential request proof jwt` (finding 3) |
| | EUDIPLO's status list token's `iss` | as 10.1.0 sends it (below) |

Each control is checked for its reason, not just for a failure:
EUDIPLO's answer to the wallet's response (`400`, which names nothing:
EUDIPLO puts the reason in the session) and its session, read back
through its management API (`GET /api/session/{id}`): `status`
`failed`, `outcome.source` `verifier`, and the `failureCode` and
`errorReason` the case names; the mdoc's revocation, which EUDIPLO
classifies as another failure, also by the session's log
(`GET /api/session/{id}/logs`, `LOG_SESSION_STORE=errors`), which
names the status. Each negative presentation differs from the relayed
case, which EUDIPLO accepts, in its one change; each revocation control
from the case before it in the status alone; the Annex C control from
the Annex C case in the origin alone. The wallet's refusals are graded
by its own error. A failure of the run itself (setup, TLS, the wallet
stopping before its response) is not a refusal.

The issuer's controls are graded by EUDIPLO's OAuth error, which names
the reason (`error` and `error_description`, as the wallet reports
them), at the stage the wallet stopped (`token`, `credential`), with
EUDIPLO's issuance session still `active`: it issued nothing. Each
differs from a passing case in one thing: the wrong `tx_code`, the
untrusted provider and the revoked attestation from `issue-sdjwt` (the
revoked one's status list fetched again after the run clears EUDIPLO's
cache), the Key Attestation level from `issue-ka`, the DPoP proof's
`htu` from `issue-sdjwt`; each revocation from its status case in the
revocation alone, the unknown Status Issuer from `status-sdjwt` in the
wallet's `StatusIssuers` alone. The two notes are shown by elimination
too: the same PAR without `nonce` passes EUDIPLO's validation, to its
client authentication (`invalid_client`); the same key-attested proof
naming its key in `jwk` is accepted (`issue-ka`).

## How it's set up

- **EUDIPLO** runs as its `docker-compose.yml` runs it, but for: a
  config folder of the run's ([`scripts/setup`](scripts/setup)),
  imported at startup into a fresh SQLite database
  (`CONFIG_IMPORT_MODE=replace`, `CONFIG_VARIABLE_STRICT=abort`); its
  own TLS listener (`TLS_ENABLED`) under the run's CA, at
  `https://localhost:$BASE_PORT+1` (`PUBLIC_URL`), and inside its
  container at `https://localhost:3000` (`INTERNAL_URL`), where it
  fetches its own trust lists; the run's CA beside Node's roots
  (`NODE_EXTRA_CA_CERTS`), for the status lists it fetches over TLS it
  verifies (`NODE_ENV=production`, the image's); outbound calls to
  `eudiplo.test` alone, a private address
  (`OUTBOUND_URL_ALLOWED_HOSTS`, `OUTBOUND_URL_ALLOW_PRIVATE_NETWORK`);
  and throwaway secrets (`MASTER_SECRET`, the root client's, the
  tenant client's), made per run.
- **The tenant** (`scripts/setup`): an API client with
  `presentation:manage`, `presentation:request` and `sessions:read`;
  the Access Certificate's key chain, a P-256 key under the run's CA
  (`standalone`, its `x5c` the leaf alone), which signs every request
  (`x509_hash`) and, with `readerAuth`, the Annex C DeviceRequest; a
  key chain signing its trust lists; the managed trust list
  `oid4vcgo-issuers`, two external entities, OID4VCgo's issuer's
  SD-JWT VC CA and its IACA, each its entity's issuance and revocation
  certificate, since the issuer signs its status lists with the
  credentials' own signers; `other-issuers`, a CA that issued nothing;
  and the presentation configs `pid-sdjwt`, `pid-mdoc`,
  `pid-mdoc-annexc` (trusting `oid4vcgo-issuers`) and
  `pid-sdjwt-untrusted` (`other-issuers`), every one with
  `statusCheckMode` `strict`, EUDIPLO's default. EUDIPLO lists a
  managed list's entities as EAA providers, so neither PID is a PID to
  it (ARF's 24-hour rule for PIDs without status doesn't apply; both
  carry status anyway).
- **OID4VCgo's issuer** is `cmd/conformance-issuer` in its production
  setup, its config [`../eudi/scripts/setup-issuer`](../eudi/scripts/setup-issuer)'s
  as in the walt.id run's status list cases: production assurance,
  sealed SQLite stores (its status lists' reservations among them),
  pre-authorized code offers, DPoP nonces, `jwt` proofs carrying a Key
  Attestation, batches of 5; Wallet Attestations and Key Attestations
  from OID4VCgo's Wallet Provider ([`../walletprovider`](../walletprovider)),
  trusted by their `x5c` chain and their status checked on its lists
  (`attestation_status_allow_loopback`). It's `https://localhost:…` to
  the wallet; its status lists, `status_lists.base_url`, are
  `https://eudiplo.test:$BASE_PORT+4`, which EUDIPLO's container maps
  to this host (`host-gateway`), through the walt.id run's
  [`serve`](../waltid/scripts/serve)'s tap, which logs each fetch.
- **OID4VCgo's wallet** is `walletflow`, at development assurance,
  through [`../waltid/scripts/wallet`](../waltid/scripts/wallet), the
  walt.id and Credo runs': it redeems an offer of the issuer's,
  attested by the Wallet Provider, checks the credential (its chain to
  the issuer's CA or IACA), and presents it with its default selection
  to the request, trusting Verifiers whose Access Certificate chains to
  the run's CA. Each presentation's credential is the one the same
  wallet received just before; with `-revoke` the issuer revokes every
  copy first.
- **Negative presentations.** The wallet's transport changes the
  SD-JWT VC presentation on its way to EUDIPLO (the walt.id wallet's
  `-tamper`, [`tamper.go`](../waltid/scripts/wallet/tamper.go)), as an
  attacker relaying it would, nothing of it in the library: it replaces
  the request object's response encryption key with its own, signs the
  request again with EUDIPLO's Access Certificate key (setup's
  `verifier-key.pem`), decrypts the wallet's response, makes its one
  change, signs the Key Binding JWT again with the holder's key, and
  encrypts it again to EUDIPLO.
- **Status lists.** EUDIPLO caches a status list for its `ttl`, five
  minutes without one, and the issuer's tokens carry none; so before
  each revocation control the run clears the tenant's cached status
  lists (`DELETE /api/cache/status-list`) and checks EUDIPLO fetched
  the list again.

### EUDIPLO's issuer

- **The tenants** (`scripts/setup`'s `issuer.go`): the Verifier's
  tenant issues too, and a second, `oid4vcgo-enc`, sets
  `credentialRequestEncryption` and `credentialResponseEncryption`. Each
  has the built-in authorization server (`requireDPoP`,
  `walletAttestationRequired`), `dPopRequired`, `batchSize` 2, and
  `walletProviderTrustLists` naming its managed list `wallet-providers`:
  one entity, `providerType` `wallet-provider`, the Wallet Provider's
  CA its issuance and revocation certificate (the provider signs its
  status lists with its attestations' signer), checked strictly
  (`walletAttestationStatusCheckMode` `strict`). Its key chains sign
  SD-JWT VCs under a CA of the run's (`eudiplo-issuer-ca.pem`), mdocs
  by a Document Signer under an IACA (`eudiplo-iaca.pem`), and each
  format's status list: the SD-JWT VCs' by a certificate under that CA
  naming EUDIPLO's `PUBLIC_URL`, the iss EUDIPLO gives its status lists;
  the mdocs' by an ISO/IEC 18013-5 status list signer under the IACA.
  The credential configs: `pid-sdjwt` and `pid-mdoc`, `pid-sdjwt-ka`
  (`keyAttestationsRequired`, `key_storage` `iso_18045_moderate`,
  `jwt` proofs), `pid-sdjwt-kap` (the same, `attestation` proofs) and
  `pid-sdjwt-ka-high` (`iso_18045_high`); each bound to a key, with a
  status list entry, its claims `family_name`, `given_name` and
  `birth_date` static. EUDIPLO regenerates a status list on each
  change (`STATUS_IMMEDIATE_UPDATE`), rather than when its `ttl`
  (an hour) runs out, so a revocation is seen at once.
- **The Wallet Provider** is a second instance of OID4VCgo's
  ([`../walletprovider`](../walletprovider)): its status lists
  published as `https://eudiplo.test:$BASE_PORT+9/statuslists`
  (`-base-url`), where EUDIPLO fetches them through a second
  [`serve`](../waltid/scripts/serve) tap, which logs each fetch. Its
  Wallet Attestations carry `wallet_name`, `wallet_link` and the
  instance key's status in the top-level `status` claim (OpenID4VCI 1.0
  Appendix E), its Key Attestations `key_storage` `iso_18045_moderate`
  and `status`. The first instance, the Verifier cases', is the
  untrusted provider.
- **OID4VCgo's wallet** is `walletflow` at development assurance, the
  same driver: `-check-status` checks each credential's status
  (`Wallet.CheckStatus`, without the observing transport, which the
  status list fetcher's address policy doesn't take), `-status-issuer`
  names EUDIPLO as a Status Issuer for the tenant's credentials
  (`Config.StatusIssuers`), `-revoke-call` has EUDIPLO revoke the
  session's credentials before the check, `-revoke-instance` has the
  Wallet Provider revoke the instance once it has attested it,
  `-tamper-dpop` signs each Credential Request's DPoP proof again for
  another `htu` ([`dpop.go`](../waltid/scripts/wallet/dpop.go)), and
  `-redirect-uri` redeems an authorization code offer, following the
  authorization endpoint's redirects as a browser would
  ([`authorize.go`](../waltid/scripts/wallet/authorize.go)): EUDIPLO's
  built-in server asks the holder nothing.

#### Wallet and Key Attestations

EUDIPLO 10.1.0 verifies a Wallet Attestation with
`@openid4vc/openid4vci` (`oauth-client-attestation+jwt`, its PoP's
`aud` the authorization server, `cnf.jwk`, expiry), then builds a path
from its `x5c` to a certificate a wallet-provider trust list lists as
`WalletSolution` or `WalletSolution/Issuance`, each certificate of it
within its validity, and checks its status entry: TS3 1.5's
`client_status.status` or the top-level `status`, either accepted, on a
status list typed `statuslist+jwt`, its `sub` the entry's URI, signed
under the provider's revocation or attestation certificate. A Key
Attestation is checked the same way (`key_storage_status.status` or
`status`), its `attested_keys` holding the proof's key and its
`key_storage` one the configuration accepts. It requires none of TS3's
other claims (`wallet_name`, `wallet_link`, `eudi_wallet_info`), no
`typ` beyond the library's, and no `exp` in a TS3 status claim. So
OID4VCgo's Wallet Provider needed no change: EUDIPLO's trust list names
its CA as a wallet provider.

### The Digital Credentials API

The run stands in for the page and the browser, as for the EUDI and
Multipaz runs' DC API cases: it creates the request for the page's
origin (`https://shop.eudiplo.test`, `expected_origin`), hands the
wallet what `navigator.credentials.get()` hands the platform
(`{protocol, data, origin}`, the walt.id wallet's `-dcapi`,
[`dcapi.go`](../waltid/scripts/wallet/dcapi.go):
`walletflow.StartDCAPIPresentation` for `openid4vp-v1-signed`,
`StartMdocPresentation` for `org-iso-mdoc`), and posts what the wallet
hands back to EUDIPLO's `response_uri`, as EUDIPLO's documentation has
the page do: for OpenID4VP the request object from the session
(`requestObject`) as `data.request`, the wallet's data posted
unchanged; for Annex C EUDIPLO's `device_request` and
`encryption_info` as `deviceRequest` and `encryptionInfo`, the
wallet's `EncryptedResponse` posted as `{"data": …}`. The wallet
recognizes the Annex C reader under the run's CA, its revocation
unchecked.

## What EUDIPLO sends

| From | What | Seen with 10.1.0 |
|---|---|---|
| Verifier | response encryption JWK (OpenID4VP 1.0 §8.3 requires `alg`) | one key, `alg` `ECDH-ES`, a `kid`, `use` `enc` |
| Verifier | `trusted_authorities` | its `etsi_tl` reference replaced with `aki`: the key identifiers of the listed issuance certificates (here both CAs) |
| Issuer | status list token `iss` | EUDIPLO's `PUBLIC_URL`, not the tenant's credential issuer identifier the SD-JWT VC names (`…/issuers/{tenant}`): it signs its lists as a Status Issuer, which a wallet that binds a list to the credential's issuer has to be told of |
| Issuer | `credential_request_encryption`, `credential_response_encryption` | always offered, `encryption_required` only when the tenant sets it; walletflow encrypts whenever it is offered |

None is a deviation: Token Status List draft-14 lets another entity
than the issuer sign the list, and `walletflow` refuses one it wasn't
told of (the control above).

## EUDIPLO's deviations

Found by these runs; not reported upstream.

1. **A revoked mdoc is refused as `trust_list_unavailable`.** EUDIPLO
   refuses an mdoc whose status list entry is INVALID, as it should,
   but its session's `failureCode` is `trust_list_unavailable` and its
   `errorReason` "The trusted list could not be loaded, so the
   credential could not be validated.", which tells a relying party
   its trust list is down rather than that the credential is revoked;
   only the session log names the status (`Verifying the status list
   … failed: Status for id '…' is not Valid (0), but is instead '1'`).
   A revoked SD-JWT VC isn't classified (`failureCode` absent) and its
   `errorReason` names the status. The run asserts both as 10.1.0
   answers, so that a change is noticed.
2. **Its PAR refuses parameters it doesn't know.** The built-in
   authorization server validates a pushed authorization request
   against a closed schema (`.strict()`): an unknown parameter is
   refused, `400`, `Validation failed`, `Unrecognized key: "nonce"`,
   where RFC 6749 §3.1 has the authorization server ignore request
   parameters it doesn't recognize, and a pushed authorization request
   carries the authorization request's parameters (RFC 9126 §2.1). `fapigo`'s client, under walletflow,
   always sends OpenID Connect's `nonce`, so the authorization code
   flow stops at PAR. The run notes it, and fails once it changes.
3. **A key-attested `jwt` proof naming its key by index isn't
   verified.** A `jwt` proof carrying a Key Attestation may name its
   key by its index in `attested_keys` (`kid` `0`, walletflow's
   default; ETSI TS 119 472-3 asks for it, OpenID4VCI 1.0 Appendix F.1
   allows it); EUDIPLO answers `invalid_proof`, `Error verifying credential
   request proof jwt`, as Credo, on the same library, does (its finding
   7). Naming it in `jwk` (`-proof-key-by-jwk`) is accepted. The run
   notes it, and fails once it changes.

## What isn't covered

- EUDIPLO's Verifier against OID4VCgo's other wallet engine
  (`wallet`, `cmd/conformance-wallet-vp`), and EUDIPLO's issuer against
  `cmd/conformance-wallet`: later directions.
- EUDIPLO's issuer: the authorization code flow, PAR, PKCE and its
  refresh tokens (finding 2; its built-in server needs no login, so
  `-redirect-uri` would follow it headlessly); the `chained`, `oid4vp`
  and `external` authorization servers (a login at an OpenID provider,
  a presentation); deferred issuance (an attribute provider that
  defers); signed issuer metadata; a plain Credential Request refused
  by the encrypting tenant (walletflow always encrypts what's offered);
  a proof with a stale or another `nonce` (the request is encrypted to
  EUDIPLO, so the transport can't change it); a revoked Key Attestation
  apart from its Wallet Attestation (the provider revokes an instance,
  both with it); TS3 1.5 `client_status` and `key_storage_status`,
  which OID4VCgo's provider doesn't issue; a suspension (1-bit lists).
- The wallet at production assurance. The walt.id wallet's production
  mode is the walt.id run's (its leaf policies name walt.id's
  certificates, and it requires CRLs, which OID4VCgo's issuer's CAs
  don't publish); walletflow at production assurance presenting
  credentials OID4VCgo's issuer issued is the EUDI run's
  `verifier-production` job.
- The same-device flow and `request_uri_method=post`: EUDIPLO's
  `uri` (`request_uri_method=get`, then a redirect) isn't followed;
  the cross-device link it gives is answered.
- `x509_san_dns`, transaction data, OpenID Federation, a suspension
  (the issuer's list takes 1 bit), and negative mdoc presentations
  (the transport changes SD-JWT VCs only).
- An unsigned request: EUDIPLO signs every request.

## Running it

Docker, Go, jq, curl and openssl (the image is `linux/amd64`; on Apple
silicon it runs emulated):

```sh
interop/eudiplo/run.sh
EUDIPLO_TAG=latest interop/eudiplo/run.sh
```

`BASE_PORT` (21700) moves the listeners (it and the next nine),
`COMPOSE_PROJECT_NAME` names EUDIPLO's container, and `WORK` keeps the
run's files: each case's wallet outcome (`*-wallet.json`), EUDIPLO's
session (`*-session.json`), a Verifier case's session log
(`*-session-log.json`), an issuer case's offer (`*-offer.json`), and
the parties' logs. On Linux the tap listens on the Docker bridge's gateway,
which EUDIPLO's container reaches as `eudiplo.test`.

## Moving the pin

`run.sh` pins the image by digest, its tag in a comment. To move it,
read the release's notes and EUDIPLO's upgrade guide
(`apps/docs/docs/upgrade/`), especially changes to the config folder's
documents (`scripts/setup` writes their `$schema` versions), the
verifier's session outcome and failure codes, trust lists and status
checks, the issuer's offers, authorization servers, wallet and key
attestation checks and status lists; run `EUDIPLO_TAG=<tag> interop/eudiplo/run.sh`; then take the
digest (`docker inspect -f '{{index .RepoDigests 0}}'
ghcr.io/eudiplo/eudiplo:<tag>`) and update `EUDIPLO_IMAGE` and its
comment, and the versions above. The weekly run tests the `latest`
tag, to show a break before the pin moves.
