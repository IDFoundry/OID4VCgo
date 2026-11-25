# EUDIPLO interop

Interop with [EUDIPLO](https://github.com/openwallet-foundation-labs/eudiplo),
the OpenWallet Foundation Labs' Credential Issuer and Verifier
middleware (TypeScript, NestJS; no wallet), run from its published image
(`ghcr.io/eudiplo/eudiplo`). [`run.sh`](run.sh) runs every case against
it, from [`.github/workflows/eudiplo-interop.yml`](../../.github/workflows/eudiplo-interop.yml).
One direction so far: EUDIPLO's Verifier, presented to by OID4VCgo's
wallet.

EUDIPLO isn't a fully independent implementation of the protocols:
it builds on the same TypeScript libraries as Credo
([`../credo`](../credo/README.md)), `@openid4vc/openid4vp` and
`@openid4vc/oauth2` (10.1.0 pins 0.10.0 of each; Credo 0.7.4, 0.6.0),
`@sd-jwt/*` (0.25.0; Credo, 0.21.1) and `@owf/mdoc` (0.10.0; Credo,
0.8.3). So some of its refusals are those libraries' (its Key Binding
JWT `nonce` refusal reads `Verify Error: Invalid Nonce`, as Credo's
does), and a gap in them would show in both runs. What is EUDIPLO's
own is around them: its trust lists, its status checks, its sessions,
its Digital Credentials API and Annex C endpoints.

EUDIPLO 10.1.0 implements OpenID4VP 1.0 (final), as its
[protocol reference](https://docs.eudiplo.dev/reference/protocols)
says, and as what it sends shows: `client_id` prefixes (`x509_hash:`),
`dcql_query`, `client_metadata.vp_formats_supported` with 1.0's member
names (`sd-jwt_alg_values`, `kb-jwt_alg_values`, `issuerauth_alg_values`,
`deviceauth_alg_values`), `encrypted_response_enc_values_supported`,
`aud` `https://self-issued.me/v2`, `response_mode` `direct_post.jwt`
and `dc_api.jwt`, `expected_origins` in a DC API request; and
`walletflow`, which takes 1.0 alone, answers each. Of the other
specifications, it names the SD-JWT VC and Token Status List drafts
without a version, and ISO/IEC TS 18013-7 Annex C.

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

Neither is a deviation.

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

## What isn't covered

- EUDIPLO's issuer, and EUDIPLO's Verifier against OID4VCgo's other
  wallet engine (`wallet`, `cmd/conformance-wallet-vp`): later
  directions.
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

`BASE_PORT` (21700) moves the listeners (it and the next six),
`COMPOSE_PROJECT_NAME` names EUDIPLO's container, and `WORK` keeps the
run's files: each case's wallet outcome (`*-wallet.json`), EUDIPLO's
session (`*-session.json`) and its log (`*-session-log.json`), and the
parties' logs. On Linux the tap listens on the Docker bridge's gateway,
which EUDIPLO's container reaches as `eudiplo.test`.

## Moving the pin

`run.sh` pins the image by digest, its tag in a comment. To move it,
read the release's notes and EUDIPLO's upgrade guide
(`apps/docs/docs/upgrade/`), especially changes to the config folder's
documents (`scripts/setup` writes their `$schema` versions), the
verifier's session outcome and failure codes, trust lists and status
checks; run `EUDIPLO_TAG=<tag> interop/eudiplo/run.sh`; then take the
digest (`docker inspect -f '{{index .RepoDigests 0}}'
ghcr.io/eudiplo/eudiplo:<tag>`) and update `EUDIPLO_IMAGE` and its
comment, and the versions above. The weekly run tests the `latest`
tag, to show a break before the pin moves.
