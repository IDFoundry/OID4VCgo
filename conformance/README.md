# Conformance

OIDF live-conformance-suite harnesses for OID4VCgo's own roles,
mirroring FAPIgo's own `conformance/` structure (binaries wiring the
real production package behind real HTTP, Docker attaching to the
suite's own network, `oidf-config/` per test plan, a generator script
producing throwaway key material rather than committing any). All four
roles below are now driven live. For the W3C Digital Credentials API
(`dc_api.jwt`) module lists, the Wallet-VP driver stands in for the
browser (see `wallet-vp/README.md`'s "dc_api.jwt"): that checks the
wallet's protocol handling against the suite, but no real browser or
platform hand-off. The OID4VCI Wallet role's `issuer_initiated_dc_api`
and the Verifier's `dc_api.jwt` lists aren't driven.

Conformance testing is tracked separately per role — passing one role's
plan says nothing about another's, even where both sides share this
repo's own JOSE/DCQL code, because the protocol behaviour and
negative-test expectations differ.

## OIDF Certification

**OpenID Certified™** by Oscar Sanderson (Implementer) that OID4VCgo
0.12.0 (Deployment) conforms to the profiles below. This is official
[OpenID Foundation certification](https://openid.net/certification/),
submitted to and published by OIDF, not merely a self-run pass against
the live conformance suite. As with any conformance certification, it
is a statement of tested conformance for the listed deployment
version, not an OIDF endorsement of OID4VCgo generally, and it doesn't
automatically extend to a later release without its own renewed
submission (OpenID Certification Terms and Conditions §4(a)).

| Certification | Role | Profiles certified | Listing |
| --- | --- | --- | --- |
| OID4VCI 1.0 + HAIP 1.0 | Issuer | sd_jwt_vc × {issuer_initiated, wallet_initiated}; mdoc × {issuer_initiated, wallet_initiated} | [openid.net](https://openid.net/certification/certified-oid4vci-haip-final/) |
| OID4VCI 1.0 + HAIP 1.0 | Wallet | sd_jwt_vc × {wallet_initiated, issuer_initiated by_value, issuer_initiated by_reference}; mdoc × the same three | [openid.net](https://openid.net/certification/certified-oid4vci-haip-final/) |
| OID4VP 1.0 + HAIP 1.0 | Verifier | sd_jwt_vc direct_post.jwt; iso_mdl direct_post.jwt | [openid.net](https://openid.net/certification/certified-oid4vp-haip-final/) |
| OID4VP 1.0 + HAIP 1.0 | Wallet | sd_jwt_vc direct_post.jwt; iso_mdl direct_post.jwt | [openid.net](https://openid.net/certification/certified-oid4vp-haip-final/) |

Each listing links the signed test results for every certified profile.
The DC API (`dc_api.jwt`) variants are not certified. The Wallet's
are run against the local suite with a scripted browser stand-in (see
above), which certification would not cover.

Later releases are checked against the same test plans by the
[OID4VCI](../.github/workflows/oid4vci-conformance.yml) and
[OID4VP](../.github/workflows/oid4vp-conformance.yml) conformance
workflows, which run daily and on demand. Those runs, and the per-role
write-ups below, are the self-run work that produced the evidence for
these certifications, not a substitute for them.

The certified binaries run at development assurance:
`cmd/conformance-issuer` builds its `issuer` and FAPIgo `server` with
`AssuranceDevelopment`, `cmd/conformance-verifier` its `verifier`, and
`cmd/conformance-wallet` its `wallet` and FAPIgo `client`;
`cmd/conformance-wallet-vp` fetches each Request Object through a
`wallet.Wallet` at `AssuranceDevelopment`.

Uncertified runs cover the issuer's production setup: the daily
OID4VCI workflow's four "Issuer production" legs run
`cmd/conformance-issuer` with its `production` configuration (built
with the `conformance_production` tag), its `issuer` and FAPIgo
`server` under `AssuranceProduction` with sealed SQLite stores
(`sqlstore`, `fapigo/sqlstore`), an access token key loaded from its
configuration, audit sinks, and Wallet Attestation and key attestation
status checks, taking only `jwt` proofs carrying a key attestation in
their `key_attestation` header (`haip.RecommendedIssuerConfig`), with
no `attestation` proof type, and trusting key attestations by their
`x5c` chain (`issuer.X5CAttestationVerifier`). They drive every
entry of the HAIP issuer plan's module list — its 61 modules,
`happy-flow` and `fail-unknown-credential-configuration` under both
plain and encrypted credential requests, 63 runs — wallet- and
issuer-initiated, and its 21 OID4VCI-specific modules (23 runs) under
`mdoc` and under deferred issuance; see `issuer/README.md`'s
"Production setup" for the verdicts and where they differ from the
development runs. Every issuer run, development and production,
requires DPoP nonces at PAR, the token endpoint and the Credential
Endpoint, and trusts key attestations by their `x5c` chain. What
production assurance adds, or a deployment uses instead, the OIDF
runs still don't exercise, in particular:

- The wallet roles under production assurance: `cmd/conformance-wallet`
  and `cmd/conformance-wallet-vp` run only at development here (the
  interop runs drive the wallet at production: "OID4VCgo's wallet at
  production assurance", below). The
  Verifier's does run under production, through `verifier.Transactions`:
  the daily OID4VP workflow's "Verifier transactions" legs serve the
  Verifier plan's whole module list for both formats with
  `cmd/conformance-verifier`'s transactions engine, over a sealed
  SQLite store (`verifier/README.md`'s "Transactions engine").
- The issuer's production setup beyond its single-instance SQLite
  stores: PostgreSQL, several instances sharing them
  (`DeploymentHorizontallyScaled`), and certificate revocation checks
  on the signers of the status lists Wallet Attestations' and key
  attestations' `status` claims name, which it declines
  (`certrevocation.NoCheck`). The suite's attestations carry no
  `status` claim, so the status checks are configured but never fetch
  a list. (The attestation signers' own certificates are checked
  against CRLs: see "Certificate revocation" below.)
- A credential the issuer has revoked. Every issuer run, development
  and production, gives each credential it issues its own entry in the
  issuer's Token Status List (`status_lists`: `statuslist.Allocator`
  and `Publisher`, the reservations in `sqlstore` under production),
  and the suite fetches and checks the list for every one: an SD-JWT
  VC's JWT, its `x5c` chain to `status_list_trust_anchor_pem`, an
  mdoc's CWT, its `x5chain` to the IACA and its signer against ISO/IEC
  18013-5 Table B.9, and the entry VALID (`issuer/README.md`'s
  "Credential status"). No module has the issuer revoke or suspend a
  credential, so the suite never reads a status but VALID. The EUDI
  verifier, walt.id and Multipaz interop runs below do: a credential
  revoked partway through is refused (or read INVALID) by the other
  side's own status check.
- Certificate revocation where the suite's own CA issues the
  certificate: its per-run mdoc IACA (the Verifier's and the Wallet's
  `mso_mdoc` runs) publishes no CRL a binary could fetch, so those
  Document Signers aren't checked. See "Certificate revocation".
- Refresh tokens: under the VCI plans the suite takes the scope from
  the credential configuration's single scope-token and never asks for
  `offline_access`, and `fapigo/server` grants no scope that wasn't
  requested, so it issues no refresh token and the suite skips
  `fapi2-security-profile-final-refresh-token`; `cmd/conformance-wallet`
  never refreshes either.
- What `verifier.Transactions` does beyond those legs: narrowing the
  Request Object to a posted `wallet_metadata` (the suite's
  `request_uri_method=post` fetch carries only a `wallet_nonce`; the
  EUDI interop run posts one), the cross-device flow (the legs begin
  same-device requests), its Digital Credentials API requests (`BeginDCAPI`, `BeginMdocDCAPI`; the suite
  runs drive no `dc_api.jwt` Verifier list), PostgreSQL and several
  instances sharing a store, and `TransactionsConfig.Status`'s own
  production check of the status list fetch: the suite serves its
  lists from a private Docker address, so the legs run the same status
  policy as the `Accept`.
- `walletflow`: the suite drives `wallet` through
  `cmd/conformance-wallet` and `cmd/conformance-wallet-vp`, never
  `walletflow`, which the interop runs and the mobile libraries use.
- Fetching a Request Object entirely as a production wallet does:
  `cmd/conformance-wallet-vp` fetches `request_uri` through
  `wallet.Wallet.FetchAuthorizationRequest` (and
  `FetchAuthorizationRequestPost`), verifying the suite's TLS
  certificate, which `run-modules` pins, but over its own HTTP client,
  which reaches the suite on its private Docker address where
  `wallet`'s hardened one refuses it.
- Authorization errors shown on the Authorization Server's own page
  are checked only as far as the suite's `REVIEW` verdict goes: under
  the issuer's production setup the modules that end on that page wait
  for a screenshot of it, which the scripts don't upload, so no one
  checks what the page says. At development `cmd/conformance-issuer`
  redirects them to a registered redirect URI, which production
  refuses.

## Certificate revocation

Wherever the certificate OID4VCgo checks is issued by a CA the harness
makes, the runs check it against that CA's CRL as a deployment would:
the CA (`internal/conformancecrl.Authority`) names an https CRL
distribution point in every certificate it issues and publishes a
signed CRL there (`conformancecrl.Publisher`), and the binary under
test fetches it back over the network with a
`certrevocation.Refresher` (`conformancecrl.Trust`): https only, each
distribution point bound to its CA, a revoked certificate refused with
`certrevocation.ErrRevoked` and one whose CA has no current CRL with
`ErrNoCurrentCRL`. Two things differ from production: the distribution
points are on the Docker network or loopback, which the fetcher may
dial for those hosts alone, and their TLS certificate is pinned rather
than chained to the system roots. The publisher runs in the binary's
own process or container, serving lists the driver signed with the CA's
key; nothing in the check is short-circuited.

Each run with CRL checks also has negative controls, graded by their
reason: a certificate its CA's CRL revokes, and one from a CA whose
distribution point serves only a CRL past its `nextUpdate`. A refusal
for any other reason fails the control.

| Run | Checked against CRLs | Controls, and the reason each must give |
| --- | --- | --- |
| Issuer, every leg (development and production) | Wallet Attestation signers (`server.ClientCertificateCRLs` on `X5CAttesterChain`), key attestation signers (`issuer.X5CAttestationVerifier`) | the plain `happy-flow` with a revoked attester certificate: PAR answered `invalid_client` "attester certificate is revoked"; with an attester CA without a current CRL: `server_error` "failed to check the attester certificate's revocation status" — read from the module's log of the PAR response, reported `CONTROL=REFUSED` |
| Wallet (OID4VCI), every leg | the SD-JWT VC issuer's and its Token Status List signer's certificates (`VerifyIssuedCredentialParams.IssuerRevocation`, `statuslist.VerifyOptions.Revocation`) | wallet-initiated `sd_jwt_vc` legs: the credential issuance module with a revoked issuer certificate, and one from a CA without a current CRL: the wallet refuses the credential, `errors.Is` `ErrRevoked` / `ErrNoCurrentCRL` |
| Verifier `sd_jwt_vc`, both engines (`verifier.Transactions` under production) | the credential issuer's and the status list signer's certificates (`X5CIssuerKeyResolver.Revocation`, `statuslist.VerifyOptions.Revocation`) | `happy-flow` with a revoked issuer certificate, and one from a CA without a current CRL: the result page's `reason: untrusted_issuer` and `certrevocation: certificate is revoked` / `no current CRL from the certificate's issuer` |
| Wallet-VP, all four legs | the Verifier's Request Object certificate (`X5CVerifierRoots.Revocation`) | `direct_post.jwt` legs: `happy-flow` with a revoked Verifier certificate, and one from a CA without a current CRL: the wallet refuses before answering, `untrusted verifier: … certrevocation: certificate is revoked` / `… no current CRL from the certificate's issuer` |

Not checked, and why:

- The suite's own certificates: the per-run mdoc IACA and Document
  Signers in the Verifier's and the Wallet's `mso_mdoc` runs (and the
  CWT status list signers under it) publish no CRL. Those runs keep
  `certrevocation.NoCheck` (the Verifier) or no check (the Wallet).
- The Issuer's key attestation controls: its `invalid_proof` response
  says only "attestation 0: verification failed", by design, so a
  refusal can't be graded by its reason from the suite's log. Key
  attestation certificates are still checked against their CA's CRL in
  every leg.
- The production issuer's attestation status list signers (above):
  no list is ever fetched.

The interop runs that check revocation are listed in their own
sections below.

## OID4VCgo's side in the interop runs

In the interop runs below, OID4VCgo's issuers, verifiers and Wallet
Provider run as a deployment runs them wherever the other side can
meet them there: production assurance, durable stores (`sqlstore` and
`fapigo/sqlstore`, sealed, in a SQLite file), `verifier.Transactions`
rather than the binary's session engine, and OID4VCgo's
`walletprovider.Provider` ([`interop/walletprovider`](../interop/walletprovider),
over its v1 protocol; only the platform evidence is a stand-in,
`walletprovidertest.FakeVerifier`) where a Go or Kotlin wallet of the
run's takes Wallet Attestations. The binaries are built with the
`conformance_production` tag ([`interop/production.sh`](../interop/production.sh)).
What stays at development, and why, is beside each case in its README.
The wallets' own settings are those of their runs.

| Run | OID4VCgo's side as deployed | Still development, and why |
| --- | --- | --- |
| EUDI wallet library → verifier | SD-JWT VC and mdoc presentations and every verifier-side control: `verifier.Transactions`, `AssuranceProduction`, sealed SQLite | the `request_uri_method` choices, the Digital Credentials API and the default engine's own controls: the binary's transactions engine asks for `post` and routes no DC API |
| EUDI wallet library ← issuer | the `production` profile: `AssuranceProduction` for the Authorization Server and the Credential Issuer, sealed SQLite, DPoP nonces, every attestation from the Wallet Provider through its agent, its revocation refused; the `production-scaled` profile: the same as two instances sharing PostgreSQL, split between them | the other profiles: `attestation` proofs and `jwt` proofs without a key attestation, which production doesn't take |
| OID4VCgo's wallet ← EUDI PID Issuer | — | the Wallet Provider: the EUDI stack requires TS3 claims (`client_status`, `key_storage_status`, ...) `walletprovider` doesn't issue |
| OID4VCgo's issuer → OID4VCgo's wallet → EUDI verifier | the issuer's production setup, its status lists in `sqlstore`, revoked through its `POST /status`; the wallet attested by the Wallet Provider, its credentials in `sqlstore` | the fixtures (`scripts/setup`, `scripts/serve`) for what the issued credentials don't cover: the default engine, the `openid4vp` profile, the DC API, `x509_san_dns`, `vct#integrity`, a suspension, and the wallet's own refusals |
| walt.id Wallet2 → verifier | the PID and mDL presentations and the untrusted-issuer control: `verifier.Transactions`, `AssuranceProduction`, sealed SQLite; the PID's verifier as two instances sharing PostgreSQL, split between them | the `request_uri_method` choices (the default engine) |
| walt.id: issuer → OID4VCgo's wallet → Verifier2 | the issuer's production setup, its status lists in `sqlstore`; the wallet attested by the Wallet Provider | — |
| walt.id Wallet2 ← issuer | — | Wallet2 adds no key attestation, which production requires; its attester protocol isn't `walletprovider`'s |
| Multipaz: walletflow ← Multipaz issuer | the Wallet Provider, trusted and untrusted | — |
| Multipaz wallet → verifier, ← issuer | — | cross-device and DC API presentations, which the binary's transactions engine doesn't route; `attestation` proofs with a bare-key key attestation, which production doesn't take |
| Polaris | — | OID4VCgo's side is the wallet alone |

Status list fetches stay able to reach loopback in every run
(`status_list_allow_loopback`, and the production issuer's
`attestation_status_allow_loopback`): a production fetcher dials
public addresses only, which a runner has none of to serve from, so
the binaries run the same status policy where production can't inspect
its fetcher (the verifier's `Accept`, the issuer's wrapped key
attestation check) and log that they do.

### PostgreSQL, and two instances sharing it

Two legs run OID4VCgo's side on PostgreSQL (`sqlstore.Postgres` and
`fapigo/sqlstore`'s, the `production.database_url` setting; a
`postgres:17-alpine` service container pinned by digest in CI) as two
instances of one deployment behind one URL:
[`interop/splitproxy`](../interop/splitproxy), standing in for the load
balancer, terminates TLS with the server's own certificate and sends
each request to the instance its route names, so that what one
instance issues the other must accept. Each instance migrates the
schema as it starts and sweeps the stores every second (`Sweep`, from
every instance, as [DEPLOYING.md](../DEPLOYING.md) has a deployment
do), and the run fails if either never swept or a sweep failed.

- The EUDI wallet library ← issuer's `production-scaled` profile
  (`interop/eudi/run-issuer.sh`, with `POSTGRES_URL`): the
  `production` profile's cases and controls, the Authorization Server
  under `server.DeploymentHorizontallyScaled` (so its stores and keys
  must declare `CrossInstanceConsistent`), the c_nonce key shared.
  PAR, the Token, Nonce and Notification Endpoints are instance a's,
  the consent and the Credential Endpoint b's, and a request whose
  DPoP proof carries no nonce goes to the other instance, which
  challenges it: so a's request_uri is used at b, b's codes are
  redeemed at a, a's access tokens, c_nonces and DPoP nonces are taken
  by b, b's DPoP nonces by a. Two cases of its own send a request to
  the instance its route doesn't name, and the issuer issues a Token
  Status List whose indices both reserve in the shared store.
- walt.id Wallet2 → verifier (`interop/waltid/run.sh`, with
  `POSTGRES_URL`): the PID's transactions verifier, its request begun
  at a, its Request Object fetched at b, the response taken by a and
  its `response_code` redeemed at b.

The split is proven from each side: every response carries the
instance that served it (`X-Interop-Instance`), which the EUDI driver
records and checks each exchange of each case against; the proxy logs
each request with its instance and why it went there; and the
instances' own logs show what each served (their audit events, a
transaction begun, fetched, redeemed). The controls of their own are
graded by the refusing instance's reason: a pre-authorized code minted
by b and redeemed at a, redeemed again at b (400 `invalid_grant`,
"pre-authorized_code is unknown or already used"), and a
`response_code` minted by a and redeemed at b, redeemed again at a
(refused, a logging `verifier: unknown presentation request`). The
Wallet Provider stays one instance on SQLite.

## Interop with polaris-oid4vp

Besides the OIDF suite, `.github/workflows/polaris-interop.yml` runs
`cmd/conformance-wallet-vp` against [polaris-oid4vp](https://github.com/EgorKhaklin/polaris-id),
an independent OpenID4VP 1.0 + HAIP verifier, using its author's script
(`lab/interop/oid4vcgo/run.sh`, Apache-2.0, thanks to Egor Khaklin): the
presentation must be accepted, and four controls refused — a replayed
request, a `client_id` that isn't the signed request's, an issuer CA the
verifier doesn't trust, and a verifier CA the wallet doesn't trust. The
OIDF suite has no negative wallet-side cases like those. The script's
wallet config sets no `verifier_tls_trust_anchors_pem`, so the wallet
there doesn't verify the verifier's TLS certificate (it says so at
startup): these cases test the request object's signature and chain,
not TLS. Nor does it set `verifier_crl`: the Verifier's certificate
isn't checked for revocation there, its CA being the script's own.

It runs on each pull request (outside `mobile/`), with the wallet built
from the pull request's checkout, so a regression shows before it's
released; daily, against the newest release; on each release, against
that release's tag (not sqlstore's); and by hand. polaris-id is pinned
to a reviewed commit (polaris-oid4vp v1.0.0), since its verifier runs
from source on the runner (a read-only token, no secrets). Move the pin
only after reading the change. The weekly run tests polaris-id's `main`
instead, unreviewed, to show a break before the pin moves, and opens an
`interop-polaris-latest` issue when it fails. A run takes about a
minute.

## Interop with the EUDI reference verifier

`.github/workflows/eudi-interop.yml` runs `cmd/conformance-wallet-vp`
against the EUDI Wallet reference implementation's
[Verifier Endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint),
from its published image pinned by digest, configured as strictly as it
allows: SD-JWT VC and mdoc presentations under its `haip` and
`openid4vp` profiles and over the DC API, with the SD-JWT VC's Type
Metadata checked and each credential's status list entry read, and an
SD-JWT VC presentation to the verifier configured with an
`x509_san_dns` client_id, to a wallet opted in to that prefix, must be
accepted, and controls (credentials revoked or suspended partway
through the run, a mismatched `vct#integrity`, untrusted CAs on either
side, a replayed request, a mismatched `client_id`, an unheld
credential) refused (`interop/eudi/run-verifier.sh`). The status lists
are published by OID4VCgo's `statuslist` (an `Allocator` and a
`Publisher`, as an issuer publishes them). walletflow's presentations
of both formats present what OID4VCgo's side issued, as deployed:
`cmd/conformance-issuer` in its production setup issues them over
OID4VCI to `walletflow`, attested by the Wallet Provider, which stores
them in `sqlstore` and presents them from there in later launches; the
issuer then revokes each, which the verifier, having accepted it, then
refuses for its status (`StatusNotValid`, `DocumentHasBeenRevoked`).
The verifier never verifies a Status List Token's signature, so the
run shows it reads the entry and refuses a revoked credential, not that
it would refuse a forged list.
The wallet checks the verifier's Access Certificate against its CA's
CRL, fetched over https from the distribution point it names, and
refuses it, for that reason, when the CA revokes it or publishes no
current CRL.
See
[`interop/eudi/README.md`](../interop/eudi/README.md) for the cases,
what the verifier doesn't check, and moving the pin.

The same workflow runs three more directions. The EUDI wallet library
for presentation,
[eudi-lib-jvm-openid4vp-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt),
presents SD-JWT VC and mdoc PIDs to `cmd/conformance-verifier`, over
the redirect flow and the DC API, from a pinned JVM driver, the
redirect flow and the verifier's controls through `verifier.Transactions`
under production assurance, with `request_uri_method=post`
(`interop/eudi/run-wallet.sh`). The EUDI wallet library for issuance,
[eudi-lib-jvm-openid4vci-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt),
obtains credentials from `cmd/conformance-issuer`: both formats, by the
pre-authorized code and the authorization code flows, with every proof
type, batches, encryption, signed metadata, deferral, notifications
and DPoP nonces, each credential verified on the wallet side, and
controls refused (`interop/eudi/run-issuer.sh`). And OID4VCgo's
`wallet` and `walletflow` obtain SD-JWT VC and mdoc PIDs from the EUDI
[PID Issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer),
run as its own pinned docker-compose stack (Keycloak with
attestation-based client authentication, the status list service),
verifying each credential, and the SD-JWT VC's status: the status list
service's CWT tokens don't verify, so the wallet refuses an mdoc's
status list and its revocation isn't shown
(`interop/eudi/run-pid-issuer.sh`). There the wallet checks every
issuer certificate (the Document Signer's, the SD-JWT VC signer's, the
status list signer's and the metadata signer's) against its CA's CRL,
and refuses a credential, for that reason, whose signer the IACA
revoked or whose IACA publishes no current CRL. The other two
directions don't check revocation yet: the EUDI libraries present and
obtain credentials signed under the scripts' CAs with
`certrevocation.NoCheck` on OID4VCgo's side.
Their cases and each component's deviations from the specifications
are in the same README.

All four run on each pull request, daily and on each release against
their pins. The weekly run against EUDI's `latest` images covers only
the two image-based runs, the Verifier Endpoint and the PID Issuer;
the two wallet libraries are pinned exactly and run only with the
pinned runs.

## Interop with walt.id

`.github/workflows/waltid-interop.yml` runs OID4VCgo against walt.id's
Community Stack v2 (Issuer2, Verifier2 and Wallet2, from
[walt-id/waltid-identity](https://github.com/walt-id/waltid-identity)),
from its published images pinned by digest, in all four directions:
`walletflow` obtaining SD-JWT VC and mdoc credentials from Issuer2 and
presenting them to Verifier2 (a signed `x509_hash` request, the
response encrypted), and walt.id's Wallet obtaining PIDs from
`cmd/conformance-issuer` (HAIP, with a Wallet Attestation and DPoP) and
presenting them to `cmd/conformance-verifier`; controls (untrusted
issuers, Verifiers and attesters, an unsigned request, and
presentations to Verifier2 whose Key Binding JWT `nonce` or `aud`, or
a disclosure, was changed on the way) refused. Verifier2 also checks
the Token Status List of SD-JWT VC and mdoc PIDs `cmd/conformance-issuer`
issued (its `credential-status` policy, which fetches the issuer's
list, verifies its signature and reads the entry), and refuses one the
issuer revoked after issuing it. `walletflow` checks Issuer2's and
Verifier2's certificates against the run CA's CRL, and refuses a
credential whose signer the CA revoked or which it can't check (no
current CRL), and a Verifier whose Access Certificate it revoked, for
those reasons; it checks no revocation where it takes credentials from
`cmd/conformance-issuer`, nor do the walt.id-to-OID4VCgo directions.
Verifier2 accepts a PID
under a certificate nobody configured it with, a known gap the run
notes, failing if it changes. It runs
on each pull request, daily and on each release against the pinned
images, and weekly against walt.id's `latest` images. See
[`interop/waltid/README.md`](../interop/waltid/README.md) for the cases,
walt.id's deviations and other observations, and moving the pins.

## Interop with Multipaz

`.github/workflows/multipaz-interop.yml` runs OID4VCgo's mdoc readers
and holder against [Multipaz](https://github.com/openwallet-foundation/multipaz)'s,
from its published library pinned by version and checksum, each side in
each role: in person (ISO/IEC 18013-5: QR engagement, session
encryption, reader authentication, a device signature and deviceMac),
`walletflow` as holder and `proximity` as reader; and over the Digital
Credentials API (ISO/IEC TS 18013-7 Annex C, `org-iso-mdoc`),
`walletflow` as wallet and `mdocdcapi` as verifier; and OpenID4VP 1.0,
Multipaz's wallet presenting SD-JWT VC PIDs and mDLs to
`cmd/conformance-verifier` and `walletflow` presenting them to Multipaz's
Verifier, cross-device and over the Digital Credentials API; and
OpenID4VCI 1.0, Multipaz's wallet obtaining PIDs from
`cmd/conformance-issuer` and `walletflow` obtaining an mDL and PIDs from
Multipaz's issuer (Wallet Attestation, DPoP, Key Attestation proofs).
The messages pass whole between the two programs, with no radio.
Controls (untrusted readers, Verifiers, issuers and attesters, a
DeviceResponse over another session transcript, an answer for another
origin, a mismatched `x509_hash` client_id, and, to Multipaz's
Verifier, a Key Binding JWT naming another nonce and an mDL signed over
another session transcript) are refused. Multipaz's
`RevocationChecker` reads the Token Status List entries of the PID and
mDL `walletflow` presents to its Verifier, from lists OID4VCgo's
`statuslist` publishes, VALID, and INVALID once the issuer side has
revoked them. Multipaz's Verifier accepts a
Key Binding JWT naming another Verifier as `aud`, a known gap the run
notes, failing if it changes. No certificate's revocation is checked
in this run yet (`certrevocation.NoCheck` or none): Multipaz's IACA and
reader CA are made by the driver through Multipaz's own API, and the
certificates OID4VCgo issues for it name a distribution point nothing
serves. It runs on each pull request,
daily and on each release against the pinned release, and weekly
against Multipaz's newest release on Maven Central. See
[`interop/multipaz/README.md`](../interop/multipaz/README.md) for the
cases, Multipaz's deviations, and moving the pin.

## OID4VCgo's wallet at production assurance

The runs above drive OID4VCgo's wallet at development assurance,
which reaches loopback and private addresses and, for walletflow,
skips production's checks. Three runs drive it again at production
assurance, each in a job of its own (`WALLET_ASSURANCE=production`):
walletflow's `Development` false and its own HTTP client, or `wallet`
and `fapigo/client` at `AssuranceProduction` over `fapihttp.NewClient`'s;
sqlstore's durable stores where receiving credentials requires them
(`internal/prodwallet`); every certificate checked against its CA's
CRL; no trust relaxed. Production's clients never dial loopback, and
reach a private address only for a host named in
`walletflow.Config.AllowedPrivateHosts` (`wallet.Config.Fetch`'s and
`fapihttp.TransportConfig`'s for the core engine), so the wallet runs,
built for Linux, in a container on an internal Docker network, on a
private subnet Docker assigns, which the other side's containers join
under the names their URLs carry, and those names are the hosts it's
given to allow, as a deployment inside its own network names its
services; its system roots are the run's TLS CA, through
`SSL_CERT_FILE` ([`interop/prodnet.sh`](../interop/prodnet.sh)).
Those, and the CRL publishers on the wallet's own loopback, are all
that isn't production's defaults.

| Run (job) | At production assurance | Attestations |
| --- | --- | --- |
| EUDI PID Issuer (`eudi-interop.yml` `pid-issuer-production`) | walletflow and the core engine: PIDs in both formats, a batch, from the issuer's offer, a revocation read; controls: untrusted metadata, untrusted IACA, revoked signer, no current CRL, revoked Wallet Attestation | the run's stand-in Wallet Provider: the stack requires EUDI TS3 claims that `walletprovider` doesn't issue |
| EUDI Verifier Endpoint (`eudi-interop.yml` `verifier-production`) | walletflow: both formats issued by OID4VCgo's issuer's production setup, stored in sqlstore, presented by both `request_uri_method`s under `x509_hash`, then revoked by the issuer and refused by the verifier; `cmd/conformance-wallet-vp`'s walletflow engine: the fixture under `x509_san_dns`; controls: mismatched `client_id`, untrusted verifier CA, revoked Access Certificate, no current CRL, untrusted TLS certificate | OID4VCgo's Wallet Provider, for its issuer |
| walt.id Issuer2 and Verifier2 (`waltid-interop.yml` `production`) | walletflow: three credentials received, PID and mDL presented; controls: untrusted issuer CA, revoked signer, no current CRL, unsigned request, untrusted Verifier CA, revoked Access Certificate | none: Issuer2 asks for neither |

Each control is graded by its refusal's reason, as in development, and
no other side sends anything production's wallet refuses. Multipaz's
in-person and Annex C holder runs at production assurance in its own
run, fetching nothing; its OpenID4VP and OpenID4VCI wallets, which
fetch from servers the driver runs on loopback, and the OIDF Wallet
and Wallet-VP plans stay at development: the local suite is on
loopback, and its TLS certificate names no `subjectAltName`, which
production's verification requires (see
[`wallet-vp/README.md`](wallet-vp/README.md)). The Polaris run's
config is polaris-id's own script's, which sets no assurance.

## Keeping the local suite current

These binaries only genuinely mirror what `certification.openid.net`
(the hosted instance) checks if the local, self-hosted suite checkout
(a real clone of `gitlab.com/openid/conformance-suite`, run via Docker
Compose; the runs against it are `conformance/scripts/run-oid4vci.sh`
and `run-oid4vp.sh`, sharing `conformance/scripts/lib.sh`) stays
reasonably current. It doesn't update itself: at one point it was found 569
commits/two upstream releases stale, and that gap had silently masked
three real bugs in this repo (a Wallet-VP response-encryption-key
selection bug, a Wallet `issuer_state` threading gap, and non-compliant
mdoc signing certificates) that a from-scratch conformance run on a
current suite immediately surfaced. Before trusting a local "all
green" result as still meaningful, `docker pull` the suite's own images
and diff the current release tag's changelog
(`https://gitlab.com/openid/conformance-suite/-/tags`) against what's
running — an upgrade is worth doing periodically even without a
specific reason to suspect drift, not just when something seems off.

- **`verifier/`** — OID4VP 1.0 Final/HAIP Verifier role
  (`oid4vp-1final-verifier-haip-test-plan`): `cmd/conformance-verifier`
  stands up `verifier.Verifier` behind real HTTP; the suite plays
  Wallet. **Confirmed live against a real, locally-run OIDF suite**:
  `run-sdjwt-modules` (`sd_jwt_vc`) and `run-mdoc-module` (`iso_mdl`)
  drive every module the plan lists for their format, each graded
  against an expected verdict (`verifier/README.md`'s table): a
  presentation the Verifier must accept ends `FINISHED`/`REVIEW` (it
  answers `200`, and the suite waits for a screenshot of its result
  page, which the scripts fill) with the result page reporting it
  verified; one it must refuse is answered `400`, which the suite
  grades `FINISHED`/`PASSED` itself. The module's log must hold no
  `FAILURE` or unexpected `WARNING`, and a module the plan lists with
  no expected verdict fails the run. The harness checks every
  credential's status: the two revocation modules (a revoked Token
  Status List entry, and for `iso_mdl` an mdoc on its identifier list)
  must be refused, and an accepted module must have fetched its
  credential's status list, the suite's lists trusted by the same
  anchors as the credentials (`verifier/README.md`'s "Credential
  status"). Found and
  fixed three real gaps along the way:
  `internal/jwe`'s Concat KDF never incorporated the sender's
  `apu`/`apv` header members, silently deriving the wrong CEK against
  the suite's own `direct_post.jwt` responses (which always set both);
  this binary's own Request Object signing certificate was self-signed
  (the suite's `ValidateRequestObjectSignatureAgainstX5cHeader` check
  rejects that outright, and it was silently failing on every module
  without affecting the suite's own summary counts); and
  `verifier.BuildAuthorizationRequest` never set `client_metadata`'s
  own `vp_formats_supported`, a field OID4VP marks REQUIRED here. See
  `verifier/README.md`.
- **`wallet-vp/`** — OID4VP 1.0 Final/HAIP Wallet role, the
  direct_post.jwt module list and the three dc_api.jwt ones
  (`oid4vp-1final-wallet-haip-test-plan`; see `wallet-vp/README.md`'s
  "dc_api.jwt"):
  `cmd/conformance-wallet-vp` stands up `wallet`'s own presentation
  half behind real HTTP; the suite plays Verifier. Confirmed live end
  to end against `cmd/conformance-verifier` itself, and **every
  direct_post.jwt module is run live by `run-modules`**: every module
  the main plan lists, plus those only a second plan under a real
  `credential_type` lists (`eudi_pid` for `sd_jwt_vc`, `mdl` for
  `iso_mdl`: `all-mandatory-claims`, the PID claims-path modules,
  `age-over-18`), each graded on what the wallet did as well as the
  suite's verdict and log (`wallet-vp/README.md`'s "Expected
  verdicts"): a refusal can only end `REVIEW`, so a wallet that
  presents where it must refuse is caught by its own action. The DC API-only
  modules 404 for this variant and run under dc_api.jwt. Five real
  gaps found and fixed along the way: the
  same x5c-header/self-signed-leaf pair already found for
  `credential/sdjwtvc.Issue`, two request-object validation gaps this
  binary's own `requestobject.go` had — a request carrying
  `redirect_uri` alongside `response_uri`, or an unrecognized
  `transaction_data` type, was silently ignored and this binary POSTed
  its response anyway instead of refusing the request — and, later,
  genuine `request_uri_method=post` support (a fresh `wallet_nonce`
  sent over POST, and the fetched Request Object rejected outright if
  its own `wallet_nonce` claim doesn't echo it back). All fixed and
  re-confirmed live: the seven positive-behavior modules clean
  (`FINISHED`/`PASSED` or `WARNING`, zero `FAILURE`s — including
  `alternate-happy-flow`, whose own fragment-carrying `redirect_uri`
  is now relayed to the suite's own implicit-submission URL
  automatically, the exact wire shape pinned down by decompiling the
  suite's own `fapi-test-suite.jar` rather than guessed), and
  `run-modules` grades `all-mandatory-claims` the same way. Of the
  eight negative tests, five answer with an OID4VP error response
  whose exact code `run-modules` checks, and the suite
  grades them `PASSED`; three (`invalid-request-object-signature`,
  `mismatched-client-id`, `invalid-client-id-prefix`) are refused
  before `response_uri` is called and end `REVIEW` once the script
  fills the suite's screenshot placeholder. Its three `dc_api.jwt`
  module lists (unsigned, signed, multi-signed requests over the
  Digital Credentials API) are
  driven too, `run-modules` standing in for the browser: all 34
  modules of each credential format end as expected. See
  `wallet-vp/README.md`.
- **`issuer/`** — OID4VCI 1.0 Final/HAIP Issuer role
  (`oid4vci-1_0-issuer-haip-test-plan`): `cmd/conformance-issuer` pairs
  a real `fapigo/server.Server` (FAPI 2.0 Security Profile Final,
  Wallet Attestation client authentication) with a real
  `oid4vcgo/issuer.Issuer`; the suite plays Wallet. Confirmed live
  end to end in-repo (PAR → consent → token → nonce → credential),
  a permanent regression test that surfaced and fixed three real bugs.
  **Confirmed live against the real OIDF suite**: `metadata-test`
  is a full `PASSED` (fixed by serving this binary's AS metadata at
  both `/.well-known/openid-configuration` and RFC 8414's own
  `/.well-known/oauth-authorization-server` — entirely an
  OID4VCgo-side router fix, not FAPIgo's). `client2` support was added
  (`Config.Client2`, optional) and confirmed both by a real PAR-
  authentication unit test and live against the suite itself.
  `happy-flow` hit a `fapigo/server` design decision (`Config.Extensions`
  rejecting any parameter without a pre-registered `Definition`) that
  conflicted with the suite's own PAR-2.1–PAR-2.4 check — raised with
  FAPIgo's maintainers as a design question rather than filed as a
  plain bug; they agreed and fixed it upstream (`fix!: ignore
  unrecognized authorization request parameters at PAR/CIBA`, FAPIgo
  PR #304). `go.mod` pinned to the fix; re-run live:
  `happy-flow` now completes. That full run surfaced one more real gap
  (the same x5c requirement `wallet-vp/README.md` already documents,
  this time in `issuer.SDJWTSigner`), fixed the same way. **All 21
  OID4VCI-specific modules in the plan are now run live** (the other
  40 are the generic FAPI 2.0 Security Profile Final battery — see the
  later update below, which covers those). Two more real gaps found and fixed: this binary's TLS
  listener had no `MinVersion`/`CipherSuites` set, so Go's own TLS 1.3
  default suite (always including ChaCha20-Poly1305) tripped the
  suite's own FAPI-RW-8.5 cipher probe — fixed by wiring in
  `fapigo/server.FAPIRWTLSCipherSuites`, the exact configuration
  FAPIgo's own OpenID-Certified `cmd/conformance-as` already uses; and
  a genuine RFC 9901 §10.1 linkability issue — two credentials issued
  moments apart (`happy-flow-multiple-clients`, one per client) carried
  `exp` values differing by the real inter-issuance gap, a correlation
  side-channel — fixed by rounding `exp` to the start of the issuance
  day (`sdjwtvc.RoundedExp`). Both fixes apply
  everywhere `exp`/TLS are exercised, not just the module that caught
  them — re-confirmed live: every module that previously carried the
  `exp`-claim `WARNING` (`happy-flow` and its three siblings including
  `multiple-clients`, plus `fail-on-access-token-in-query`) is now
  `FINISHED`/`PASSED` with zero log entries at `WARNING` or worse.
  **Update: `metadata-test-signed` — real support added, not just made
  to pass.** Previously self-`SKIPPED` (HAIP §4.1 only conditions
  signed metadata on ecosystem policy, so it stayed genuinely
  optional); `credentialIssuerMetadataHandler` now does real content
  negotiation (OID4VCI §12.2.2/§12.2.3) — plain JSON by default,
  a signed compact JWS (`typ: "openidvci-issuer-metadata+jwt"`, every
  metadata parameter as a top-level claim, the same `x5c`/signing-key
  pair issued credentials use) when a request's `Accept` header asks
  for `application/jwt`. Confirmed live: `FINISHED`/`PASSED`, with the
  suite's own `VCIDecodeSignedCredentialIssuerMetadata` check
  independently verifying the JWS signature via its `x5c` header, not
  just the `Content-Type` header.
  **Update: `batch-issuance` — real support added, not just made to
  pass.** Previously self-`SKIPPED` (HAIP only requires *advertising*
  support, never a MUST to implement it); turned out
  `issuer.RequestCredential` already fully implements OID4VCI §3.3.2
  batch issuance — `cmd/conformance-issuer`'s own wiring just never
  opted in. `wiring.go` now sets `BatchCredentialIssuance` with a
  `batch_size` of 5. Confirmed live: `FINISHED`/`PASSED`, with the
  suite sending a real 5-proof batch and independently verifying
  distinct disclosure salts, distinct `cnf` binding keys each matching
  one of the sent proofs, and non-linkable time claims across all 5
  issued credentials — not just a metadata flag flip.
  **Update: `fail-unsupported-encryption-algorithm` — real support
  added, not just made to pass.** Previously self-`SKIPPED` (HAIP never
  references OID4VCI §10 encryption, so it stayed fully optional);
  turned out `issuer`'s own `DecryptRequestBody`/`EncryptResponseBody`
  already fully implement §10 — `wiring.go` now opts in
  (`A128GCM`/`A256GCM`, deliberately excluding `A192GCM` so
  "unsupported" stays real). Driving this live surfaced three more
  genuine, pre-existing gaps in the already-implemented `issuer`
  package, never exercised before this wiring made the code path
  reachable: `credential_request_encryption.jwks` was a bare array
  instead of a required JSON Web Key Set object; published keys had no
  `alg` member (§10 requires one); and `EncryptResponseBody` never
  validated a Wallet-declared `alg` mismatch in
  `credential_response_encryption.jwk`, silently encrypting anyway
  instead of rejecting it. Also fixed: every §10 failure used the
  generic `invalid_credential_request` code instead of §8.3.1.2's own
  dedicated `invalid_encryption_parameters`, which the suite
  specifically checks for. Confirmed live after all four fixes:
  `FINISHED`/`PASSED`, zero log entries at `WARNING` or worse, plus a
  genuine positive encrypt→issue→encrypt→decrypt round trip through
  the real HTTP binary (not just the library's own internals).
  **Final tally: all 21 OID4VCI-specific modules `FINISHED`/`PASSED`
  or correctly `SKIPPED`** — 10 of 10 applicable negative tests
  `PASSED`. (Key attestation's own `fail-invalid-key-attestation-signature`
  used to self-`SKIPPED` here too — a deliberate, spec-legitimate
  Issuer-role scope choice per HAIP §4.5.1's own
  conditional-on-ecosystem-policy language, not a gap, with the
  Wallet-side MUST already covered separately in
  `wallet/README.md`. **Update: now genuinely `PASSED`** — this
  binary additively advertises the `attestation` proof type alongside
  `jwt` and wires a real `AttestationVerifier`, closing the Issuer-side
  gap too; see the base-plan update below for the fix and live
  verification, since this module isn't in this battery's own default
  driven list.)
  **Update: the plan's own 5th module-list entry, the generic FAPI2SP
  battery, is driven too**, via a new tool
  (`conformance/issuer/scripts/run-fapi2sp-battery`). Its default
  module list (`haipBattery`) is now 60 modules: the exact 39+1
  battery+Discovery set, derived directly from the Java source, plus
  20 of the plan's 21 OID4VCI-specific modules (all but
  `fail-invalid-key-attestation-signature`, which has its own
  `-credential-proof-type-hint attestation` run). When this battery was
  first driven it was 42 modules (the 40 plus 2 sanity checks), and
  then 43 with `happy-flow-skip-notification`. Unlike the Wallet
  role, this role needs no custom flow-driving code at all — the suite
  itself plays client and drives PAR→authorize→consent→callback→token
  through its own internal headless browser, the same `browser`
  automation-config mechanism FAPIgo's own OpenID-Certified
  `cmd/conformance-as` already relies on. Surfaced and fixed real gaps:
  a missing `x5c` on the suite's own emulated Client Attestation
  signing key, a required `status_list_trust_anchor_pem` field (unused
  then; the suite now checks the issuer's status lists against it), and — the highest-value find — a universal, suite-side
  HtmlUnit/Bootstrap JS bug that leaves browser-driven modules
  `WAITING` forever with no timeout, needing the same
  `unblock-implicit-callback.py`-style workaround FAPIgo's own
  `cmd/conformance-as` already needs, now ported to Go. **Update:
  `attempt-reuse-authorization-code-after-one-second` is now a clean
  `PASSED`**, not a `WARNING` — `wiring.go` was wiring two separate
  in-memory revocation stores (one the AS writes to on detected code
  reuse, a different one the Credential Endpoint reads from) instead
  of sharing one, the same wiring bug FAPIgo's own `cmd/conformance-as`
  already found and fixed for the identical finding. **All 42 modules
  of that first battery `FINISHED` twice in a row for stability**:
  `PASSED` except one expected `SKIPPED` (`refresh-token`: no refresh
  token is issued without `offline_access`), and one expected `REVIEW`
  (a human-review negative test) — no `FAILURE`s; the daily run
  expects the same of the 60-module battery.
  **Runs**: the daily OID4VCI workflow (`run_issuer` in
  `conformance/scripts/lib.sh`) drives `run-fapi2sp-battery` ten
  times — `haipBattery` with no flags and with `-issuer-initiated`
  (the script sends each OID4VCI module's Credential Offer to the
  suite's `credential_offer_endpoint` itself), `vciBattery` (the
  plan's 21 OID4VCI-specific modules) with `-credential-format mdoc`
  with and without `-issuer-initiated`, with `-deferred`, and with
  both, and, against the production setup (`-production`),
  `productionBattery` (the plan's 61) wallet- and issuer-initiated
  and `vciBattery` under `mdoc` and under `-deferred`. The first four
  are the role's four certification profiles; see
  `issuer/README.md`'s "Runs".
  **Update: the suite's own base (non-HAIP) `oid4vci-1_0-issuer-test-plan`
  is driven too**, via `run-fapi2sp-battery -base-plan` — the same 21
  module classes already covered above (no FAPI2SP battery in this
  plan), just under `fapi_profile=vci` instead of `vci_haip`, with
  every axis the HAIP plan's own module list pins now supplied
  explicitly at plan-creation time instead. **Update: both of this
  plan's own two expected skips are now closed.**
  `fail-invalid-key-attestation-signature` is now genuinely `PASSED` —
  `wiring.go` wires a real `AttestationVerifier` and additively
  advertises the `attestation` proof type (OID4VCI Appendix F.3)
  alongside `jwt`; `issuer.resolveAttestationProofKeys` already fully
  implemented this, the binary just never opted in — same shape as the
  revocation-store fix above. `fail-unsupported-encryption-algorithm`
  is now genuinely `PASSED` too — a new
  `-credential-encryption=encrypted` flag drives
  `vci_credential_encryption=encrypted` so the module can actually run
  instead of self-skipping; doing so surfaced one more real,
  independent wiring gap: `internal/jwe`'s own `zip=DEF` (RFC 7516)
  compression support was never turned on (`ZipValuesSupported` was
  nil on both `RequestEncryption`/`ResponseEncryption`), so
  `happy-flow` under this variant failed rejecting a JWE compression
  parameter it fully supports — fixed the same way. All 21 base-plan
  modules `FINISHED`/`PASSED` under both the default `plain` and new
  `encrypted` variant, twice for stability each, no `FAILURE`s. A
  dedicated `-credential-proof-type-hint=attestation` invocation
  (`keyAttestationBattery`) also confirms a genuine, validly-signed Key
  Attestation JWT successfully issues a credential (`happy-flow`), not
  just that an invalid one is rejected.
  **Update: `mso_mdoc` credential format is driven too** — the first
  time either role in this repo has exercised mdoc against the real
  suite. `credential/mdoc`/`issuer.RequestCredential`'s own
  `MdocClaims`/`MdocSigner` dispatch were already fully implemented and
  unit-tested; `wiring.go` just never opted in. Added a second
  `CredentialConfiguration` from the same issuer identity (one issuer,
  two formats), confirmed via a new full-stack unit test
  (`TestFullFlow_MdocCredentialIssuance`, real CBOR/COSE/MSO
  verification via `credential/mdoc.Verify`) and live, twice for
  stability, via `run-fapi2sp-battery -credential-format mdoc` (the 2
  sanity-check modules; the other 40 battery modules don't exercise
  credential format at all). Full `sd_jwt_vc` battery re-confirmed
  regression-free. **Update: mdoc signing certificates are now
  ISO/IEC 18013-5 Annex B compliant** — a suite upgrade added
  certificate-profile checks the shared, generic issuer identity always
  failed (confirmed live as a `WARNING`, not yet a `FAILURE`). Fixed
  with a dedicated mdoc-only Document Signer/IACA root identity
  (`internal/conformancecert.GenerateMdocIACA`/
  `GenerateMdocDocumentSigner`, unit-tested against the suite's own
  decompiled checks), wired in as an optional fallback so the shared
  identity's existing behavior for `dc+sd-jwt` is untouched. Live-
  verified twice: both sanity modules `FINISHED`/`PASSED` with the
  certificate `WARNING` gone. See `issuer/README.md`.
- **`wallet/`** — OID4VCI 1.0 Final/HAIP Wallet role
  (`oid4vci-1_0-wallet-haip-test-plan`): `cmd/conformance-wallet`
  drives `oid4vcgo/wallet`/`fapigo/client` as an outbound HTTP client
  — the suite itself plays the entire emulated Authorization Server
  and Credential Issuer for this role, the opposite shape from
  `issuer/`. **Confirmed live against a real, locally-run OIDF suite,
  all 22 module instances this binary drives `FINISHED`/`PASSED`**:
  the 4 in-scope modules × all 3 issuance-mode/encryption crossings
  (12 module instances) — `credential-issuance`,
  `credential-issuance-notification`, `client-attestation-challenge`
  (proving FAPIgo PR #318's `client.ChallengeSource` against the
  suite's own independent Attestation Challenge Endpoint
  implementation, not just FAPIgo's own unit tests), and
  `batch-credential-issuance`, each crossed with `immediate`+`plain`,
  `deferred`+`plain` and `immediate`+`encrypted` — plus the HAIP plan's
  4th module-list entry, the generic FAPI2SP client conformance
  battery (10 more module instances, always at the fixed
  `immediate`+`plain` crossing). Driving the encrypted crossing
  surfaced a genuine pre-existing bug in `wallet` itself — its
  ephemeral response-decryption JWK never declared its own `alg`,
  which §8.2 requires — now fixed with a regression test. Driving the
  battery surfaced two more real findings, both in this binary: it
  needed real RFC 8414 discovery (FAPIgo's own `client.Discover` can't
  be used here — it speaks OIDC Discovery's own convention, and this
  suite explicitly test-fails that), used to both build endpoints and
  catch the suite's own issuer-mismatch negative test; and the battery
  never wires up the Attestation Challenge Endpoint at all (unlike the
  4 VCIWallet* modules), so this binary now only opts into
  `client.ChallengeSource` for the modules that actually implement it.
  **Update: HAIP §4.5.1's Key Attestation (Appendix D) requirement is
  now driven too, both ways OID4VCI conveys it — confirmed live, all
  22 module instances `FINISHED`/`PASSED` for each, via a new
  `-proof-type` flag: `attestation` submits a standalone Key
  Attestation JWT as its own proof type (Appendix F.3); `jwt-key-attestation`
  nests one inside an ordinary jwt-type proof's own header (Appendix
  D.1).** Turned out nothing needed building for the standalone case:
  both `wallet.Wallet.GenerateAttestationProof` and the whole
  `oid4vcgo/attestation` package already fully implemented Key
  Attestation JWT issuance (OID4VCI Appendix D.1) — this binary's own
  `keyattestation.go` just had to mint one (a new dedicated CA/leaf,
  `client_attestation.key_attestation_trust_anchor_pem`) and submit it.
  `AGENTS.md`'s prior "nothing implements this yet" note predated that
  package landing and has been corrected. The nested case needed one
  small new `wallet` primitive, `GenerateProofWithKeyAttestation`
  (`wallet/proof.go`), plus a design choice for the batch module
  driven by reading the suite's own validation source rather than a
  failed run: one Key Attestation JWT naming every key in the batch,
  embedded identically in every proof, rather than one attestation per
  proof — see `wallet/README.md`'s own "Status" section for why.
  **Update: the `issuer_initiated` flow variant is driven too**
  (`-issuer-initiated`) — confirmed live, all 22 module instances
  `FINISHED`/`PASSED`. Turned out this binary never needs to receive an
  inbound request at all: the suite's own headless browser only
  dispatches to a URL when the plan config declares a matching
  automation script, which this binary doesn't, so it just queues the
  Credential Offer redirect URL — already fully resolved, `issuer_state`
  included — in the module's own `/api/log`, which this binary now
  simply polls. Driving this also surfaced a real, general bug in
  `fapigo/client`, not this binary: echoing back an offer's own
  `issuer_state` as a PAR extension broke every time PAR needed to
  retry on a DPoP nonce challenge, because `buildPushedRequestForm`
  mutated its caller's own shared `params` map — fixed upstream
  ([FAPIgo PR #322](https://github.com/IDFoundry/FAPIgo/pull/322),
  merged, `go.mod` pinned past it). `-credential-offer-variant
  by_reference` has the suite send a `credential_offer_uri` instead of
  the inline offer; `wallet.Wallet.ResolveCredentialOffer` fetches it.
  The daily OID4VCI workflow (`run_wallet` in
  `conformance/scripts/lib.sh`) drives the role's six certification
  profiles, each all 22 module instances: `sd_jwt_vc` and `mdoc`, each
  `wallet_initiated`, `issuer_initiated` by value and
  `issuer_initiated` by reference, and a seventh run with
  `-proof-type jwt-key-attestation` (see `wallet/README.md`'s "Runs").
  In each, the wallet reads its endpoints from the Credential Issuer's
  and Authorization Server's metadata, pins the suite's TLS
  certificate, and verifies every credential it receives (signature,
  chain, holder binding, status list entry) before the module can
  pass.
  `issuer_initiated_dc_api` isn't
  covered: it needs the Digital Credentials API on the issuance side,
  which no driver here stands in for.
  **Update: the suite's own base (non-HAIP) `oid4vci-1_0-wallet-test-plan`
  is driven too**, via `-base-plan` — the same 4 `VCIWallet*` modules
  already covered above (one `immediate`+`plain` crossing, no FAPI2SP
  battery reuse in this plan), plus a 5th module HAIP's own plan
  explicitly excludes: a Token-Response-without-`authorization_details`
  variant, which needed no wallet code changes since this binary never
  read that field in the first place. All 5 modules `FINISHED`/`PASSED`,
  twice for stability.
  **Update: `mso_mdoc` credential format is driven too**, via
  `-credential-format mdoc` — needed zero `wallet` package changes
  (`RequestCredential`'s own credential-response handling is entirely
  format-agnostic), just the new flag plus a matching
  `-credential-configuration-id`/`-scope` naming the suite's own
  mdoc-format fixture (`eu.europa.ec.eudi.pid.mdoc.1`/`eudi.pid.mdoc.1`).
  All 22 module instances `FINISHED`/`PASSED`, twice for stability. See
  `wallet/README.md`.
