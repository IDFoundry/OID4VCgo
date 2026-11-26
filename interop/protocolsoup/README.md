# ProtocolSoup interop

Interop with [ProtocolSoup](https://github.com/ParleSec/ProtocolSoup)
(ParleSec, Go, Apache-2.0), a protocol playground whose federation
service holds an OpenID4VCI 1.0 Credential Issuer and an OpenID4VP 1.0
Verifier, with a separate wallet harness (`backend/cmd/walletharness`),
a holder driven over HTTP. [`run.sh`](run.sh) runs every case against
it, from [`.github/workflows/protocolsoup-interop.yml`](../../.github/workflows/protocolsoup-interop.yml),
in four directions: ProtocolSoup's Verifier, presented to by
OID4VCgo's wallet; ProtocolSoup's issuer, issuing to OID4VCgo's wallet
([`issuer.sh`](issuer.sh)); and ProtocolSoup's wallet harness,
receiving from OID4VCgo's issuer and presenting to OID4VCgo's verifier
([`holder.sh`](holder.sh)). Both are sourced by `run.sh`.

ProtocolSoup publishes no images for a commit, so the run builds two
from the pinned commit, as its `docker-compose.yml` builds them: the VC
service, `docker/Dockerfile.backend` with `SERVICE_CMD=./cmd/server-vc`
(the OpenID4VCI and OpenID4VP plugins, with the OAuth 2.0 and OIDC ones
its authorization code grant needs), and `docker/Dockerfile.wallet-harness`.
The workflow caches them by commit.

ProtocolSoup is an independent implementation: its JOSE, SD-JWT VC,
mdoc (CBOR, COSE) and protocol code is its own, on `go-jose`,
`golang-jwt`, `fxamacker/cbor` and `veraison/go-cose`, sharing nothing
with FAPIgo, OID4VCgo, the `@openid4vc`/`@sd-jwt`/`@owf/mdoc` libraries
Credo and EUDIPLO build on, or the EUDI reference libraries.

## OpenID Certification

Checked on openid.net on 2026-11-26: ProtocolSoup is listed in
[OID4VCI 1.0 + HAIP 1.0](https://openid.net/certification/certified-oid4vci-haip-final/)
as Issuer ("ProtocolSoup v4.0.0", SD-JWT VC and mdoc, issuer- and
wallet-initiated, 10-Aug-2026) and Wallet ("ProtocolSoup v4.1.0",
SD-JWT VC and mdoc, wallet-initiated and issuer-initiated by value and
by reference, 12-Aug-2026); and in
[OID4VP 1.0 + HAIP 1.0](https://openid.net/certification/certified-oid4vp-haip-final/)
as Verifier ("ProtocolSoup v4.0.0", `sd_jwt_vc` and `iso_mdl`,
`direct_post.jwt`, 11-Aug-2026) and Wallet (v4.0.0, the same two,
10-Aug-2026). Its [trust page](https://protocolsoup.com/trust) says the
same, and that certification covers those named versions and profiles
only. The pin (`v4.1.1-45-g477f404`) is a later, uncertified commit of
master.

## Cases

Each case is the result `run.sh` prints; a `control` must be refused
for the reason given, and a `note` is a known gap (below), asserted as
the pinned commit behaves so that the run fails once it changes.

OID4VCgo's issuer → OID4VCgo's wallet → ProtocolSoup's Verifier:

| Case | What happens |
|---|---|
| `sdjwt` | The SD-JWT VC PID, to a signed `x509_hash` request in ProtocolSoup's HAIP mode (`profile: haip`: DCQL, `direct_post.jwt`, A128GCM and A256GCM offered); ProtocolSoup verifies it, its issuer by its chain to `OID4VP_SD_JWT_TRUST_ANCHOR_PEM`, and only `family_name` and `birth_date` are disclosed |
| `sdjwt-san-dns` | The same to its general profile's `x509_san_dns` client (`walletflow.Config.AcceptX509SANDNS`) |
| `dcapi` | The same over the Digital Credentials API (`openid4vp-v1-signed`, `dc_api.jwt`), the run standing in for the page |
| relay | The response relayed through the wallet's transport, re-encrypted, changed in nothing else: accepted |
| control | The Key Binding JWT's `nonce`, then its `aud`, changed: `nonce_mismatch`, `audience_mismatch` |
| control | A disclosure's value changed: `disclosure_invalid` (its digest not referenced) |
| control | The Issuer-signed JWT signed again under a self-signed certificate: `credential_signature_invalid`, its chain untrusted |
| control | The wallet trusting another Verifier CA refuses the request, for its chain |
| control | A DC API request handed to the wallet from an origin its `expected_origins` doesn't name: the wallet refuses it |
| note | The mdoc PID: finding 2 |
| note | An SD-JWT VC with a status list reference: finding 1 |

ProtocolSoup's issuer → OID4VCgo's wallet:

| Case | What happens |
|---|---|
| `issue-haip` | `UniversityDegreeCredentialSDJWTHAIP`, pre-authorized with a `tx_code`; a Wallet Attestation from OID4VCgo's Wallet Provider at the Token Endpoint, a DPoP-bound token with DPoP nonces, a `jwt` proof carrying the provider's Key Attestation (key named by `jwk`, finding 3); the Credential Request and Response encrypted |
| `issue-sdjwt` | `UniversityDegreeCredentialSDJWT` under walletflow's default profile: a batch (5 copies), DPoP, encrypted |
| `deferred` | ProtocolSoup's deferred offer: 202, then issued from the Deferred Credential Endpoint |
| `status` | The wallet checks the HAIP credential's Token Status List entry on ProtocolSoup's list: VALID |
| control | A wrong `tx_code`: `invalid_grant: invalid tx_code` |
| control | A Wallet Attestation from OID4VCgo's other provider, under a CA ProtocolSoup doesn't trust: `invalid_client`, for its chain |
| control | The wallet trusting another issuer CA refuses the credential, for its chain |
| note | A key-attested proof naming its key by index: finding 3 |
| note | ProtocolSoup's mdocs, both configurations: finding 4 |

OID4VCgo's issuer → ProtocolSoup's wallet harness (`POST /api/import`):

| Case | What happens |
|---|---|
| `harness-sdjwt` | The SD-JWT VC PID: the harness's own Wallet Attestation (its attester key under a CA of its own, which the issuer trusts, its certificate naming the client's attester), DPoP with the issuer's DPoP nonces; it checks the credential by its chain |
| `harness-tx-code` | The same with a `tx_code` |
| control | A wrong `tx_code`: the issuer's `invalid_grant` (`tx_code does not match`), which the harness reports |
| control | The harness's Wallet Attestation under a CA the issuer doesn't trust: 401 `invalid_client` |
| control | A harness trusting another CA for credentials refuses the SD-JWT VC, for its chain |
| note | The mdoc PID: finding 2, as the harness has it |
| note | The issuer under its production setup: finding 5 |

ProtocolSoup's wallet harness → OID4VCgo's verifier (`POST /api/resolve`, `/api/present`):

| Case | What happens |
|---|---|
| `present-sdjwt` | `cmd/conformance-verifier`'s signed `x509_hash` request by reference (`request_uri_method` post), the response encrypted (`direct_post.jwt`); the verifier verifies the PID (issuer, holder binding, status) and only `family_name` and `given_name` are disclosed |
| control | `approve_external_trust` false: the harness presents nothing (`external verifier trust approval is required`) |
| control | The verifier's Access Certificate under a CA the harness doesn't trust: refused, though approved, for its chain |
| control | The verifier trusting another issuer CA refuses the credential, for its chain |
| control | A PID the issuer revoked once issued: the verifier refuses it, for its status |

## How it's set up

[`scripts/setup`](scripts/setup/main.go) writes the run's throwaway
CA (TLS, ProtocolSoup's request object signer, OID4VCgo's Access
Certificates), a CA nothing trusts, and the harness's attester and key
attester keys (private JWKs carrying their certificate, as
`WALLET_CLIENT_ATTESTATION_*_JWK_JSON` take them) under an attester CA
of its own. `interop/eudi/scripts/setup-issuer` writes OID4VCgo's
issuer's config and the PIDs' CAs.

ProtocolSoup's VC service runs with Redis for its replay stores (its
`demo` environment requires it), its base URL
`https://localhost:$PS_PORT` behind `interop/waltid/scripts/serve`'s
TLS proxy, and, by its own settings: its request object signer
(`OID4VP_X509_SANDNS_CERT_CHAIN_PEM`, `_PRIVATE_KEY_PEM`), the issuer's
SD-JWT VC CA (`OID4VP_SD_JWT_TRUST_ANCHOR_PEM`) and IACA
(`MDOC_IACA_ROOT_PEM`), the Wallet Provider's CA for Wallet and Key
Attestations (`OID4VCI_CLIENT_ATTESTATION_TRUST_ANCHOR_PEM`,
`OID4VCI_KEY_ATTESTATION_TRUST_ANCHOR_PEM`), and DPoP nonces at both
its authorization server and resource endpoints, as its hosted
deployment runs. It makes its IACA and signers at startup, into a
mounted directory, whose `iaca_root.pem` OID4VCgo's wallet then
trusts for both formats: its SD-JWT VC signer is certified under the
same IACA.

OID4VCgo's issuer runs its production setup (sealed SQLite stores,
Key Attestations required, DPoP nonces), as in the EUDIPLO run,
without status lists for ProtocolSoup's Verifier (finding 1). For the
harness, a second instance (`start_hissuer`, in profiles) is
`https://oid4vcgo.test:…` behind serve's tap, which the harness's
container maps to this host; its credentials carry status list
entries at `https://localhost:…`, where OID4VCgo's verifier fetches
them. It runs at development assurance, without Key Attestations,
for the harness's cases (finding 5), as the Credo run runs it for
Credo's holder; its `production` profile shows finding 5.

The harness reaches only public addresses, besides its two trusted
hosts, `WALLET_ISSUER_BASE_URL` and `WALLET_TARGET_BASE_URL`: the run
names OID4VCgo's issuer and verifier there. Its TLS roots are the
run's CA (`SSL_CERT_FILE`); it checks request objects' chains against
`WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM`, and credentials against
`WALLET_MDOC_IACA_ROOT_PEM`, which, despite its name, it checks an
SD-JWT VC's `x5c` against too (after the issuer's JWKS, which
OID4VCgo's issuer doesn't sign credentials with). Every call names one
`X-Wallet-Session`, and `/api/present` the `credential_configuration_id`
to present (without it the harness picks a ProtocolSoup configuration,
and asks its own issuer for it). `approve_external_trust` is the
holder's consent to a Verifier other than the harness's target's
`/oid4vp/response`: the request's signature and chain are checked
first, approved or not, as the untrusted Verifier control shows.

ProtocolSoup rate-limits every protocol endpoint to 100 requests a
minute per client (`core.RateLimiter`, no setting): `run.sh`'s `pace`
waits out a minute once 40 requests have gone through serve's proxy.

## What ProtocolSoup sends

- Its encrypted requests' `client_metadata.jwks` holds one ECDH-ES key
  with a `kid`; its general profile's unencrypted (`direct_post`)
  requests carry no `jwks`, which walletflow, answering only
  `direct_post.jwt`, refuses.
- Its issuer offers `credential_request_encryption` (not required) and
  answers every Credential Request walletflow encrypts with an
  encrypted response; `batch_credential_issuance.batch_size` 20.
- Its HAIP configurations require a Wallet Attestation and DPoP; its
  others take an anonymous pre-authorized code, yet bind the token to
  DPoP when the wallet sends a proof.
- The harness's Token Request carries a Client Attestation PoP with
  `iss` (the client_id) and a DPoP proof retried with the issuer's
  nonce; its Key Attestation carries `iat`, `attested_keys` and the
  `c_nonce`, no `exp` (finding 5).

## ProtocolSoup's deviations

Found by this run, at the pinned commit; not reported upstream.

1. **Its Verifier fetches status lists only from public addresses.**
   A referenced token's status list URI must be HTTPS and resolve to
   no loopback, private or link-local address
   (`validateExternalStatusListURI`), with no setting to allow one, so
   an SD-JWT VC whose list a CI run serves is refused,
   `credential_status_invalid`: "status list URI must not target
   private or local addresses". Failing closed is right; the cost is
   that revocation isn't testable against it here. From its source,
   not exercised: it also requires a status list token signed by the
   credential's own issuer key, where the Token Status List lets a
   Status Issuer sign it; it treats a status list URI as its own when
   its host name matches its base URL's, whatever the port; and it
   checks no status for mdocs.
2. **It requires a Document Signer certificate to carry Basic
   Constraints.** `mdoc.validateDocumentSignerCertificate` refuses one
   without the extension ("document-signer certificate must have Basic
   Constraints CA=false"). ISO/IEC 18013-5 Annex B's Document Signer
   profile doesn't include it, RFC 5280 lets an end-entity certificate
   leave it out, and OID4VCgo's issuer does
   (`conformancecert.GenerateMdocDocumentSigner`). Its Verifier and
   its harness share the check, so no mdoc of OID4VCgo's is accepted
   by either.
3. **A key-attested `jwt` proof must name its key by `jwk`.** One
   naming it by its index in `attested_keys` (`kid` "0",
   walletflow's default) is refused, "proof JOSE key reference is not
   supported; use jwk", as Credo's and EUDIPLO's issuers do;
   `walletflow.Config.ProofKeyByJWK` covers it.
4. **Its mdocs' MSO is signed before their signer's certificate.** It
   rounds `validityInfo.signed` and `validFrom` down to the UTC day
   (`roundCredentialIssuanceTime`, as for a JWT credential's `iat`),
   while its Document Signer certificate, made at startup, starts five
   minutes before it: walletflow refuses the mdoc ("MSO signed
   …T00:00:00Z, outside the document signer certificate's validity").
   A deployment whose signer is older than a day wouldn't show it;
   this run always does, unless it crosses midnight UTC, when the note
   reads as a change.
5. **The harness's Key Attestations carry no `exp`**, which OpenID4VCI
   1.0 Appendix D.1 requires of one used with the `jwt` proof type;
   OID4VCgo's issuer, under its production setup (which requires a Key
   Attestation in every `jwt` proof), refuses it: "its key_attestation
   has no exp". ProtocolSoup's own issuer takes it as optional.

## What isn't covered

- **mdoc, every direction**: findings 2 and 4 stop each before its
  presentation; the mdoc paths of ProtocolSoup's Verifier (its
  handover, its encrypted responses) aren't reached.
- **Revocation against ProtocolSoup**: its Verifier can't fetch the
  run's lists (finding 1); its own status lists are all VALID, with no
  API to revoke.
- **The authorization code flow (PAR, PKCE)**: its authorization
  endpoint authenticates the holder on its mock identity provider's
  login form, which the wallet driver doesn't fill.
- **The harness as a HAIP holder of key-attested credentials**: only
  at development assurance (finding 5); the harness checks no status,
  and can't be made to send a changed presentation, so OID4VCgo's
  verifier's refusals are shown for the issuer's chain and status
  only. Its `/submit` one-click path, which keys its store by request,
  not session, isn't used.
- `verifier_attestation`, `did:web` and `redirect_uri` clients, and
  JWT VC/JSON-LD formats, which OID4VCgo doesn't implement.

## Running it

    interop/protocolsoup/run.sh
    PROTOCOLSOUP_REF=master interop/protocolsoup/run.sh

Needs docker, go, jq, curl and openssl; `WORK` names the work
directory (default a fresh temporary one), `BASE_PORT` the first of
the 27 loopback ports it uses (default 21800).
`PROTOCOLSOUP_IMAGES="VC_IMAGE WALLET_IMAGE"` uses images already
built; `PROTOCOLSOUP_IMAGE_CACHE`, a directory, saves the images built
for a commit and loads them for it again. The work directory holds
the run's keys: the workflow uploads only its logs and the parties'
answers.

## Moving the pin

`run.sh` pins a master commit (`PROTOCOLSOUP_PIN`). To move it, read
ProtocolSoup's `CHANGELOG.md` and commits since the pin, especially
`backend/internal/protocols/oid4vci`, `oid4vp`, `internal/mdoc`,
`internal/vc` and `cmd/walletharness` (its environment settings and
API), and the Dockerfiles; run `PROTOCOLSOUP_REF=<commit> interop/protocolsoup/run.sh`;
then update `PROTOCOLSOUP_PIN`, its date comment, and this README
(the certification check too, when it names a certified release). The
weekly run tests master, to show a break before the pin moves; a
dispatch takes any commit, branch or tag.
