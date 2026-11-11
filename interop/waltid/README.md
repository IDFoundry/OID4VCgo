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
| | The request unsigned, naming its `x509_hash` client | the wallet refuses |
| | The wallet trusts an unrelated Verifier CA | the wallet refuses |
| Wallet2 ← OID4VCgo's issuer | SD-JWT VC PID: Wallet Attestation and PoP, DPoP, pre-authorized code | issued |
| | mdoc PID, the same | issued |
| | The Wallet Attestation from an attester the issuer doesn't trust | the issuer refuses (`invalid_client`) |
| Wallet2 → OID4VCgo's verifier | That SD-JWT VC PID, `x509_hash`, `direct_post.jwt`, `request_uri_method` none, `get` and `post` | verified |
| | That mdoc PID | verified, only the requested elements disclosed |
| | The verifier's Access Certificate under an unrelated CA | Wallet2 refuses (`X509TrustAnchorMismatch`) |
| | The verifier trusts an unrelated issuer CA | the verifier refuses the credential |

OID4VCgo's side is `walletflow` ([`scripts/wallet`](scripts/wallet)),
`cmd/conformance-verifier` and `cmd/conformance-issuer`, the latter two
configured as in [`../eudi`](../eudi/README.md): the issuer is the EUDI
issuer run's ([`setup-issuer`](../eudi/scripts/setup-issuer)), under
HAIP.

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
   credentials from the run's CA, which it was never told about. Its
   other policies (`allowed-issuer`, an ETSI trust list, a VICAL) don't
   take X.509 roots, so the run tests Verifier2's handling of OID4VCgo's
   wallet's presentation, not its issuer trust.

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

## What isn't covered

- The authorization code flow, in either direction, and Issuer2's
  Wallet Attestation: Issuer2 runs with anonymous pre-authorized codes.
- Status lists: Issuer2's credentials carry none, and OID4VCgo's
  verifiers here check none.
- Verifier2's issuer trust (finding 3), its DC API flows, and Wallet2's
  checks of the credentials it's issued.
- Wallet2 receiving from Issuer2: walt.id with itself.

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
