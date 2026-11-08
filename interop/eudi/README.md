# EUDI interop

Interop runs against the [EUDI Wallet reference implementation](https://github.com/eu-digital-identity-wallet)'s
own components, run locally from their published images. They run in
CI from [`.github/workflows/eudi-interop.yml`](../../.github/workflows/eudi-interop.yml).

## Wallet ↔ EUDI Verifier Endpoint

[`run-verifier.sh`](run-verifier.sh) presents from
`cmd/conformance-wallet-vp` to
[eudi-srv-verifier-endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint),
driving the verifier through its own REST API (`POST /ui/presentations`
to start a transaction, `GET /ui/presentations/{id}` for the result) and
standing in for the same-device launch and the browser:

| Case | Expected |
|---|---|
| SD-JWT VC PID, `haip` profile, `direct_post.jwt` | accepted |
| The same, `openid4vp` profile | accepted |
| mdoc PID, `haip` profile | accepted |
| mdoc PID, `openid4vp` profile | accepted |
| mdoc PID over the Digital Credentials API (`openid4vp-v1-signed`) | accepted |
| The answered request launched again | refused |
| The verifier trusts an unrelated issuer CA | the verifier refuses the credential |
| The launch's `client_id` isn't the signed request's | the wallet refuses |
| A query for a credential the wallet doesn't hold | the verifier receives `access_denied` |
| The wallet trusts an unrelated CA for the verifier | the wallet refuses |
| A revoked SD-JWT VC (its status list entry invalid) | the verifier refuses it |
| An SD-JWT VC whose `vct#integrity` doesn't match its Type Metadata, before the verifier has the metadata cached | the verifier refuses it |
| A revoked mdoc | the verifier refuses it |

Each accepted case also completes the same-device return: the wallet
follows the verifier's `redirect_uri`, and the verifier releases the
`vp_token` only for that `response_code`.

The verifier is run as strictly as it can be configured:

- Each credential carries a Token Status List reference, and the
  verifier checks it (`VERIFIER_VALIDATION_STATUSCHECK_ENABLED`): a JWT
  Status List Token for the SD-JWT VC, a CWT one for the mdoc.
- SD-JWT VC Type Metadata is required (`always_required`), resolved for
  `urn:eudi:pid:1` and checked against the credential's `vct#integrity`
  (`..._INTEGRITY_ENABLED`).
- It fetches both over TLS it verifies: the `self-signed` profile, which
  makes its HTTP client trust any certificate, is off, and the CA of
  [`scripts/serve`](scripts/serve), which serves the documents, is added
  to its trust store through the image's `ca-certificates` binding.
- Each transaction names the issuer CA it trusts (`issuer_chain`); with
  no trust validator configured, the verifier would otherwise trust any
  issuer.

The run also checks the verifier fetched each status list and the Type
Metadata, so a run in which it silently skipped a check fails.

What v0.12.0 doesn't check, whatever its configuration:

- A Status List Token's signature: it passes statium a signature check
  that always succeeds (`StatusListTokenValidator`), so the run shows
  that it reads the list, but not that it would refuse a forged one.
- `vct#integrity`, once it has resolved the Type Metadata: it caches the
  resolved metadata by `vct` alone (`VerifierContext`, the
  `ResolveTypeMetadata` it registers), and checks the integrity only on
  a cache miss. So the mismatched-integrity control runs first, on a
  cold cache, and the run presents the same credential again once the
  cache is warm: that is accepted, and the run notes it without failing,
  and says so if a later image refuses it.

Every key, certificate and document is throwaway, made per run by
[`scripts/setup`](scripts/setup):

- the wallet's fixture credentials, an SD-JWT VC under a CA and an mdoc
  under an IACA, and their x5c-signed Status List Tokens (index 0 valid,
  1 invalid);
- the PID's Type Metadata;
- the verifier's Access Certificate (its Request Object signing key, a
  leaf under a CA the wallet trusts; EUDI refuses a self-signed one), its
  TLS listener, and a Relying Party registration certificate, which EUDI
  refuses a transaction without;
- `scripts/serve`'s TLS certificate, for `host.docker.internal`, under
  its own CA.

What isn't covered:

- `request_uri_method` post: the EUDI verifier refuses a
  `wallet_metadata` without `issuer` and `response_types_supported`
  (it parses it as RFC 8414 Authorization Server metadata, which
  requires both), and `cmd/conformance-wallet-vp` sends only
  `vp_formats_supported`.
- Plain `direct_post`: `cmd/conformance-wallet-vp` always encrypts its
  response.
- ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): the EUDI verifier has no
  such endpoint.

Run it locally (Docker, Go, jq, curl and openssl; on Apple silicon the
amd64 image runs emulated and takes a couple of minutes to start):

```sh
interop/eudi/run-verifier.sh
VERIFIER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:latest interop/eudi/run-verifier.sh
```

`PORT`, `WALLET_PORT` and `SERVE_PORT` (18443, 18444 and 18445) move
the listeners, and `WORK` keeps the run's files. On Linux, `serve`
listens on the Docker bridge's gateway, which the verifier reaches as
`host.docker.internal`.

### Moving the pin

The image is pinned by digest in `run-verifier.sh`. The weekly run tests
EUDI's `latest` image, and opens an `interop-eudi-latest` issue when
that fails. To move the pin, read the release's changes, then set the
digest of its `vX.Y.Z` tag:

```sh
docker buildx imagetools inspect ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:vX.Y.Z
```
