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

Each accepted case also completes the same-device return: the wallet
follows the verifier's `redirect_uri`, and the verifier releases the
`vp_token` only for that `response_code`.

Every key and certificate is throwaway, made per run by
[`scripts/setup`](scripts/setup): the wallet's fixture credentials
(an SD-JWT VC under a CA, an mdoc under an IACA), the verifier's Access
Certificate (its Request Object signing key, a leaf under a CA the
wallet trusts; EUDI refuses a self-signed one), its TLS listener and a
Relying Party registration certificate, which EUDI refuses a
transaction without. Each transaction names the issuer CA it trusts
(`issuer_chain`).

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
- Status lists: the fixture credentials carry no status.

Run it locally (Docker, Go, jq, curl and openssl; on Apple silicon the
amd64 image runs emulated and takes a couple of minutes to start):

```sh
interop/eudi/run-verifier.sh
VERIFIER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:latest interop/eudi/run-verifier.sh
```

`PORT` and `WALLET_PORT` (18443 and 18444) move the listeners, and
`WORK` keeps the run's files.

### Moving the pin

The image is pinned by digest in `run-verifier.sh`. The weekly run tests
EUDI's `latest` image, and opens an `interop-eudi-latest` issue when
that fails. To move the pin, read the release's changes, then set the
digest of its `vX.Y.Z` tag:

```sh
docker buildx imagetools inspect ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:vX.Y.Z
```
