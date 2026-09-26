# Passport → verifiable digital credential demo

Takes a [gmrtd](https://github.com/gmrtd/gmrtd) portable passport file,
verifies it against the issuing country's own signatures, and turns it
into a verifiable digital credential in **both** `mso_mdoc` and
`dc+sd-jwt`, issued over OID4VCI (HAIP).

> **Status:** complete end to end — passport verification, both
> credential formats, the OID4VCI issuer, a browser wallet and a
> command-line wallet, and an OpenID4VP verifier demonstrating both
> trust paths. An iOS wallet and
> live NFC capture are next (see [Roadmap](#roadmap)).

This is a separate Go module: it's the only code in this repository
that depends on gmrtd. It builds against this checkout of the library
(`replace` in `go.mod`), and release-please ignores it.

## How it works

```
gmrtd portable file ─► passport.Verify ─► passport.Evidence ─┬─► credential.MdocClaims  ─► issuer.RequestCredential ─► mso_mdoc
   (all raw LDS files)   (gmrtd Passive       (identity +     └─► credential.SDJWTClaims ─► issuer.RequestCredential ─► dc+sd-jwt
                          Authentication)      raw SOD/DGs)
```

Both credentials carry the same content:

- **Identity attributes** — names, date of birth, age claims, sex,
  nationality, issuing country, document number, expiry.
- **The raw ICAO data groups** — `icao_sod`, `icao_dg1`, and `icao_dg2`
  / `icao_dg11` when the passport has them — **one selectively
  disclosable element (mdoc) or claim (SD-JWT) each**, byte-for-byte as
  read from the chip.

## Two ways to trust the credential

A verifier can choose:

1. **Trust this demo's issuer.** Check the credential's issuer signature
   and use the identity attributes. The issuer verified the passport
   before issuing, but the country did not sign this credential — the
   issuer is making a new assertion.
2. **Trust only the issuing country.** Request `icao_sod` + `icao_dg1`
   and re-run ICAO Passive Authentication against its own CSCA trust
   anchors (e.g. with gmrtd). The SOD holds a separate hash per data
   group, so this works without disclosing the photo (DG2) or DG11.

What the second path does and doesn't give you:

- It removes trust in this issuer **for the data**: the issuer can't
  invent attributes the country didn't sign.
- It does **not** remove trust in the issuer **for holder binding**.
  Passport data can be copied; what ties it to the person presenting it
  is the credential's device key (mdoc `DeviceKey` / SD-JWT `cnf`) plus
  the issuer's checks at issuance.

## Limitations to be aware of

- **A portable file proves the data is authentic, not that the uploader
  holds the passport.** When the file carries chip authentication
  evidence it's reported, but that only shows a genuine chip was read at
  some point. Binding the read to this issuance needs an issuer-chosen
  Active Authentication challenge (gmrtd's `verifier.WithAAChallenge`) —
  planned for the live-NFC phase. Note that `WithAAChallenge` only
  rejects a *mismatched* challenge: a file without AA evidence passes,
  so the issuer must itself require that AA ran and succeeded.
- **Date of birth from the MRZ has no century.** Without DG11 (e.g.
  Singapore passports), gmrtd returns `YYMMDD`:
  - one plausible century → `birth_date` is issued, century inferred;
  - both plausible (typical for a child: age 12 or 112) → **no
    `birth_date`**; age claims use the **youngest** reading, so they can
    only understate age, never overstate it.
- **Age claims go stale.** A child's `age_over_18: false` becomes wrong
  on their 18th birthday, so the credential expires at the next age
  threshold the holder crosses (and never after the passport expires).
- **MRZ names may be truncated or transliterated.** `names_from_mrz`
  says when names came from the MRZ rather than DG11.
- **The SOD is unique to the passport.** Disclosing `icao_sod` links
  presentations across verifiers, whatever the credential format.
- **Identifiers are provisional.** The doctype, namespaces and claim
  names (in `credential/names.go`) should be aligned with ISO/IEC
  23220-4's DTC namespace before this is presented as interoperable.

## Running the demo

```sh
go run ./cmd/wallet-provider     # once: wallet-provider.pem, .jwks.json and -ca.pem
go run ./cmd/issuer              # https://127.0.0.1:8543 — writes issuer-tls.pem, issuer-ca.pem
go run ./cmd/verifier            # https://127.0.0.1:9443 — writes verifier-tls.pem, verifier-ca.pem
go run ./cmd/webwallet           # https://127.0.0.1:7443 — writes webwallet-tls.pem; trusts verifier-ca.pem
```

The wallets answer only verifiers whose request-signing certificate
chains to a trusted verifier CA (`-trust-verifier-ca`, default
`verifier-ca.pem`), so start the verifier before the web wallet. A
restarted verifier has a new CA; restart the web wallet too.

All three use self-signed certificates: accept them in the browser, or
trust the written `.pem` files. (The issuer uses 8543 rather than 8443
so it doesn't collide with a locally running OIDF conformance suite.)

**In the browser (web wallet):**

1. **Issue.** Open https://127.0.0.1:8543 and upload a gmrtd portable
   passport file. It's verified against gmrtd's built-in ICAO CSCA
   master list; click **Open in web wallet**, continue to the issuer,
   approve, and you're back in the wallet with both credentials.
2. **Verify.** Open https://127.0.0.1:9443, choose a trust path, and
   click **Open in web wallet**. The wallet shows who's asking and
   exactly which claims each format would disclose; choose a format
   and **Share** (or **Decline**). The verifier page shows the result.

**From the terminal (CLI wallet)** — same store, so both wallets see the
same credentials; like the web wallet, it shows who's asking and what
they'd see, and asks before sharing:

```sh
go run ./cmd/wallet receive 'openid-credential-offer://?credential_offer=...'
go run ./cmd/wallet list
go run ./cmd/wallet present [-format dc+sd-jwt] [-yes] 'openid4vp://?client_id=...&request_uri=...'
```

The CLI's `receive` prints the authorization URL: open it, approve, and
it picks up the redirect on `http://127.0.0.1:8765/callback`; add
`-headless` to approve automatically. Both wallets keep credentials
(with their holder keys) in `wallet-store/`.

`cmd/wallet-provider` creates the demo's **stand-in Wallet Provider**:
a key, and a certificate for it from a demo Wallet Provider CA. The
issuer registers one wallet client (`passport-vdc-wallet`, with both
wallets' redirect URIs), and trusts that key in two ways:

- **Wallet Attestations**, by `kid`, through the provider's JWK Set.
- **Key Attestations**, through the CA certificate. Each credential
  request must prove its holder key with a Key Attestation: the
  `attestation` proof type (OID4VCI 1.0 Appendix F.3), which is the
  only proof type the issuer offers. The attestation carries the
  provider's certificate as `x5c` and the issuer's `c_nonce`, as HAIP
  1.0 §4.5.1 requires.

The wallets use the provider's private key to attest themselves and
their holder keys, which a real wallet would never hold. The provider
files, the TLS certificate and the wallet store are all git-ignored; the
store keeps holder keys unencrypted.

The issuer runs over HTTPS even locally because the library's wallet
can't yet discover a loopback `http` issuer: `wallet.Config.Fetch.AllowLoopbackHTTP`
lets it fetch the metadata, but decoding `credential_issuer` as a
`fapi.URL` always requires `https`.

### The issuance flow

| Step | Endpoint | What happens |
|---|---|---|
| Upload | `POST /passport` | gmrtd verification → a transaction T holding the `Evidence` (in memory, 10 minutes, at most 100 at once) → a credential offer with `issuer_state` = T, as a link and a QR code |
| PAR | `POST /par` | fapigo verifies Wallet Attestation + PoP and DPoP; this app records `request_uri` → T from the form's `issuer_state` |
| Approve | `GET /authorize`, `POST /authorize/decision` | shows the passport holder's name; approval authorizes **subject = T**, granting the scopes the wallet requested |
| Token | `POST /token` | DPoP-bound access token with `sub` = T |
| Credential | `POST /nonce`, `POST /credential` | the token's `sub` finds T's `Evidence`; the requested configuration (`passport_mdoc` or `passport_sdjwt`) is encoded, bound to the key the Key Attestation attests, and signed |

`issuer_state` has to be captured at PAR because fapigo doesn't surface
extension values at the authorization step (see the library's
`issuer/authorization_server.go`). Only plain form parameters are read,
so a wallet sending `issuer_state` inside a signed request object isn't
supported.

Also served: `/.well-known/openid-credential-issuer` (signed metadata),
`/.well-known/oauth-authorization-server`, `/jwks`, and the SD-JWT VC
type metadata at the `vct` URL (`/vct/passport/1`).

**Demo shortcuts:**

- **`issuer_state` is a bearer secret.** The approval step doesn't
  authenticate the holder, so whoever has the credential offer — a
  photographed QR code, a forwarded link — can redeem it with any wallet
  the Wallet Provider attests, and get the passport's data in a
  credential bound to *their* key.
- **An offer is reusable until it expires (10 minutes).** Issuing a
  credential doesn't consume the transaction, so the same offer can be
  redeemed more than once, by more than one wallet. Only each pushed
  authorization request (`request_uri`) and each approval are single-use.
  (Keeping the transaction is what lets one wallet receive both formats,
  in batches.)
- The signing keys and certificates (one for credentials, one for the
  issuer metadata, under one demo CA) are generated per process (a
  restart invalidates issued credentials); everything is in memory.
- **Key Attestations assert nothing about key storage.** They leave out
  `key_storage` and `user_authentication`, because the demo's holder keys
  are ordinary software keys. The issuer checks who attested a key, not
  how well it is protected.
- **Wallet Attestations use `kid`, not `x5c`.** HAIP 1.0 requires `x5c`,
  but fapigo's server resolves the attester's key only by `kid` from the
  client's registered JWK Set.

A production issuer would authenticate the holder at the approval step
(for example by re-reading the passport over NFC with an issuer-chosen
Active Authentication challenge), and bind each transaction to the one
wallet that first redeems it.

### The verification flow

The verifier sends **one** request accepting the credential in either
format (a DCQL credential set with one option per format); the wallet
answers with whichever it holds (`-format` picks when it holds both).
It checks:

| | Trust the issuer | Trust only the issuing country |
|---|---|---|
| Requested | `family_name`, `given_name`, nationality, `age_over_18` | `icao_sod`, `icao_dg1` — nothing else, not the photo |
| Issuer signature | verified, chained to the demo issuer's CA (`issuer-ca.pem`) | verified, likewise |
| Holder binding | key-binding / device signature over the verifier's nonce | likewise |
| Data trusted because… | the demo issuer signed it | ICAO Passive Authentication over the SOD + DG1 passes against the CSCA master list: the country signed it |

The request is a signed Request Object (`x509_hash` client identifier,
certificate issued by a per-process demo verifier CA) fetched from its
`request_uri`; the response is an encrypted `direct_post.jwt`, routed
to its request by the JWE's key ID. Selective disclosure is real: in
either mode the verifier receives only what it asked for.

The result page's address uses a random ID that never leaves the
verifier, separate from the `state` the wallet sees (OpenID4VP
§14.3.3), so the request link (or its QR code) doesn't reveal the
result. Anyone can encrypt a response to the request's public key, so
a response that fails to verify leaves the request open; the first one
that verifies is recorded and closes it.

The wallets accept a request only if its signing certificate chains to
a verifier CA they trust (`verifier-ca.pem`), as OpenID4VP §5.9.3
requires, and show that certificate's name when asking the holder. The
CLI wallet asks before sharing too (`-yes` skips it, for scripts).

## Running the tests

```sh
go test ./...
```

Tests needing a real passport are skipped unless you point
`PASSPORT_VDC_SAMPLE` at a gmrtd portable file **outside this
repository**:

```sh
PASSPORT_VDC_SAMPLE=/path/to/passport.gmrtd go test ./...
```

A real passport file is personal data. Never commit one — `*.gmrtd` is
in `.gitignore` as a backstop. CI runs everything else — including a full
end-to-end issuance of both formats (`issuerapp`'s
`TestEndToEnd_IssuesBothFormats`, and `verifierapp`'s end-to-end tests
presenting each format for each trust path — with synthetic passport
evidence, whose fake SOD must fail the ICAO check) — until gmrtd provides a
synthetic test passport (a test CSCA → DSC → SOD
generator, planned for gmrtd itself).

## Layout

| Package | Role |
|---|---|
| `passport` | gmrtd → verified `Evidence`; the birth-date rule |
| `credential` | `Evidence` → `mdoc.Claims` / `sdjwtvc.Claims`; validity and age claims |
| `issuerapp` | the OID4VCI issuer: fapigo Authorization Server + oid4vcgo Issuer + upload page |
| `walletprovider` | the stand-in Wallet Provider that signs Wallet Attestations and Key Attestations |
| `walletapp` | the wallet: receive (offer → discovery → HAIP Authorization Code flow → credentials) and present (OpenID4VP, selective disclosure); credential store |
| `verifierapp` | the OpenID4VP verifier: either-format requests, both trust paths |
| `webwallet` | the browser wallet: credential cards, receive via the issuer's approval page, consent before presenting |
| `passport.VerifyDataGroups` | the verifier's ICAO check over a disclosed SOD + DG1 |
| `cmd/issuer`, `cmd/verifier`, `cmd/webwallet`, `cmd/wallet`, `cmd/wallet-provider` | runnable binaries |

## Roadmap

1. ~~**Issuer**~~ — done.
2. ~~**Wallet CLI**~~ — done.
3. ~~**Verifier**~~ — done.
4. **iOS wallet**, then **live NFC capture** with an issuer-chosen Active
   Authentication challenge.
