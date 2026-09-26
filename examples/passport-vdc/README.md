# Passport → verifiable digital credential demo

Takes a [gmrtd](https://github.com/gmrtd/gmrtd) portable passport file,
verifies it against the issuing country's own signatures, and turns it
into a verifiable digital credential in **both** `mso_mdoc` and
`dc+sd-jwt`, issued over OID4VCI (HAIP).

> **Status:** passport verification, both credential encoders, the
> OID4VCI issuer and a command-line wallet are in place. A verifier
> comes next (see [Roadmap](#roadmap)).

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
go run ./cmd/wallet-provider     # once: wallet-provider.pem + wallet-provider.jwks.json
go run ./cmd/issuer              # https://127.0.0.1:8443, writes issuer-tls.pem
```

Open https://127.0.0.1:8443 (the issuer's certificate is self-signed —
`issuer-tls.pem`) and upload a gmrtd portable passport file. It's
verified against gmrtd's built-in ICAO CSCA master list, and the result
page shows a credential offer for both formats. Then, in another
terminal:

```sh
go run ./cmd/wallet receive 'openid-credential-offer://?credential_offer=...'
go run ./cmd/wallet list
```

`receive` prints the authorization URL: open it, approve, and the
wallet picks up the redirect on `http://127.0.0.1:8765/callback` and
stores both credentials (with their holder keys) in `wallet-store/`.
Add `-headless` to approve automatically.

`cmd/wallet-provider` creates the demo's **stand-in Wallet Provider**
key. The issuer registers one wallet client (`passport-vdc-wallet`) and
accepts Wallet Attestations signed by that key; the wallet uses the
private half to attest itself — which a real wallet would never hold. The
key, the TLS certificate and the wallet store are all git-ignored; the
store keeps holder keys unencrypted.

The issuer runs over HTTPS even locally because the library's wallet
can't yet discover a loopback `http` issuer: `wallet.Config.Fetch.AllowLoopbackHTTP`
lets it fetch the metadata, but decoding `credential_issuer` as a
`fapi.URL` always requires `https`.

### The issuance flow

| Step | Endpoint | What happens |
|---|---|---|
| Upload | `POST /passport` | gmrtd verification → a transaction T holding the `Evidence` (in memory, 10 minutes) → a credential offer with `issuer_state` = T |
| PAR | `POST /par` | fapigo verifies Wallet Attestation + PoP and DPoP; this app records `request_uri` → T from the form's `issuer_state` |
| Approve | `GET /authorize`, `POST /authorize/decision` | shows the passport holder's name; approval authorizes **subject = T**, granting the scopes the wallet requested |
| Token | `POST /token` | DPoP-bound access token with `sub` = T |
| Credential | `POST /nonce`, `POST /credential` | the token's `sub` finds T's `Evidence`; the requested configuration (`passport_mdoc` or `passport_sdjwt`) is encoded, bound to the wallet's proof key and signed |

`issuer_state` has to be captured at PAR because fapigo doesn't surface
extension values at the authorization step (see the library's
`issuer/authorization_server.go`). Only plain form parameters are read,
so a wallet sending `issuer_state` inside a signed request object isn't
supported.

Also served: `/.well-known/openid-credential-issuer` (signed metadata),
`/.well-known/oauth-authorization-server`, `/jwks`, and the SD-JWT VC
type metadata at the `vct` URL (`/vct/passport/1`).

**Demo shortcuts:** the approval step doesn't authenticate the holder,
so `issuer_state` is a bearer secret until the transaction expires; the
signing key and certificate are generated per process (a restart
invalidates issued credentials); everything is in memory.

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
`TestEndToEnd_IssuesBothFormats`: the demo wallet, built on a real
fapigo client and oid4vcgo wallet, against the demo issuer over TLS,
with synthetic passport evidence) — until gmrtd provides a
synthetic test passport (a test CSCA → DSC → SOD
generator, planned for gmrtd itself).

## Layout

| Package | Role |
|---|---|
| `passport` | gmrtd → verified `Evidence`; the birth-date rule |
| `credential` | `Evidence` → `mdoc.Claims` / `sdjwtvc.Claims`; validity and age claims |
| `issuerapp` | the OID4VCI issuer: fapigo Authorization Server + oid4vcgo Issuer + upload page |
| `walletprovider` | the stand-in Wallet Provider that signs Wallet Attestations |
| `walletapp` | the wallet: offer → discovery → HAIP Authorization Code flow → credentials; browser or headless approval; credential store |
| `cmd/issuer`, `cmd/wallet`, `cmd/wallet-provider` | runnable binaries |

## Roadmap

1. ~~**Issuer**~~ — done.
2. ~~**Wallet CLI**~~ — done.
3. **Verifier** — one request accepting either format, and both trust
   paths side by side.
4. **iOS wallet**, then **live NFC capture** with an issuer-chosen Active
   Authentication challenge.
