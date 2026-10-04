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
   (all raw LDS files)   (gmrtd Passive       (identity,      └─► credential.SDJWTClaims ─► issuer.RequestCredential ─► dc+sd-jwt
                          Authentication)      portrait, file)
```

Both credentials carry the same content:

- **Identity attributes** — names, date of birth, age claims, sex,
  nationality, issuing country, document number, expiry.
- **The portrait** — DG2's face image as a displayable JPEG (mdoc
  `portrait` bytes, SD-JWT `picture` as a `data:image/jpeg` URL).
  Passports usually store it as JPEG 2000, which browsers can't show, so
  the issuer converts it (pure Go, [go-jpeg2000](https://github.com/mrjoshuak/go-jpeg2000)).
  It's the demo issuer's copy, not country-signed: a verifier that
  needs the country's signature requests the passport file instead.
  Omitted when the passport has no usable face image.
- **The passport file** — `gmrtd_verifiable_doc`: the uploaded gmrtd
  portable file, byte-for-byte. It holds every data group read from the
  chip (DG1 MRZ, DG2 photo, DG11 and the rest, plus the SOD) and any
  chip authentication evidence. It's **one** selectively disclosable
  element (mdoc) or claim (SD-JWT): withheld unless asked for, but
  disclosing it discloses all of that.

## Two ways to trust the credential

A verifier can choose:

1. **Trust this demo's issuer.** Check the credential's issuer signature
   and use the identity attributes. The issuer verified the passport
   before issuing, but the country did not sign this credential — the
   issuer is making a new assertion.
2. **Trust only the issuing country.** Request `gmrtd_verifiable_doc`
   and re-verify it with one call — `passport.Verify`, i.e. gmrtd's
   `verifier.Verify` — against its own CSCA trust anchors. The verifier
   needs no knowledge of the individual data groups: gmrtd runs Passive
   Authentication and its document checks, replays any chip
   authentication evidence, and returns the parsed identity and photo.
   The price is disclosure: the verifier receives the whole passport
   content, not a chosen subset.

The verifier page also offers **several passports**: the first path,
for a group such as a family travelling together. Its DCQL query sets
`multiple` (OpenID4VP 1.0 §6.1), so the wallet may answer with several
credentials. The web and CLI wallets let the holder choose whose
passports to share, all in one format; the verifier checks each and
lists every person. It accepts up to ten, and refuses one person
presented twice. Every other request takes exactly one credential.

What the second path does and doesn't give you:

- It removes trust in this issuer **for the data**: the issuer can't
  invent attributes the country didn't sign.
- Chip authenticity is replayed from evidence recorded when the chip
  was read: it shows a genuine chip answered then, not that it's
  present now.
- It does **not** remove trust in the issuer **for holder binding**.
  Passport data can be copied; what ties it to the person presenting it
  is the credential's device key (mdoc `DeviceKey` / SD-JWT `cnf`) plus
  the issuer's checks at issuance.

## Limitations to be aware of

- **A portable file proves the data is authentic, not that the uploader
  holds the passport.** When the file carries chip authentication
  evidence it's reported, but that only shows a genuine chip was read at
  some point. Binding the read to this issuance needs an issuer-chosen
  Active Authentication challenge (gmrtd's `reader.Reader.WithAAChallenge`, checked with `verifier.Verifier.WithAAChallenge`) —
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
  threshold the holder crosses.
- **Expired passports are accepted.** Expiry ends a passport's use for
  travel; it doesn't make the chip data any less authentic, and Passive
  Authentication verifies it just the same. The credential's validity
  isn't tied to the passport's: it carries `expiry_date`, and the issuer
  and verifier pages flag an expired passport, so a verifier that needs
  a current document checks that claim.
- **MRZ names may be truncated or transliterated.** `names_from_mrz`
  says when names came from the MRZ rather than DG11.
- **The passport file is all-or-nothing.** Disclosing it hands the
  verifier every data group — photo, DG11 personal details, the lot.
  Its SOD is also unique to the passport, so it links presentations
  across verifiers, whatever the credential format.
- **The file format is gmrtd's own** (`gmrtd-verifiable-doc`, versioned),
  not an ICAO standard encoding: a verifier needs gmrtd — a compatible
  version — to read it.
- **Identifiers are provisional.** The doctype, namespaces and claim
  names (in `credential/names.go`) should be aligned with ISO/IEC
  23220-4's DTC namespace before this is presented as interoperable.

## Running the demo

From this directory (`examples/passport-vdc`), one command starts the
issuer, verifier and web wallet together, with the Wallet Provider's
service the wallets get their attestations from:

```sh
go run ./cmd/demo
```

It prints the URLs and runs until Ctrl-C. What should survive a
restart is kept in `.demo-state/`: the TLS certificate the servers
share, the stand-in Wallet Provider's key (only its service reads it), the issuer's CA, signing keys
and status list, and the wallet's credentials. So a restart keeps your
credentials verifying and your revocations in force, and the browser
doesn't warn again. `go run ./cmd/demo -reset` deletes it and starts
over. It holds credentials made from your passport, and their holder
keys, unencrypted: delete it (or `-reset`) when you're done.

**1. Open the demo in a browser.** The servers use a self-signed
certificate. The easiest way past it:

```sh
go run ./cmd/demo -open
```

This starts Chrome (or Chromium; `-chrome` gives its path) on the three
URLs, in a separate profile under `.demo-state/chrome-profile` that
accepts the demo's certificate — only that one, identified by its key —
without a warning. Chrome shows a banner about an unsupported
command-line flag; that's expected. Use that window for the whole demo.

Otherwise, in the browser you'll use, open https://127.0.0.1:8543,
https://127.0.0.1:9443 and https://127.0.0.1:7443 and accept the warning,
or trust `.demo-state/tls-cert.pem`. The certificate is reused on every
run, so this is once. The issuer uses 8543 rather than 8443 so it doesn't
collide with a locally running OIDF conformance suite.

**2. Issue, in the browser.** Use the same browser throughout: the
issuer's redirect back is bound to the browser that started receiving
(see below).

1. Open https://127.0.0.1:8543 and upload a gmrtd portable passport
   file. It's verified against gmrtd's built-in ICAO CSCA master list.
2. The offer page shows a QR code, an **Open in web wallet** button and
   a six-digit confirmation code. Click **Open in web wallet**, confirm,
   and continue to the issuer.
3. On the issuer's approval page, enter the confirmation code and
   **Approve**. You're back in the wallet with both credentials, each
   showing the passport photo.

**3. Verify.**

1. Open https://127.0.0.1:9443, choose a trust path, click
   **Open in web wallet**, then **Review the request**. (The wallet
   fetches a request only when you ask it to, so another site linking
   to it can't make it contact anything.)
2. The wallet shows who's asking and exactly which claims each format
   would disclose; choose a format and **Share** (or **Decline**).
3. The wallet brings you back to the verifier's page, which shows the
   verified claims, "Revocation status: valid" and, for the country
   trust path, the ICAO Passive Authentication result.

**No passport? Issue gmrtd's sample passport, unchecked.** Click
**Issue gmrtd's sample passport without checking it** on the upload page
instead of choosing a file (the counter and review options apply to it
too). It's gmrtd's `document.SampleDocument`: ICAO 9303-10 worked-example
data groups, with an unrelated real security object. Its issuing
country is "UTO", which no country's CSCA covers, so Passive
Authentication fails before it checks a hash or a signature.

The button simulates an issuer that skipped Passive Authentication. The
sample is issued as an ordinary passport credential, so it shows the
difference between the two trust paths:

- **Trust the issuer:** the verifier accepts the sample's claims ("JOHN
  J SMITH"), because the credential carries the demo issuer's valid
  signature. It can't know the issuer didn't check.
- **Trust only the issuing country:** re-verifying the passport file
  fails Passive Authentication, because no country signed this data.

Only the issuer's own pages know. The offer page reads "Sample passport
— issued without checking", and the review and status pages mark its
credentials. The sample isn't one consistent person either: DG11's names
come with DG1's sex and nationality, and the document expired in 2012.

`go run ./cmd/demo` offers it, and `cmd/issuer` does with
`-allow-sample-document`. Never turn it on where anyone else relies on
the issuer.

**Optional: issue at the counter.** Tick **Issue at the counter** when
uploading. The offer then carries a pre-authorized code (OID4VCI's other
grant, §3.5), and the page shows a PIN instead of a confirmation code.
In the web wallet, open the offer and enter the PIN: it's received at
once, with no trip to the issuer's approval page. The CLI wallet asks
for the PIN on the terminal (or takes `-headless -code <PIN>`).

**Optional: issue after a review.** Tick **Hold for an operator's
review** when uploading. The wallet then gets no credentials at once:
the issuer defers them (OID4VCI 1.0 §9), and the web wallet lists them
under **Waiting for the issuer**. Approve or deny each on the issuer's
review page (https://127.0.0.1:8543/review), then click **Check now**
in the wallet: an approved credential is stored, a denied one is
dropped. The CLI wallet waits, polling, until you decide.

**4. Revoke.** On the issuer, open **Issued credentials and revocation**
(https://127.0.0.1:8543/status) and **Revoke** one credential. Verify
again sharing that format: the verifier rejects it as revoked, while
the other format is still accepted. The verifier fetches the status
list on every check, so a revocation applies at once.

**From the terminal (CLI wallet)** — `-state` points it at the demo's
store and trust files, so both wallets see the same credentials; like
the web wallet, it shows who's asking and what they'd see, and asks
before sharing:

```sh
go run ./cmd/wallet receive -state .demo-state 'openid-credential-offer://?credential_offer=...'   # the offer page's link
go run ./cmd/wallet list -state .demo-state
go run ./cmd/wallet present -state .demo-state [-format dc+sd-jwt] [-yes] 'openid4vp://?client_id=...&request_uri=...'   # the verifier page's link
```

The CLI's `receive` prints the authorization URL: open it, approve with
the confirmation code, and it picks up the redirect on
`http://127.0.0.1:<port>/callback`, listening on a port the operating
system picks for that authorization (RFC 8252 §7.3; the issuer
registers the wallet as a native app, so it accepts any loopback port).
Add `-headless -code <confirmation code>` to approve automatically.

The issuer's redirect back is bound to the wallet that asked (fapigo's
protection against login CSRF, RFC 9700 §4.7): the web wallet sets a
session cookie when it sends the browser to the issuer, so the approval
must be completed in that same browser; the CLI's flow is bound to its
own process.

### Running the servers separately

To run each server on its own (for example to restart or debug one),
start them in this order from this directory, each in its own
terminal. Each reads the `.pem` files the previous one wrote here, and
keeps everything in memory:

**Start the four servers:**

```sh
go run ./cmd/wallet-provider     # terminal 1: https://127.0.0.1:6443 — writes wallet-provider.pem (once), wallet-provider-ca.pem, wallet-provider-tls.pem
go run ./cmd/issuer              # terminal 2: https://127.0.0.1:8543 — writes issuer-tls.pem, issuer-ca.pem; trusts wallet-provider-ca.pem
go run ./cmd/verifier            # terminal 3: https://127.0.0.1:9443 — writes verifier-tls.pem, verifier-ca.pem; trusts issuer-ca.pem and issuer-tls.pem
go run ./cmd/webwallet           # terminal 4: https://127.0.0.1:7443 — writes webwallet-tls.pem; trusts issuer-ca.pem, verifier-ca.pem and the other TLS certificates
```

The wallets keep only credentials whose issuer certificate chains to a
trusted issuer CA (`-trust-issuer-ca`, default `issuer-ca.pem`), and
answer only verifiers whose request-signing certificate chains to a
trusted verifier CA (`-trust-verifier-ca`, default `verifier-ca.pem`).
The verifier trusts the issuer's CA (`-issuer-ca`) for credentials and
its TLS certificate (`-trust`, default `issuer-tls.pem`) for fetching
its status list.

**Restarting.** Every start generates a new CA and TLS certificate, and
the others load them only when they start. The Wallet Provider keeps
its key and CA in `wallet-provider.pem`, but not its TLS certificate:
after restarting it, restart the web wallet. After restarting the issuer,
restart the verifier and then the web wallet; after restarting the
verifier, restart the web wallet. Credentials issued by an earlier
issuer run no longer verify (the CA they chain to is gone), so delete
`wallet-store/` and issue again.

**Accept the certificates.** The servers use self-signed
certificates: in the browser you'll use, open https://127.0.0.1:8543,
https://127.0.0.1:9443 and https://127.0.0.1:7443 once each and accept
the warning (or trust the written `.pem` files). The issuer uses 8543
rather than 8443 so it doesn't collide with a locally running OIDF
conformance suite.

The wallets keep credentials (with their holder keys) in `wallet-store/`
here; the CLI wallet reads it by default. Stop the servers with Ctrl-C.

### The stand-in Wallet Provider

`cmd/demo` (into `.demo-state/wallet-provider.pem`) and
`cmd/wallet-provider` run the demo's **stand-in Wallet Provider**: an
HTTPS service holding a key, and a certificate for it from a demo
Wallet Provider CA, naming
the provider's identifier (`-wallet-provider-issuer`) as a URI SAN. The
issuer registers one wallet client (`passport-vdc-wallet`, with both
wallets' redirect URIs), and trusts that key through the CA
certificate: every attestation it signs carries the provider's
certificate as `x5c`, which must chain to the CA.

A Wallet Attestation is accepted only if that certificate names the
Wallet Provider the client is registered with (fapigo's
`AttesterIssuerInCertificate`), so a CA certifying several Wallet
Providers can't let one attest for another's wallets. A
`wallet-provider.pem` created before this has no such name; delete it
and rerun `cmd/wallet-provider`.

- **Wallet Attestations** authenticate the wallet at PAR and the token
  endpoint (HAIP 1.0 §4.4.1; fapigo's `X5CAttesterChain`).
- **Key Attestations** prove each holder key. Each credential
  request must prove its holder key with a Key Attestation: the
  `attestation` proof type (OID4VCI 1.0 Appendix F.3), which is the
  only proof type the issuer offers. The attestation carries the
  provider's certificate as `x5c` and the issuer's `c_nonce`, as HAIP
  1.0 §4.5.1 requires.

The wallets never hold the provider's key. They ask its service
(`walletprovider.Client`, `-wallet-provider-url`):

- `POST /wallet-attestation` with the wallet's `client_id` and the
  instance key it proves possession of at PAR and the token endpoint,
  for a Wallet Attestation.
- `POST /key-attestation` with fresh holder keys and the issuer's
  `c_nonce`, for a Key Attestation over them.

It attests only the demo wallet's `client_id`, and, unlike a real
Wallet Provider, any key it's sent without checking who's asking: a
real one would first check platform evidence (app integrity, keys in
secure hardware) that the request comes from a genuine instance of its
wallet. The provider files, the TLS certificates and the wallet store
are all git-ignored; the store keeps holder keys unencrypted.

Run separately, the servers each generate a self-signed certificate
for `127.0.0.1` and `localhost`, and the wallets trust all of them, so
any one server's TLS key could impersonate the others to the wallets.
That's a local-demo shortcut; a deployment's servers have certificates
for their own names.

The servers run over HTTPS even locally, as a real deployment would, so
the demo wallets reach them with `wallet.Config.Fetch.AllowLoopbackHosts`
(https to literal loopback hosts only). The library's wallet can
discover a loopback `http` issuer too, with `AllowLoopbackHTTP`; the
demo verifier's `response_uri`, though, must be `https`.

### The issuance flow

| Step | Endpoint | What happens |
|---|---|---|
| Upload | `POST /passport` | gmrtd verification → a transaction T holding the `Evidence` (in memory, 10 minutes, at most 100 at once) → a credential offer with `issuer_state` = T, as a link and a QR code, and a six-digit confirmation code |
| PAR | `POST /par` | fapigo verifies the Wallet Attestation (its `x5c` chain to the Wallet Provider CA) + PoP and DPoP; the Wallet sends the offer's `issuer_state` (T) |
| Approve | `GET /authorize`, `POST /authorize/decision` | reads T back from the interaction request's `issuer_state`, seals the interaction (handle and request) into an encrypted cookie on this browser (fapigo's `interactioncookie`), then asks for the confirmation code (the page shows no passport data). The decision is read back from that cookie, so it can't name another offer, and only that browser can submit it; a cross-origin post is refused. Approval with the right code **claims T** — no other authorization can reach it — and authorizes **subject = T**, granting the scopes the wallet requested |
| Token | `POST /token` | DPoP-bound access token with `sub` = T |
| Credential | `POST /nonce`, `POST /credential` | the request and response are both encrypted (OID4VCI 1.0 §10, required by the issuer's metadata: the credential carries passport data); the token's `sub` finds T's `Evidence`; the requested configuration (`passport_mdoc` or `passport_sdjwt`), if not already issued for T, is encoded, bound to the key the Key Attestation attests, given its own random index in the issuer's Token Status List, and signed; once both are issued, T and its passport data are dropped. The wallet checks each credential before keeping it: issuer signature chaining to `issuer-ca.pem`, bound to its own holder key, and the offered vct or doctype |
| Notify | `POST /notification` | the wallet reports each credential it kept as `credential_accepted`, or one that failed its checks as `credential_failure` (OID4VCI 1.0 §11); the status page lists what the wallets reported |

Also served: `/.well-known/openid-credential-issuer` (signed metadata),
`/.well-known/oauth-authorization-server`, `/jwks`, the SD-JWT VC
type metadata at the `vct` URL (`/vct/passport/1`), and the Token
Status List every credential references (`/statuslists/1`).

### The pre-authorized code flow

An offer issued at the counter skips the browser: the issuer has already
checked who it's for (here, whoever uploaded the passport), so the offer
carries a pre-authorized code bound to the transaction, and the holder
needs only the PIN, given separately.

| Step | Endpoint | What happens |
|---|---|---|
| Offer | `POST /passport` | the transaction T is claimed at once; a pre-authorized code is stored with T as its subject and the six-digit PIN as its `tx_code` |
| Token | `POST /token` | fapigo/server reads the request once (`TokenEndpointRequestFromHTTP`), and `grant_type` routes it. fapigo/server authenticates the wallet by its Wallet Attestation and PoP (`AuthenticateAttestedClient`, HAIP 1.0 §4.4.1), refuses a `client_id` naming another client, and verifies the DPoP proof with the same replay record and nonce policy as its own grants (`VerifyTokenRequestBinding`). Only then does `issuer.ExchangePreAuthorizedCode` (`issuer.VerifiedPreAuthorizedCode`) redeem the code and PIN (five wrong PINs void it). The token is signed with the Authorization Server's keys, names T as its subject and the wallet as its client, and is DPoP-bound |
| Credential | `POST /nonce`, `POST /credential` | as for the authorization code flow, the wallet presenting the token with `wallet.DPoPResourceClient` |

The Authorization Server's metadata lists the grant in
`grant_types_supported` (fapigo/server's `Config.AdditionalGrantTypes`).
The wallet's Wallet Attestation and PoP come from the same fapigo/client
it uses for the authorization code flow (`ClientAttestationHeaders`).

### Deferred issuance

A passport uploaded for review isn't issued at once. Each Credential
Request still has its proof and nonce checked, but the issuer answers
202 with a `transaction_id` and a polling `interval` instead of the
credential (OID4VCI 1.0 §9), keeping a copy of the passport's
`Evidence` for that request until an operator decides, for at most an
hour.

| Step | Endpoint | What happens |
|---|---|---|
| Defer | `POST /credential` | `issuer.CredentialRequest.Defer`: the transaction is bound to the access token's client and subject, so only that wallet's token can poll it |
| Decide | `GET /review`, `POST /review/decision` | the operator approves or denies; the page shows the issuing country, passport expiry and chip-authentication evidence, not names or the document number |
| Poll | `POST /deferred_credential` | the Deferred Credential Endpoint's `Resolve` hook carries out the decision on the wallet's next poll: an approved credential is issued (with its own status list index) and returned; a denied one is answered `credential_request_denied`; an undecided one is answered 202 again |

The wallet keeps its access token in memory while it polls, so a
deferred credential the web wallet is waiting for doesn't survive a
wallet restart.

### Revocation

Each credential carries a reference to the issuer's Token Status List
(draft-14): an SD-JWT VC in its `status` claim, an mdoc in its MSO's
`status`. Every credential gets its own random, unused index (HAIP 1.0
§6.1). The issuer serves the list at `/statuslists/1` as a JWT, or as a
CWT when the request's `Accept` asks for `application/statuslist+cwt`
(what an mdoc's reference uses), signed by the document signer with its
certificate in `x5c` / `x5chain` (HAIP 1.0 §6.1).

The issuer's **Issued credentials** page (`/status`, linked from its
home page) lists every issued credential by index, format and time,
and revokes one with a button. The verifier checks every presented
credential against the list: the token's certificate must chain to the
issuer CA, and the credential's entry must be valid. A revoked,
suspended or uncheckable credential is rejected, and a valid one shows
"Revocation status: valid" on the result page. The list is cacheable
for 60 seconds.

**Demo shortcuts:**

- **The holder isn't authenticated.** An offer is redeemed once, by one
  wallet: the first approval with the right confirmation code claims
  it, its DPoP-bound access token can fetch each format once, and five
  wrong codes void it. So a leaked offer link on its own is useless. But
  the code is shown next to the QR code, so whoever sees the offer page
  — over a shoulder, in a screenshot — can still redeem it first, with
  any wallet the Wallet Provider attests, and get the passport's data
  in a credential bound to *their* key.
- The signing keys and certificates (one for credentials, one for the
  issuer metadata, under one demo CA) are unencrypted files in
  `.demo-state/` under `cmd/demo`, and generated per process under
  `cmd/issuer` (where a restart invalidates issued credentials). Offers,
  sessions and tokens are in memory either way.
- **Anyone who can reach the issuer can revoke.** The `/status` page has
  no login; it refuses only cross-origin form posts. It records no
  passport data, and names credentials by a random handle rather than
  their status list index, so it can't be used to match a presented
  credential to when it was issued. Under `cmd/demo` it's kept across
  restarts; under `cmd/issuer` it's forgotten (as are the signing keys).
- **The approval page doesn't show the passport.** It's reached with the
  offer link, before the confirmation code is checked, so it only names
  the wallet and the formats; the uploader saw the passport on the offer
  page.
- **Key Attestations assert nothing about key storage.** They leave out
  `key_storage` and `user_authentication`, because the demo's holder keys
  are ordinary software keys. The issuer checks who attested a key, not
  how well it is protected.

A production issuer would authenticate the holder at the approval step
instead, for example by re-reading the passport over NFC with an
issuer-chosen Active Authentication challenge.

### The verification flow

The verifier sends **one** request accepting the credential in either
format (a DCQL credential set with one option per format); the wallet
answers with whichever it holds (`-format` picks when it holds both).
It checks:

| | Trust the issuer | Trust only the issuing country |
|---|---|---|
| Requested | `family_name`, `given_name`, nationality, `age_over_18`, and the portrait when there is one (DCQL `claim_sets`) — shown on the result page | `gmrtd_verifiable_doc` — the whole passport file, photo included |
| Issuer signature | verified, chained to the demo issuer's CA (`issuer-ca.pem`) | verified, likewise |
| Revocation | the issuer's Token Status List says the credential is valid | likewise |
| Holder binding | key-binding / device signature over the verifier's nonce | likewise |
| Data trusted because… | the demo issuer signed it | gmrtd re-verifies the file (Passive Authentication against the CSCA master list, document checks): the country signed it. The result page shows the file's photo and chip authenticity |

The request is a signed Request Object (`x509_hash` client identifier,
certificate issued by a per-process demo verifier CA) fetched from its
`request_uri`; the response is an encrypted `direct_post.jwt`, routed
to its request by the JWE's key ID. Selective disclosure is real: in
either mode the verifier receives only what it asked for — though in
the ICAO mode that's the whole passport file.

Each request also names the issuer CA in DCQL `trusted_authorities`
(its Authority Key Identifier, the `aki` type HAIP 1.0 §5 requires):
the wallet offers only credentials whose issuer certificate that CA
issued, and the verifier checks it again on the response.

Each request made on the verifier's page can be answered two ways:

- **On the same device** (**Open in web wallet**), the flow HAIP 1.0
  §5.1 requires: when the answer verifies, the verifier holds it and
  replies with a `redirect_uri` carrying a fresh `response_code`
  (OpenID4VP §8.2, §13.3). The wallet sends the browser there, and the
  verifier releases the result only if that browser presents the
  session cookie set when the request was made. A redirect back in any
  other browser session is rejected, and an answer whose redirect never
  comes back is never accepted.
- **From another device** (the QR code, or the CLI wallet), a separate
  request: there is no redirect back, and the verifier's page shows the
  result once the answer verifies.

The result page's address uses a random ID that never leaves the
verifier, separate from the `state` the wallet sees (OpenID4VP
§14.3.3), and for a request made in a browser it opens only in that
browser (the session cookie), so the request link (or its QR code)
doesn't reveal the result. Anyone can encrypt a response to the
request's public key, so a response that fails to verify leaves the
request open; the first one that verifies closes it.

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
evidence, whose fake passport file must fail the ICAO check) — until gmrtd provides a
synthetic test passport (a test CSCA → DSC → SOD
generator, planned for gmrtd itself).

## Layout

| Package | Role |
|---|---|
| `passport` | gmrtd → verified `Evidence` (the issuer's upload check, and the verifier's ICAO check of a disclosed file); the birth-date rule; the portrait |
| `credential` | `Evidence` → `mdoc.Claims` / `sdjwtvc.Claims`; validity and age claims |
| `issuerapp` | the OID4VCI issuer: fapigo Authorization Server + oid4vcgo Issuer + upload page |
| `walletprovider` | the stand-in Wallet Provider: signs Wallet Attestations and Key Attestations, as an HTTPS service (`Handler`) the wallets call (`Client`) |
| `walletapp` | the wallet, on oid4vcgo's `walletflow` sessions: receive (offer → discovery → HAIP Authorization Code flow or pre-authorized code → credentials) and present (OpenID4VP, selective disclosure); credential store |
| `verifierapp` | the OpenID4VP verifier: either-format requests, both trust paths, revocation checks |
| `webwallet` | the browser wallet: credential cards, receive via the issuer's approval page, consent before presenting |
| `cmd/demo` | runs the issuer, verifier and web wallet together, with persistent state |
| `cmd/issuer`, `cmd/verifier`, `cmd/webwallet`, `cmd/wallet`, `cmd/wallet-provider` | runnable binaries |

## Roadmap

1. ~~**Issuer**~~ — done.
2. ~~**Wallet CLI**~~ — done.
3. ~~**Verifier**~~ — done.
4. **iOS wallet**, then **live NFC capture** with an issuer-chosen Active
   Authentication challenge.
