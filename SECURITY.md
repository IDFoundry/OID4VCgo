# Security Policy

OID4VCgo implements OpenID4VCI + OpenID4VP under the HAIP 1.0 profile —
protocol code intended to run in high-assurance, security-critical
deployments (digital identity wallets, credential issuers and verifiers).
If you believe you've found a vulnerability (a protocol violation, a
cryptographic weakness, an authentication/authorization bypass, or
anything else with security impact), please report it privately rather
than opening a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the **Security** tab on
this repository and select **Report a vulnerability**. This creates a
private advisory visible only to maintainers until a fix is ready, rather
than a public issue.

If private reporting isn't available for any reason, open a regular issue
asking a maintainer to open a private channel — please don't include
vulnerability details in a public issue.

## Supported versions

OID4VCgo is under early active development and pre-1.0 (APIs may still
change) — see the [latest release](https://github.com/IDFoundry/OID4VCgo/releases/latest)
for the current tag. Reports against `main` or the latest tag are the
ones we can act on.

## Certificate revocation

A verified X.509 chain says nothing about a certificate its CA has since
revoked. The verifier's issuer trust checks revocation:
`verifier.X5CIssuerKeyResolver` and `verifier.X5ChainIssuerKeyResolver`
require a `Revocation` (a `certrevocation.Checker`) and accept a
credential only through a verified path from its issuer's certificate
to a trust anchor on which no certificate is revoked. Supply your CAs'
CRLs with `certrevocation.CRLs{Lists: ...}`: fetch each CA's CRL from
the distribution point its certificates name (ISO/IEC 18013-5 Annex B
makes one mandatory for an IACA's), keep the parsed lists in memory and
refresh them before their nextUpdate. `certrevocation.Refresher` does
this for you: give it the distribution point URLs and the CA
certificates that sign their CRLs, run `go r.Run(ctx)`, and pass
`r.Checker()`. It fetches only from public addresses by default, keeps
the last good list when a fetch fails, and refuses a list that isn't
signed by one of those CAs or is older than the newest it has accepted
from that CA, so an unreachable or tampered-with distribution point
(CRLs are often served over plain http) can't evict or roll back a good
list. Bind each URL to its CA with `URLIssuers`, and persist what
`OnAccept` hands over to pass back as `Floors` on restart. A missing or
stale CRL fails closed. A trust anchor that isn't self-signed, a
pinned leaf or an intermediate CA among the roots, is checked against
its CA's CRL too, so that CA's certificate must be in `CRLs.Issuers`
(`r.Checker()` sets the Refresher's own `Issuers` there), or the
anchor is refused. Where revocation is checked, put only self-signed
roots in the trust anchors, not a CA's whole chain: an intermediate
there needs its own CA's CRL. The Refresher's rollback floor is kept
per CA, by name and key, so one CA can't raise another's by using its
name; `NewRefresher` refuses two `Issuers` by one name with different
keys unless `AllowSameNameIssuers` is set, as for a CA that re-keyed
under its name.
`certrevocation.NoCheck{}` declines the check explicitly, for
short-lived certificates or a trust framework that removes compromised
issuers from the anchor set itself.

Every other X.509 trust decision can check revocation too, through a
`certrevocation.Checker` beside the roots it applies to. Each role is
configured on its own, since `CRLs` fails closed for a CA it has no
current list from and an ecosystem may publish CRLs for some roles and
not others. A wallet must choose for each role it uses: outside
`Development`, `walletflow.New` refuses a role whose roots are set
without a Checker (`certrevocation.NoCheck{}` to decline), as
`wallet.New` does under `wallet.AssuranceProduction` for issuer metadata
and an `X5CVerifierRoots`, and the mobile `NewWallet` refuses a role
named in neither `revocation` nor `no_revocation_check`. Elsewhere — a
development wallet, or the standalone functions and reader-side options
below — a nil Checker checks nothing, and the certificate is trusted
from its chain and validity period alone:

- a wallet's issuer trust on receipt
  (`wallet.VerifyIssuedCredentialParams.IssuerRevocation`,
  `walletflow.Config.IssuerRevocation`);
- a Verifier's request-signing certificate
  (`wallet.X5CVerifierRoots.Revocation`);
- signed issuer metadata (`wallet.Config.IssuerMetadataRevocation`,
  `walletflow.Config.IssuerMetadataRevocation`);
- a registrar's certificate (`registration.Registrars.Revocation`,
  `walletflow.Config.RegistrarRevocation`);
- an mdoc reader's certificate (`proximity.ReaderTrust.Revocation`,
  `mdocdcapi.ReaderTrust.Revocation`,
  `walletflow.Config.MdocReaderRevocation`);
- a proximity reader's document signer
  (`proximity.WithIssuerRevocation`, required at every assurance
  level);
- a status list signer (`statuslist.VerifyOptions.Revocation`,
  `walletflow.Config.StatusRevocation`; `verifier.StatusPolicy`
  passes it on from its `statuslist.Checker`, and requires it under
  `verifier.AssuranceProduction`);
- a key attestation's or jwt proof's certificate, at the issuer
  (`issuer.X5CAttestationVerifier.Revocation`,
  `issuer.X5CProofBindingKeyResolver.Revocation`), which
  `issuer.AssuranceProduction` requires, as `certrevocation.NoCheck{}`
  to decline.

The mobile library exposes them as the wallet's and reader's `crls` and
`revocation` configuration, and the wallet's `no_revocation_check`,
with `SetCRLs` to replace the lists before they expire
(`mobile/ABI.md`). `dcql.AKITrustedAuthoritiesChecker` checks none of
its own: the verifier hands it the path its issuer key resolver already
checked. A Wallet Attestation's signer is verified by
FAPIgo's server (`server.X5CAttesterChain`), whose `Revocation`
(`server.ClientCertificateCRLs`, or
`server.NoClientCertificateRevocationCheck{}` to decline) is required
since FAPIgo v0.62.0; the attestation's own status claim is checked by
`server.Dependencies.ClientAttestationStatus`, which production
requires (`haip.WalletAttestationStatusList` for a Token Status List,
`server.NoClientAttestationStatusCheck{}` to decline). A key
attestation's status claim is checked by
`issuer.Dependencies.AttestationStatus`
(`issuer.StatusListAttestationStatus`). Both bind the Status List
Token's signer to the attestation's own key, or with
`ListSignerUnderAttesterCA` to the CA that issued its certificate. Since
FAPIgo v0.66.0 it also refuses a signer certificate issued for another
role (`server.DefaultAttesterLeafPolicy`) and an `x5c` carrying the
trust anchor.

## Known limitations

These are risks the library documents rather than closes: most because
closing them is up to a party it doesn't control, the rest because
they're not yet closed in the library.

- **Access tokens not restricted to one Credential Issuer.** A wallet
  asks for its access token for the offer's Credential Issuer (RFC 8707
  `resource`), but only the Authorization Server can restrict the token
  to that issuer: one that doesn't addresses it to itself, and every
  Credential Issuer it serves may take it for its own. Any offer's
  metadata can name any Authorization Server (`authorization_servers`),
  so the Credential Issuer a wallet sends its token to needn't be one
  the Authorization Server knows of or trusts. Two cases:
  - Under `walletflow.ProfileOpenID4VCI` a wallet takes a Bearer access
    token where the Authorization Server issues one (OpenID4VCI §13.2).
    The issuer the wallet presents it to can redeem it at another
    Credential Issuer using the same Authorization Server, for a
    credential about the End-User. `walletflow.ProfileHAIP` takes only
    DPoP-bound tokens, which the issuer can't present without the
    wallet's DPoP key.
  - DPoP doesn't stop the token's own holder. A token's subject is
    meaningful to the Credential Issuer it was issued for (a
    pre-authorized code's `Subject`, or the user its consent step
    signed in), and another Credential Issuer on the same Authorization
    Server, taking the token for its own, issues its own holder of that
    subject value's credential, to the token's holder. The wallet
    chooses the token's `resource`: a wallet that isn't honest asks,
    for one Credential Issuer's offer, for a token addressed to
    another. The library closes this only where the deployment wires
    all four of:
    - each `issuer.Issuer` refuses a token whose audience doesn't name
      it (`AuthorizedRequest.Audience`, which `issuer/fapiresource`
      reports, and which `AssuranceProduction` requires;
      `Config.AcceptedAccessTokenAudiences` opts out for an
      Authorization Server serving it alone, one of its
      `AuthorizationServers`). Set `serverresource.Options.Resource` to
      each Credential Issuer's identifier; a verifier of your own must
      report the audience;
    - each Credential Issuer's consent step grants only that issuer
      (`GrantedAuthorization.Resources` from
      `Issuer.AuthorizationResources`), and denies a request naming
      another resource. Left nil, the Authorization Server grants
      every resource the wallet named;
    - each pre-authorized token is issued with
      `RedeemedPreAuthorizedCode.Resource` alone, and so is its refresh
      token (`server.IssueRefreshTokenRequest.Resources`), and the
      Token Request's own `resource` parameters go to
      `ExchangePreAuthorizedCodeRequest.Resources`, which refuses any
      other with `invalid_target`;
    - no Credential Issuer shares its identifier with an Authorization
      Server that serves others. Every token the Authorization Server
      issues without a resource is addressed to itself, and a
      Credential Issuer with that identifier takes it for its own,
      whichever issuer's grant it came from: a refresh token issued
      without `Resources`, or any grant from before the upgrade, then
      gets the holder of one issuer's grant another's credential. Give
      the Authorization Server an identifier of its own, or else
      confine every wallet client to the Credential Issuers with
      FAPIgo's `AllowedResources`, listing each: it then issues no
      token addressed to itself, and refuses the refresh of a grant
      made without resources with `invalid_target`. `issuer.New` can't
      tell an Authorization Server that serves others, so it can't
      refuse either setup, nor an `AcceptedAccessTokenAudiences` entry
      naming such an Authorization Server.

    `cmd/conformance-issuer`, the passport-vdc demo and `walletflowtest`
    wire all four: each is its own Authorization Server, serving no
    other Credential Issuer. Where the Authorization Server signs in
    subjects local to each Credential Issuer, a deployment missing any
    of them lets the holder of one issuer's account collect another
    issuer's holder's credentials.
- **Transaction code phishing.** A pre-authorized offer's PIN goes to
  the issuer the offer names, at `RedeemPreAuthorizedCode`, before the
  wallet sees anything that issuer signs: `IssuerRoots` judge an issuer
  only when its credential arrives. A phishing offer naming an
  attacker's issuer, beside a PIN prompt the holder believes is for a
  genuine service, hands the attacker the PIN, or a genuine offer's
  code and PIN once intercepted (OpenID4VCI 1.0's Security
  Considerations, "Transaction Code Phishing"). Credential trust is
  unaffected. So `walletflow.New` refuses a wallet that receives
  credentials without deciding which issuers' offers it takes, in one
  of three ways:
  - `Config.CredentialIssuers` lists them: `StartIssuance` refuses any
    other issuer's offer with `ErrUntrustedIssuer`, before fetching its
    metadata or asking for the PIN;
  - `IssuerMetadataRoots` with `RequireSignedIssuerMetadata` and
    `RequireIssuerMetadataName` takes only issuers whose metadata is
    signed by a certificate under those roots that names them, checked
    in `StartIssuance` too; it may be combined with the list;
  - `AllowAnyCredentialIssuer` takes any issuer's offer, and leaves
    this attack to the application.

  The mobile libraries take the same three, as `credential_issuers`,
  `issuer_metadata_roots` with `require_signed_issuer_metadata` and
  `require_issuer_metadata_name`, and `allow_any_credential_issuer`
  (Swift and Kotlin: `issuers.credentialIssuers`, `issuerMetadata`,
  `issuers.allowAnyCredentialIssuer`), and refuse an unlisted issuer's
  offer with `untrusted_issuer` (mobile/ABI.md). Either way, lead the
  PIN prompt with `Offer.CredentialIssuer`: the issuer's display name
  is its own metadata's, which unsigned metadata lets it choose.
- **Relayed key attestations.** A key attestation names no audience,
  and the `c_nonce` it carries comes from an unauthenticated Nonce
  Endpoint (OpenID4VCI 1.0 Appendix D, §7). An issuer can hand a wallet
  a `c_nonce` it fetched from another issuer, and redeem the key
  attestation the wallet returns there as the `attestation` proof type,
  for a credential about whoever its own access token names, bound to
  the wallet's keys. That works whether the wallet sent the key
  attestation as that proof type or in a jwt proof's `key_attestation`
  header, which carries the same JWT, and against any issuer that takes
  the `attestation` proof type. Two things limit it:
  - an `issuer` under production assurance refuses the `attestation`
    proof type unless `Config.AllowAttestationProofType` takes it, so by
    default only jwt proofs, whose `aud` names the issuer, are redeemed;
  - walletflow refuses an SD-JWT VC whose `iss` isn't the offer's
    (unless `Config.AllowForeignIss`). `issuer` names itself in `iss`
    when `Prepare` sets none, but SD-JWT VC doesn't require `iss`, and
    an mdoc names no issuer: for those, nothing on the wallet's side
    stops the relay but the issuers it trusts.
- **The first CRL fetched over plain http.** `certrevocation.Refresher`
  refuses a list older than one it has accepted from the same CA, or
  than its `Floors`, but nothing bounds the first list it ever accepts
  from a CA. Over plain http, an attacker on the path can answer that
  fetch with any list the CA signed that is still inside its validity,
  one predating a revocation, for as long as the CA's CRL cadence
  allows (ISO/IEC 18013-5 Annex B allows long ones for an IACA). Set
  `RequireHTTPS` where the distribution points serve https; otherwise
  seed `Floors` with a list obtained over a trusted channel.
- **DCQL integers above 2^53.** A DCQL query decoded from JSON holds its
  numbers as float64, so a `values` filter on an integer larger than
  2^53 in magnitude is rounded: it can match a claim one off it, and
  miss its own. This applies to the wallet's filter and the verifier's
  check alike.
- **Relayed cross-device requests.** In the cross-device flow nothing
  ties the device that shows a QR code to the one that started the
  Verifier's session (OpenID4VP 1.0 §14.2). An attacker can start a
  session at a genuine Verifier, show its QR code on a page of their
  own, and receive the result when the holder presents to it: the
  request is genuinely the Verifier's, so the wallet's checks pass.
  `verifier.Transactions` closes this for the same-device flow, where
  the result is released only to the browser that began the request,
  through a single-use `response_code` (HAIP 1.0 §5.1), and for the
  Digital Credentials API, whose response is bound to the requesting
  page's origin (`TransactionsConfig.Origins`). A cross-device
  presentation can only be judged by the holder, from the Verifier the
  wallet names on its consent screen. Where the Verifier's session must
  be bound to the person presenting, such as a login, use the
  same-device flow or the Digital Credentials API, not a QR code.
- **Response endpoint timing.** `verifier.Transactions` answers every
  refused or unknown answer to its response endpoint with the same
  reply, so whoever holds a request's QR code can't learn from it
  whether the holder has presented. The time taken still differs: a
  refused answer to a pending request is recorded on the transaction
  (`LastError`), a store write, and one to an answered or expired
  request isn't. Over a quiet network, the timing can tell that party
  whether and when the holder presented.
- **Key storage evidence on iOS.** A Wallet Provider attests the
  wallet's keys to issuers (OpenID4VCI 1.0 Appendix D, HAIP 1.0
  §4.5.1), and its `key_storage` claim is only as good as its evidence.
  The Android library hands the provider each key's Android Key
  Attestation chain, over the provider's challenge, when the keys are
  made by `AndroidKeystoreKeyStore`. iOS has no attestation of Secure
  Enclave keys a provider can verify: App Attest attests the app, not
  where its keys live. An iOS provider's `key_storage` rests on the app
  keeping keys in the Secure Enclave, as `KeychainKeyStore` does, not on
  hardware evidence. The mobile libraries' "Going to production" guides
  say what a provider checks on each platform.
- **One mdoc device key may both MAC and sign.** With
  `walletflow.ProximityDeviceMACPreferred`, a proximity presentation
  MACs with the credential's device key where it can and signs where it
  can't, and OpenID4VP and the DC API always sign. Nothing records which
  mechanism a key has used, though ISO/IEC 18013-5 §12.4.4 has each key
  use one. The deniability a MAC gives is then lost for that key; no
  attack on the key is known.
- **BLE peers aren't known before a message decrypts.** ISO/IEC
  18013-5's BLE retrieval puts each side's service UUID in the clear in
  its adverts, and the reader's Ident, which a holder in mdoc central
  client mode checks, can be read by any device and served by another:
  it tells sessions apart, it doesn't authenticate. Status messages
  aren't encrypted (§9.1.1.4). Until a message decrypts, the holder
  (`proximity.DeviceSession.TrySessionEstablishment`) and a reader in
  mdoc peripheral server mode (`ReaderSession.TryVerify`) reject what
  doesn't, a bare status included, and the mobile libraries pass over
  the device that sent it and go on looking, within their timeouts.
  What remains is availability: a reader in mdoc central client mode
  still takes the first device that starts a session, a device that
  answers nothing holds a reader until its idle timeout, and a
  holder's decline is reported once no other device answers in the
  reader's connect timeout. `mobile/MOBILE.md` lists the rest.
- **Linkability across credentials.** `walletflow` warns before a
  presentation would hand one Verifier a copy another has seen
  (`Presentation.Linkable`), judging copies of one credential against
  each other. It doesn't compare values an issuer reuses across
  credentials (a status list index, `sub` or `jti` shared by the
  SD-JWT VC and the mdoc of one issuance, or kept by a refresh): two
  Verifiers given those can link the holder with no warning. HAIP 1.0
  §6.1 makes avoiding such values the issuer's job.
- **A credential matched only through `aka_vcts`.** The wallet's DCQL
  matching treats an SD-JWT VC's `aka_vcts` as types it is of, and
  `wallet.DefaultSelection` takes the first matching credential, with no
  preference for one whose own `vct` was asked for. A credential that
  claims another type through `aka_vcts` can be offered, and
  pre-selected, for a request for that type. A Verifier decides whether
  its issuer may issue that type: authorize each of
  `IssuerAuthorization.MatchedTypes`, not only `Type`.
- **Names bound by URI under DNS name constraints.** Several checks
  bind a signer to a party by a URI subject alternative name in its
  certificate: `issuer.AttestationIssuerInCertificate`,
  `verifier.X5CIssuerKeyResolver.RequireIssuerName` and the status
  list signer bound by `statuslist.VerifyOptions.Issuer` for an https
  `iss`, `wallet.Config.RequireIssuerMetadataName`,
  `VerifyIssuedCredentialParams.RequireIssuerName`, and a
  `registration` JWT's `iss` (fapigo's `AttesterIssuerInCertificate`
  is another). Each holds only where no trusted CA can certify that
  URI for another party. RFC 5280 §4.2.1.10 applies each name
  constraint type to names of its own type, and crypto/x509 follows
  it: a CA a trust list confines to its member's DNS domain with
  `dNSName` constraints can still certify any URI, so a member can
  sign in another member's https name. Only `uniformResourceIdentifier`
  constraints, on the member's CA or a CA above it, confine its URIs,
  and only their host, not their path. Under trust lists shared by
  several parties, bind by anchor instead
  (`issuer.AttestationIssuerBoundToAnchor`, fapigo's
  `AttesterIssuerBoundToAnchor`, the verifier's
  `IssuerAuthorization.IssuerAnchor` or `RootsByVCT`), or, where the
  check takes them (a Key Attestation's or SD-JWT VC's `iss`), name
  parties by `dns:` identifiers under `dNSName` constraints.

## What to include

- The affected package/file and, if possible, a minimal reproduction.
- The specific OID4VCI / OID4VP / HAIP / FAPI 2.0 requirement or security
  property you believe is violated (a spec section reference helps — see
  [SPECIFICATIONS.md](SPECIFICATIONS.md) for exact versions).
- Whether the issue is exploitable against a default configuration or
  requires a specific, non-default setup.

## Response

We'll acknowledge reports and work with you on a fix and coordinated
disclosure timeline before any public advisory is published.
