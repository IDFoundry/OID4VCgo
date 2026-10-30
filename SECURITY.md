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
  (`proximity.WithIssuerRevocation`);
- a status list signer (`statuslist.VerifyOptions.Revocation`,
  `walletflow.Config.StatusRevocation`; `verifier.RequireValidStatus`
  passes it on from the `statuslist.Checker` it's given);
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
requires (`server.NoClientAttestationStatusCheck{}` to decline).

## Known limitations

These are risks the library documents rather than closes, because
closing them is up to a party it doesn't control:

- **Bearer access tokens.** Under `walletflow.ProfileOpenID4VCI` a
  wallet takes a Bearer access token where the Authorization Server
  issues one (OpenID4VCI §13.2). It asks for the token for the offer's
  Credential Issuer (RFC 8707 `resource`), but only the Authorization
  Server can restrict the token to that issuer. If it doesn't, an
  issuer sharing the Authorization Server with another can redeem the
  token it receives at the other, for a credential about the End-User.
  `walletflow.ProfileHAIP` takes only DPoP-bound tokens.
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
