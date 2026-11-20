# Upgrading

What to change when upgrading OID4VCgo, release by release. Each entry
covers the breaking changes a caller has to act on; CHANGELOG.md lists
everything else. A release that pins a new FAPIgo release passes on
that release's own breaking changes: see FAPIgo's UPGRADING.md for
them. Entries start at v0.55.0; for earlier releases see
CHANGELOG.md's BREAKING CHANGES sections.

## v0.84.0 → v0.85.0

### A Wallet's error code is kept only when a specification defines it (`verifier`)

`Transactions` records a Wallet's error response as the request's
`LastError`, and sends a same-device request's browser back to
`RedirectURI` with its code as `error`. Anyone holding the request's
QR code or link can send one, so the code is now kept as sent only when
RFC 6749 §4.1.2.1, RFC 9101 §7 or OpenID4VP 1.0 §8.5 defines it, and
any other code is recorded and redirected as `unrecognized_error`.
Before, any code that was a plain token of up to 64 characters was
kept, and another was recorded without a code and redirected as
`invalid_request`. A page that reads `error` at its `RedirectURI`, or
`LastError`, sees `unrecognized_error` for those codes. `OnRefused`
still gets an encrypted error response's own code.

### Transactions' Request Objects carry `iat` and `exp` (`verifier`)

The Request Objects `Transactions` serves — `BeginWith`'s, each
`RequestObjectPost`'s and `BeginDCAPI`'s — now carry `iat`, when they
were signed, and `exp`, the request's `ExpiresAt` (RFC 7519). A Wallet
that checks `exp`, as this package's does, refuses a copy served after
the request stopped being answerable. One whose
clock runs ahead of the Verifier's by more than the request's
remaining `Lifetime` refuses it too, so keep the Verifier's clock
synchronized. `BuildAuthorizationRequest` and
`BuildDCAPIAuthorizationRequest`, which know no lifetime, are
unchanged.

### A Digital Credentials API origin must be one a platform reports (`wallet`, `walletflow`, `mobile`)

`wallet.ParseDCAPIRequest` and `ParseDCAPIRequestData`, and so
`walletflow`'s and the mobile libraries' `StartDCAPIPresentation`, now
refuse a calling origin unless it is a serialized web origin, spelled
as a browser gives a page's (`https://verifier.example`, with no path,
trailing slash, user info, default port or uppercase), or an Android
app's (`android:apk-key-hash:` and the unpadded base64url SHA-256 of
its signing certificate). Anything else, an opaque origin's `null`
included, is refused with a plain error before the request is read:
`walletflow.ErrMalformedRequest`, and `invalid_input` across the
mobile boundary. Before, any non-empty origin was accepted and the
presentations were bound to it as given. Pass the origin exactly as the
platform reports it: Chrome's through Credential Manager, and the
Android library's own for an app, already have this form.

## v0.83.0 → v0.84.0

### FAPIgo v0.77.0: a claim may be requested with at most 64 values

OID4VCgo now requires FAPIgo v0.77.1 and fapigo/sqlstore v0.9.1; see
FAPIgo's UPGRADING.md, section v0.77.0. An Authorization Server
(`fapigo/server`) refuses, with `invalid_request` naming the claim, a
PAR or backchannel authentication request whose OIDC `claims`
parameter (OIDC Core §5.5.1) gives one claim, in `id_token` or
`userinfo`, more than 64 `values`. Give a claim at most 64 acceptable
values; real requests give a handful. Before, a large `value` with many
`values` cost the Authorization Server about 3 s of CPU for each
completed authorization. DCQL `values` in a presentation request are
unaffected.

A `storage.GrantRegistry` of your own may now honour the new
`storage.GrantListing.Key`, listing only the subject's unexpired entry
with that key, so a refresh-token issuance no longer reads all of the
subject's grants. A store that ignores it stays correct, only slower;
fapigo/sqlstore v0.9.1 honours it.

### `VerifyResponse` refuses a response after four failed presentations

`VerifyResponse`, and so `Transactions.HandleResponse` and
`HandleDCAPIResponse`, now counts every presentation it discards
because a check of its credential failed: its issuer signature,
validity or digests (`ReasonInvalidCredential`), an issuer chain the
built-in `X5CIssuerKeyResolver` or `X5ChainIssuerKeyResolver` doesn't
verify, or its holder binding (`ReasonHolderBinding`). Once
`MaxFailedPresentationsPerResponse` (4) of a response's presentations
have failed, across its Credential Queries, the response is refused as
`ReasonMalformed` ("4 presentations in one response failed to verify")
at the next presentation, before it is verified. Before, each was
discarded and the rest verified, so a response with more than four
such presentations beside valid ones is now refused instead of
answered by the valid ones. Presentations that verify aren't counted,
nor are ones discarded for not answering their query, for unrequested
claims, or because a trusted issuer is refused (revocation, leaf
policy, `IssuerAuthorized`, `trusted_authorities`). A Wallet's own
credentials don't fail their signatures or holder binding, so an
honest response isn't affected. `MaxFailedIssuerChainsPerResponse` is
unchanged, and still applies alone through `ResponseIssuerChains`
(`mdocdcapi`).

### A credential presented twice is refused before either copy is verified

A response presenting one credential twice for one Credential Query
(or, under `DistinctCredentials`, for two) is now refused at the
second copy, before it is verified, whether or not the first verified.
Before, the response was refused only when a copy of a credential that
verified did; copies that failed were each verified and discarded. The
refusal is the same `ReasonMalformed` error as before.

### A production Verifier requires an SD-JWT VC issuer key resolver that verifies chains

Under `AssuranceProduction`, `VerifyResponse` and `NewTransactions`
(so every Transactions flow, the Digital Credentials API's included)
now refuse a `VerifyResponseRequest.IssuerKeys`
(`TransactionsConfig.Verify.IssuerKeys`) that doesn't verify issuer
certificate chains: one that is neither an
`SDJWTVCIssuerChainResolver` nor a wrapper that `Unwrap`s to one, as
`MdocIssuerKeys` already had to be for mdocs. Such a resolver gives no
`IssuerAnchor`, and an `IssuerChain` that is the credential's
unverified `x5c` header, so neither `IssuerAuthorized` nor
`trusted_authorities` can tell which trusted CA vouched for an issuer.
`AssuranceDevelopment` is unchanged.

Migrate by one of:

- `verifier.X5CIssuerKeyResolver` as `IssuerKeys`, with `RootsByVCT`
  where each type has its own issuers' anchors.
- A resolver of your own that wraps one (caching, logging) implementing
  the new `verifier.SDJWTVCIssuerKeyResolverWrapper`:
  `Unwrap() verifier.SDJWTVCIssuerKeyResolver` returning the wrapped
  `X5CIssuerKeyResolver` or other chain resolver. `VerifyResponse` then
  takes the verified chain and `IssuerAnchor` from it (an
  `X5CIssuerKeyResolver`'s with the credential, so its `RootsByVCT`
  applies), and the system root pool check reaches it too.
- Where issuers' keys are trusted without certificates (from issuer
  metadata's JWKS, or DIDs), set the new
  `VerifyResponseRequest.AllowUnanchoredSDJWTVCIssuers`. `IssuerAnchor`
  is then nil for every SD-JWT VC, so `IssuerAuthorized` must identify
  issuers by other means it trusts: `IssuerAuthorization.Issuer` from a
  resolver that resolves each issuer's keys by its `iss` and says so
  (`IssuerNameBinding`), never `ClaimedIssuer` or `IssuerChain`.

### A state's IACA must name its state on its document signers (`mdoc`, `verifier`, `proximity`, `mdocdcapi`, `wallet`)

An mdoc's document signer certificate was compared with its IACA's
`stateOrProvinceName` only when both carried one. So an IACA scoped to
a state (`C=US, ST=US-CA`) could issue a document signer without a
state, and sign mDLs claiming another state's `issuing_jurisdiction`
(`US-NY`), which was then checked against nothing.

`mdoc.CheckDocumentSigner`, and so every mdoc verification (OpenID4VP,
Annex C, the proximity reader and the wallet's receipt check), now
refuses a path whose IACA names a state or province its document
signer doesn't name alike, as ISO/IEC 18013-5 Annex B has it.
`issuing_jurisdiction` is then held to that state. An IACA without a
state is unaffected.

### Authorize issuers by the anchor that verified them, not by names

No API is removed, but an issuer authorization hook that decides as
the earlier docs said is forgeable where the issuer roots are several
providers'. Any trusted CA can certify a leaf naming another provider's
issuer, so `IssuerAuthorization.Issuer` under
`X5CIssuerKeyResolver.RequireIssuerName` holds only where no other
trusted CA can issue a certificate with that name. And any trusted root
can share another's subject name and copy its key identifier into the
certificates it signs, so the issuer name and authority key identifier
of `IssuerChain`'s last certificate don't tell which root verified it.
This applies to `VerifyResponseRequest.IssuerAuthorized`
(`TransactionsConfig.Verify.IssuerAuthorized`, the org-iso-mdoc path
included), `mdocdcapi.VerifyParams.IssuerAuthorized` and
`proximity.WithIssuerAuthorization`.

A hook that decides by `Issuer`, or by names or key identifiers in
`IssuerChain`, should move to one of:

- `IssuerAuthorization.IssuerAnchor` (new; also
  `VerifiedCredential.IssuerAnchor`, `mdocdcapi.Verified.IssuerAnchor`),
  the DER of the configured root that verified the chain, compared by
  key with the anchors you assign to each type:
  `verifier.AnchorIs(a.IssuerAnchor, pidRoots...)`, or
  `verifier.AnchorHasKeyIdentifier(a.IssuerAnchor, akiValues...)` with
  the values a `trusted_authorities` "aki" query would name. Refuse a
  nil `IssuerAnchor`: the issuer key resolver verified no chain.
- Per-type roots, with no hook: the new `X5CIssuerKeyResolver.RootsByVCT`,
  keyed on the credential's signed `vct`, as `X5ChainIssuerKeyResolver.RootsByDocType`
  (and `proximity.WithIssuerRootsByDocType`) are for mdocs. Under
  `RootsByVCT`, a credential's `aka_vcts` are held to their types'
  anchors too, and `ResolveIssuerChains` refuses, since it isn't given
  the `vct`.

`MdocIssuer.CheckAnchored` is `Check` with the anchor, for a verifier
of its own mdocs. A `Transaction` record now carries the anchor of each
verified credential (`issuer_anchor`); a record from an earlier release
reads with none.

### `StatusIssuers` no longer decides a chained mdoc's status list (`verifier`, `proximity`, `mdocdcapi`)

`StatusPolicy.StatusIssuers` (or `RequireValidStatusFrom`'s, or
`AnyStatusListSigner`) used to accept a Status Issuer's signature on an
mdoc's `status_list` even when the mdoc's issuer chain was known.
ISO/IEC 18013-5 §12.3.6.2 has such a list signed under the CA that
signed the document signer, or by the certificate the MSO names. So a
Status Issuer trusted for SD-JWT VC issuers decided the status of
every trusted IACA's mDLs, a revoked one included.

It now decides an mdoc's `status_list` only where it already decided
its `identifier_list`: for an mdoc verified with no issuer chain whose
MSO names no status `Certificate`. Every other mdoc's lists must be
signed as §12.3.6.2 says.

A deployment whose mdoc issuers delegate their status lists to
another signer has them name it in the MSO's status `Certificate`, or
verifies those mdocs without an issuer chain.

### A `StatusPolicy` refuses a Checker that names the list signer

`verifier.StatusPolicy` now refuses a `Checker` whose `Options` set
`Issuer`, `IssuerKey` or `UnboundSigner`: `CheckStatusDecision`, so
`NewTransactions`, `VerifyResponse`, `mdocdcapi.VerifyParams.Status`
and a proximity reader's `WithStatus`, refuse the configuration at
every assurance level, and `StatusPolicy.Check`, `RequireValidStatus` and
`RequireValidStatusFrom` refuse every check. Before, `Issuer` or
`IssuerKey` set there replaced the binding each check makes between a
status list's signer and the credential's own issuer: an mdoc's list
was no longer held to the CA that signed its document signer (ISO/IEC
18013-5 §12.3.6.2), nor, with `StatusIssuers`, an SD-JWT VC's list to
its issuer or an accepted Status Issuer, so a list signed with the
pinned key decided every credential's status. Drop the fields: the
binding is per credential. A separate Status Issuer is
`StatusPolicy.StatusIssuers`'s to accept.

### Fetch errors no longer quote `credential_offer_uri` or `request_uri`

A failed fetch of a by-reference Credential Offer's
`credential_offer_uri`, or of an OpenID4VP request's `request_uri`,
returned an error quoting it whole, though each serves what it refers
to (a by-reference offer its pre-authorized code) to anyone who reads
the logs. The error now names a placeholder instead, `"(the
credential_offer_uri)"` or `"(the request_uri)"`, in its text and in the
`*url.Error` that `errors.As` finds, whose `Op` and cause are kept:
`errors.Is` and `errors.As` still find a timeout, a refused connection
or `fapihttp.ErrSSRFBlocked`. This applies to
`wallet.Wallet.ResolveCredentialOffer`, `FetchAuthorizationRequest` and
`FetchAuthorizationRequestPost`, and so to `walletflow`'s
`StartIssuance` and `StartPresentation`. A malformed
`openid4vp://` link's parse error likewise names `"(the request
link)"`, and a relative `request_uri` is no longer quoted. Code that
read the URL back out of the error has it from its own input. Errors
from the other endpoints (metadata, nonce, token, credential,
notification, status lists) still quote their URLs, which carry no
secret.

### Under `claim_sets`, a presentation may disclose only its satisfied options' claims (`verifier`, `dcql`)

`VerifyResponse` (and `Transactions`) without `AllowUnrequestedClaims`
took any claim a Credential Query's `claims` named, whichever
`claim_sets` option the presentation satisfied. So a presentation
satisfying "or failing that, a name" could also carry an address
whose `country` failed the other option's `values` filter (`DE`
asked, `FR` sent), and the result kept it.

It now takes only the claims of the options the presentation
satisfies, values filters included, as OpenID4VP 1.0 §6.4.1 has the
Wallet send. A claim of any other option is refused as
`ReasonUnrequestedClaims`. A presentation that satisfies several
options may carry each one's claims. This library's wallet sends one
option's claims, and is unaffected. With `AllowUnrequestedClaims`,
nothing changes.

`dcql.CredentialQuery` gains `SatisfiedSDJWTVCPresentationPaths` and
`SatisfiedMdocClaimPaths`, which return those claims' paths.

### A DCQL credential query's `meta` is limited to 4 KiB (`dcql`, `wallet`, `walletflow`, mobile)

`dcql.Query.Validate` now refuses a credential query whose `meta` is
over `dcql.MaxMetaBytes` (4096 bytes, as sent). A Wallet refuses such
a presentation request as malformed (`invalid_request`), a Verifier
refuses to build one, and `dcql.NewSDJWTVCMeta` and `NewMdocMeta`
refuse to make one. A real `meta` is far smaller: 64 `vct_values` of 60
bytes each fit. Before, only the request's size bounded it, and a
wallet read it again for every credential it held.

A Wallet's parsed `AuthorizationRequest.Query` now carries each
`dc+sd-jwt` or `mso_mdoc` credential query's `meta` with only
`vct_values` or `doctype_value`; the members a Wallet ignores are
dropped. `walletflow` matches a request's queries together with the
new `wallet.MatchEachCredentialQuery`, and `StartPresentation` and
`StartDCAPIPresentation` now return the context's error when it ends
during matching, rather than a request with no credentials listed.

### A Wallet Provider revocation whose status writes fail is finished later

`walletprovider`'s `Suspend`, `Resume` and `Revoke` store the
instance's state, set its keys' statuses, then record the new
`Instance.KeyStatusesFor`, the state they're all set for. While it
isn't the instance's `State`, the transition is pending, and:
- `RevokeWhere` selects a revoked instance again, finishing its
  revocation with its first reason, and counts it. It no longer stops
  at the first instance it fails to revoke: it goes on, and returns a
  `*walletprovider.RevokeWhereError` naming each failed instance
  (`Failed`, with each one's error), stopping when its context ends,
  listing fails, or after 100 failures. Code that compared its error
  with `==`, or relied on its stopping, uses `errors.As`.
- A request from a suspended or revoked instance (`VerifyRequest`, and
  `WalletAttestation`/`KeyAttestation` called directly) sets its keys'
  statuses before it's refused for its state, as before. A failure is
  logged at error level with the instance's ID.
- `Config.OnRecheckRefused` is now called for an automatic revocation
  or suspension whose transition failed too, before the request fails
  as the provider's own failure: with the instance as stored, its
  `KeyStatusesFor` not its `State`. `Revoke` or `Suspend` it then.

An instance stored before this release has no `KeyStatusesFor`, so a
suspended or revoked one is pending: its next request, or a
`RevokeWhere` run matching it, sets its statuses once more.
`RevokeWhere` counts such revoked instances too.

A custom `walletprovider.InstanceStore` keeps the new
`KeyStatusesFor` field; `walletprovidertest.TestInstanceStoreContract`
checks it. sqlstore's store keeps it in its record with no migration.
A store that dropped it would leave every suspended or revoked
instance pending, its statuses set again at each of its requests and
each `RevokeWhere` run matching it.

### JSON is refused at 131,072 tokens, and answers at their first member out of bounds

Every JSON document OID4VCgo parses from another party (Request
Objects, metadata, credentials, a Verifier's answers, a Wallet
Provider's requests and the rest) is now checked in one pass and
refused at its first token over 131,072, counting values and member
names, with an error wrapping "json: too many tokens". The largest
honest documents measured hold under 11,000 (an issuer's metadata of
100 KB, Google's Android attestation status list of 180 KB, whose
parser is bounded by its entry cap instead); nothing else refused or
accepted changes. A Verifier's own transaction records aren't bounded.

The Verifier refuses an answer where it first goes out of bounds,
before decoding the rest, with the `Reason` its later refusal had:

- `Transactions` refuses a `vp_token` at its first member that isn't
  one of the request's Credential Queries (`ReasonNotAnswered`, "vp_token
  answers a credential query the request doesn't make"), where
  `VerifyResponse` refused it after decoding all of it.
- `ParseDirectPostJWTResponse`, and so `Transactions`, refuses a
  `vp_token` of more than 64 members, or of more than
  `MaxPresentationsPerQuery` presentations for one (`ReasonMalformed`),
  which `VerifyResponse` refused anyway. An error response's
  `vp_token`, if it has one, is held to the same bounds before the
  error is returned.
- `HandleDCAPIResponse` and `HandleMdocDCAPIResponse` refuse data of
  more than 1,024 tokens; an honest one is a `response` string, or an
  `error` and its description.

A Wallet Provider refuses a request body of more than 128 + 64 ×
`Policy.MaxKeys` tokens (768 by default), and a key in it
(`registration_key`, `instance_key`, `keys`) with a member other than
its key type's (`kty`, `crv`, `x`, `y`; `d` is refused as before),
those RFC 7517 §4 registers (`use`, `key_ops`, `alg`, `kid`, `x5u`,
`x5c`, `x5t`, `x5t#S256`) and Web Crypto's `ext`, or with one of those
of another JSON type, as `invalid_request`, as it already refused an
unknown member elsewhere in a body. `walletprovider.Client` and the
Swift and Kotlin `HttpWalletProvider`s send `kty`, `crv`, `x` and `y`
only, unchanged.

### A name bound by URI needs URI name constraints, not DNS ones

Nothing changes in what's accepted, but a deployment that relies on
`dNSName` name constraints to keep the members of a shared trust list
apart is not covered where a check binds a signer by a URI subject
alternative name: `issuer.AttestationIssuerInCertificate`,
`X5CIssuerKeyResolver.RequireIssuerName` (and
`walletflow.Config.RequireIssuerName`) for an https `iss`, the status
list signer named by `statuslist.VerifyOptions.Issuer`,
`wallet.Config.RequireIssuerMetadataName`, and a `registration` JWT's
`iss`. RFC 5280 §4.2.1.10 applies `dNSName` constraints to DNS names
only, and crypto/x509 follows it: a member CA confined to its own
domain can still certify another member's https URI. The earlier docs
named only "an intermediate without name constraints" as the risk.

Where such a trust list is shared, move to one of:

- an anchor-bound mode: `issuer.AttestationIssuerBoundToAnchor` (and
  fapigo's `AttesterIssuerBoundToAnchor`), or, at a Verifier,
  `IssuerAuthorization.IssuerAnchor` or `X5CIssuerKeyResolver.RootsByVCT`;
- `uniformResourceIdentifier` name constraints on each member's CA,
  which confine a URI's host, though not its path;
- `dns:` identifiers, under the `dNSName` constraints, where the check
  takes them (a Key Attestation's or SD-JWT VC's `iss`).

### A signed DC API request is checked for its origin first (`wallet`, `walletflow`)

`wallet.ParseDCAPIRequest` and `ParseDCAPIRequestData`, and so
`walletflow.StartDCAPIPresentation`, now refuse a signed or
multi-signed request whose `expected_origins` doesn't name the calling
origin, or that has none, before checking its signature, chain,
`response_type`, `response_mode` or anything else, and with the same
plain error whatever else is wrong with it. Such a request used to get a
`*RequestRejectedError` (`invalid_request`), and so a
`walletflow.RequestRefusedError` with a `DCAPIResponse` for the page,
when it was signed by a Verifier the wallet trusts but asked for another
response mode, as a redirect-flow Request Object does; and
`ErrUntrustedVerifier` when the wallet didn't trust it. Any page could
tell those apart, and so learn which Verifiers the wallet trusts. A
request from an origin it names is checked as before.

Nothing needs to change, as long as the app fails the platform's call
the same way for every error that isn't a `RequestRefusedError`, as
`StartDCAPIPresentation`'s documentation now asks: the mobile libraries
already do.

### An `openid_credential` object carries at most 256 claims, and is registered 6 deep

`oid4vci.AuthorizationDetailRARDefinition`'s `Validate` now refuses an
object with more than `oid4vci.MaxAuthorizationDetailClaims` (256)
claims descriptions, whatever size the registry allows it, as
`invalid_authorization_details`: at the pushed authorization request,
at the token endpoint, and at the issuer's pre-authorized Token
Endpoint (`RedeemPreAuthorizedCode`, `ExchangePreAuthorizedCode`),
before the code is spent. A credential has far fewer claims, and 256 is the
most a Verifier may ask of one (`dcql.MaxClaimsPerCredential`). A
grant made before this release with more claims in one object no
longer refreshes: FAPIgo refuses it as `invalid_grant`, and the Wallet
starts a new issuance. Its `ValidateGrant` and `ValidateNarrowing` now
compare claims, locations and identifiers in time linear in the
objects' size, deciding as before.

Register the type in a registry 6 deep: an object's `claims` are 5
deep and a claims description's `display` 6, and a shallower registry
refuses them. At the token endpoint of a pre-authorized code, that
refusal comes after `RedeemPreAuthorizedCode` has spent the code, so
the Wallet's offer is lost: check `extension.NewRARRegistry`'s
`maxDepth`. `cmd/conformance-issuer` and the passport-vdc demo now
register it 6 deep, where they registered it 4 deep.

### The preview lists an object or array the Verifier receives empty

`wallet.PreviewedCredential.AlwaysDisclosed` (and walletflow's
`Disclosure.AlwaysDisclosed`) now lists an SD-JWT VC object or array
that reaches the Verifier empty because it holds only decoy digests or
only claims the presentation doesn't send, as it already listed a
literal `{}` or `[]`. The Verifier learns that the claim exists. A
consent screen showing `AlwaysDisclosed` may show more entries; one
inside a Disclosure a selected claim sends is in `DisclosedAlong`, and
a registration's coverage check counts it.

### A nil `*X5CVerifierRoots` or `*NoVerifierTrust` is refused

`wallet.New`, and so `walletflow.New`, now refuses a
`Config.VerifierTrust` that is a nil `*wallet.X5CVerifierRoots` or
`*wallet.NoVerifierTrust`, and `ParseAuthorizationRequest` and
`ParseDCAPIRequest` refuse one as their `VerifierTrust`. Before, it
was accepted and the first signed request panicked. Pass the value, a
non-nil pointer, or no `VerifierTrust` (a nil interface) for a Wallet
that only receives credentials.

### A deferred record with neither marker is refused (`issuer`)

A deferred transaction record with neither `CredentialIdentifier` nor
`RequestedByConfigurationID`, saved by OID4VCgo v0.81.0 and before or
written by a deployment without them, was checked against the access
token granting its credential configuration alone. That let a token
for another dataset of the configuration collect it. v0.83.0 audited
each such poll (`AuditEventLegacyDeferredAuthorization`) and
deprecated the fallback. It's now gone:
- a poll for such a record is refused with `invalid_transaction_id`,
  as for an unknown transaction;
- `DeferredCredentialHandler` calls `Resolve` for none;
- the event is never recorded. The constant stays, deprecated, and
  will be removed.

Before upgrading, check on v0.83.0 that
`AuditEventLegacyDeferredAuthorization` has been silent for a full
`Limits.DeferredTransactionLifetime`. No such record is then left
pending. One still pending when you upgrade can't be collected: its
Wallet asks for the credential again.

A deployment that writes `DeferredTransactionRecord`s itself sets
`CredentialIdentifier` for a request by `credential_identifier`, or
`RequestedByConfigurationID` for one by `credential_configuration_id`,
as `RequestCredential` does.

### A production Digital Credentials API `Transactions` needs a `Scope` (`verifier`)

Under `AssuranceProduction`, `verifier.NewTransactions` refuses a
`TransactionsConfig` without `RequestURIBase` (one that serves the
Digital Credentials API alone, OpenID4VP or org-iso-mdoc) unless it
sets `Scope`.

Every such `Transactions` of one Verifier derived the same scope. So a
lax policy's `HandleDCAPIResponse` could complete a strict policy's
request: the answer was verified under the lax policy's `Verify`,
`Status` and `Accept`, and the strict policy's `Lookup` reported it
done.

Give each policy a `Scope` of its own, the same on every replica. A
transaction begun before the upgrade under the derived scope is
`ErrTransactionUnknown` to the new one, so let those expire first, or
upgrade between requests.

### An org-iso-mdoc `IssuerAuthorized` hook gets a `CredentialQueryID`

On the org-iso-mdoc path (`Transactions.HandleMdocDCAPIResponse`, and
`mdocdcapi.VerifyResponse` and `VerifyResponseDocuments`),
`IssuerAuthorization.CredentialQueryID` was empty. It is now the
`CredentialQueryID` the verified document carries, which `Accept` and
`Status` see: the request's `MdocDCAPIRequest.CredentialQueryID`
(`verifier.MdocDCAPICredentialQueryID` when unset) through
`Transactions`, the document's type through `mdocdcapi` alone. A hook
that told the org-iso-mdoc path apart by an empty ID should test
`Format` and the request instead.

### An mdoc's status is its MSO's alone (`verifier.VerifiedCredential.Format`)

`VerifiedCredential` has a new `Format` field, `"dc+sd-jwt"` or
`"mso_mdoc"`, which `VerifyResponse`, `Transactions`,
`mdocdcapi.Verified.Credential` and `proximity.Verified.Credential`
set. For an `"mso_mdoc"` credential, `StatusListRef` reads the MSO's
status (`MdocStatus`) alone: an mdoc with a namespace named `status`
and no MSO status now has no status, where before every status check
refused it, reading the namespace as an SD-JWT VC `status` claim. A
`VerifiedCredential` built elsewhere, with `Format` empty, is read as
before.

`verifiertest.TestTransactionStoreContract` now checks a store keeps
`Format`. One that stores transactions through `TransactionCodec`, as
sqlstore's does, needs no change: the codec sets it from the
transaction's query.

### An SD-JWT VC holding a number beyond 2^53 − 1 is refused (`sdjwtvc`, `verifier`, `wallet`, `walletflow`)

An SD-JWT VC's claims decode into float64s, and no float64 holds
every integer beyond ±(2^53 − 1) exactly: 9007199254740993 decoded as
9007199254740992. So two values an issuer signed apart, account
numbers say, verified as one, and a DCQL `values` filter for one
matched the other.
- `sdjwtvc.Verify`, and so every verifier, wallet and walletflow check
  of an SD-JWT VC, now refuses an issuer JWT payload or Disclosure
  holding a number beyond ±`sdjwtvc.MaxSafeInteger`, in whatever form:
  an integer, a fraction or an exponent.
- `sdjwtvc.Issue` refuses to sign one.

An issuer whose claims hold such numbers issues them as strings. A
credential issued with one before can't be verified or presented any
more: reissue it.

### A Key Binding JWT's `iat` may be in the future by the clock skew alone

`sdjwtvc.VerifyKeyBindingJWT`, and so `VerifyResponse`, accepted a Key
Binding JWT whose `iat` was up to `MaxKeyBindingAge` in the future (five
minutes, say). The future side is now bounded by `MaxClockSkew`
(`VerifyResponseRequest.MaxClockSkew`, `sdjwtvc.VerifyOptions.MaxClockSkew`,
`KeyBindingCheck.MaxClockSkew`), and never by more than
`MaxKeyBindingAge`, as status and identifier lists already bound a
future `iat`. A Verifier that leaves `MaxClockSkew` zero now refuses a
presentation from a wallet whose clock runs even a second ahead of its
own (`holder_binding`, "key binding JWT iat is too far in the
future"): set it, a minute is typical, as it also widens a
credential's validity window.

### A proximity reader tries each answer in mdoc peripheral server mode (`proximity`, mobile)

In mdoc peripheral server mode a reader connects to whichever device
advertises the holder's service UUID, which is in the clear, and
`ReaderSession.Verify` ended the session on that device's first
answer: junk, or a bare status 20 reported as `ErrDeclined`. A reader
driving its own BLE in that mode should pass answers to the new
`ReaderSession.TryVerify` (or `TryVerifyDocuments`; the mobile
`ProximityReaderSession.TryHandleMessage`, additive within ABI 16): an
answer that doesn't decrypt, or a bare status, is
`ErrResponseRejected` (the `rejected` event) and leaves the session
open. Disconnect from that device, pass over it, and send the same
SessionEstablishment to the next one, within your connect timeout; a
rejected status 20 also wraps `ErrDeclined`, to report if no other
device answers. A holder that hasn't connected goes on advertising, so
once no other device advertises the UUID for a few seconds, the
decline can be reported without waiting out that timeout. `Verify` is
unchanged.

The Swift and Kotlin readers do this themselves, and their holders in
mdoc central client mode now leave a device whose first message Go
rejects and connect to the next, instead of staying with it. A
reader's `declined` state is then reported once no other device
advertises the holder's service for 5 seconds, or, while others do,
once `connectSeconds` (`connect`) ends: up to 60 seconds after the QR
code is scanned, by default.

A holder now refuses a SessionEstablishment whose EReaderKeyBytes is
over `proximity.MaxEReaderKeyBytes` (1,024 bytes) or carries a
COSE_Key parameter other than kty, kid, alg, crv, x and y, and a
negotiated NFC Handover Request over `MaxHandoverRequestBytes` (1,024
bytes) or 16 records: its device key signs both as sent. ISO/IEC
18013-5's Annex D, Multipaz and this package's own readers send far
less.

### Wallet Provider refusals count only at their status, and `evidence_required` retires a refresh grant (`walletprovider`, `walletflow`, mobile)

A `walletprovider.RefusedError` now matches `ErrRegistrationExpired`,
`ErrInstanceKeyExpired` or `ErrInstanceKeyRegistered` only at the
status `Provider.Handler` answers its code with (403, or 409 for
`instance_key_registered`; the new `walletprovider.CodeStatus`):
`walletflow` forgets a refresh grant on these, and the same code in a
redirect or in a proxy's answer in front of the provider isn't the
provider's refusal. The Swift and Kotlin `HttpWalletProvider` drop
such a code, and `instance_revoked`, at any other status, so they no
longer forget their registration on it. A native provider of your own
that marks refusals `[refused:code]` should do the same: the mark
carries no status.

`walletprovider.CodeError` now also names `ErrEvidenceRequired` for
`evidence_required` (`CodeEvidenceRequired`, at 400), and a refresh
whose Wallet Attestation is refused so is `ErrReissueRequired`
(`reissue_required` on mobile), with its grant and instance key
forgotten: the provider deleted its record of the key after
`Config.InstanceKeyRetention`, and a client that can't make fresh
evidence for an existing key, as on Android, can't recover it. Before,
each later refresh failed again as `platform`.
A refresh's Key Attestation refused with `evidence_required` is
returned as is (`platform` on mobile) and keeps the grant: the
provider answers it there for a request that carried no evidence
for the new holder keys, before it looks at the instance key the
refresh's Wallet Attestation has just used.

On Android, `HttpWalletProvider` now refuses, without a request,
holder keys made over no holder challenge it remembers unexpired,
rather than send them with the current challenge, which the provider
used up while refusing them; and it fetches a challenge for a new key
outside the lock its attestations take. Neither platform's
`HttpWalletProvider` is covered by `network.tlsPins`: pin your
provider with `NSPinnedDomains` (iOS) or a network security
configuration's `<pin-set>` (Android), as the "Going to production"
guides now say.

### A credential refreshed or deleted as `Respond` runs is reported as changed (`walletflow`, mobile)

A refresh or a deletion that lands after a presentation's `Respond`
has reserved a credential's copy, and before it loads the copy's
holder key, deletes that key: one in another goroutine, process or
`Wallet` sharing the stores. `Respond` (OpenID4VP, org-iso-mdoc and in
person) now reports it as it does a credential changed before it
reserved the copy: `ErrCredentialChanged` for one refreshed, and
`ErrInvalidSelection` for one deleted (`invalid_selection` on mobile),
where it was the KeyStore's `ErrNotFound` (`not_found`). Nothing is
sent either way: start the presentation again. A holder key missing
from a credential that's still as reserved is still `ErrNotFound`.

### A mobile configuration naming a member twice is refused (mobile)

`NewWallet` and `NewProximityReader` now refuse, as `invalid_input`, a
configuration in which an object, at any depth, names a member twice,
and `RespondDocuments` an answer in `answersJSON` that does. Only the
last of the two counted, so a check of the configuration's text that
reads the first `"development": false` passed one that went on to set
`"development": true`. Like the library's other JSON parsing, they
also refuse text that isn't UTF-8 or escapes a lone surrogate. The
Swift and Kotlin libraries encode their configurations from typed
values, which can't name a member twice: only JSON written or
assembled as text is affected.

### A wallet bounds the deferred credentials pending from an issuer (`walletflow`, mobile)

`StartIssuance` now refuses an offer, and `RefreshCredential` a
refresh, while the issuer has `DefaultMaxPendingDeferredPerIssuer`
(64) deferred credentials pending in the `DeferredStore`, or the
wallet `DefaultMaxPendingDeferred` (256) in all, with an error
wrapping the new `walletflow.ErrTooManyDeferred` (`unavailable` with
the detail `too_many_deferred` on mobile), before anything is sent to
the issuer. Each pending one keeps its holder keys and an access token
until it's polled to an end or abandoned, and an issuer that deferred
every request had the wallet make up to 32 more, with their holder
keys and Key Attestations, for each offer the holder accepted. Nothing
pending or held is lost: poll the pending ones (`Wallet.Deferred`), or
`Abandon` those the issuer won't issue, and its offers are taken
again. A pending one whose access token has expired
(`PendingDeferred.AccessTokenExpiresAt`) doesn't count: the issuer
won't be polled with it, so it will never be issued. It still stays,
with its keys, until it's abandoned, as before. The new
`Config.MaxPendingDeferredPerIssuer` and
`Config.MaxPendingDeferred` change the bounds; zero keeps the
defaults. The mobile configuration keeps the defaults.

### A Wallet Provider has a production assurance level (`walletprovider`, `androidkey`, `appattest`)

`walletprovider.Config` has a new `Assurance` field, an
`AssuranceLevel` as the issuer and the verifier have. Zero keeps
today's behaviour (`AssuranceDevelopment`). Under the new
`walletprovider.AssuranceProduction`, `New` refuses:

- `walletprovidertest.FakeVerifier`, or a type embedding it, among
  `Dependencies.Evidence`: its evidence is a JSON document anyone can
  write, so a provider built with it registers anyone and attests any
  key, at whatever security level it was set to report.
- `Instances`, `InstanceKeys` and `Challenges` stores that don't seal
  their records (`sealing.Store`), as `RequireSealedStore` does, unless
  the new `Config.UnsealedStores` accepts them, as the issuer's
  `Config.UnsealedStores` does: only where they're as protected as the
  provider's signing key. `RequireSealedStore` refuses them at any
  level, `UnsealedStores` or not.
- An evidence verifier whose `CheckConfiguration`, of the new optional
  `walletprovider.ConfigurationCheck`, refuses the level.
  `appattest.EvidenceVerifier` refuses a `Verifier` with
  `AllowDevelopment`, and `androidkey.EvidenceVerifier` one whose
  `Revocation` is a `StatusSource` with `AllowLoopback`, each wrapping
  its package's `ErrConfig`. `androidkey`'s
  `AllowUncheckedLegacyEvidence` is taken, for an upgrade window. A
  verifier of your own that wraps one of them in a named field hides
  the method: forward it, or embed the wrapped verifier.

Set it in production, with your stores sealed (sqlstore's `DB` with an
`Options.Sealer`). `New` calls `CheckConfiguration` at every level,
with the provider's level; the two verifiers refuse only under
production, so other levels are unchanged.

### A holder takes a reader's kid and alg only as RFC 9052 types them, and short (`proximity`, `walletflow`, mobile)

A holder now refuses a SessionEstablishment whose EReaderKey carries a
kid that isn't a byte string of at most 64 bytes, or an alg that isn't
an integer or a text string of at most 64 bytes: its device key signs
the EReaderKeyBytes as sent, and a reader could put close to 1 KiB of
its own choosing there as a kid, or anything at all as an alg. An
ephemeral key needs neither, and ISO/IEC 18013-5's Annex D, Multipaz
and this package's own readers send neither. Such a message is
refused as one that doesn't decode: `TrySessionEstablishment`
rejects it, and `HandleSessionEstablishment` ends the session.

### Text shown to the holder loses its variation selectors (`walletflow`, `proximity`, mobile)

Text from another party that the holder is shown (an issuer's display
metadata, a reader's names, an error's text) now has every variation
selector dropped, U+FE0F, which asks for an emoji's colour
presentation, among them. Each shows as nothing, so a run of them can
carry text no one sees, or set apart a name that looks the same as
another. An emoji in an issuer's name then shows in its default
presentation. A proximity request whose second-edition information
names a controller ID with a variation selector now stands without
that information (`RequestInfoError`), as one with a format character
already did.

### A logo whose host isn't ASCII in its last label is dropped (`walletflow`, mobile)

`walletflow` now drops a logo URI whose host isn't ASCII in its last
label (or, under `arpa`, in the label before it), as it drops one
naming an IP address or a local name. An image loader maps such a host
(IDNA, UTS #46) before resolving it, and full-width or other
compatibility forms of digits, letters and full stops can spell an IP
address or a local name there: `https://１２７.０.０.１/l.png` loads
from 127.0.0.1. An internationalized name in its A-labels (`xn--…`), as
RFC 3986 §3.2.2 asks a URI to carry it, is judged as before, and so is
one whose last label is ASCII, such as `bücher.example`; an issuer
whose logo URI names a host under an internationalized top-level
domain in its U-labels loses its logo until it writes the A-labels.

The filter judges names only. If your app loads logos with a client
that connects to any address, have it refuse loopback, private and
link-local addresses, as the demo apps' `LogoStore` does: a public name
can resolve to one.

### A status list address that embeds a non-public IPv4 address is refused, however written (`statuslist`)

`statuslist.Fetcher`, which every status and identifier list check
uses, now decodes two more IPv6 forms that embed an IPv4 address, as
FAPIgo's fapihttp does: SIIT's IPv4-translated `::ffff:0:a.b.c.d` and
an ISATAP interface identifier (`…:0:5efe:a.b.c.d` or
`…:200:5efe:a.b.c.d`, under any prefix). A translator or router on the
path delivers such an address to the IPv4 one, so it's refused when
that IPv4 address is: loopback unless `AllowLoopback`, private or
link-local unless `AllowPrivate`. A zone in an IPv6 literal
(`[…%25eth0]`) no longer hides an address from the policy's ranges and
embeddings. A status list served at such an address needs the same
setting as one served at its IPv4 address.

## v0.82.0 → v0.83.0

### A production issuer treats a deferred transaction without `ExpiresAt` as lapsed

Under `AssuranceProduction`, `RequestDeferredCredential`,
`IssueDeferredCredential` and `DenyDeferredCredential` now answer a
`DeferredTransactionRecord` with a zero `ExpiresAt` as lapsed
(`invalid_transaction_id` to the Wallet, `ErrDeferredTransactionResolved`
to the caller). `RequestCredential` has always set it, so only a
record a deployment wrote itself, or one migrated from a store that
didn't keep it, is affected. Set `ExpiresAt` on such records. Under
`AssuranceDevelopment` a zero `ExpiresAt` still never lapses.

### The legacy deferred-transaction check is audited, and deprecated

A deferred record with neither `CredentialIdentifier` nor
`RequestedByConfigurationID` (saved by v0.81.0 and before, or written
by a deployment without them) is still released to any token granting
its credential configuration. Each such poll now records an
`AuditEventLegacyDeferredAuthorization`: a success when the token
grants the configuration, a failure when it doesn't. An `AuditSink`
that switches over `AuditEventType` should handle the new value. Once
none has been recorded for a full `Limits.DeferredTransactionLifetime`,
none of those records is pending. This fallback will be removed in a
later release, after which such records are refused; a deployment
creating records itself should set one of the two fields.

### `androidkey.EvidenceVerifier` logs what `AllowUncheckedLegacyEvidence` lets through

Each instance or instance key `AllowUncheckedLegacyEvidence` accepts
without judging it in full (no Facts kept, or Facts without validity
periods) is now logged at `slog.LevelWarn` to the new
`EvidenceVerifier.Logger` (nil means `slog.Default()`), naming the
instance and, for an instance key, its thumbprint. Turn the option
off once none is logged.

## v0.81.0 → v0.82.0

### FAPIgo v0.76.0: an attester's `x5c` must be one path, in order

OID4VCgo now requires FAPIgo v0.76.0; see its UPGRADING.md, section
v0.76.0. A Wallet Attestation whose `x5c` lists its certificates out
of order, repeats a subject or a public key, or ends with more than two
copies of one CA is refused with `invalid_client` at PAR, the Token
Endpoint and the attested pre-authorized code exchange
(`server.X5CAttesterChain`). Wallets must send `x5c` leaf first, each
certificate followed by the one that certifies it, as RFC 7515 §4.1.6
and HAIP 1.0 require; a CA cross-certified to two anchors may be sent as
the last two. Before, an unauthenticated caller could send CA
certificates that certify each other and cost the Authorization Server
about 60 ms of CPU per request. FAPIgo still checks an ordered chain
from the leaf up before its anchor, with keys on any curve, so one of
10 P-521 certificates still costs about 20 ms per request: keep PAR and
the Token Endpoint behind a rate limit.

### A Credential Issuer refuses an access token issued for another

An `issuer.Issuer` now refuses an access token whose audience doesn't
name its `Config.Issuer`, as 401 `invalid_token`.
`issuer/fapiresource` reports every token's audience
(`AuthorizedRequest.Audience`). An `AuthorizedRequest` built by your
own verifier must report it too: under `AssuranceProduction`, one with
`Audience` nil is refused with a plain error (a 500) by
`RequestCredential`, `RequestDeferredCredential`, `RequestNotification`
and `IssueNotificationID`. Outside production a nil `Audience` still
isn't checked, and that verifier must accept only tokens issued for
this Credential Issuer itself.

Nothing changes where the Credential Issuer shares its Authorization
Server's identifier and is that Authorization Server's only Credential
Issuer (`cmd/conformance-issuer` and the passport-vdc demo). One that
shares the identifier of an Authorization Server serving others still
takes every token that Authorization Server issues without a resource,
from any of their grants: see below. Otherwise the Authorization
Server's tokens are addressed to itself unless restricted to a
resource, and are now refused. Either:

- restrict them to the Credential Issuer: list `Config.Issuer` in the
  Authorization Server's `server.Config.Resources`, and pass
  `RedeemedPreAuthorizedCode`'s new `Resource` as
  `server.IssueAccessTokenRequest.Resources` (and the
  `IssueRefreshTokenRequest`'s) when you issue a pre-authorized
  code's token; wallets ask for the authorization code flow's tokens
  with it as their `resource`. Set `serverresource.Options.Resource`
  to `Config.Issuer` too, one resource verifier per Credential Issuer;
  or
- when the Authorization Server issues tokens for this Credential
  Issuer alone, list its identifier in the new
  `issuer.Config.AcceptedAccessTokenAudiences`, and in
  `Config.AuthorizationServers`: `New` refuses an accepted audience
  that isn't one of them. Never do so for one serving several
  Credential Issuers: each would then take another's token for its
  own, and issue its own holder's Credential for that token's subject.

With several Credential Issuers on one Authorization Server, the
Wallet's `resource` chooses which of them a token is for, so also:

- have each Credential Issuer's consent step grant only that issuer:
  set `GrantedAuthorization.Resources` from the new
  `Issuer.AuthorizationResources(InteractionRequest.Resources)`, and
  `server.Deny` the request when it returns an error
  (`issuer.ErrResourceNotThisIssuer`). Left nil, a request for one
  Credential Issuer's offer that names another as its `resource` gets a
  token for the other, under the subject this one's consent step signed
  in. See the recipe in `issuer/authorization_server.go`;
- at the pre-authorized Token Endpoint, pass the request's `resource`
  parameters (`server.TokenEndpointRequest.Resources()`) as the new
  `ExchangePreAuthorizedCodeRequest.Resources`, which refuses any but
  `Config.Issuer` with 400 `invalid_target` (RFC 8707 §2) before the
  code is consumed, and issue the token with
  `RedeemedPreAuthorizedCode.Resource` alone, and its refresh token
  too (`IssueRefreshTokenRequest.Resources`). Never pass the request's
  own resources as `IssueAccessTokenRequest.Resources`: the token would
  then be good at the Credential Issuers they name too;
- give the Authorization Server an identifier none of them has,
  listed in each one's `Config.AuthorizationServers`. A Credential
  Issuer sharing it takes every token the Authorization Server issues
  without a resource for its own: one refreshed from a refresh token
  issued without `Resources`, say, from another Credential Issuer's
  grant. If one must keep sharing it, confine every wallet client to
  the Credential Issuers with FAPIgo's `AllowedResources`
  (`storage.RegisteredClientConfig`, and
  `server.Config.AutomaticRegistration`), listing each: the
  Authorization Server then issues no token addressed to itself, and
  refuses with `invalid_target` a request naming no resource, so that
  Credential Issuer's Wallets must name it too. `issuer.New` can't
  tell an Authorization Server serving others, so it refuses neither
  setup.

`cmd/conformance-issuer`, the passport-vdc demo and `walletflowtest` now
list their Credential Issuer in `server.Config.Resources`, which turns
on resource indicators at their Authorization Server: a Wallet naming
any other `resource`, at PAR or the Token Endpoint, gets
`invalid_target` where the parameter used to be ignored. A deployment
that copies their wiring does the same. Wallets built on `walletflow`
name the offer's Credential Issuer, which is accepted.

What Wallets and existing grants see:

- a Wallet that names no `resource` in its authorization request (the
  Multipaz 0.102.0 client, for one) is denied, with `access_denied`,
  by the consent step of a Credential Issuer whose Authorization
  Server has an identifier of its own and isn't listed in its
  `AcceptedAccessTokenAudiences`. OpenID4VCI 1.0 §5.1.2 has it name
  the Credential Issuer;
- a pre-authorized Token Request naming the Credential Issuer's
  identifier spelled another way (a trailing slash, an upper-case host,
  an explicit default port) is refused with `invalid_target`:
  resources are compared exactly;
- grants made before the upgrade carry no resource, so their refresh
  tokens refresh into tokens addressed to the Authorization Server.
  Where it has an identifier of its own, a Credential Issuer not
  listing it in `AcceptedAccessTokenAudiences` now refuses those with
  `invalid_token`, and the Wallet must authorize again; revoke such grants to have it learn so at the Token Endpoint.
  Where a Credential Issuer shares the identifier of an Authorization
  Server serving others, end them before the upgrade serves anyone:
  `AllowedResources` refuses their refresh with `invalid_target`, or
  revoke them. See `issuer/authorization_server.go`'s "Refreshing
  credentials".

### `issuer.NewError` answers token errors with 401 and 403

`issuer.NewError(issuer.ErrorInvalidToken, …)` now answers 401, and
`NewError(issuer.ErrorInsufficientScope, …)` 403, as RFC 6750 §3.1 has
them, each with its `WWW-Authenticate` challenges; both answered 400
before. Every other code still answers 400.

### A custom DeferredTransactionStore persists RequestedByConfigurationID

`DeferredTransactionRecord` has a new field,
`RequestedByConfigurationID`, which marks a transaction deferred from
a request by `credential_configuration_id`. `RequestDeferredCredential`
then releases it only to a token the Credential Endpoint would accept
that request from. A store that saves the whole record (the in-memory
store, `sqlstore`) needs nothing. A store that maps fields one by one
must persist it too, in `Update` as well as `Create`: a record read
back without it is checked as one saved before it existed, against the
configuration alone. `issuertest.TestDeferredTransactionStoreContract`
now checks that `Update` keeps it, and `CredentialIdentifier`.

During a rolling upgrade, the old check still applies to transactions
deferred before the upgrade, until they expire, and to any transaction
a v0.81.0 replica updates (its `Update` writes the record back without
the marker). Finish the rollout before relying on it, or drain
pending deferred transactions first.

### Role separation of mdocs under `IssuerRoots` (`walletflow`, `credential/mdoc`)

With `MdocIssuerRoots` unset, mdocs are received under `IssuerRoots`
and checked with `MdocIssuerLeafPolicy`. Outside development,
`walletflow.New` now holds that pair to role separation too, beside
`IssuerRoots` with `IssuerLeafPolicy`, and
`mdoc.LenientDocumentSignerPolicy` no longer counts as a policy that
tells roles apart. A `Config` whose `IssuerRoots` (for mdocs) or
`MdocIssuerRoots` may share a trust anchor with another role's pool,
with an opt-out or `mdoc.LenientDocumentSignerPolicy` as its mdoc
policy, is refused with the existing "may share a trust anchor"
error: separate the pools, set `MdocIssuerRoots`, or require the
document signer's extended key usage
(`mdoc.DefaultDocumentSignerPolicy`).

### Held SD-JWT VCs re-checked with the default issuer check (`walletflow`, mobile)

`CheckStatus` now re-checks a held SD-JWT VC's issuer chain with the
policy receipt applies (`wallet.IssuerLeafPolicyFor`): with no
`IssuerLeafPolicy` (`issuer_require_eku` in the mobile configuration),
v0.81.0's default issuer check. A credential received before v0.81.0,
or under `verifier.AnyIssuerLeaf`, whose issuer certificate that check
refuses becomes `invalid` with reason `issuer_untrusted`. Set
`IssuerLeafPolicy: verifier.AnyIssuerLeaf` to keep such credentials,
for `IssuerRoots` that anchor issuers' certificates alone.

For an SD-JWT VC without a policy, `wallet.IssuerLeafPolicyFor` returns
`verifier.DefaultSDJWTIssuerLeafPolicy` itself, so `walletflow.New`
counts it as the default it is: a production `Config` that sets it as
`IssuerLeafPolicy`, on `IssuerRoots` that may share a trust anchor with
another role's pool, is refused with "may share a trust anchor", as
one with no policy is.

### An mdoc needs a `HolderKey` (`wallet`)

`wallet.VerifyIssuedCredential` now refuses an mdoc when neither
`VerifyIssuedCredentialParams.HolderKey` nor `HolderKeys` is set, even
if its `Configuration` declares no cryptographic binding: an mdoc's MSO
always names a device key, and without one of them it would be one the
wallet never proved it holds. Pass the key, or keys, proved in the
Credential Request. walletflow always did.

### DPoP requests to non-normal endpoint paths (`wallet`, `walletflow`, mobile)

`Wallet.DPoPResourceClient`'s `Do` and the DPoP-bound token requests
(`RequestPreAuthorizedCodeToken`, and `RequestRefreshToken` with a
`DPoPKey`)
now refuse, before sending anything, an endpoint whose path has a `.`
or `..` segment or a percent-encoded unreserved character (`%2e`,
`%7E`, …), as fapigo/client's protected resource client already does:
a front end routing by the raw path and a server comparing the
normalized `htu` would read it as different resources. This reaches
pre-authorized code tokens, deferred credential polls and refreshes
without client authentication. An issuer whose metadata names such an
endpoint must name it in normal form. `Wallet.GenerateDPoPProof` applies
the same rule to its `htu`, and refuses one that isn't a URL, for a
caller building DPoP requests of its own.

### Presented certificate chains are checked in order

Every verifier of a chain another party presents — an SD-JWT VC's or
proof's `x5c`, an mdoc's `x5chain`, a reader's chain, a status list's,
a Request Object's — now refuses one whose certificates aren't listed
in order, leaf first, each the issuer of the one before; one in which
two certificates share a subject name or public key; and one with an
intermediate's P-521 key, or RSA key over 3072 bits, unless a
configured trust anchor the chain reaches has a key of that type. The
chain must also be anchored at one of its top two certificates: its
last certificate is a trust anchor or is issued by one, and signed the
one before it; failing that, the one before it is itself an anchor, or
is issued by an anchor whose subject and key the last one carries (a
re-issue or cross-certificate of that anchor). A chain carrying two
or more certificates past its anchor is refused, such as a
cross-certificate followed by the CA that issued it when only the
cross-certified anchor is trusted. No API changes. A
partner whose chains are now refused has to send them in order,
leaving out certificates that aren't on the path; the SPECIFICATIONS.md
"Known strictness" entry has the details.

These rules differ from FAPIgo's for a Wallet Attestation's `x5c`
(see above): FAPIgo accepts both certificates of a CA cross-certified
to two anchors as the last two, which these refuse as a repeated
subject, and chains of up to 10 certificates, where these allow 8.

### A signer's chain repeating a subject or key (`walletprovider`, `statuslist`, `identifierlist`, `issuer`, `verifier`, `credential/sdjwtvc`, `attestation`)

`walletprovider.New`, `statuslist.IssueTokenX5C`,
`statuslist.IssueTokenCWTX5Chain`, `identifierlist.IssueToken`,
`issuer.New` (the `SDJWTSigner` and `MdocSigner` chains),
`issuer.NewMetadataHandler`, `issuer.SignMetadataJWS`, `verifier.New`
(`ClientCertificateChain`), `sdjwtvc.Issue` (`IssuerIntermediates`),
and `attestation.Issue` and `attestation.IssueWalletAttestation` (a
`Header.X5C`) refuse a signer chain in which two certificates share a
subject name or a public key, such as a CA key rollover's new-with-old
certificate followed by the old CA's. Every verifier here, and FAPIgo
v0.76.0's Wallet Attestation check, already refuses such a chain, so
an issuer, verifier or Wallet Provider configured with one now fails
at startup rather than at every party that checks what it signs.
Configure the chain without the rollover certificate.

### A Status List Token's `x5c` without its trust anchor (`statuslist`, `wallet`, `walletflow`, `verifier`)

`statuslist.CheckX5C`, and every status check of a JWT Status List
Token, refuses a token whose `x5c` includes the trust anchor (a
self-issued certificate after the leaf), as HAIP 1.0 §6.1 has the
sender leave it out and every other JOSE `x5c` check here already did.
A Status List Provider whose tokens include their root has to issue
them without it; a chain passed to `statuslist.IssueTokenX5C` never
could include it. A CWT token's `x5chain`
may still include the anchor.

### A Request Object with a bad signature (`wallet`, `walletflow`, mobile)

A signed Request Object's signature is now checked, with its `x5c`
leaf's key, before its chain. One whose signature doesn't verify, or
whose leaf doesn't parse or has an oversized RSA key, is refused as
such even when its chain is untrusted: its error no longer wraps
`wallet.ErrUntrustedVerifier`. Over the Digital Credentials API,
`walletflow` reports it as `ErrMalformedRequest`, and the mobile
libraries as `invalid_input` rather than `untrusted_verifier`.

### `sdjwtvc.KeyBindingCheck.ExpectedSDHash` is required

`sdjwtvc.VerifyKeyBindingJWT` refuses an empty `ExpectedSDHash`, as it
does an empty `ExpectedAudience` or `ExpectedNonce`, and refuses a Key
Binding JWT without `sd_hash` (RFC 9901 §4.3). A caller of it directly
passes the presentation's hash: `Presentation.SDHash(alg)`.
`sdjwtvc.Verify` and the verifier already did.

### SD-JWT VC disclosures are refused after the issuer (`verifier`, `credential/sdjwtvc`)

`VerifyResponse` now reads only an SD-JWT VC presentation's
Issuer-signed JWT before resolving the issuer's key and verifying its
signature (RFC 9901 §7.1), and decodes only the Disclosures its
digests reference. A presentation with an undecodable, repeated or
unreferenced Disclosure, or with more parts than its digests could
reference, used to be refused as `malformed`; it is now refused as
`untrusted_issuer` when its issuer isn't trusted, and otherwise as
`invalid_credential`. Code that matches on `Error.Reason`,
`DiscardedPresentation.Code` or a transaction's `LastError` sees the
new reasons. `sdjwtvc.VerifyPresentation` refuses such a presentation
after verifying the Issuer-signed JWT, with that error instead of a
parse error.

### Issuer chains per response (`verifier`)

`VerifyResponse` verifies each distinct issuer certificate chain once
per response when `IssuerKeys` is an `X5CIssuerKeyResolver` or
`MdocIssuerKeys` an `X5ChainIssuerKeyResolver` itself. A resolver of
your own, one dispatching to several built-in resolvers for instance,
has each of its calls verified in full, under that call's resolver's
`LeafPolicy` and `Revocation`. Through a built-in resolver, once
`MaxFailedIssuerChainsPerResponse` (4) of a response's distinct issuer
chains haven't verified (no configured root anchors them, a signature
in them doesn't verify, or a certificate doesn't parse or is outside
its validity), the response is refused as a whole, `malformed`, when
it reaches another distinct chain, which is left unverified. Chains
that verify aren't counted, even when the leaf policy or revocation
then refuses them, so a response presenting credentials from many
issuers, revoked ones among them, isn't refused by it. A response
holding more than four credentials from issuers no root anchors is,
even beside a valid one (an optional credential set of foreign loyalty
cards before a required PID, say), when they come first.

Through a built-in resolver, an SD-JWT VC's Issuer-signed JWT, or an
mdoc's `IssuerAuth`, is now checked with the key of the `x5c` or
`x5chain` leaf it presents before its chain is verified, so a genuine
chain replayed under a signature its key didn't make costs no chain
check. Such a presentation is refused `invalid_credential` even when
its chain is untrusted, where it was `untrusted_issuer`; one whose
leaf doesn't parse is still refused `untrusted_issuer`. A resolver of
your own sees no change.

The Digital Credentials API's org-iso-mdoc answers (ISO/IEC TS 18013-7
Annex C) get the same, with an `X5ChainIssuerKeyResolver`:
`mdocdcapi.VerifyResponse` and `VerifyResponseDocuments`, and so
`Transactions.HandleMdocDCAPIResponse`, check each document's
`IssuerAuth` with its `x5chain` leaf's key before its chain, verify a
chain the answer's documents share once, and apply
`MaxFailedIssuerChainsPerResponse`. No API changes. A verifier of mdocs
of its own can do the same through the new
`verifier.ResponseIssuerChains`, one per response, whose
`ResolveMdocIssuer` takes the document's `IssuerAuth`;
`verifier.ResolveMdocIssuer` is unchanged.

### The Request Object at a request_uri is sealed with its record (`verifier`)

`verifier.TransactionCodec` writes version 3 records
(`TransactionCodecVersion`), whose sealed fields are also bound to the
hash of the signed Request Object `Begin` stores: a store writer
without the sealing key could put another request's Request Object
there, and have the holder answer that one. Such a record no longer
opens. `Transactions.RequestObject`, and `RequestObjectHandler`'s GET,
still serve the stored Request Object, signing nothing per fetch.

- Version 1 and 2 records still open, without their Request Object,
  which they don't bind: a request begun before the upgrade has its
  Request Object signed from its sealed fields for each GET (a billed
  call with a KMS-backed signer) until it expires. Written back, a
  record is version 3.
- An earlier release doesn't read version 3: during a rolling deploy,
  a request begun or updated on an upgraded replica fails on one not
  yet upgraded, so finish the rollout quickly (a request lives
  `TransactionsConfig.Lifetime`), and a rollback fails the requests the
  new release wrote.
- A codec without a `Sealer`, and any other unsealed store, binds
  nothing and serves the Request Object as stored, as before: whoever
  can write such a store can change every field a Request Object is
  signed from. A store that seals transactions its own way must bind
  `RequestObject` as `TransactionCodec` does, or not return it, which
  has it signed for each fetch.
- A request_uri POST is signed for each fetch, as before. Rate limit
  the request_uri endpoint with the response endpoints (DEPLOYING.md).

The request_uri now answers 500 `server_error`, where it answered 404,
when the store fails, when it answers with another transaction's
record, and when a record doesn't open or is stripped of its sealed
fields: a store that fails isn't a request that's unknown. Alert on
those as on any other server error.

### App Attest chains (`walletprovider/appattest`)

`VerifyAttestation` takes only Apple's chain shape: an `x5c` of exactly
two certificates (`MaxChainLength` is now 2), each with an ECDSA P-256
or P-384 key, checked before any signature is. Apple's attestations
already have this shape; a test chain of your own with RSA keys, or
with more certificates, is now refused `ErrMalformed`.

### Android Key Attestation chains (`walletprovider/androidkey`)

`Verifier.Verify` refuses a chain of one certificate (`ErrMalformed`)
and a leaf whose key is a root's (`ErrUntrustedRoot`). A chain's last
certificate anchors it when it is one of `Verifier.Roots` byte for
byte or is signed by one (a self-signed re-issue of a root is);
carrying a root's public key no longer suffices. The chain's top is
checked against the roots, and each certificate's validity, before
any signature below the top, and those signatures are then checked
from the top down, so a chain of any keys no root anchors costs no
check with them. A chain that is both unanchored and has a broken
link is now refused `ErrUntrustedRoot` (was `ErrChainSignature`), and
a certificate outside its validity is reported before a broken link.
Android's chains are unaffected.

### Android status list outages (`walletprovider`, `walletprovider/androidkey`)

`androidkey.StatusSource` now refreshes Google's list in the
background ahead of `MaxAge`, and, while fetching fails, keeps using
the last list for the new `Grace` past `MaxAge` (12 hours by
default). Set `Grace` negative for the old behaviour, a list never
used past `MaxAge`. During `Grace`, a certificate Google has listed
REVOKED or SUSPENDED since the last successful fetch is still
accepted, until a fetch succeeds: the list judged by can be up to
`MaxAge` plus `Grace` old (36 hours by default). Keep `Grace` short of
a day, or set it negative where that's too long. A fetch is no
longer cut short by the request that started it, and a caller waiting
for one stops when its own context ends.

When no list can be had, Android requests are now answered HTTP 503
`server_error` with a `Retry-After` (the time until `StatusSource`
fetches again: up to its `RetryAfter`, a minute by default; 30 seconds
for an error that doesn't say). A registration was answered 403
`evidence_rejected`, and a recheck before a Wallet or Key Attestation
HTTP 500 `server_error`. A Key Attestation whose holder key evidence
can't be judged now fails with 503 too, where the key was left out of
the attestation, or the request refused `no_key_attested` if that left
none. `androidkey.EvidenceVerifier` wraps
`ErrStatusUnavailable` in the new `walletprovider.ErrUnavailable`,
which `Provider.Register`, `WalletAttestation` and `KeyAttestation`
return without `ErrEvidenceRejected`. A custom `EvidenceVerifier` or
rechecker that can't decide for now can wrap `ErrUnavailable` too.
The Swift and Kotlin `HttpWalletProvider` already treat a 5xx as
retryable; with the Go `Client`, a `RefusedError` with `Status` 503 is
one to retry.

### Revocation outranks policy in rechecks (`walletprovider`, `walletprovider/androidkey`)

An Android recheck consults Google's status list first, so a REVOKED
or SUSPENDED certificate revokes or suspends the instance even when a
root removed from `Roots` or a tightened `Verifier` would refuse it
too; a list that can't be fetched no longer stops a root or policy
refusal. The provider runs an instance's rechecker even when its own
`Policy` refuses the instance or instance key, and, when the instance
is refused for another reason, still rechecks the instance key a Wallet
or Key Attestation request names: a REVOKED or SUSPENDED certificate
of that key's own chain revokes or suspends the instance, answered
`evidence_rejected` where it was `policy_refused`. Fresh evidence a
registered instance sends, a new instance key's chain or a holder
key's, that Google's list names REVOKED or SUSPENDED now revokes or
suspends the instance too, where it only refused the request (a holder
key's is answered `evidence_rejected`, not `no_key_attested`):
`androidkey.EvidenceVerifier.Verify` wraps
`walletprovider.ErrEvidenceRevoked` or `ErrEvidenceSuspended`, as
`Recheck` does, and a custom `EvidenceVerifier` can too. That holds
only for evidence the provider gets to verify: a request refused
first, the instance not active, its registration evidence or (for a Key
Attestation) its instance key refused, as on `registration_expired`
or `policy_refused`, or its challenge not valid, revokes nothing on
the evidence it carries. And
`Config.OnRecheckRefused` is now called for a `Policy` refusal too
(`ErrPolicy`, the instance left active): an alert keyed on that
callback sees refusals it didn't before.

### Instances of an unconfigured evidence Kind (`walletprovider`, `walletprovider/androidkey`)

An instance whose evidence `Kind` has no verifier in
`Dependencies.Evidence` is now refused, `policy_refused`, and reported
to `OnRecheckRefused`, where it used to be attested without rechecks.
Keep a verifier for every Kind your instances registered with.
`androidkey.EvidenceVerifier`'s `Recheck` and `RecheckInstanceKey`
return `ErrConfig` (the provider's HTTP 500) for an instance of
another Kind than `androidkey.EvidenceKind`, where they accepted it,
and its `Verify` refuses evidence of another Kind with `ErrConfig`, so
such an adapter registers no instance (`evidence_rejected`): don't
serve the adapter under a Kind of your own.

### A wallet decides which issuers' offers it takes (`walletflow`)

A pre-authorized offer's transaction code goes to the issuer the offer
names before `IssuerRoots` judge that issuer, so a phishing offer
naming an attacker's issuer, beside a genuine service's PIN, hands the
attacker the PIN (SECURITY.md, "Transaction code phishing").
`walletflow.New` now refuses, at every assurance level, development
included, a `Config` that receives credentials (`IssuerRoots`,
`MdocIssuerRoots` or `MdocIssuerRootsByDocType` set) without deciding
which issuers' offers it takes, in one of three ways:

- `CredentialIssuers`, the Credential Issuer Identifiers it takes
  offers from: `StartIssuance` refuses any other's offer with
  `ErrUntrustedIssuer` before fetching its metadata;
- `IssuerMetadataRoots` (holding a certificate) with
  `RequireSignedIssuerMetadata` and `RequireIssuerMetadataName`, all
  three: only issuers whose metadata a certificate under those roots
  signs and names them in, also checked in `StartIssuance`. It may be
  combined with `CredentialIssuers`, and both then apply;
- the new `AllowAnyCredentialIssuer`, which takes any issuer's offer
  and leaves the phishing to the application. It can't be set with
  either of the others.

An empty identifier in `CredentialIssuers` is refused too. A wallet
that receives no credentials needs none of them.

`CredentialIssuers` now applies on every path that talks to an issuer,
not only to offers. Under a `Config` that no longer lists an issuer, as
after an app update drops it, `ResumeIssuance`, `RefreshCredential` and
a resumed `Deferred`'s `Poll` refuse with `ErrUntrustedIssuer` before
sending it anything, where they used to complete the authorization,
redeem the refresh token or poll there. Deleting a credential then
forgets its refresh grant without revoking it at that issuer. Nothing
held is forgotten: a pending authorization stays until it expires, a
credential and its refresh grant stay until deleted, and a `Deferred`
stays pending until `Abandon`. Listing the issuer again resumes them.
Code that dropped an issuer on purpose deletes or abandons what it
holds from it.

Issuer metadata refused under `RequireSignedIssuerMetadata` or
`RequireIssuerMetadataName`, because it isn't signed or its
certificate or `sub` names another issuer, now wraps
`ErrUntrustedIssuer`, in `StartIssuance` and on each of those paths,
where it used to be a plain error. `ErrUntrustedIssuer` is now the new
`wallet.ErrUntrustedIssuer`, which `wallet.FetchCredentialIssuerMetadata`
wraps for the same refusals, and its message changed. A signer whose
chain doesn't reach `IssuerMetadataRoots` is reported as before.

```go
// Before
w, err := walletflow.New(walletflow.Config{
	IssuerRoots: issuerRoots, // ...
}, deps)
// After: the issuers you take offers from
w, err := walletflow.New(walletflow.Config{
	IssuerRoots:       issuerRoots,
	CredentialIssuers: []string{"https://issuer.example.com"}, // ...
}, deps)
// Or, where issuers can't be listed: signed metadata naming its issuer
w, err := walletflow.New(walletflow.Config{
	IssuerRoots: issuerRoots, IssuerMetadataRoots: metadataRoots,
	IssuerMetadataRevocation: metadataCRLs.Checker(),
	RequireSignedIssuerMetadata: true, RequireIssuerMetadataName: true, // ...
}, deps)
```

### DCQL queries over the limits are refused before duplicates are dropped (`wallet`, `walletflow`, mobile)

A presentation request whose DCQL query has more than 64 credential
queries (`dcql.MaxCredentialQueries`), or a credential query with more
than 256 claims queries (`dcql.MaxClaimsPerCredential`), is now
refused as malformed, duplicates counted. v0.81.0 dropped duplicate
claims queries first, so a credential query repeating the same claims
over the limit used to be answered. Also, a claims query value of `-0`
is no longer a duplicate of one of `0`. A Verifier keeps its query
within the limits, without repeats.

### Mobile: a wallet decides which issuers' offers it takes (gomobile ABI 16, Swift, Kotlin)

The mobile configuration takes the same three ways: `credential_issuers`
(Swift and Kotlin `issuers.credentialIssuers`);
`issuer_metadata_roots` with `require_signed_issuer_metadata` and
`require_issuer_metadata_name` (`issuerMetadata.roots`,
`requireSigned`, `requireName`); or `allow_any_credential_issuer`
(`issuers.allowAnyCredentialIssuer`). `NewWallet`, Swift's
`Wallet(configuration:)` and Kotlin's `Wallet` constructor refuse a
configuration with issuer roots and none of them, or with
`allow_any_credential_issuer` beside either of the others, as
`invalid_input`. `startIssuance` refuses an unlisted issuer's offer
with the new `untrusted_issuer` code (`WalletError.Code.untrustedIssuer`,
`WalletException.Code.untrustedIssuer`), before asking for its PIN.
The same code refuses resuming an authorization, refreshing a
credential or polling a deferred one from an issuer the configuration
no longer lists, keeping what the wallet holds from it, and an issuer
whose metadata isn't signed, or is signed naming another issuer, under
`require_signed_issuer_metadata` and `require_issuer_metadata_name`
(`protocol` before). `ABIVersion` is 16: the Swift and Kotlin libraries need a framework
built from this release.

```swift
// Before
WalletConfiguration(clientID: id, redirectURI: uri, issuers: .init(roots: issuerRoots), ...)
// After
WalletConfiguration(clientID: id, redirectURI: uri,
                    issuers: .init(roots: issuerRoots, credentialIssuers: ["https://issuer.example.com"]), ...)
```

```kotlin
// Before
WalletConfiguration(clientID = id, redirectURI = uri, issuers = WalletConfiguration.IssuerTrust(roots = issuerRoots), ...)
// After
WalletConfiguration(
    clientID = id, redirectURI = uri,
    issuers = WalletConfiguration.IssuerTrust(roots = issuerRoots, credentialIssuers = listOf("https://issuer.example.com")), ...
)
```

A JSON configuration adds `"credential_issuers": ["https://issuer.example.com"]`.

### Full status lists (`walletprovider`)

Once the current period's status lists are full, a recorded instance
key last used in the previous period now keeps its index there, and
its Wallet or Key Attestation names it, where the request used to fail
with HTTP 500. Such a renewal takes none of the instance's
`MaxInstanceKeysPerPeriod`, and is attested even once the instance has
used that up (it isn't answered 429 `too_many_instance_keys`). A key
whose index is older, and every new instance key, are still refused
until a period's lists have room. When
a key moves to a later period's lists, its old index is kept as
`InstanceKey.PreviousStatus` whenever that list is still served, not
only when it's the previous period's, so `Suspend`, `Resume` and
`Revoke` set an index two periods back too.

### Status list capacity (`walletprovider`)

`DefaultStatusListSize` is now 2^20, up from 2^16: a period's lists
hold about 33.5M instance keys, not 2.1M. A provider that leaves
`Config.StatusListSize` zero takes the new size as soon as it starts,
for the lists of the current period too, which grow: their indices
handed out stay where they are, and the lists are published at the
new size. While a rolling upgrade runs, a replica still on the old
size can't publish a list in which a new one handed out an index past
2^16 (HTTP 500 for that list), nor set that index's status, so roll
out quickly, or set
`StatusListSize: 1 << 16` for the upgrade and raise it in a later
rollout. Never lower it below an index a served list holds. The same
goes for rolling back: v0.81.0 with `StatusListSize` left zero
silently takes 2^16 again, and can't publish a list holding an index
past it (HTTP 500 for that list), nor set that index's status, until
the list retires. Set `StatusListSize: 1 << 20` before rolling back. A
list of
2^20 two-bit statuses packs to 256 KiB, within a Relying Party's
default 1 MiB token limit whatever its statuses; an issuer's
`statuslist.Cache` keeps 256 KiB for each of the provider's lists it
reads, so 128 of them take half its default 64 MiB `MaxBytes`.

### Recently registered instances take a share of the status lists (`walletprovider`)

The keys of an instance registered in the current or previous status
list period (`Instance.CreatedAt`) now take indices from the period's
first `Config.RecentInstanceStatusLists` lists alone: 16 of the 64 by
default (`DefaultRecentInstanceStatusLists`). Other instances' keys
take indices from any list: from those 16 with a chance in proportion
to their share while they're no fuller than the other lists,
otherwise from list 16 onwards, the 16 only once the rest are full.
So the 16 hold established wallets' keys about as densely as the rest
do, and established wallets' keys don't take the room recent
instances' need while the rest have it. Many instances
registered at once can then fill no more than that share of a period,
where they used to be able to fill every list and have every other
wallet's attestations refused until the period ended.

- Once the share is full, a recent instance's new instance key is
  refused until the next period as on full lists (HTTP 500
  `server_error`, wrapping `statuslist.ErrListsFull`), logged at warn
  as "the status lists of the current period that recently registered
  instances take indices from are full". Its recorded key on the
  previous period's lists keeps its index, as on full lists. Nothing
  is revoked or forgotten. A burst that fills the share refuses new
  wallets' first keys for two periods, not one: its instances are
  still recent in the next period, and their recorded keys move there
  without evidence, filling the share again.
- Size `StatusListSize` for the share too. Where r of a period's keys
  are recent instances', they all fit while the period uses no more
  than 1/(1+3r) of its capacity, at worst (established keys used early
  in the period). An Android wallet that registers again when its
  Remote Key Provisioning certificates expire is a new, recent
  instance each time (DEPLOYING.md).
- `StatusListFill` has a new `RecentInstanceLists` field and a
  `RecentInstanceFree` method; `Lists` are in list order. Alert on
  `RecentInstanceFree` falling fast early in a period (DEPLOYING.md).
- Attestations now name lists across the period, so an issuer fetches
  more than one of the provider's lists. A key on list 16 or later
  tells it its instance was registered before the previous period.
  One on lists 0 to 15 is a recent or an established instance's:
  about four times as likely a recent one's as a key across all lists
  is, and certainly one once recent instances' keys alone fill the
  share.
- `SweepStatusLists` now counts every list of a period, not up to the
  first empty one.
- Raise `RecentInstanceStatusLists` for a launch that registers most
  of your fleet within a period or two; `MaxStatusListsPerPeriod` turns
  the share off.

### The passport-vdc demo's status indices files

The demo's Wallet Provider and issuer keep their status list indices
(`wallet-provider-status-indices.json`, `status-indices.json`) in a
new format, each list its reserved indices or a bitmap, whichever is
shorter, and rewrite a file of the earlier format in it on the first
change. A demo from v0.81.0 or before refuses to start on a file
written in the new format: to roll back, give the older demo a state
directory of its own, or delete the status indices file and the Wallet
Provider's instances file with it. The files, and the demo's other
state files, are now flushed to disk before and after they're
replaced.

### A first message that doesn't decrypt no longer ends a BLE session (`proximity`, `walletflow`, mobile)

Any device in BLE range can write to a holder's GATT server before its
reader does. A first message that doesn't decode or decrypt for this
engagement is now rejected, the session left waiting for its reader,
where it used to end the session with status 10 or 11:

- `walletflow.ProximityPresentation.HandleMessage` returns an event
  with the new `Rejected` set, `Ended` unset, no `Send`, and `Err`
  wrapping the new `proximity.ErrEstablishmentRejected`. A custom
  transport must send nothing, drop the device that sent it, if it can
  tell, and keep listening, handing the next first message, from any
  device, to `HandleMessage`. However many arrive, none ends the
  session: your transport's timeout for the reader's request must.
  NFC data retrieval is unchanged.
- `proximity.DeviceSession.TrySessionEstablishment` is new: it is
  `HandleSessionEstablishment` for a message whose sender isn't yet
  known to be the reader, returning `ErrEstablishmentRejected` for such
  a message, which `StatusFor` gives no status reply.
  `HandleSessionEstablishment` still closes the session on any error.
- The gomobile façade reports it as the `rejected` event of
  `ProximityPresentation.HandleMessage` (within ABI 15). OID4VCWallet
  handles it; an app calling the façade itself must too.
- The certificate names `Request()` gives, `subject`, `issuer` and
  `subject_alt_names`, are now cleaned as the reader's `name` is, up to
  1,024 characters each: an app that matched them against raw
  certificate text may see them differ.
- OID4VCWallet's GATT server lists every device that writes State
  0x01, up to 64, displacing the one heard from least recently, and
  hands each one's first message to Go: devices that never saw the QR
  code can't keep the reader out by holding places. The request
  timeout starts at the first device's State 0x01, which may not be
  the reader's. A holder in central client mode passes over a device
  whose Ident was read and differs, or that has none, for 10 seconds,
  not the session; an Ident read that fails, a dropped link or a stall
  costs a connection attempt instead (3 on iOS, 10 on Android), and no
  longer passes the device over. Nothing changes in the API.

### NFC: a bounded Transact, and HandoverRead for the Handover Select only (`proximity/nfcapdu`)

- `nfcapdu.Transact` now gives up once the new `nfcapdu.TransactTimeout`
  (3 minutes) has passed since the exchange started, with an error,
  however much of the answer has arrived: an mdoc answering a byte at a
  time could otherwise hold the reader for hours. A MaxMessage answer in
  full-size responses takes under two minutes at a usual NFC round trip.
- Under TNEP negotiated handover, `Holder.Process` reports `Step.HandoverRead`
  only when the reader has read the Handover Select the negotiation
  returned in full. Reading a staged write's NLEN 0, or a status, service
  select or deselect answer served after the Handover Request, no longer
  reports it, so the native app no longer commits the NFC engagement on
  those. Static handover is unchanged.

## OID4VCWallet 0.39.0 → 0.40.0

Built from OID4VCgo v0.81.0 (see its entry below, whose wallet
changes reach the mobile libraries); the gomobile ABI is still 15.

### A Wallet Provider's request for fresh evidence (Swift, Kotlin)

`HttpWalletProvider` now forgets its registration on
`registration_expired`, as on `instance_revoked`, registers again and
sends the Wallet Attestation request once more. A refresh whose grant's
instance key the provider no longer attests (`instance_key_expired`,
`registration_expired`, or `instance_key_registered` after registering
again) deletes the grant and its key and fails with `reissue_required`:
issue the credential again. An app with its own Wallet Provider
callbacks reports such a refusal as `[refused:code]`, as before, and
forgets its registration on `registration_expired` itself.

Update Android wallets to this release before their Wallet Provider
refuses legacy or expired evidence (v0.81.0 below): an older wallet
refused so fails every attestation until its app data is cleared.

### Configurations are grouped (Swift, Kotlin)

`WalletConfiguration` and `ProximityReaderConfiguration` take their
options in groups instead of one flat list. The same names are used in
Swift and Kotlin. A configuration decoded from JSON is unaffected: the
JSON keeps its flat keys, and encodes as before.

```swift
// Before
ProximityReaderConfiguration(issuerRoots: iacas, readerKeyID: id, readerChain: chain,
                             revocation: [.issuer, .status], crls: crls, statusCheck: .check)
// After
ProximityReaderConfiguration(
    issuers: .init(roots: iacas),
    readerAuthentication: .init(keyID: id, chain: chain),
    revocation: .init(roles: [.issuer, .status], crls: crls),
    statusCheck: .check)
```

In both configurations:

| Before | After |
|---|---|
| `revocation` | `revocation.roles` |
| `noRevocationCheck` | `revocation.declined` |
| `crls`, `crlIssuers` | `revocation.crls`, `revocation.crlIssuers` |
| `crlDistributionPoints` | `revocation.distributionPoints` |
| `crlDistributionPointsFromRoots` | `revocation.distributionPointsFromRoots` |
| `crlRequireHTTPS` | `revocation.requireHTTPS` |
| `statusMaxBytes` | `status.maxBytes` (`StatusLists`) |
| `identifierListMaxBytes` | `status.identifierListMaxBytes` |
| `statusCacheMaxAgeSeconds` | `status.cacheMaxAgeSeconds` |
| `statusCacheDir` | `status.cacheDir` |
| `development = true`, `developmentRoots` | `development = Development(roots:)`; nil is production |

`ProximityReaderConfiguration` only:

| Before | After |
|---|---|
| `issuerRoots` | `issuers.roots` |
| `issuerRootsByDocType` | `issuers.rootsByDocType` |
| `anyIssuerForAnyType` | `issuers.anyIssuerForAnyType` |
| `acceptMDLSignerWithoutEKU` | `issuers.acceptMDLSignerWithoutEKU` |
| `readerKeyID`, `readerChain` | `readerAuthentication = ReaderAuthentication(keyID:chain:)`; nil sends unsigned requests |
| `requireMDLSignerEKU` (deprecated) | removed: the default check already requires the extended key usage |

`maxClockSkewSeconds` and `statusCheck` stay where they were.

`WalletConfiguration` only (`clientID` and `redirectURI` stay where
they were):

| Before | After |
|---|---|
| `issuerRoots`, `issuerRequireEKU` | `issuers.roots`, `issuers.requireEKU` |
| `mdocIssuerRoots`, `mdocIssuerRootsByDocType`, `mdocIssuerRequireEKU` | `issuers.mdocRoots`, `issuers.mdocRootsByDocType`, `issuers.mdocRequireEKU` |
| `acceptMDLSignerWithoutEKU`, `requireIssuerName`, `allowForeignIss`, `statusIssuers` | the same names under `issuers` |
| `issuerMetadataRoots`, `issuerMetadataRequireEKU` | `issuerMetadata.roots`, `issuerMetadata.requireEKU` |
| `requireSignedIssuerMetadata`, `requireIssuerMetadataName` | `issuerMetadata.requireSigned`, `issuerMetadata.requireName` |
| `maxIssuerMetadataAgeSeconds` | `issuerMetadata.maxAgeSeconds` |
| `verifierRoots`, `verifierRequireEKU` | `verifiers.roots`, `verifiers.requireEKU` |
| `acceptX509SANDNS`, `registrarRoots`, `registrarRequireEKU`, `mdocReaderRoots`, `mdocReaderRequireEKU`, `requireTrustedMdocReader` | the same names under `verifiers` |
| `requireSignedDCAPIRequests` (Kotlin) | `verifiers.requireSignedDCAPIRequests` |
| `tlsPins`, `allowedPrivateHosts` | `network.tlsPins`, `network.allowedPrivateHosts` |
| `locales`, `batchSize`, `requestRefresh`, `proofKeyByJWK`, `proofKeyByIndex` | the same names under `issuance` |
| `issuanceProfile` | `issuance.profile` |
| `copyPolicy`, `proximityDeviceAuth` | `presentation.copyPolicy`, `presentation.proximityDeviceAuth` |

Two JSON configurations Go refused are now refused when they're
decoded, before any call reaches Go: `development_roots` without
`development`, and `require_mdl_signer_eku` set together with
`accept_mdl_signer_without_eku`.

## v0.80.0 → v0.81.0

### Android Wallet Provider evidence past its validity (`walletprovider/androidkey`)

`androidkey.EvidenceVerifier` now refuses, at every recheck, an
instance or instance key whose kept attestation chain has a
certificate outside its validity period. Remote Key Provisioning's
certificates are short-lived, so this reaches wallets in the field
within weeks. It also refuses records it can't judge in full: an
instance registered with v0.75.3 or before, an instance key recorded
with v0.80.0 or before, and facts saved by v0.80.0 or before.

- **Wallet's answer:** `403 registration_expired` (the registration's
  chain) or `403 instance_key_expired` (an instance key's), new codes.
  The instance stays active: the wallet registers again or attests a
  new instance key. `walletprovider.Client` returns
  `ErrRegistrationExpired` and `ErrInstanceKeyExpired` for them
  (`errors.Is`), and walletflow and OID4VCWallet 0.40.0 recover on
  their own; older mobile wallets don't (see above).
- **Upgrade window:** set `EvidenceVerifier.AllowUncheckedLegacyEvidence`
  to keep accepting the legacy records, their expiry unchecked, while
  wallets update. DEPLOYING.md shows how to find the instances still
  affected before ending it. Leave it unset in a new deployment.
- **Recheck refusals of your own:** an `EvidenceRechecker` or
  `InstanceKeyRechecker` that wraps the new
  `walletprovider.ErrEvidenceExpired` gets the same two codes instead
  of `evidence_rejected`.

### Instance keys rechecked (`walletprovider`)

The provider now keeps the verifier's facts about each instance key's
evidence (`InstanceKey.EvidenceFacts`) and rechecks them, through the
new `InstanceKeyRechecker`, each time it relies on the key: a revoked
certificate revokes the instance, a suspended one suspends it.
`androidkey.EvidenceVerifier` implements it. A custom
`InstanceKeyStore` must keep `EvidenceFacts`; `sqlstore`'s stores the
whole record and needs no change.

`appattest.EvidenceVerifier` is now an `EvidenceRechecker`: an instance
whose App Attest key is a development key once `AllowDevelopment` is
off, or whose app is no longer in `Apps`, is refused (`policy_refused`)
but left active.

### Deferred credentials keep their `credential_identifier` (`issuer`)

`DeferredTransactionRecord.CredentialIdentifier` is new: a transaction
requested by `credential_identifier` is answered only to a token that
still authorizes that identifier. A custom `DeferredTransactionStore`
must keep the field; `sqlstore`'s stores the whole record. A record
saved before the upgrade keeps the configuration check.

### A wallet's default SD-JWT VC issuer check (`wallet`, `walletflow`, mobile)

With no `IssuerLeafPolicy` (`issuer_require_eku` in the mobile
configuration), a wallet now refuses an SD-JWT VC whose issuer
certificate a Verifier refuses by default
(`verifier.DefaultSDJWTIssuerLeafPolicy`): one whose key usage doesn't
allow digital signatures, that is an OCSP signer, whose extended key
usage lists only other roles' purposes (TLS, code signing, email, time
stamping, IPsec) or includes mdoc reader authentication, or whose
every path has an intermediate restricted so. Set `IssuerLeafPolicy:
verifier.AnyIssuerLeaf` to accept any chain-verified leaf again, for
`IssuerRoots` that anchor issuers' certificates alone.

### Role separation ignores opt-outs and defaults (`walletflow`)

Outside development, `walletflow.New` refuses two roles' pools that may
share a trust anchor unless each has a leaf policy telling its
certificates apart. Setting an opt-out (`verifier.AnyIssuerLeaf`,
`registration.AnyRegistrarLeaf`, `proximity.AnyDocumentSigner`,
`issuer.AnyAttestationLeaf`, `statuslist.AnyListSigner`,
`identifierlist.AnyListSigner`) or a role's default
(`verifier.DefaultSDJWTIssuerLeafPolicy`,
`registration.DefaultRegistrarLeafPolicy`,
`issuer.DefaultAttestationLeafPolicy`) no longer passes that check. A
`Config` that relied on one is refused with the existing "may share a
trust anchor" error: separate the pools, or set a policy that requires
the role's extended key usage.

## v0.79.0 → v0.80.0

### FAPIgo v0.75.0

OID4VCgo now requires FAPIgo v0.75.0, which also carries v0.74.0's
changes; see FAPIgo's UPGRADING.md, sections v0.75.0 and v0.74.0. Both
are breaking for redirect URIs only: a redirect URI must be written
exactly as it is sent.

- **Refused now:** an uppercase scheme or host
  (`https://RP.example/cb`), an uppercase private-use authority
  (`com.example.app://Wallet/cb`), a character RFC 3986 doesn't allow
  left unencoded in the path or query, a malformed `%` escape, a `.`
  or `..` path segment (written or as `%2e`), and an empty or
  impossible port (`https://rp.example:/cb`, `:0`).
- **Wallet (`walletflow`, `mobile`):** `walletflow.New` refuses a
  `Config.RedirectURI` written that way (the mobile configuration's
  `redirect_uri`). Write it in the form the error gives, and register
  the same string with the issuer. `com.example.app:/cb`,
  `eu.europa.ec.euidi://authorization` and loopback `http` redirects
  are unaffected.
- **Issuer (`haip`, `issuer`):** `storage.NewRegisteredClient` refuses
  a wallet client registered with such a URI, and a client stored
  before the upgrade that a repository rebuilds with it fails to
  resolve. Re-register it in the normalized form, and update the
  wallet's configuration to match. `fapi.CheckRedirectURIForm` runs
  the same check ahead of registration.
- **Also in these releases:** FAPIgo no longer issues a refresh token
  whose grant was revoked while it was being issued.

## v0.78.0 → v0.79.0

### Wallet (`walletflow`, `mobile`)

- **New, opt-in: `walletflow.Config.AllowedPrivateHosts`** (the mobile
  configuration's `allowed_private_hosts`, `allowedPrivateHosts` in the
  Swift and Kotlin libraries). Nothing changes unless you set it.
  Outside `Development`, walletflow reaches public addresses only;
  this names hosts it may also reach at a private address (issuers,
  Verifiers, status lists, and for `mobile` CRL distribution points
  inside your own network), as `wallet.Config.Fetch.AllowedPrivateHosts`
  does for `wallet`. Each entry is a host name, matched exactly: `New`
  refuses an IP address, a wildcard, a port or a loopback name. A
  listed host is still refused at a loopback, link-local or other
  non-public address, and TLS is still required. If you worked around
  the public-addresses-only client by passing your own
  `Dependencies.HTTP`, that client's private hosts didn't reach
  walletflow's metadata, request_uri and status list fetches; set
  `AllowedPrivateHosts` instead, and if you keep your own client, build
  it with `fapihttp.NewClient` and the same
  `TransportConfig.AllowedPrivateHosts`: outside `Development`, `New`
  refuses one whose list differs.

### In-person presentation (`proximity`, `walletflow`, `mobile`)

- **Second-edition requests are read whole.**
  `walletflow.ProximityPresentation` now decodes and verifies the whole
  DeviceRequest (`proximity.DecodeDeviceRequest`,
  `VerifyDeviceRequest`), not only its document requests. What changes
  for a request that carries the second edition's fields:
  - A reader that signs only through `readerAuthAll` is now recognised:
    it was `unauthenticated` before, so `RequireTrustedMdocReader`
    ended the session.
  - Every signature the request carries must verify. A `readerAuthAll`
    that doesn't, or is malformed, makes the reader `invalid`; it used
    to be ignored.
  - With a `readerAuthAll`, only its signers can be the reader. A
    trusted per-document `readerAuth` no longer makes the reader trusted
    when the whole-request signer isn't.
  - A request whose `readerAuthAll` isn't an array of 1 to 8
    signatures, or whose `deviceRequestInfo` isn't
    `#6.24(bstr .cbor map)` (null, untagged, over 64 KiB, malformed,
    duplicate keys), is refused with the status 11/12 error response.
    Both used to be ignored.

  First-edition requests, with per-document `readerAuth` only, are
  handled as before.
- **New: the request's information.** `ProximityPresentation.RequestInfo()`
  (the mobile `Request()` JSON's `request_info`, `requestInfo` in the
  Kotlin and Swift libraries) is the request's use cases, document sets
  and purpose hints, with `Signed` saying whether a verified
  whole-request signature covers them. `Signed` isn't reader trust, and
  neither shows that a purpose is true. Information whose known fields
  this library can't read leaves it nil without refusing the request
  (`DeviceRequest.RequestInfoError` says why).
- `proximity.ParseDeviceRequest` and `VerifyReaderAuth` are unchanged.
  If you call them directly, move to `DecodeDeviceRequest` and
  `VerifyDeviceRequest` to take `readerAuthAll` and the information
  into account.

## v0.77.1 → v0.78.0

### Verifier (`verifier`)

- **New, opt-in: `request_uri_method=post` for `verifier.Transactions`**
  (OpenID4VP 1.0 §5.10). Nothing changes unless you set
  `TransactionsConfig.RequestURIMethodPost`. With it, `Begin`'s links
  carry `request_uri_method=post`, and `RequestObjectHandler` answers
  a Wallet's POST (`application/x-www-form-urlencoded`, at most
  32 KiB) with the Request Object signed for that fetch: its
  `wallet_nonce`, and a `client_metadata` narrowed to the formats,
  algorithms and `enc` values its `wallet_metadata` shares with the
  Verifier. A `wallet_metadata` that isn't a JSON object, or shares
  nothing the request can be made with, is refused with a 400
  `invalid_request`. A Wallet that doesn't support POST fetches with
  `GET` (§5.1), which is still served. Mount the handler for both
  methods (`mux.Handle("/request-objects/{id}", …)`, not
  `"GET /request-objects/{id}"`), and set the option on every instance
  serving the `request_uri` before any of them begins a request with
  it: one without it answers a POST with 405, and a Wallet stops at an
  HTTP error (§5.10.2). `RequestObjectPost` does the same for a
  handler of your own. Nothing new is stored: each POST re-signs with
  the transaction's own nonce, `state` and response key, so
  `TransactionCodec` and `sqlstore` are unchanged, and a record from
  either version is read by the other.

## v0.76.0 → v0.77.0

### Wallet (`wallet`, `walletflow`, `mobile`)

- **A jwt proof carrying a Key Attestation names its key by index by
  default.** `walletflow` now names it by its index in the
  attestation's `attested_keys` (`kid` `"0"`, no `jwk`,
  `wallet.Wallet.GenerateProofWithAttestedKeyIndex`), which OpenID4VCI
  1.0 Appendix F.1 permits and ETSI TS 119 472-3 issuers, such as the
  EUDI reference PID issuer, require. An issuer that takes the key only
  in `jwk` now refuses the proof: set the new
  `walletflow.Config.ProofKeyByJWK` (the mobile configuration's
  `proof_key_by_jwk`, `proofKeyByJWK` in the Swift and Kotlin
  libraries) for it. `Config.ProofKeyByIndex` is deprecated and has no
  effect; remove it. `walletflow.New` refuses it set with
  `ProofKeyByJWK`. Only a key-attested jwt proof changes: `walletflow`
  sends one under `ProfileHAIP` where the issuer takes a key
  attestation, or where it requires one (`key_attestations_required`).
- **A pre-authorized code Token Request authenticated by a Wallet
  Attestation carries `client_id`**, the attestation's `sub`
  (`wallet.Wallet.RequestPreAuthorizedCodeToken` with a
  `ClientAttestation`), as an Authorization Server that doesn't redeem
  pre-authorized codes anonymously needs (OpenID4VCI 1.0 §6.1, §12.3)
  and checks against the attestation
  (draft-ietf-oauth-attestation-based-client-auth-07 §6.3). Nothing to
  change, unless your `ClientAttestationSource` returns an attestation
  without a `sub`, which is now refused before the request is sent.
- **The `wallet_metadata` walletflow posts with a `request_uri_method=post`
  fetch now carries `response_types_supported` (`["vp_token"]`),
  `response_modes_supported` (`["direct_post.jwt"]`) and `issuer`
  (`"https://self-issued.me/v2"`).** OpenID4VP 1.0 §10 takes wallet
  metadata from RFC 8414, which requires `issuer` and
  `response_types_supported`, and a Verifier that parses it so, such as
  the EUDI reference verifier, refused the fetch without them. The
  `issuer` is the one Request Object `aud` the wallet accepts (§5.8),
  so nothing else changes. A wallet built on `wallet` that posts its
  own metadata to `FetchAuthorizationRequestPost` may want the same
  members.
- **New, opt-in: the `x509_san_dns` Client Identifier Prefix**
  (OpenID4VP 1.0 §5.9.3), for Verifiers that use it instead of
  HAIP's `x509_hash`. Nothing changes unless you set
  `wallet.Config.AcceptX509SANDNS`, `walletflow.Config.AcceptX509SANDNS`
  (the mobile configuration's `accept_x509_san_dns`, `acceptX509SANDNS`
  in the Swift and Kotlin libraries), or the `AcceptX509SANDNS` of
  `wallet.ParseAuthorizationRequestParams`, `ParseDCAPIRequestParams`
  or `ParseDCAPIRequestDataParams`. It needs a `VerifierTrust` that
  verifies chains to anchors: `New` refuses it with none,
  `NoVerifierTrust`, or an `X5CVerifierRoots` without `Roots`, and the
  mobile configuration without `verifier_roots`. Every dNSName in a
  certificate under those anchors then names a Verifier the wallet
  answers, so set it only where they certify Verifiers alone, or with a
  `LeafPolicy` (`verifier_require_eku`) telling Verifiers'
  certificates apart. `walletflow` then lists `x509_san_dns` in the
  `wallet_metadata` it posts.
- **A native app's redirect URI may be a private-use URI with an
  authority**, `reverse.domain://name[/path]` (such as
  `eu.europa.ec.euidi://authorization`, the EUDI wallet app's), as well
  as RFC 8252 §7.1's `reverse.domain:/path`, through FAPIgo v0.73.0:
  `walletflow.New` and the mobile `NewWallet` take one where they
  refused it. The name is letters, digits, `-`, `.`, `_` and `~`, with
  no port, userinfo or IP address, and the URI is matched exactly.
  Nothing to change.

### Issuer (`issuer`, `haip`)

- **A native client (`storage.ApplicationTypeNative`) may register a
  private-use redirect URI with an authority**, through FAPIgo
  v0.73.0, as some deployed wallets do. Nothing to change. The
  authority is any text the client registered, not a destination: a
  consent page that shows where the browser goes next shows a
  private-use URI's scheme, which names the app, not its authority as
  a host.

## v0.75.3 → v0.76.0

### Issuer (`issuer`)

- **Under `AssuranceProduction`, the stores holding holders' data must
  seal it.** `issuer.New` refuses a `PreAuthorizedCodes`,
  `CredentialOffers`, `Notifications` or `DeferredTransactions` store
  that doesn't implement `sealing.Store` with `SealsRecords` true, as
  `verifier.NewTransactions` refuses an unsealed `TransactionStore`.
  With `sqlstore`, give the DB a Sealer:
  `sqlstore.New(sqlDB, dialect, sqlstore.Options{Sealer: sealer})`,
  with `sealer` from `sealing.AESGCMSealer` and a 32-byte key kept
  outside the database (see DEPLOYING.md's "Seal records at rest");
  its issuer stores then declare it. A store of your own implements
  `SealsRecords`. `Nonces` needn't. Set `Config.UnsealedStores` only
  where the stores are as protected as the issuer's own keys.

### Status lists (`statuslist`, `identifierlist`)

- **`identifierlist.Checker.Check` with a `Cache` returns identifiers
  of the caller's own**: their bytes are copied, not the Cache's, so a
  caller may change them. Nothing to change, unless you relied on
  them being shared.

### Verifier (`verifier`, `mdocdcapi`)

- **Under `AssuranceProduction`, a `StatusPolicy` needs
  `Checker.Cache`.** `CheckStatusDecision`, and so `NewTransactions`,
  `VerifyResponse`, `mdocdcapi` and `proximity`, refuse one without:
  it would fetch every issuer's status list again for each answer,
  whatever its ttl. Create one `statuslist.NewCache` per process and
  set it as every `statuslist.Checker`'s `Cache`, as
  `issuer.StatusListAttestationStatus` already required.
- **Under `AssuranceProduction`, `NewTransactions` refuses `MdocDCAPI`
  without `Origins`**, even with a `RequestURIBase`: `BeginMdocDCAPI`
  refused every request there. Set `Origins` to the pages that make
  org-iso-mdoc requests, or leave `MdocDCAPI` unset. A redirect-flow
  `Transactions` (`RequestURIBase`, no `MdocDCAPI`) still needs no
  `Origins`; its `BeginDCAPI` refuses each request, as before.

- **An org-iso-mdoc answer through `verifier.Transactions` must
  disclose every requested element.** `HandleMdocDCAPIResponse` used to
  complete a `BeginMdocDCAPI` request with whatever the document
  disclosed, though the request's `Query` has a claim for each element
  and an OpenID4VP answer must satisfy its query: an `Accept` shared
  between the two read a withheld element as absent without being
  told. It now refuses such an answer with `ReasonNotAnswered`, as an
  OpenID4VP answer not satisfying its query, and the request stays
  open. To accept a partial answer, as before, set
  `MdocDCAPIRequest.AllowWithheld`; `VerifiedCredential.Withheld` then
  names what was withheld, which `Accept` checks.
  `mdocdcapi.Verified.Credential()` carries `Missing` as `Withheld`
  too.
- **A `TransactionStore` keeps the new `Transaction.MdocAllowWithheld`**
  and a stored result's `VerifiedCredential.Withheld`.
  `TransactionCodec` (and so `sqlstore`) does, and binds
  `MdocAllowWithheld` into a sealed record;
  `verifiertest.TestTransactionStoreContract` checks a store of your
  own keeps both.

### New, and deprecated (`sealing`, `verifier`)

- **`sealing` holds the sealer every store uses:** `sealing.Sealer`,
  `sealing.AESGCMSealer` and `sealing.Store`. `verifier.AESGCMSealer`
  and `verifier.TransactionSealer` still work, as deprecated forwards
  to them: replace `verifier.AESGCMSealer(key)` with
  `sealing.AESGCMSealer(key)`. The sealed values are the same, so
  records sealed before open as they did.
- **`Transactions.BeginWith(ctx, verifier.BeginOptions{Query,
  BrowserBinding, SameDevice})`** begins a redirect-flow request from
  named fields; `Begin` stays, as a wrapper over it. Prefer
  `BeginWith`.
- **A `TransactionStore` may declare it seals as a `sealing.Store`**
  (`SealsRecords`), beside `verifier.SealingStore`.

### sqlstore

- **The issuer stores implement `sealing.Store`**: `SealsRecords` is
  true when the DB has a Sealer, as the issuer now requires under
  `AssuranceProduction`.

### Mobile libraries (OID4VCWallet, ABI 15)

- **Android's `DigitalCredentials.register` registers claim names
  only.** `RegistrationOptions.claimValues` now defaults to false, so
  no claim value reaches Credential Manager before the holder agrees;
  pass `claimValues = true` to register them as before.
- **A holder who dismisses a holder key's prompt is `cancelled`**, not
  `platform`: Swift's user, system and app cancels and
  `errSecUserCanceled`, and Kotlin's `HolderCancelledException`
  (`BiometricPromptAuthenticator` throws it, for a system cancel too).
  A `KeyStore` of your own marks its error `[cancelled]` (mobile/ABI.md).
- **A Wallet Provider's refusal keeps its error code**: still
  `platform`, with the provider's code (`instance_not_active`,
  `instance_revoked`, `invalid_signed_request`, …) as the detail, from
  `WalletProviderRefusedError` / `WalletProviderRefusedException`, or a
  provider of your own marking its error `[refused:code]`.
- **An `*_require_eku` must be a canonical dotted OID** (no sign, no
  leading zero), and two roles that may share a trust anchor are
  compared by OID: `1.2.3.04` is refused as the same usage as
  `1.2.3.4`.
- **The gomobile `MdocPresentation.Respond` and `RespondDocuments`
  parse their JSON strictly**:
  each element is exactly two strings, and nothing may follow the
  array.
- **Android trusts only `android` and `com.android.credentialmanager`
  as platform Credential Manager callers**, installed with the system
  image and signed with the platform key; Google Play services is
  pinned as before.
- **Android API 26–29:** `AndroidKeystoreKeyStore()` still refuses per-use
  holder authentication there; `AndroidKeystoreKeyStore.Options.forDevice()`
  gives options that work on every API level.
- **`require_mdl_signer_eku` is deprecated** (Swift and Kotlin
  `ProximityReaderConfiguration.requireMDLSignerEKU`, Go
  `proximity.RequireMDLDocumentSignerEKU`): the default document signer
  check already requires the mDL document signer extended key usage, so
  setting it changes nothing. Drop it; the key is still accepted within
  ABI 15 and goes at the next ABI version.
- **`Wallet.sweepOrphanedKeys` refuses a key store under the Wallet
  Provider registration key's prefix**, or one covering it
  (`org.idfoundry.oid4vcgo.`, say), deleting nothing: a `StoreError` in
  Swift, `IllegalArgumentException` in Kotlin. Give the wallet's key
  store a prefix of its own, as the default one is. A sweep also no
  longer deletes keys the store didn't make: in Swift, only keys a
  `KeychainKeyStore` labelled (and it throws for an empty `tagPrefix`);
  in Kotlin, only key pairs, never a secret key such as the credential
  store's under a custom `keyAlias`.

### Behaviour that changes without a code change

- **`verifier.TransactionCodec` writes version 2 records**
  (`TransactionCodecVersion`), whose sealed fields are also bound to
  the transaction's status, expiry, nonce, state and kid: someone who
  can write the store but hasn't the Sealer's key can no longer reopen
  a completed request or extend one's expiry. Version 1 records still
  open, and are written back as version 2. An earlier release doesn't
  read version 2: during a rolling deploy, a request begun or updated
  on an upgraded replica fails on one not yet upgraded, so finish the
  rollout quickly (a request lives `TransactionsConfig.Lifetime`), and
  a rollback fails the requests the new release wrote.
- **`walletprovider` bounds the status list indices one instance's
  instance keys take in a period** (`Config.MaxInstanceKeysPerPeriod`,
  default `DefaultMaxInstanceKeysPerPeriod`, 128): each recorded key
  takes one, and each recorded key first used in a period takes
  another. Past it, a Wallet Attestation that would take one more is
  refused with `ErrTooManyInstanceKeys`, which `Handler` answers
  `429 too_many_instance_keys`, until the next period. Before, one
  registered instance could fill a period's lists and leave every
  other instance `ErrListsFull`. Raise it if your wallets use more
  instance keys a period, or if `StatusListPeriod` is much longer
  than a week.
- **`walletprovider` rechecks Android instances before each
  attestation.** `androidkey.EvidenceVerifier` now reports the facts
  of the registration chain (`VerifiedEvidence.Facts`), which the
  provider keeps as `Instance.EvidenceFacts`, and is an
  `EvidenceRechecker`: before each Wallet and Key Attestation, it
  judges them by its `Verifier` as it is then. An instance whose chain
  has a certificate Google's status list now names, whose root is no
  longer configured, or that a tightened `Verifier` policy (apps,
  patch level, boot, security level) now refuses, is refused even
  for an instance key it recorded before — `evidence_rejected` or
  `policy_refused`. A status list the `Verifier` can't get fails the
  request as the provider's own (`500`) rather than refusing it.
  Instances registered before this release have no facts, and aren't
  rechecked; `androidkey.InstanceFacts` decodes them for a
  `RevokeWhere` match, which also makes a refused instance's live
  attestations `INVALID`.
- **`walletprovider` revokes an Android instance whose chain Google's
  status list names `REVOKED`, and suspends one it names
  `SUSPENDED`**, before refusing the request: its live attestations
  then read `INVALID` (or `SUSPENDED`) at an issuer's next status
  check, without a `RevokeWhere`, and its later requests are refused
  `instance_revoked` (or `instance_not_active`). The instance's
  `Reason` says so. A suspended one stays suspended once Google lifts
  the suspension, until `Resume`. A root removed from
  `androidkey.Verifier.Roots`, a tightened `Verifier` policy, or a list
  entry with another status still only refuses the request. An
  `EvidenceRechecker` of your own triggers this by wrapping the new
  `walletprovider.ErrEvidenceRevoked` or `ErrEvidenceSuspended` in its
  refusal.
- **`walletprovider` Suspend or Resume racing Revoke leaves the
  instance's keys `INVALID`.** Each transition reads the instance
  again after setting its keys' statuses, and sets them again for the
  state it then has, so the last state stored wins.
- **`walletflow` refuses a batch whose copies' claim structure
  differs**, as invalid ("claims differ"): the Issuer JWT and every
  disclosed value, at any depth and in arrays, must leave each claim
  plaintext in every copy or selectively disclosable in every copy.
  Only the Issuer JWT's top-level plaintext claims were compared, so
  copies disclosing a claim's members separately in one and within
  the claim's Disclosure in another were accepted.
- **`walletflow.Presentation.Respond` returns
  `ErrCredentialChanged` when the copy it would present discloses
  other claims than `Preview` showed** — selected, always disclosed
  or disclosed along with them — as one stored before the check above
  could, once the copy previewed is presented or found revoked.
  Nothing is sent; start the presentation again.
- **`wallet.SubmitDirectPostResponse` refuses a `redirect_uri` with
  the `intent`, `content` or `android-app` scheme**, which on Android
  launch an app component of the Verifier's choosing or read a content
  provider's data, as it refuses `javascript` and `file`.
- **A pre-authorized Token Request's `authorization_details` `claims`
  now narrow the token.** `issuer.Issuer.ExchangePreAuthorizedCode`
  and `RedeemPreAuthorizedCode` mint each requested object with its
  `claims`, so `CredentialRequest.AuthorizedClaims` is those claims
  rather than nil (every claim): a `Prepare` that honours it issues
  only them, as for an authorization code. A requested object with
  malformed `claims` (empty, a path that isn't a claims path pointer,
  a path described twice) is refused with
  `invalid_authorization_details`, and one naming `locations` is
  minted with this Credential Issuer's, even without
  `authorization_servers`.
- **`credential/mdoc.Issue` refuses an MSO signed outside the Document
  Signer certificate's validity** (`Claims.Signed` before its
  `NotBefore` or after its `NotAfter`, ISO/IEC 18013-5 §9.3.1), which
  every reader refuses. With `mdoc.RoundedValidity`, `Signed` is the
  start of the UTC day: a Document Signer certificate needs a
  `NotBefore` more than a day back, or issuance fails until the next
  day.
- **`credential/mdoc.Issue` refuses a `Claims.Status.URI` that isn't
  an https URL**, as decoding already did.
- **`credential/sdjwtvc.Issue` refuses a `Claims.Additional` name that
  is a reserved claim in another case** (`"Exp"`, `"CNF"`), which the
  verifier refused, **or isn't valid UTF-8**.
- **A deferred transaction's key attestations are verified again under
  the proof type they arrived under**:
  `issuer.DeferredTransactionRecord.KeyAttestationProofType` records
  it, and a store must persist it like any other field (an
  `issuertest` contract checks it). A record without it, saved
  earlier, is checked against every proof type's algorithms as
  before.
- **`mdocdcapi.Incoming.RespondDocuments` (and `Respond`) refuse an
  mdoc of another type than its document request asks for**, read
  from its MSO's `docType` before any key signs, as `proximity`
  already did. It used to sign and send it under the requested type,
  for the reader to refuse.
- **`proximity.ParseDeviceRequest` and `mdocdcapi.ParseRequest`
  refuse a DeviceRequest asking for one document type twice**
  (`proximity.ErrCBORValidation` for the former), as readers here
  already refuse a DeviceResponse with two documents of one type.
- **An NFC reader waits `nfcapdu.MaxTNEPWait` (5 seconds) at most for
  a tag's answer to a TNEP message**, however long the tag's service
  parameters ask for: up to TNEP's maximum, several minutes, before.
- **`oid4vpmdoc.UnmarshalDeviceResponse` refuses a DeviceResponse
  whose `version` isn't 1.x**, as `proximity` and `mdocdcapi` already
  did; it used to ignore the member. A verifier receiving an OpenID4VP
  `mso_mdoc` presentation refuses one too.

### Wallet Provider (`walletprovider`)

- **`Config.OnRecheckRefused`**, if set, is called with every refusal
  an `EvidenceRechecker` makes and the instance as stored afterwards
  (revoked or suspended for Google's verdict, active otherwise), on the
  request's path: alert on it, or revoke from your own logic.
- **`Config.RequireSealedStore`** makes `New` refuse `Instances`,
  `InstanceKeys` and `Challenges` stores that don't seal their records
  (`sealing.Store`). sqlstore's stores report
  whether their `DB` has an `Options.Sealer` (sqlstore needs the
  release with this change). It's off by default; set it in
  production (DEPLOYING.md).

### Wallet Provider stores

- **A custom `walletprovider.InstanceStore` keeps three more
  `Instance` fields** — `EvidenceFacts`, `IndexPeriodStart` and
  `IndicesInPeriod` — and copies `EvidenceFacts` as it copies `Key`
  and `Credential`. `walletprovidertest.TestInstanceStoreContract`
  now checks both. sqlstore's store keeps them in its record with no
  migration.

## v0.74.0 → v0.75.3

No API changes a caller has to act on; v0.75.0 adds one opt-in.

### Go 1.26.11

v0.75.3 (and sqlstore v0.11.1) raise the `go` directive to 1.26.11,
for the standard library's fix for GO-2026-6859. A module requiring
them builds with Go 1.26.11 or later: with an older toolchain, `go`
downloads 1.26.11 (`GOTOOLCHAIN=auto`, the default) or refuses to
build (`GOTOOLCHAIN=local`). `go get` raises your module's `go`
directive to match; raise your build images' Go too.

### Behaviour that changes without a code change

- **`mdocdcapi` refuses an `EncryptionInfo` recipient key that isn't
  P-256** (v0.74.1). A key on another curve used to be accepted and
  the response sealed with DHKEM(P-384) or DHKEM(P-521) instead of
  Annex C's DHKEM(P-256) suite.
- **`mdocdcapi` refuses an `EncryptedResponse` with members or tags
  Annex C doesn't define** (v0.74.1), rather than ignoring an unknown
  member or dropping a tag on the protocol.
- **`credential/mdoc` refuses a received `status_list` without `idx`
  or `uri`, or with a `uri` that isn't https, when decoding**
  (v0.74.1). A missing `idx` used to decode as 0, so a status check
  read another credential's entry; an http `uri` was refused only by a
  status check, when it fetched the list.
- **`proximity.RequireMDLDocumentSignerEKU` is now
  `DefaultDocumentSignerPolicy`** (v0.75.1): a reader using it refuses
  everything the default refuses, such as an OCSP signer's certificate
  carrying the mDL document signer extended key usage, which it used
  to accept. The mobile reader's `require_mdl_signer_eku` uses it.
- **`walletflow` refuses a copy with no holder key left** (v0.75.2),
  as invalid, instead of panicking, as when a `KeyStore` gives two
  keys one ID. Such a `KeyStore` needs fixing: each key needs its own
  ID.

### Wallet (`wallet`, `walletflow`)

- **Opt-in: `walletflow.Config.ProofKeyByIndex`** (v0.75.0) names a
  jwt proof's key by its index in the Key Attestation's
  `attested_keys` (`kid` `"0"`, no `jwk`), through
  `wallet.Wallet.GenerateProofWithAttestedKeyIndex`, for an issuer that
  requires that form (ETSI TS 119 472-3; the EUDI reference PID
  issuer). It's off by default, since an issuer taking only `jwk`
  refuses the index.

## v0.73.0 → v0.74.0

### FAPIgo v0.72.0 and fapigo/sqlstore v0.8.0

OID4VCgo now requires FAPIgo v0.72.0, and its `sqlstore` tests and
passport-vdc fapigo/sqlstore v0.8.0; see FAPIgo's UPGRADING.md.

- **fapigo/sqlstore's `Batching()` methods are gone:** take
  `Grants: asDB.BatchingGrants()` and
  `Revocation: asDB.BatchingRevocation()` in `server.Dependencies`,
  and `BatchingRevocation` from `fapisqlstore.ResourceServer` for a
  separate Credential Endpoint.
- **Only a wrapper that embeds `server.JWTAccessTokens`,
  `server.NoBackchannelNotifications` or
  `resource.NoRevocationUntilExpiry` changes:** see FAPIgo's
  UPGRADING.md for what each must now declare.
- **Rotate a Sealer's key in two deploys:** `RotatingSealer(old, new)`
  on every instance, then `RotatingSealer(new, old)`. The earlier docs
  made the new key current in one deploy, which leaves the instances
  not yet redeployed unable to open what the others seal. Keep the old
  key while records it sealed exist.

### sqlstore (v0.11.0)

- **Requires FAPIgo v0.72.0, and fapigo/sqlstore v0.8.0 in its
  tests:** wire FAPIgo's stores with the batching accessors and rotate
  a Sealer in two deploys, as above.
- **Migrate locks per schema on Postgres:** nothing to change. A
  rolling upgrade from an earlier release still migrates once: the
  earlier release's Migrate and this one's wait for each other.

## v0.72.1 → v0.73.0

### FAPIgo v0.71.0 and fapigo/sqlstore v0.7.0

OID4VCgo now requires FAPIgo v0.71.0, and its `sqlstore` tests and
passport-vdc fapigo/sqlstore v0.7.0; see FAPIgo's UPGRADING.md.

- **Wire FAPIgo's sqlstore through `Batching()`** to keep the batched
  revocation checks and token records fapigo/sqlstore v0.6.0 gave
  without it: `Grants: asDB.Grants().Batching()` and
  `Revocation: asDB.Revocation().Batching()` in
  `server.Dependencies`, and `Revocation.Batching()` from
  `fapisqlstore.ResourceServer` for a separate Credential Endpoint.
  `serverresource` takes its revocations from the server's
  `Dependencies`, so it batches with them. Without the adapters every
  answer is the same, from a query per key.
- **memstore's `RevocationStore` and `GrantStore` lose `IsAnyRevoked`
  and `RecordIssuedTokens`:** call `IsRevoked` per key, or
  `RecordIssuedAccessToken` then `RecordIssuedRefreshToken`.

### Wallet Provider (`walletprovider`)

- **An App Attest key registers one instance.** `Register` refuses
  evidence whose credential another instance registered with
  (`VerifiedEvidence.CredentialID`, which `appattest.EvidenceVerifier`
  sets to the App Attest key ID) with `ErrInstanceKeyRegistered`
  (`409 instance_key_registered`), as Apple asks a server to refuse a
  key ID it has seen. `InstanceStore.Create` enforces it, atomically,
  through the new `Instance.CredentialID`: a custom store keeps the
  field and returns `ErrExists` for a non-empty one another instance
  has (a `UNIQUE` column, `NULL` when empty), as
  `walletprovidertest.TestInstanceStoreContract` now checks; sqlstore's
  and the in-memory store do. A store that doesn't still works, without
  the check. Instances registered before have no `CredentialID`: a
  new registration with one of their App Attest keys isn't refused.

### sqlstore (v0.10.0)

- **Migration 0014 adds `oid4vc_walletprovider_instances.credential_id`**
  with a `UNIQUE` index. Run `Migrate` before deploying: `CheckSchema`
  fails without it. A replica from before, running beside, inserts
  `NULL` and so skips the check for the instances it registers.

## v0.72.0 → v0.72.1

### Wallet Provider (`walletprovider`)

- **Evidence after registration must be of the Kind the instance
  registered with**, as well as from its platform and app: an
  instance registered with `apple-app-attest` evidence is refused
  evidence another iOS verifier reads, which would skip App Attest's
  assertion and counter checks. A provider whose instances send a
  different Kind later than at registration has them register again.
- **Mount `StatusLists` with `http.StripPrefix`** of
  `StatusListBaseURI`'s path, as the example and DEPLOYING.md now do:
  it serves `GET /{start}/{n}`, so mounted under a path without
  stripping it every list answered `404`.

## v0.71.0 → v0.72.0

### sqlstore (v0.9.1)

- **Migration 0013 drops the `oid4vc_status_list_counts` view**, which
  0010 left so that a replica from before v0.69.0 still counted a
  list's reserved indices. Finish upgrading every replica to v0.69.0
  or later before running `Migrate`: once the view is gone, an older
  one can no longer count a list's reserved indices, so its Allocator
  fails. A query of your own that read the
  view reads `SUM(reserved)` from `oid4vc_status_list_count_shards`
  grouped by `uri` instead, or calls `StatusIndices().Reserved`.

## v0.69.0 → v0.70.0

### Issuer (`issuer`)

- **A stateless c_nonce is spent under an Owner of its own**
  (`"c_nonce spent by " + Config.Issuer`), and an issuer without
  `NonceKeys` refuses a stateless nonce with `invalid_nonce` rather
  than consuming it from the store. In v0.69.0 a spent nonce's record
  looked like an issued nonce's, so a replica without `NonceKeys`
  sharing the store accepted it again. A custom `NonceSpender` must
  refuse a `Spend` of a nonce recorded under any Owner, as
  `issuertest.TestNonceSpenderContract` now checks; sqlstore's and the
  in-memory store do. Until the last v0.69.0 replica is replaced,
  keep `NonceKeys` the same on every replica.
- **Rotate `NonceKeys` in two steps** under a rolling deploy: deploy
  the new key after the old one everywhere, then first, then drop the
  old one after `NonceLifetime` (`Dependencies.NonceKeys`). Putting the
  new key first in one step makes a replica that hasn't taken it yet
  refuse nonces another issued with it.

### Status lists (`statuslist`)

- **A `Cache` with a `Store` should have a `StoreKey`** (at least 32
  random bytes, kept elsewhere than the store's records and the same
  across processes). A 304 confirms the validators a kept record names,
  not the token kept with them, so without a key anyone able to write
  the store could bring back a token from before a revocation. Without
  a key, a kept token is now used on a 304 only within the Cache's
  `MaxAge` of its iat (and its iat plus ttl, if sooner); an older one is
  downloaded, which costs a download per list on a launch more than
  `MaxAge` after its token was issued. Records written before this
  release carry no MAC: with a key, they're dropped and downloaded once.
- `NewDirCacheStore` refuses a directory anyone can write to.
- While another replica holds the lease on signing a shared token
  (`Publisher.Tokens`), a replica now waits on it only for a bounded
  time, then signs its own: a holder that can't sign no longer keeps the
  others serving a token from before a revocation. A custom
  `TokenStore` needs no change.
- `AllocateN` counts a list's reserved indices again every 64 indices
  it reserves there, so a batch larger than 64 makes a count per 64.

### Mobile (`status_cache_key`)

- The Swift and Kotlin libraries authenticate the lists
  `statusCacheDir` keeps with a key they make and keep (the Keychain;
  an Android Keystore key wrapping it), and pass it as
  `status_cache_key`. An app calling the framework directly with
  `status_cache_dir` should pass one too (ABI.md).

### SD-JWT VC (`credential/sdjwtvc`)

- **`Issue` refuses a self-signed `IssueOptions.IssuerCertificate`**
  given alone, as it did one given with intermediates (HAIP 1.0
  §6.1.1). Issue from a certificate a CA signed.
- **`Claims.VCTIntegrity` and Type Metadata's `extends#integrity` and
  `uri#integrity` must be integrity metadata strings** (draft-13 §7):
  `sha256-`, `sha384-` or `sha512-` and the base64 of a digest of that
  length. `Issue` and `TypeMetadata.Validate` refuse anything else.
- `Verify` accepts the transitional `vc+sd-jwt` typ (draft-13 §3.2.1)
  when the new `VerifyOptions.AcceptLegacyTyp` is set. Nothing changes
  by default: only `dc+sd-jwt` is accepted, by the verifier and wallet
  too.

### Verifier (`verifier`, `mdocdcapi`)

- **`BuildAuthorizationRequest` requires a `State`** when a credential
  query sets `require_cryptographic_holder_binding` to false (OID4VP 1.0
  §5.3), and refuses one with characters other than ASCII letters,
  digits, `-`, `.`, `_` and `~`. `Transactions` already sent one.
- **An Annex C credential's `CredentialQueryID` is its document type**
  (`mdocdcapi.Verified.Credential`), where it was empty, and
  `VerifyResponseDocuments` returns the documents, and runs `Accept`, in
  the order of `Pending.Documents`. An `Accept` that relied on the
  holder's order, or on an empty `CredentialQueryID`, must change.

### Wallet (`wallet`, `walletflow`)

- **A Verifier's `redirect_uri` with the `mdoc-openid4vp` or
  `eudi-openid4vp` scheme is refused**, as the other Wallet invocation
  schemes already were (`SubmitDirectPostResponse`, `Respond`), and so,
  in `walletflow`, is one with the scheme of the Wallet's own
  `Config.RedirectURI`: `Respond`, `Decline` and a refusal's redirect
  fail with `wallet.ErrResponseDelivered`, the response having reached
  the Verifier. Follow a redirect only from `Presented.RedirectURI`.
- **A DC API request for another `response_type` or `response_mode`**
  is a `wallet.RequestRejectedError` with `invalid_request`, which
  `StartDCAPIPresentation` returns as a `RequestRefusedError` carrying
  `{"error":"invalid_request"}` for the page, where it was an
  `ErrMalformedRequest`.

## v0.68.0 → v0.69.0

Upgrade sqlstore with it, to v0.9.0: they release together.

### Before rolling out: one `Migrate` (sqlstore v0.9.0)

Run `Migrate` once, from one process, before the first replica on
v0.69.0 starts: it applies migrations 0009 to 0012 in order, and an
older replica keeps working beside the migrated schema while the rest
roll out. What each does, and what it locks on Postgres:

- **0009** indexes `oid4vc_walletprovider_instance_keys`' `sweep_after`
  (a plain `CREATE INDEX`: writes to that table wait while it builds,
  a time that grows with its rows; a database without a Wallet
  Provider has none).
- **0010** keeps each status list's count of reserved indices in 32
  rows (`oid4vc_status_list_count_shards`), so concurrent reservations
  in one list no longer wait for each other. It holds
  `oid4vc_status_indices` against reservations only while it copies
  one count per list, so for as long as copying a row per list takes,
  not one per index. `oid4vc_status_list_counts` becomes a view
  summing the shards, so an older replica still counts correctly.
- **0011** adds `oid4vc_status_list_versions` and
  `oid4vc_status_list_tokens` (new tables), with a trigger that raises
  a list's version whenever one of its statuses changes, whichever
  release changes it.
- **0012** adds `oid4vc_status_list_tokens.signer`.

### Behaviour that changes without a code change

- **`CredentialRequest.PerCredential` runs for every Credential of a
  batch before the first is signed**, not between signings. A hook
  that relied on the earlier Credentials being signed already must
  change. The new `PerBatch` (also on `DeferredIssuance`) is called
  once with the whole batch: with `statuslist.Allocator.AllocateN` it
  reserves a batch's status indices in one round trip.
- **Keep one `statuslist.Allocator` per process** (per `Store`). It
  now validates its settings once and remembers which lists it found
  full, so one built per call starts afresh each time. Don't copy one
  once used; a change to `Lists`, `Bits` or `FillLimit` is still
  picked up.
- **`statuslist.Cache` keeps failures for `CacheOptions.MaxFailureAge`**,
  30 seconds by default. While a failed fetch is kept, checks of the
  same uri fail with its error and don't fetch again; while a token a
  check refused is kept, checks verify that token again and don't
  fetch it. So once a status list server recovers, or reissues a list
  checks refused, checks can take up to `MaxFailureAge` to see it. Set
  it shorter for a quicker retry, or call `Purge`.
- **`DB.Sweep` deletes Wallet Provider instance keys past their
  `RetainUntil`** (below).

### Status lists (`statuslist`, `identifierlist`)

- **A custom `IndexStore` must implement `Delete(ctx, uri)`**, which
  forgets every reservation of a list its caller no longer allocates
  from. `statuslisttest.TestIndexStoreContract` checks one;
  `MemoryIndexStore` and sqlstore's `StatusIndices` implement it
  (sqlstore's deletes in batches, and an interrupted one finishes when
  called again).
- **New: replicas can share signed tokens.** Set
  `statuslist.Publisher.Tokens` (and `identifierlist.Publisher.Tokens`)
  to sqlstore's `db.StatusListTokens()` when more than one replica
  serves a list: one replica then signs each list's token after a
  status changes, and the others serve it within `TokensCheck` (5
  seconds by default). Without it each replica signs its own, as
  before. A stored token is served only by a Publisher with the same
  signing certificate, so after a key or certificate rotation replicas
  sign afresh. A `TokenStore` of your own must keep each token as put,
  `Signer` included; `statuslisttest.TestTokenStoreContract` checks
  one.

### Issuer (`issuer`)

- `PerCredential`'s new order and `PerBatch`: see above.

### Wallet Provider (`walletprovider`)

- **Run `SweepStatusLists` periodically** (daily, say, from one
  process; running it concurrently or again is safe). It deletes the
  reserved indices of the periods' lists no longer served, which
  nothing else deletes, and gives instance keys recorded before this
  release a `RetainUntil` when the store implements the new
  `UnretainedInstanceKeyLister` (sqlstore's and the memory store do):
  a key on a period's list counts from that period's start, and one on
  the single list from v0.67.0 and before from the current period's.
- **Instance keys are kept for `Config.InstanceKeyRetention`** after
  the start of the last period they were used in: zero means 90 days,
  or three `StatusListPeriod`s when longer. A store may then delete
  one (`InstanceKey.RetainUntil`; sqlstore's `DB.Sweep` does, and a
  custom `InstanceKeyStore` that never does is still correct). Size it
  for the longest an issuance may go unused and still be refreshed:
  after deletion a Wallet Attestation for the key needs fresh
  evidence, which Android Key Attestation can't give for an existing
  key, and a Key Attestation naming it is refused with
  `unknown_instance_key`; the credential must be issued again.
- **Delete the single status list from v0.67.0 and before** (your old
  `Config.StatusListURI`) once, with `IndexStore.Delete`: it hasn't
  been served or changed since v0.68.0, and nothing else deletes it.
- **Set `Dependencies.StatusListTokens`** (sqlstore's
  `db.StatusListTokens()`) when more than one replica serves the
  provider's status lists, as for `Publisher.Tokens` above.

### Mobile (the Swift library)

- **The Swift library runs on iOS 15.** Its package and XCFramework
  now require iOS 15 or later, where they required iOS 16. Nothing
  changes for an app on iOS 16 or later. Neither the ABI nor the
  Kotlin library changes.
- **`ProximityTimeouts` is in seconds on iOS 15.**
  `ProximityTimeouts(connectSeconds:requestSeconds:idleSeconds:)` and
  the `connectSeconds`, `requestSeconds` and `idleSeconds` properties
  (`TimeInterval`) work on every version. The `Duration` initializer
  and the `connect`, `request` and `idle` properties are still there,
  and code using them still compiles unchanged, but they're now
  `@available(iOS 16.0, macOS 13.0, *)`. An app lowering its own
  deployment target to iOS 15 uses the seconds forms, or puts its
  `Duration` code behind `if #available(iOS 16.0, *)`.

## v0.67.0 → v0.68.0

### Wallet Provider (`walletprovider`)

Status lists now rotate by period, so a provider's capacity is the
instance keys used in a period, not every one ever recorded.

- **`Config.StatusListURI` is `Config.StatusListBaseURI`**: the lists
  are under it, at `{base}/{start}/{n}`, so it has no query and doesn't
  end in `/`. With `Handler` at the provider's URL it's that URL
  followed by `StatusPath`, as `StatusListURI` was.
- **`Config.StatusListPeriod`** is new: how long one period's lists
  hand out indices, by default `DefaultStatusListPeriod` (7 days); a
  whole number of seconds, at least `WalletAttestationTTL` and
  `KeyAttestationTTL`, and at most a year. Changing it later stops
  serving the old period's lists at once: the attestations naming
  them fail status checks until they expire.
- **`Config.StatusListSize` is per list**, and a period has up to
  `MaxStatusListsPerPeriod` (64) lists, of which half of each is
  handed out: size it for the instance keys used in a period. When
  they're all used, an attestation for a new key, or for one moving
  to the period, fails until the next period.
- **`Provider.StatusList()` is `Provider.StatusLists()`**, an
  `http.Handler` serving `GET /{start}/{n}` relative to
  `StatusListBaseURI`. `Handler` serves it under `StatusPath`;
  `GET StatusPath` itself is now `404`.
- **Custom `InstanceKeyStore`s implement `Update`**, a compare-and-swap
  on the new `InstanceKey.Revision`, like `InstanceStore.Update`, and
  `Create` stores Revision 1. `InstanceKey` also gains `PreviousStatus`;
  store it. `walletprovidertest.TestInstanceKeyStoreContract` checks
  both. sqlstore's needs its migration 0008 (below).
- **Attestations issued before the upgrade fail status checks** until
  they expire (within their TTL, a day at most): they name the old
  single list, which is no longer served. Each recorded instance key
  moves to the current period's lists at its next attestation, and a
  suspended or revoked instance still gets none.

### sqlstore (v0.7.1 and v0.8.0)

- **Run `Migrate`.** Migration 0007 keeps a count of each status
  list's reserved indices and adds a partial index over the indices
  with a status, so `StatusIndices().Reserved` and `Statuses` no longer
  read every row of a list. `CheckSchema` fails until it has run. A
  release before it still runs against the migrated schema, so migrate
  first, then roll out. On PostgreSQL the index build blocks writes to
  `oid4vc_status_indices` while it runs: about two seconds for a list
  of eight million indices.
- **Run `Migrate` again for migration 0008**, from the release after
  v0.7.1. It adds a `revision` column to
  `oid4vc_walletprovider_instance_keys`, which
  `WalletProviderInstanceKeys().Update` compares and increments; a row
  from before is at revision 1. `CheckSchema` fails until it has run.
  A release before it still runs against the migrated schema, so
  migrate first, then roll out.

## v0.66.0 → v0.67.0

### Wallet (`walletflow`)

- **`WalletProvider.KeyAttestation` takes the issuance's instance
  key:** `KeyAttestation(ctx, instanceKey crypto.PublicKey, keys
  []*ecdsa.PublicKey, nonce string)`. `instanceKey` is the key
  `WalletAttestation` was asked to attest first for the same issuance.
  Pass it to your provider (`walletprovider.KeyAttestationRequest.InstanceKey`,
  `instance_key` on `POST /v1/key-attestation`), so the Key Attestation
  carries that key's status.
- An issuance that redeems a pre-authorized code without client
  authentication (or refreshes a grant that has none) has no instance
  key of its own. For a Key Attestation it now makes one, has
  `WalletAttestation` attest it, and deletes it when the issuance ends.
  This needs `Config.ClientID`. Without one, the credential request
  fails with `ErrProofUnsupported`.
- `walletflowtest.Provider` gives a Key Attestation only for an
  instance key it gave a Wallet Attestation for.

### Mobile (ABI 15; the Swift and Kotlin libraries)

- **`ABIVersion` is 15.** The Swift and Kotlin libraries refuse a
  framework built for another version: upgrade them together.
- **A `WalletProvider` of your own receives the instance key.**
  Swift: `keyAttestation(instanceKey:keys:nonce:)`. Kotlin:
  `KeyAttestationRequest.instanceKey` (a `KeyEvidence`), or
  `keyAttestation(instanceKey, keys, nonce)` for a provider that takes
  JWKs alone. Gomobile: `KeyAttestation(instanceKeyJWK, keysJWK,
  nonce)`. Send it to your backend as the Key Attestation's
  `instance_key`.

## v0.65.1 → v0.66.0

### Wallet Provider (`walletprovider`)

An instance is now one installation with a stable *registration key*,
and a Wallet Attestation's `cnf` is a per-issuance *instance key*
with its own status list index, so issuers can't link one issuance to
another (HAIP 1.0 §4.4.1).

- **`RegisterRequest.InstanceKey` is `RegistrationKey`**, with
  evidence over a challenge for the new `PurposeRegistration`
  (`"registration"`). `PurposeInstance` (`"instance"`) now binds an
  instance key's evidence. The registration key signs every request
  (`SignRequest`, `Client`'s `registrationKey` argument) and is never
  an instance key.
- **`Instance.Status` is gone**, and registering reserves no status
  index. Each instance key (`InstanceKey`) gets one when it's recorded.
- **`Dependencies.InstanceKeys` is required**: an `InstanceKeyStore`
  (`MemoryInstanceKeyStore` for tests;
  `walletprovidertest.TestInstanceKeyStoreContract` checks your own;
  sqlstore's is `DB.WalletProviderInstanceKeys`, from its migration
  0006, so run `Migrate`).
- **`WalletAttestationRequest` takes `InstanceKey`**, and, the first
  time an instance asks for that key, `Challenge` (`PurposeInstance`)
  and `Evidence` for it. A key already recorded for the instance needs
  neither. A key recorded for another instance, or the instance's
  registration key, is refused with `ErrInstanceKeyRegistered`.
- **`KeyAttestationRequest` takes `InstanceKey`**, the issuance's
  recorded instance key, whose status the Key Attestation carries; an
  unrecorded key is refused with the new `ErrUnknownInstanceKey`.
- **`Suspend`, `Resume` and `Revoke` set the status of every one of
  the instance's instance keys.**
- **Size `Config.StatusListSize` for issuances**, not instances: each
  new instance key uses an index for good.
- **The `/v1/` protocol changed** (mobile/WALLET_PROVIDER.md):
  `POST /v1/instances` takes `registration_key` over a `registration`
  challenge; `POST /v1/wallet-attestation` takes `instance_key`, and
  `challenge` and `evidence` for a new one; `POST /v1/key-attestation`
  takes `instance_key`; and a Key Attestation for an unrecorded
  instance key is `400 unknown_instance_key`. No released client spoke
  the old protocol.
- **Instances stored before** were registered with what is now an
  instance key, and carry a status index nothing will set any more:
  register them again.

## v0.64.0 → v0.65.0

### Credential status (`walletflow`)

- **`CheckStatus` checks a held credential's issuer certificate
  again.** Besides its status and identifier lists, it now verifies
  each live copy's signing chain (an SD-JWT VC's `x5c`, an mdoc's
  IssuerAuth `x5chain`) under the issuer roots and leaf policy
  configured now and against `Config.IssuerRevocation`, with the CRLs
  held then. A copy whose signer, or a CA above it, has been revoked
  since, or whose chain no longer verifies under the roots, is marked
  with the new `CredentialCopy.IssuerUntrusted` and isn't chosen for a
  presentation ahead of one without it; once no copy is left that
  isn't, the credential is `StatusInvalid`. This isn't final, unlike a
  list's revocation: the next check decides it again, so a CRL that no
  longer lists the certificate makes the credential valid again.
- **A credential with no status or identifier list is checked too**
  when it carries a chain and the Wallet has roots for it: `CheckStatus`
  used to return it unchanged, with an empty `Status`, and now records
  one (`StatusValid` when its chain passes). Only a credential with
  nothing to check — no list and no chain, or no roots configured for
  it — is returned as it is.
- **No current CRL is `StatusUnknown`, not an error.** A chain whose
  revocation `certrevocation.CRLs` can't decide for want of a current
  CRL (`certrevocation.ErrNoCurrentCRL`) — the issuer's under
  `IssuerRevocation`, or a status list signer's under
  `StatusRevocation`, which used to fail `CheckStatus` — now records
  `StatusUnknown`. Refresh the lists and check again. A Checker's other
  failures to decide are still errors.
- **`CredentialStatus.Reason`** says why a status is what it is:
  `ReasonStatusList`, `ReasonIdentifierList`,
  `ReasonIssuerCertificateRevoked`, `ReasonIssuerUntrusted`,
  `ReasonNoCurrentCRL` or `ReasonUnrecognizedStatus`; `""` for
  `StatusValid` and for a status recorded before. A `CredentialStore`
  of your own must keep it and `CredentialCopy.IssuerUntrusted`, as
  `storetest.TestCredentialStoreContract` now checks; one that stores
  the record as JSON, sqlstore's among them, already does.

## v0.63.0 → v0.64.0

### Status lists (`statuslist`, `identifierlist`, `walletflow`)

- **A wallet keeps the status lists it fetched.** `walletflow`'s
  `CheckStatus` now checks through a `statuslist.Cache`
  (`Dependencies.StatusCache`, or one of the Wallet's own), so a status
  changed at its issuer is seen once the kept list expires: at the
  earliest of its exp, its iat plus ttl, and 5 minutes
  (`statuslist.DefaultCacheMaxAge`) after it was fetched. Each check
  still verifies the kept list for its own credential. To see a change
  sooner, pass a Cache with a shorter `MaxAge`, or call its `Purge`.
  The mobile Wallet and proximity reader share one Cache per process.
  `statuslist.Checker` and `identifierlist.Checker` cache nothing
  unless given a `Cache`.
- **A Fetcher reuses its transport.** A `statuslist.Fetcher` copies
  its `HTTP.Transport` (or `http.DefaultTransport`) once per address
  policy and reuses the copy, keeping connections alive between
  fetches, where it copied it on every fetch. Changes made to that
  Transport after its first fetch are no longer seen: configure it
  before use, as `http.Transport` asks.

### Verifier (`verifier`)

- **A `TransactionStore` keeps `Transaction.MdocEncryptionInfo`**, set
  for the new org-iso-mdoc requests (`Transactions.BeginMdocDCAPI`). A
  store built on `TransactionCodec`, sqlstore's among them, already
  does; a store of your own must persist the field too.
  `verifiertest.TestTransactionStoreContract` checks it, and
  `BeginMdocDCAPI` refuses a store that drops it. `TransactionCodec`'s
  records keep their version and seal: those written before still
  open. An earlier release can't read an org-iso-mdoc request's record
  (an unknown field), so finish upgrading every instance sharing a
  store before beginning one.
- **`verifier.Reason` has a new value**, `ReasonMdocDCAPIResponse`, for
  an org-iso-mdoc response that didn't decrypt or verify: a `switch`
  over the reasons handles it.

### mdoc curves (`credential/mdoc`, `proximity`, `mdocdcapi`, `verifier`, `wallet`, `issuer`, `statuslist`, `identifierlist`)

ISO/IEC 18013-5 has an mdoc reader support every curve it lists. Of
those, P-384 and P-521 are now supported alongside P-256 and Ed25519,
with ES384 (`oid4vci.COSEES384`, COSE -35) and ES512
(`oid4vci.COSEES512`, -36). Material that was refused with an error
naming its curve is now accepted:

- **Verifiers and readers** verify an IssuerAuth, device signature or
  reader authentication signed on P-384 or P-521, with the algorithm of
  the verified key's curve; a COSE_Key with crv 2 (P-384) or 3 (P-521)
  is a device key. A header marked with RFC 9864's ESP384 (-51) or
  ESP512 (-52) verifies as ES384 or ES512, as ESP256 (-9) does as
  ES256. Device MAC works on any of the three curves, with the device
  key and the reader's ephemeral key on the same one.
- **A proximity reader** accepts an EDeviceKey on P-384 or P-521 and
  generates its EReaderKey on the same curve; ephemeral keys on two
  curves are refused. A holder still generates its own on P-256.
- **Status and identifier lists:** a CWT token signed by a P-384 or
  P-521 key verifies, and `statuslist.Publisher` and
  `identifierlist.Publisher` sign with one. JWT tokens stay ES256 or
  EdDSA: a `statuslist.Publisher` whose signer is on P-384 or P-521
  must set `DefaultForm` to `FormCWT`, or it signs nothing, and answers
  a request for the JWT form alone 406 Not Acceptable.
- **An issuer** may set `MdocSigner.Alg` to ES384 or ES512 with a
  P-384 or P-521 signer. `New` now refuses an `MdocSigner` whose `Alg`
  isn't its signer's key's, which before failed each issuance instead.
- **A wallet**'s `VPFormats` matches an mdoc signed on P-384 or P-521
  against `issuerauth_alg_values` listing -35 or -51, or -36 or -52.

The brainpool curves and Ed448, which Go's standard library doesn't
implement, are still refused.

## v0.62.0 → v0.63.0

### Issuer (`issuer`)

- **A wrapped X5C verifier keeps its production checks.** New ran
  `X5CAttestationVerifier`'s and `X5CProofBindingKeyResolver`'s checks
  only when the dependency was one of those types itself. They're now
  each type's `CheckConfiguration` method (`ConfigurationCheck`), which
  New calls on any `AttestationVerifier` or `ProofBindingKeys`
  implementing it, so a type of your own embedding one is held to
  them: under `AssuranceProduction`, a `Revocation` choice
  (`certrevocation.NoCheck{}` to decline) and an explicit
  `IssuerBinding`. A wrapper holding one in a named field should
  implement `CheckConfiguration` by calling the field's.
- **`locations` is required with `authorization_servers`.** With
  `Config.AuthorizationServers` set, an access token's
  `openid_credential` authorization detail grants a configuration only
  when its `locations` lists `Config.Issuer` (OpenID4VCI 1.0 §5.1.1,
  §6.2), and `RedeemPreAuthorizedCode` refuses a Token Request's
  detail without `locations`, with `invalid_authorization_details`.
  Without it, a token from an Authorization Server several issuers
  share granted one issuer's configuration at every issuer with a
  configuration of that ID. Tokens this package mints already carry
  `locations` there; have your Authorization Server keep the ones the
  Wallet asked for.
- **Anonymous pre-authorized offers need a Transaction Code in
  production.** Under `AssuranceProduction` with
  `AnonymousPreAuthorizedCode`, `CreatePreAuthorizedOffer` refuses an
  offer with neither `TxCode` nor the new `NoTxCode`: without client
  authentication, whoever sees such an offer redeems it (OpenID4VCI
  §3.5). Set `NoTxCode` to offer without one deliberately, with a
  short `Lifetime`.
- **A Notification Endpoint needs a lifetime in production.** Under
  `AssuranceProduction`, New refuses `Endpoints.Notification` without
  a positive `Limits.NotificationLifetime`: each record names the
  client and subject, and one that never expired was never swept.
- **The deprecated `MetadataHandler` doesn't fall back to unsigned
  metadata in production.** Given a signer `NewMetadataHandler`
  refuses, it now answers every request with a server error under
  `AssuranceProduction`. Use `NewMetadataHandler`, which refuses the
  signer up front.

Not breaking, but worth knowing: `New` now keeps its own copy of the
`Config`, and `Metadata` returns a copy, so changing either afterwards
no longer changes what the Issuer enforces. `Prepare` gets the claims
the token's authorization detail asks for
(`CredentialRequest.AuthorizedClaims`, or `ResolveAuthorizedClaims`
for a direct caller). And jwt proofs naming their key by `kid` beside
a `key_attestation`, carrying an optional `key_attestation` an issuer
doesn't verify, or, without a Nonce Endpoint, a key attestation issued
earlier, are now accepted, as OpenID4VCI 1.0 Appendix F.1 allows.

### Verifier (`verifier`, `mdocdcapi`)

- **Production needs a store that seals transactions.** Under
  `AssuranceProduction`, `NewTransactions` refuses a store that doesn't
  implement the new `verifier.SealingStore` returning true: one that
  keeps each transaction's response decryption key and disclosed claims
  in plaintext. `sqlstore`'s `TransactionStore` seals when its
  `TransactionCodec` has a `Sealer`, or now, when it has none, when its
  DB has one. A store of your own implements `SealsTransactions`. Where
  the store is as protected as the Verifier's keys, set
  `TransactionsConfig.UnsealedStore`.
- **`sqlstore` seals transactions with the DB's Sealer.** On a DB with
  `Options.Sealer`, `DB.Transactions(verifier.TransactionCodec{})` now
  seals, and no longer reads the unsealed transactions it wrote before:
  a request in flight when you upgrade fails. Upgrade when none is.
- **Production bounds `TransactionsConfig.Lifetime`** by
  `MaxProductionTransactionLifetime`, an hour.
- **A request for a format the Verifier can't verify is refused.**
  `BuildAuthorizationRequest` and `BuildDCAPIAuthorizationRequest`, and
  so `Begin` and `BeginDCAPI`, refuse a credential query whose format
  isn't `dc+sd-jwt` or `mso_mdoc`, or isn't in
  `Config.VPFormatsSupported`. List each format you ask for
  (`SDJWTVCFormatSupport`, `MdocFormatSupport`).
- **`DiscardedPresentation.Reason` is fixed text.** It describes the new
  `Code` field rather than repeating the verification error, some of
  which the presentation's sender wrote; `Err` keeps the error, for logs
  only, and isn't stored.
- **An SD-JWT VC's array index matches any disclosed element.** A
  presentation leaves out the array elements it doesn't disclose, so the
  verifier can't check an index's position: `["nationalities", 1]` is
  answered by any disclosed nationality, and its `values` by any
  disclosed one's. This library's Wallet's answer to an index past 0,
  refused before, now verifies. Don't rely on an element's position in
  a presented SD-JWT VC.
- **`mdocdcapi` requests expire.** `BuildRequest` sets
  `Pending.ExpiresAt` (`RequestParams.Lifetime`, five minutes by
  default, at most an hour), and `VerifyResponse` refuses a response
  after it (`ErrRequestExpired`), or a `Pending` without one. Keep the
  `Pending` whole, and server-side.

### Status lists (`statuslist`)

- **A status check must bind the list's signer.** `Checker`,
  `CheckX5C` and `CheckCWTX5Chain` used to accept any Status List
  Token signer under their roots when `VerifyOptions` set neither
  `Issuer` nor `IssuerKey`: under roots several issuers share, any of
  them could sign a list deciding another's credential's status.
  They now refuse such a check unless the new
  `VerifyOptions.UnboundSigner` decides the signer, as
  `identifierlist`'s already did. Set `Issuer` or `IssuerKey` from
  the credential, or `UnboundSigner` to a policy of your own, or to
  `statuslist.AnyListSigner` where every signer under the roots may
  decide every credential's status (roots of one issuer alone). A
  `verifier.StatusPolicy`, `walletflow` and the mobile reader already
  bind the signer and need no change.
- **Token size follows `MaxTokenBytes`.** Tokens were capped at 1 MiB
  whatever `Fetcher.MaxBytes` said. `VerifyOptions.MaxTokenBytes`
  (default `DefaultMaxTokenBytes`, 1 MiB, at most
  `MaxTokenBytesLimit`) now sets the cap, and a `Checker` takes its
  `Fetcher.MaxBytes` when it's unset. `Publisher.Token` refuses a
  token over its own `MaxTokenBytes` (same default) instead of serving
  one Relying Parties refuse: a one-bit list of 16 million entries,
  say, needs both raised.
- **`Publisher` checks its times.** A `TTL` or `Lifetime` under a
  second, or a `TTL` longer than the `Lifetime`, now fails `Token`
  (and `ServeHTTP` with a 500) at once; it made every request fail
  before. `ServeHTTP` now serves the form an `Accept` header prefers
  by q, and never one it excludes with `q=0`.

### JOSE and COSE (all roles)

- **Small-order Ed25519 keys are refused when verifying.** A key of
  small order verifies a forged signature over any message. Parsing a
  JWK or COSE_Key, and a certificate's leaf, refused one; a key your
  own resolver returns (a `ProofBindingKeyResolver`,
  `SDJWTVCIssuerKeyResolver`, `AttestationVerifier`,
  `statuslist.VerifyOptions.IssuerKey`) now is too.
- **`typ` is compared as a media type everywhere.** `application/`
  forms and other cases (`application/kb+jwt`, `DC+SD-JWT`) are
  accepted for the SD-JWT VC, Key Binding JWT, jwt proof, Key and
  Wallet Attestation, Request Object, signed metadata and
  registration checks (RFC 7515 §4.1.9), as for status lists.
- **Out-of-range times are refused.** A Request Object's `exp` or
  `nbf`, or signed metadata's `iat`, `exp` or `nbf`, before 1970 or
  past year 9999 is refused rather than wrapped. A Key Attestation's
  `iat` and `exp` may be fractional.
- **`_sd_alg` only at the top level.** An SD-JWT with `_sd_alg` in a
  nested object, or a Disclosure named `_sd_alg`, is refused (RFC 9901
  §4.1.1).

### Wallet (`walletflow`, `wallet`)

- **`PendingDeferred` keeps the type requested.** It has `Format`,
  `VCT` and `DocType`: a `DeferredStore` of your own must keep them
  (`walletflow/storetest` checks every field; sqlstore's and the mobile
  stores do). A deferred credential polled after a restart, whose
  configuration now issues another type, is refused with
  `ErrReissueRequired` and settled, not stored. Records stored before
  aren't checked.
- **A refresh keeps the type too.** `RefreshCredential` returns
  `ErrReissueRequired` when the configuration's format, vct or doctype
  differs from the stored credential's: receive it again from a new
  offer.
- **Revoked and expired credentials aren't picked.** A copy
  `CheckStatus` found revoked ranks with an expired one, so a valid copy
  is presented first; `StoredCredential.Presentable` reports whether a
  Verifier could accept a credential now, a presentation lists those it
  couldn't last, and `DefaultSelection` never picks them (it returns
  `ErrNoMatchingCredential` when only those would answer).
- **Wallet invocation schemes in `redirect_uri`.** A Verifier's
  `redirect_uri` to `openid4vp`, `haip-vp`, `openid-credential-offer` or
  `haip-vci` is refused, as `http` and `javascript` were.
- **A signed presentation is sent even when its context is cancelled.**
  `Respond` posts on a context detached from the caller's, for up to 30
  seconds, once the presentation is signed.

## v0.61.0 → v0.62.0

### Authorization details (`oid4vci`)

- **Dropping every `credential_identifiers` entry is refused.**
  `AuthorizationDetailRARDefinition`'s `ValidateNarrowing` used to
  accept a token request (exchanging a code or a CIBA `auth_req_id`,
  or refreshing) whose `openid_credential` object left out all the
  identifiers its grant held. The access token then carried none, so
  the Wallet could ask for the configuration by
  `credential_configuration_id`, for whatever dataset the Credential
  Endpoint's `Prepare` picks rather than the one consented to, and the
  Token Response broke OpenID4VCI 1.0 §6.2, which requires them. Such
  a token request is now refused with `invalid_authorization_details`:
  keep a non-empty subset of the grant's identifiers, or send no
  `authorization_details` to keep the grant as it is.
- **Malformed objects are refused.** Every `openid_credential` object
  (`Validate`) is refused, with `invalid_authorization_details`, when
  `credential_identifiers`, `locations` or `claims` is an empty array,
  a location is empty, a claims `path` isn't a non-empty array of
  strings, nulls and non-negative integers (Appendix B.1), or two
  claims share a path (Appendix B.3). Leave a member out rather than
  sending it empty.
- **`ClaimsDescription.Validate` accepts decoded indices.** A path
  index decoded from JSON (a `float64`) is accepted when it's a
  non-negative integer; `CredentialMetadata.Validate` refused every
  one before.

### Verifier (`verifier`)

- **Sealed fields are bound to who may read the result.**
  `TransactionCodec` with a `Sealer` now binds the response decryption
  key and the result to the transaction's owner, browser binding hash,
  `same_device`, origin and query, not just its ID: someone who could
  write to the store but hadn't the key could rewrite the browser
  binding hash or owner and have `Lookup` hand them the result. A
  sealed record written by v0.61.0 or earlier no longer opens
  (`sqlstore.ErrRecordFormat` from `sqlstore`'s store): a request in
  flight when you upgrade fails, and a completed one's result is lost —
  at most `TransactionsConfig.Lifetime`'s worth, twice over. Upgrade
  when no request is in flight, or accept those failing. Records
  written without a `Sealer` are unaffected.
- **`RequestURIBase` and `RedirectURI` are checked as endpoint URLs.**
  `NewTransactions` checks both with `fapi.ParseEndpointURL`, as
  `Config.ResponseURI` already was: one with userinfo
  (`https://user:pw@…`, even a bare `@`) or a host that isn't ASCII is
  refused. Give an internationalized domain name as its `xn--` A-label.

## v0.60.0 → v0.61.0

### FAPIgo v0.69.0 (`issuer`)

OID4VCgo pins FAPIgo v0.69.0. See FAPIgo's UPGRADING.md, `## v0.69.0`,
for its own changes; these are the ones that reach an issuer running
`fapigo/server` beside `issuer`.

- **Attester certificates with large RSA keys are refused.** A Wallet
  Attestation whose `x5c` carries an RSA key over 4096 bits, or with an
  exponent other than 65537, is refused with `invalid_client`. Use
  2048–4096-bit RSA with e = 65537, or EC.
- **Token bindings must be passed unchanged.** `IssueAccessToken` and
  `IssueRefreshToken` refuse, with a `server_error`, a `TokenBinding`
  or `AttestedClient` changed after `VerifyTokenRequestBinding` or
  `AuthenticateAttestedClient` returned it. Pass both as returned, for
  the current request, as the passport-vdc demo's pre-authorized code
  Token Endpoint does
  ([`issuerapp/preauth.go`](examples/passport-vdc/issuerapp/preauth.go)).
- **Pushed request parameters are bounded.** `state`, `nonce`, `scope`,
  `login_hint` and `acr_values` over 4 KiB, `id_token_hint` over 16
  KiB, and `code_challenge` or `dpop_jkt` over 128 bytes are refused
  with `invalid_request`.
- **At most eight `BeginAuthorization` calls per `request_uri`.** The
  ninth returns a `LocalErrorResponse` with `invalid_request_uri`. Call
  it once per visit and keep the `InteractionHandle`.
- **No query or bare `#` in URLs.** `Config.Issuer` with a query, and an
  issuer, endpoint or redirect URI ending in a bare `#`, are refused.

### fapigo/sqlstore v0.4.0

passport-vdc and `sqlstore`'s tests pin fapigo/sqlstore v0.4.0. Its
`Migrate` and `CheckSchema` refuse a SQLite file not in WAL mode: open
it with `?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)`, as
`sqlstore`'s docs already say. Its own `AESGCMSealer` refuses a weak
key, as `verifier.AESGCMSealer`, which passport-vdc and `sqlstore`'s
docs use, now does too (see Verifier below). A Credential Endpoint running in the
Authorization Server's process keeps using `serverresource.NewVerifier`
with the server's `Dependencies`; one running apart takes its stores
from fapigo/sqlstore's new `ResourceServer`.

### Certificate chains (all roles)

- **Large RSA keys are refused.** Every certificate chain OID4VCgo
  verifies — `x5c` and `x5chain` from issuers, wallets, verifiers,
  attesters and mdoc readers — now refuses a certificate whose RSA key
  is over 4096 bits or has an exponent other than 65537, before any
  signature is checked with it. Checking a signature with an unbounded
  key cost milliseconds each, and path building tries many. Use
  2048–4096-bit RSA with e = 65537, or EC. Trust anchors you configure
  aren't checked, unless a chain sent to you carries one too.
- **Your own signing chains are checked too.** The chains you
  configure to sign with are checked when they're set up or used, so
  one carrying such a key now fails there: `verifier.Config`'s
  `ClientCertificate` and `ClientCertificateChain` (`verifier.New`),
  an issuer's signers' certificates and intermediates (`issuer.New`),
  `issuer.SignMetadataJWS`'s, `sdjwtvc.IssueOptions`'
  `IssuerCertificate` and `IssuerIntermediates`, a Key Attestation's
  `x5c` (`attestation`), and a status list's or identifier list's
  signer chain (`statuslist`, `identifierlist`).

### Verifier (`verifier`)

- **`AESGCMSealer` refuses weak keys.** A key that's one byte repeated
  (all zeros, say), or all printable text — a passphrase, or a hex or
  base64 key not yet decoded — is refused, as fapigo/sqlstore's
  `AESGCMSealer` now refuses one. Generate 32 bytes with `crypto/rand`
  and decode an encoded key before passing it. Records sealed under
  such a key open only with a `TransactionSealer` of your own over it,
  beside the new one (fapigo/sqlstore's `RotatingSealer` takes both),
  until they expire: `AESGCMSealer`'s doc gives the layout it must
  read.

### sqlstore

- **SQLite must be in WAL mode.** `Migrate` and `CheckSchema` refuse a
  SQLite database whose `journal_mode` isn't `wal`: without it, most
  reads made under concurrent requests failed. Open it with
  `?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)`, as the
  package documentation already said.

### URLs (`verifier`, `mdocdcapi`)

- **No query or fragment where a URL is extended or compared.**
  `TransactionsConfig.RequestURIBase` with a query or a fragment, even
  a bare `?` or `#`, is refused: each request's `request_uri` is it
  with `/` and the request's ID appended, which landed in the query or
  fragment instead of the path. `RedirectURI` with a fragment is
  refused: the Wallet sends the browser there with the
  `response_code` in the query; a query is still allowed. An origin
  (`Origins`, and the origin a wallet's platform reports to
  `mdocdcapi`) ending in a bare `?` or `#` is refused, as one with a
  query or fragment already was: no browser serializes an origin so.

## v0.57.1 → v0.60.0

### Authorization details (`oid4vci`)

- **Dropping locations or claims is refused.**
  `AuthorizationDetailRARDefinition`'s `ValidateNarrowing` (a token
  request exchanging a code or a CIBA `auth_req_id`, or refreshing)
  and `ValidateGrant` (consent) used to accept an `openid_credential`
  object with no `locations` or no `claims` where the wider one had
  them. Without `locations` the access token was good at any Credential
  Issuer sharing the Authorization Server, and without `claims` the
  claims limit was gone. Such a token request is now refused with
  `invalid_authorization_details`, and such a grant fails consent:
  keep a non-empty subset of the granted (or requested) `locations`
  and `claims`. Dropping every `credential_identifiers` entry is still
  accepted.

### FAPIgo v0.68.0 (`issuer`)

OID4VCgo pins FAPIgo v0.68.0. See FAPIgo's UPGRADING.md, `## v0.68.0`,
for its own changes; these are the ones that reach you.

- **More attester certificates are refused.** An issuer whose
  Authorization Server verifies Wallet Attestations with
  `server.X5CAttesterChain` and the default leaf policy now refuses,
  with `invalid_client`, an attestation signed by a certificate that
  lists, or chains only through a CA restricted to, the ISO/IEC
  18013-5 mDL JWS or VICAL signer, the ISO/IEC TS 23220-4 mdoc document
  signer or reader, RFC 9336 document signing, or an RFC 6187 SSH
  extended key usage. Issue attesters a dedicated certificate; a
  Wallet Provider purpose of your own is still accepted.
- **No copy of a trust anchor in `x5c`.** An attestation whose `x5c`
  carries a certificate with the same subject and public key as a
  trust anchor, such as a re-issued or cross-signed copy, is refused.
  Send the signing certificate and its intermediates only.

### Credential Issuer (`issuer`)

- **A proof key's trust can be undecided.** A custom
  `ProofBindingKeyResolver` that can't decide a key's trust now (a DID
  Document's host answering 503, say) can wrap
  `issuer.ErrProofKeyTrustUndecided` in its error. The Credential
  Request is then answered with a server error rather than
  `invalid_proof`, and a deferred transaction stays pending
  (`ErrDeferredProofKeyTrustUnknown`) instead of being denied. Any
  other error still refuses the key.

### sqlstore

- **`Sweep` no longer deletes wallet authorizations.** An expired
  authorization in progress names the instance and DPoP keys it was
  started with, which only walletflow deletes, with the authorization,
  when it next lists them: deleted by `Sweep`, the authorization left
  its keys in the `KeyStore` for good. walletflow still forgets expired
  authorizations itself, so there's nothing to change unless you
  counted on `Sweep` emptying `oid4vc_wallet_authorizations`; its count
  no longer includes them.
- **A pre-authorized code whose Transaction Code column was changed is
  refused.** `PreAuthorizedCodeStore.Consume` now checks the readable
  `tx_code_hash` column against the code's sealed record before
  accepting it, and refuses one where they differ with an error
  wrapping `ErrRecordFormat` — a server error, not a wrong Transaction
  Code. Codes the store wrote itself always match.

### fapigo/sqlstore v0.3.0

passport-vdc and `sqlstore`'s tests pin fapigo/sqlstore v0.3.0. If you
run v0.2.0 with a `Sealer`, upgrade every instance sharing the database
at once, since a v0.2.0 instance can't open records v0.3.0 seals, then
run `SealRecords` once to re-seal the older records.

### Verifier (`verifier`)

- **A sealed record's result must stay sealed.** With a `Sealer`,
  `TransactionCodec.Unmarshal` now refuses a record carrying a
  plaintext `result`, and without one a record carrying a
  `sealed_result`. A custom store that rewrites records must keep the
  sealed fields as `Marshal` wrote them.

## v0.56.0 → v0.57.0

### Certificate revocation (`certrevocation`)

- **A trust anchor that isn't self-signed is checked.**
  `certrevocation.CRLs` now checks the last certificate of a verified
  path against its CA's CRL whenever it isn't self-signed, not only
  when it's a pinned leaf alone. An intermediate CA among the roots, as
  when a CA's whole chain is loaded as the trust anchors, was never
  checked: beside its root it gave a path ending at itself, which
  passed after the root had revoked it. Such a path now needs the
  intermediate's own CA certificate in `CRLs.Issuers`
  (`Refresher.Checker()` sets the Refresher's `Issuers`) and a current
  CRL from that CA, or it's refused with `ErrNoCurrentCRL`. Load only
  self-signed roots as trust anchors where revocation is checked; where
  an intermediate must stay among them, add its CA's certificate to
  `Issuers` and that CA's CRL distribution point to the Refresher. On
  mobile, that CA's certificate goes in `crl_issuers`.
- **Two Refresher issuers by one name.** `certrevocation.NewRefresher`
  refuses `Issuers` holding two certificates with the same subject name
  but different keys, unless `RefresherConfig.AllowSameNameIssuers` is
  set. The rollback floor is now kept per issuer name and key, so one
  such CA's lists no longer raise, or are refused by, the other's; a
  CA that re-keyed under its name may restart its CRL numbering. Set
  the option for a CA that re-keyed and still publishes CRLs under its
  old key too, and bind each of their URLs with `URLIssuers`; otherwise
  remove the certificate that doesn't belong. Floors persisted from
  `OnAccept` need no change: each is matched to the issuer whose key
  verifies it.

### Parsing

- **base64url is the RFC 7515 §2 alphabet only.** Every JWS, JWE and
  JWK segment and member, and every SD-JWT Disclosure, is refused if it
  holds a byte outside `A–Z a–z 0–9 - _`. A token that a producer broke
  across lines (`\r`, `\n`) or padded with `=` used to be read as the
  unbroken one; it is now refused. Producers that follow the RFCs never
  emit either.
- **JSON must be UTF-8.** Every JSON object this module parses (JOSE
  headers and claims, metadata, requests and responses) is refused if
  it holds bytes that aren't UTF-8 or a `\u` escape of an unpaired
  surrogate (RFC 8259 §8.1–§8.2, RFC 7493 §2.1), instead of reading
  either as U+FFFD.
- **A COSE header label may be in only one bucket.** A COSE_Sign1 or
  COSE_Mac0 (an mdoc's IssuerAuth, DeviceAuth, a CWT Status List
  Token) naming one header label in both its protected and unprotected
  headers is refused (RFC 9052 §3).

### mdoc (`credential/mdoc`)

- **`mdoc.Verify` refuses an MSO without `signed`, `validFrom` or
  `validUntil`**, or whose `validUntil` isn't later than its
  `validFrom` (ISO/IEC 18013-5 §9.1.2.4, §12.3.4). A missing timestamp
  used to read as the zero time, which `validFrom` passed.
- **`mdoc.Issue` refuses an IssuerAuth over 64 KiB**, the most
  `mdoc.Verify` accepts, instead of issuing an mdoc no reader built on
  this module would take. Each `Claims.Decoys` digest adds about 40
  (SHA-256) to 72 (SHA-512) bytes, so a configuration near `MaxDecoys`
  in more than one namespace, or with SHA-512, now fails at issuance:
  lower the counts.

### Wallet (`proximity`, `mdocdcapi`, `walletflow`, mobile)

- **A requested identifier may not hold a line or paragraph separator
  or a format character.** A proximity or Digital Credentials API mdoc
  request naming a docType, namespace or data element with U+2028,
  U+2029 or any Unicode format character (Cf: zero-width space, word
  joiner, byte order mark, soft hyphen, tag characters, as well as the
  bidirectional ones already refused) is refused as invalid, as one
  with a control character already was.
- **Error text is cleaned like display text.** Text from an issuer,
  Authorization Server or Verifier that `walletflow` puts in an error
  (`AuthorizationDeniedError`), and every mobile `Error.Message`, now
  has line and paragraph separators made spaces and invisible format
  characters dropped, and is trimmed of surrounding space. A walletflow
  control character becomes a space instead of being dropped.

### Credential Issuer (`issuer`)

- **Key attestation signing certificates.** With `LeafPolicy` unset,
  `X5CAttestationVerifier` and `X5CProofBindingKeyResolver` now apply
  `issuer.DefaultAttestationLeafPolicy`. It refuses a signing certificate
  whose key usage doesn't allow digital signatures, that is an OCSP
  signer, or whose extended key usage lists any other role's purpose:
  TLS server or client, code signing, email, time stamping, IPsec, the
  mDL document signer's, or mdoc reader authentication. It also refuses
  one reached only through an intermediate restricted to such purposes.
  Give Wallet Providers their own certificates, or set `LeafPolicy`:
  call `issuer.DefaultAttestationLeafPolicy` from yours to keep these
  refusals, or set `issuer.AnyAttestationLeaf` to accept every
  chain-verified leaf.
- **Attestation issuer binding.** Under production, an
  `X5CAttestationVerifier` left at `AttestationIssuerUnbound` is
  refused. Set `IssuerBinding` to `AttestationIssuerBoundToAnchor` (with
  `Anchors`) where the roots certify more than one Wallet Provider, or
  to `AttestationIssuerInCertificate`. Where the roots certify a single
  Wallet Provider, set `SingleWalletProvider: true`. `New` refuses
  `SingleWalletProvider` together with any other binding.
- **Attestation status lists.** Bind an `AttestationStatusChecker`'s
  Status List Token signer by the attestation's key
  (`Options.IssuerKey = a.SignerKey`), not by `a.Claims.Issuer`, as the
  interface's doc comment now says.

### mdoc document signers (`credential/mdoc`, `verifier`, `mdocdcapi`, `proximity`, `wallet`, `walletflow`, the mobile libraries)

- **The mDL document signer extended key usage is required.**
  `mdoc.DefaultDocumentSignerPolicy`, the default of
  `X5ChainIssuerKeyResolver.LeafPolicy`, of a wallet receiving an mdoc
  with no issuer leaf policy, and of the proximity reader, now refuses
  a document signer certificate whose extended key usage doesn't list
  `mdoc.MDLDocumentSignerEKU` (1.0.18013.5.1.2, ISO/IEC 18013-5 Annex
  B.1.4), including one with no extended key usage at all. Before, such
  a certificate was accepted, so a revocation list signer's certificate,
  whose extended key usage Annex B.1.7 makes optional, could sign mdocs.
  It also refuses one reached only through an intermediate whose
  extended key usage excludes it. Ask your issuers for document signer
  certificates with the extended key usage. To keep accepting document
  signers without one, set the policy to
  `mdoc.LenientDocumentSignerPolicy`: `X5ChainIssuerKeyResolver.LeafPolicy`,
  `proximity.WithDocumentSignerPolicy`, or the wallet's issuer leaf
  policy (`VerifyIssuedCredentialParams.IssuerLeafPolicy`,
  `walletflow.Config.MdocIssuerLeafPolicy`). The mobile libraries have
  no lenient option.

### Registrations (`registration`, `walletflow`)

- **`Registrars.Revocation` is required.** `Registrars.Verify` refuses
  a nil `Revocation`: pass `certrevocation.CRLs{...}`, your own
  `certrevocation.Checker`, or `certrevocation.NoCheck{}` to decline.
  `walletflow` passes `NoCheck{}` itself in development when
  `Config.RegistrarRevocation` is unset; outside development it was
  already required.
- **Registrar certificates.** With `LeafPolicy` unset,
  `Registrars.Verify` now applies `registration.DefaultRegistrarLeafPolicy`,
  which refuses the same certificates as
  `issuer.DefaultAttestationLeafPolicy` above. Set `LeafPolicy` to your
  ecosystem's own check, calling `DefaultRegistrarLeafPolicy` first, or
  to `registration.AnyRegistrarLeaf` to accept every chain-verified
  leaf. `walletflow.Config.RegistrarLeafPolicy` defaults the same way.
- **`Verify` and `VerifyWithPolicy` are deprecated.** Use
  `Registrars.Verify`, which takes a context and a revocation choice.
  The deprecated functions check no revocation and apply
  `DefaultRegistrarLeafPolicy` when no policy is given.

### Credential Issuer (`issuer`) stores

- **Records name the Credential Issuer that created them.**
  `PreAuthorizedCodeRecord`, `DeferredTransactionRecord`,
  `NotificationRecord`, `NonceIssuance`, `NonceConsumption` and
  `NonceRecord` gain `Owner`, set to `Config.Issuer`, and an `Issuer`
  honours only its own records: Credential Issuers sharing a store, such
  as the tenants of one deployment, no longer redeem each other's
  pre-authorized codes, c_nonces, transaction_ids or notification_ids.
  A custom store must persist `Owner` like any other field. Under
  production a record without one is refused, and the issuer reads its
  first pre-authorized code, deferred transaction and notification_id
  back and refuses a store that dropped it. `NonceStore.Consume`
  retires only a nonce issued with `NonceConsumption.Owner`, leaving
  another Owner's in place (`issuer.ErrNonceUnknown`), and returns its
  `Owner` in the record. A deferred transaction your own business
  process creates in the store sets `Owner` to the `Config.Issuer` of
  the issuer that will serve it. Records saved before the upgrade have
  no `Owner`: under production, let pending c_nonces, deferred
  transactions and notification_ids expire, or set their `Owner`,
  before upgrading. Pre-authorized codes are also keyed by the `Owner`
  (below).
- **Store errors: unknown versus unavailable.** Each issuer store now
  has a sentinel for a record it doesn't hold:
  `issuer.ErrNonceUnknown` (`NonceStore.Consume`),
  `issuer.ErrPreAuthorizedCodeUnknown` (`PreAuthorizedCodeStore.Consume`),
  `issuer.ErrDeferredTransactionUnknown` (`DeferredTransactionStore`'s
  `Get`, `Invalidate` and `Update`) and `issuer.ErrNotificationIDUnknown`
  (`NotificationStore.Get`). A custom store returns an error wrapping it
  for a record it never had, or one already consumed or invalidated
  (`sql.ErrNoRows`, say). Any other error, including the context's,
  now fails the request with a 500 instead of `invalid_nonce`,
  `invalid_grant`, `invalid_transaction_id` or
  `invalid_notification_id`, so an outage no longer tells a holder their
  PIN is wrong. Run the `issuertest` contracts against your stores.
- **Pre-authorized codes and Transaction Codes are stored as hashes.**
  `PreAuthorizedCodeStore` is keyed by a SHA-256 hash of the code and
  the issuing Credential Issuer, and
  `PreAuthorizedCodeRecord.TxCode` is now `TxCodeHash`, an HMAC of the
  Transaction Code keyed by the code; `Consume` compares the hash it's
  given with it (in constant time). A store keeps both as opaque
  strings. Codes outstanding at the upgrade, stored under the code
  itself, stop working: let them expire, or issue new offers. A caller
  that called `PreAuthorizedCodeStore.Issue` itself calls
  `Issuer.IssuePreAuthorizedCode(ctx, code, txCode, record)` instead,
  which is refused under production, as `CreateCredentialOffer` with a
  pre-authorized grant is: use `CreatePreAuthorizedOffer` there. An
  offer made `ByReference` still holds its code in the
  `CredentialOfferStore` until it expires.

### Verifier (`verifier`, `mdocdcapi`)

- **Revocation is its own decision, `Status`, not `Accept`.** Under
  `AssuranceProduction`, any `Accept` used to satisfy the status gate, so
  an `Accept` checking business rules alone accepted revoked
  credentials. `TransactionsConfig`, `VerifyResponseRequest` and
  `mdocdcapi.VerifyParams` now take `Status`, a `verifier.StatusPolicy`
  the library runs before `Accept`, and production requires `Status` or
  `NoStatusCheck`; an `Accept` no longer counts. Under production,
  `Status.Checker.Fetcher` must be `HardenedForProduction` and
  `Status.Checker.Options.Revocation` set (`certrevocation.NoCheck{}` to
  decline checking status list signers' certificates). Setting both
  `Status` and `NoStatusCheck` is refused at every level. Move the
  status check out of `Accept`:

  ```go
  // Before
  Accept: func(ctx context.Context, id string, r verifier.VerifyResponseResult) error {
  	if err := verifier.RequireValidStatus(checker)(ctx, id, r); err != nil {
  		return err
  	}
  	return myChecks(ctx, id, r)
  },

  // After
  Status: &verifier.StatusPolicy{Checker: checker},
  Accept: myChecks, // verifier.Chain(a, b, …) composes several
  ```

  `RequireValidStatusFrom(checker, issuers)` becomes
  `StatusPolicy{Checker: checker, StatusIssuers: issuers}`, and
  `RequireStatusReference(…)` becomes `RequireReference: true`. The
  old functions still work as `Accept`s, but don't satisfy the
  production gate. A `Status` refusal is recorded as `LastError`, as an
  `Accept` refusal is. A `statuslist.NotValidError` for INVALID now
  says "(revoked)" in its text.
- **A status naming no known mechanism is refused.** A credential whose
  status names neither a Token Status List nor, for an mdoc, an
  identifier list — another mechanism, or a misspelt key — was read as
  having no status, so `RequireValidStatus` passed an mdoc revoked
  through it. `VerifiedCredential.StatusListRef` now returns an error
  for one, and `RequireValidStatus` and `RequireStatusReference` refuse
  it, in both formats. A decoded `mdoc.Status` with neither member is
  such a status, not "none". Nothing to change unless your issuers use
  a status mechanism this library doesn't know: accept those
  credentials only with `NoStatusCheck` and a check of your own.

### Credential Issuer (`issuer`) production bounds

- **Proof ages are capped under production.** Without a Nonce Endpoint,
  `Limits.MaxProofAge` may be at most `issuer.MaxProductionProofAge` (5
  minutes): a jwt proof's `iat` is then its only freshness, and one
  proof is good for any number of Credentials. Set `Endpoints.Nonce`
  (HAIP 1.0 §4.1 requires it) to make each proof single-use instead.
- **The system clock.** `Dependencies.Clock` is optional: nil is the
  system clock. Under production `issuer.New` refuses any other `Clock`
  unless it declares `issuer.ClockAssurance` (`ReadsSystemTime() bool`,
  the same method as `fapigo/server.ClockAssurance`, so
  `server.SystemClock` declares it): a fixed or offset test clock would
  stop every lifetime the issuer enforces. Replace
  `Clock: issuer.ClockFunc(time.Now)` with nothing.
- **HAIP as a profile (`haip`).** `haip.ValidateIssuerConfig` takes the
  `Dependencies` too: `haip.ValidateIssuerConfig(cfg, deps)`. It now
  also refuses a proof type whose `ProofSigningAlgValuesSupported`
  lacks ES256 (HAIP 1.0 §7), and a nil
  `PreAuthorizedCodeClientAuthentication` when `deps.PreAuthorizedCodes`
  is set (anonymous redemption under development assurance), and it
  reports every problem it finds rather than the first. Rather than
  calling it after `issuer.New`, set `Config.Profile:
  haip.IssuerProfile{}`, and `issuer.New` runs it with its own checks.
- **Deferred transactions keep x5c- and kid-conveyed proof keys'
  headers.** `DeferredTransactionRecord` gains `ProofKeyHeaders`: for a
  binding key a jwt proof conveyed by `kid` or `x5c`, the proof's JOSE
  header, which `IssueDeferredCredential` resolves again with
  `Dependencies.ProofBindingKeys`. A certificate revoked or no longer
  trusted while the transaction was pending now denies it
  (`issuer.ErrDeferredProofKey`), and one whose revocation can't be
  decided leaves it pending (`issuer.ErrDeferredProofKeyTrustUnknown`),
  as for key attestations. A custom `DeferredTransactionStore` must
  persist `ProofKeyHeaders` like any other field (the `issuertest`
  contract checks it), and an issuer issuing such a transaction needs
  the `ProofBindingKeys` that resolved it.

### FAPIgo v0.66.0 (`issuer`, `storage`, `haip`, `oid4vci`)

OID4VCgo pins FAPIgo v0.66.0. See FAPIgo's UPGRADING.md, `## v0.66.0`,
for its own changes; these are the ones that reach you.

- **The Authorization Server verifies every pre-authorized code
  redemption's DPoP proof.** Under `AnonymousPreAuthorizedCode` the
  issuer verified the Token Request's DPoP proof itself, with its own
  replay record and nonces, so a proof used at the authorization code
  grant could be used again at the pre-authorized code grant.
  `ExchangePreAuthorizedCodeRequest` loses `DPoPProof` and
  `TokenEndpoint`. In the Token Endpoint handler, refuse a request that
  authenticates a client (a Client Attestation, a `client_assertion`
  or `client_secret`, a TLS client certificate), call
  `srv.VerifyTokenRequestDPoP(ctx, tr)` on your `fapigo/server.Server`,
  and pass what it verified, with no `ClientID`:

  ```go
  b, err := srv.VerifyTokenRequestDPoP(ctx, tr)
  if err != nil {
  	server.WriteError(w, err) // use_dpop_nonce carries its DPoP-Nonce header
  	return
  }
  res, err := iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
  	PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"],
  	Verified: &issuer.VerifiedTokenRequest{DPoPThumbprint: b.Thumbprint, NextDPoPNonce: b.NextDPoPNonce},
  })
  ```

  `AnonymousPreAuthorizedCode`'s doc comment has the whole handler.
  `ExchangePreAuthorizedCode` refuses a `Verified` naming a client under
  `AnonymousPreAuthorizedCode`, and a request without `Verified` under
  either choice.
- **Removed with it.** `issuer.Dependencies.DPoPReplay` and
  `DPoPNonces`; `issuer.Limits.MaxDPoPProofAge`, `MaxDPoPClockSkew` and
  `DPoPNonceLifetime`; `issuer.MaxProductionDPoPProofAge`;
  `issuer.DPoPReplayChecker`, `DPoPNonceStore`, `DPoPNonceIssuance`,
  `DPoPNonceLookup`, `DPoPNonceRecord`, `NoDPoPNonces` and
  `ErrDPoPNonceUnknown`; `issuer.ErrorUseDPoPNonce`,
  `ErrorInvalidDPoPProof` and `(*issuer.Error).Nonce`, which no issuer
  call returns any more; `storage.DPoPReplayChecker` and
  `storage.DPoPNonceStore`; `issuertest.TestDPoPNonceStoreContract` and
  `TestDPoPReplayCheckerContract`. Delete them from your configuration:
  the proof's age, clock skew, replay record and nonces are
  `fapigo/server`'s (`Limits.MaxDPoPProofAge`, `MaxClockSkew`,
  `Dependencies.Replay`, `Dependencies.Nonces`), under its own
  production bounds. A DPoP nonce store of your own for the issuer has
  no use any more.
- **Wallet Attestation signing certificates.** `server.X5CAttesterChain`
  now applies `server.DefaultAttesterLeafPolicy{}` when `LeafPolicy` is
  nil: an attestation signed by a certificate whose extended key usage
  names another role (TLS server or client, OCSP or code signing, the
  ISO/IEC 18013-5 mdoc reader or document signer), or reached only
  through a CA restricted to such roles, is refused with
  `invalid_client`. Give Wallet Providers dedicated attestation signing
  certificates, or set `LeafPolicy` (`server.AnyAttesterLeaf{}` to opt
  out, a `server.AttesterLeafPolicyFunc` to add your own requirement).
- **No trust anchor in a Wallet Attestation's `x5c`.**
  `server.X5CAttesterChain` refuses an attestation whose `x5c` carries
  the trust anchor, or another self-signed certificate, below the
  signing certificate (HAIP 1.0). A Wallet Provider sends the signing
  certificate and its intermediates only.
- **Client Attestation PoP age under production.** With
  attestation-based client authentication, `server.New` under
  `server.AssuranceProduction` refuses a
  `Limits.MaxClientAttestationPoPAge` above 5 minutes.
  `haip.RecommendedAuthorizationServerConfig` sets 60 seconds.
- **`openid_credential` authorization_details.** Register
  `oid4vci.AuthorizationDetailRARDefinition(maxObjects, maxBytesPerObject)`
  in `server.Config.RAR` in place of a hand-built
  `extension.RARDefinition[oid4vci.AuthorizationDetail]`. It refuses a
  Wallet's own `credential_identifiers` at the pushed authorization
  request (`invalid_authorization_details`), lets the consent add the
  ones it mints, lets a token request (code exchange, CIBA, refresh)
  only keep or drop the identifiers its grant holds — never add one,
  even to a grant that holds none (FAPIgo v0.67.0's
  `RARDefinition.ValidateNarrowing`) — and requires
  `credential_configuration_id`, which a
  definition without `Validate` didn't. A Credential Endpoint's
  `Prepare` that maps a `credential_identifier` to a dataset looks it up
  among those minted for `grant.Subject`, never by the identifier
  alone.

### Wallet stores (`walletflow`)

Several Wallets — in separate processes, such as an app and its
extension or a server's replicas — may now share one set of stores.
Every read-modify-write of a stored record is one atomic store
operation, where it used to be a read then a write under a lock inside
one Wallet. A store of your own implements the new methods:

- **`AuthorizationStore.ConsumeAuthorization(ctx, state)`** returns
  the authorization and deletes it in one step. Of concurrent calls for
  one state, exactly one gets it, and the others get an error wrapping
  `ErrNotFound`. In SQL, use `DELETE … RETURNING`, or a `SELECT … FOR
  UPDATE` and a `DELETE` in one transaction.
- **`CredentialStore.Update(ctx, id, fn)`** and
  **`GrantStore.UpdateGrant(ctx, id, fn)`** load the record, call `fn`
  on it and store the result atomically, as the issuer's
  `DeferredTransactionStore.Update` and the verifier's
  `TransactionStore.Update` already do. An unknown record is
  `ErrNotFound`. An error from `fn` stores nothing and is returned. A
  store may call `fn` again on the current record after a conflicting
  write, as an optimistic compare-and-swap does. In SQL, use a
  transaction with `SELECT … FOR UPDATE`, or a conditional `UPDATE` on a
  version column, retried.
- **New fields to persist.** `CredentialCopy.Reservation` marks the
  latest presentation that reserved the copy. A presentation that isn't
  sent undoes only its own reservation, whichever Wallet made a later
  one. `RefreshGrant.Redemption` and `RedemptionExpiresAt` claim a
  grant while a refresh redeems its token. A store that drops them
  loses that protection between Wallets.
- **`ErrRefreshInProgress`.** `Wallet.RefreshCredential` returns an
  error wrapping it when another Wallet sharing the `GrantStore` is
  redeeming the same refresh grant. Before, both would have redeemed
  the token, and an Authorization Server that rotates refresh tokens
  takes that for a replay. Try again later. A claim lapses after two
  minutes if its Wallet stopped mid-refresh. Refreshes within one
  Wallet still wait for each other.
- `walletflow/storetest` checks the new operations, including under
  concurrency. Run `TestSharedCredentialStoreContract`,
  `TestSharedAuthorizationStoreContract` and
  `TestSharedGrantStoreContract` with a separate handle per goroutine
  on one storage.
- `KeysInUse` still knows only the issuances open in its own Wallet:
  sweep keys only while no Wallet sharing the stores has an issuance or
  refresh under way.

### Mobile (ABI 13; the Swift and Kotlin libraries)

- **`ABIVersion` is 13.** The Swift and Kotlin libraries refuse a
  framework built for another version: upgrade them together.
- **A `CredentialStore` of your own implements `compareAndSwap`.**
  Swift: `compareAndSwap(id:expected:record:) throws -> Data?`. Kotlin:
  `compareAndSwap(id, expected, record): ByteArray?`. Gomobile:
  `CompareAndSwap(id, expected, record) → []byte`. Replace `id`'s
  record with `record`, or delete it when `record` is nil or empty,
  only if the stored record is byte for byte `expected`. Return what
  was stored before. This must be atomic across every process that
  shares the store. Take the same lock in `put` and `delete`, and
  compare the plaintext if the store encrypts. `FileCredentialStore`
  on both platforms now does this with a file lock in its directory,
  so an iOS app and its extension can share one through
  `FileCredentialStore.inAppGroup`.
- `RefreshCredential` can now fail with `unavailable` and the detail
  `refresh_in_progress` while another process sharing the store is
  refreshing with the same grant. It is retryable.
- Records gain `reservation` on each copy, and `redemption` and
  `redemption_expires_at` on refresh grants. The Go side writes them; a
  store keeps them as it keeps the rest of a record.
- **Mobile readers are production by default (ABI 13).** A
  `ProximityReader`'s configuration takes `no_revocation_check`,
  `any_issuer_for_any_type` and `development`, as a Wallet's.
  `NewProximityReader` refuses (`invalid_input`) a configuration that
  leaves a role's revocation (`issuer`, `status`) out of both
  `revocation` and `no_revocation_check`, or sets `issuer_roots`
  without `any_issuer_for_any_type` (otherwise name each document
  type's IACAs in `issuer_roots_by_doctype`), unless it sets
  `"development": true`, which never ships. Make those decisions in a
  reader configuration that didn't; a development or test reader can
  set `development` instead. In Swift and Kotlin,
  `ProximityReaderConfiguration` has `noRevocationCheck`,
  `anyIssuerForAnyType` and `development` (default `false`).

### Proximity reader (`proximity`, `walletflow`, mobile)

- **A reader makes a Verifier's decisions.** `NewReaderSession` and the
  NFC reader constructors now require `WithAssurance` (as
  `verifier.Config.Assurance`) and `WithIssuerRevocation`, at every
  level: pass `certrevocation.CRLs{...}`, your own
  `certrevocation.Checker`, or `certrevocation.NoCheck{}` to decline.
  A nil checker, which used to mean no check, is refused. Under
  `verifier.AssuranceProduction` they also require which issuers may
  issue which document types (`WithIssuerAuthorization`, or
  `WithAnyIssuerForAnyType`) and the documents' status
  (`WithStatus(&verifier.StatusPolicy{…})`, or `WithNoStatusCheck`,
  checked with `verifier.CheckStatusDecision`), and refuse the system
  root pool, in `WithIssuerRootsByDocType` or as `Verify`'s roots.

  ```go
  // Before
  r, err := proximity.NewReaderSession(qr, proximity.WithReaderAuth(key, chain))
  v, err := r.Verify(msg, iacas, time.Time{})
  // then check v.Status yourself

  // After
  r, err := proximity.NewReaderSession(qr,
  	proximity.WithAssurance(verifier.AssuranceProduction),
  	proximity.WithIssuerRevocation(crls), // certrevocation.NoCheck{} to decline
  	proximity.WithIssuerRootsByDocType(iacasByDocType),
  	proximity.WithAnyIssuerForAnyType(),
  	proximity.WithStatus(&verifier.StatusPolicy{Checker: statusChecker}),
  	proximity.WithReaderAuth(key, chain))
  v, err := r.Verify(ctx, msg, iacas, time.Time{})
  ```

- **`ReaderSession.Verify` takes a context**, its first argument. It
  bounds the document signer's revocation check (which used
  `context.Background()`) and the status check. `WithStatus` and
  `WithIssuerAuthorization` run in `Verify`, after the document
  verifies; their refusals are `Verify`'s errors.
- **`Verified.Credential()`** gives the document as a
  `verifier.VerifiedCredential`, for `verifier.StatusPolicy.Check` or
  `verifier.RequireValidStatus` after `Verify`. Its `IssuerChain` leaves
  out the trust anchor, as a Verifier's mdoc's does.
- **Respond after Terminate.** `walletflow.ProximityPresentation.Respond`
  fails with the new `walletflow.ErrTerminated`, sending nothing, when
  `Terminate` is called while it runs (the holder key's prompt is up,
  say); it used to return a response the app could still send. The
  mobile code is `cancelled`. The Swift and Kotlin libraries also check
  that the app hasn't cancelled before they send a response.

### Verifier (`verifier`)

- **Transaction stores keep every field.** `Begin` and `BeginDCAPI`
  read back the first transaction of each kind they create —
  cross-device, same-device, Digital Credentials API — and refuse a
  store that changed its `ID`, `KeyID`, `State`, `Nonce`,
  `ResponseDecryptionKey`, `RequestObject`, `Origin`, `Owner`,
  `BrowserBindingHash`, `SameDevice` or `Status`, or moved `ExpiresAt`
  or `RetainUntil` by a second or more. Until now only `Owner` was
  checked, and a store that dropped `SameDevice` answered a same-device
  request as a cross-device one. `verifiertest.TestTransactionStoreContract`
  now checks that `Create` and `Update` keep every field, including a
  result's claims in the types their format decodes to (an mdoc's
  integers and byte strings, not JSON's); a store that hand-encodes
  `Transaction` may fail it. Encode transactions with
  `verifier.TransactionCodec`, which keeps every field.
- **Unrequested claims are refused.** `VerifyResponse`, and so
  `Transactions`, discards a presentation that discloses a selectively
  disclosable SD-JWT VC claim, or an mdoc data element, its Credential
  Query doesn't name — every claims path of the query counts, whichever
  `claim_sets` option was chosen, and none when the query lists no
  claims — as `ReasonUnrequestedClaims`, as `mdocdcapi` already refused
  an mdoc. A Wallet that minimises its disclosures, as OpenID4VP §6.4.1
  requires (`wallet.PresentCredentials`, the OpenID Foundation
  conformance suite), is unaffected; one that presents every claim
  (`wallet.PresentSDJWTVC`, `wallet.PresentMdoc`) is refused. Set
  `VerifyResponseRequest.AllowUnrequestedClaims` (in
  `TransactionsConfig.Verify` for `Transactions`) to accept it as
  before.

## v0.55.0 → v0.56.0

This release pins FAPIgo v0.65.1, which carries the breaking changes of
FAPIgo v0.63.0, v0.64.0 and v0.65.0: see FAPIgo's UPGRADING.md for
each. Those that reach OID4VCgo's callers:

### Credential Issuer (`issuer`, `haip`) and its Authorization Server

- **Resource verifier URLs.** `serverresource.NewVerifier` and
  `resource.NewVerifier` require `ResourceURLs`: the URLs the Credential,
  Nonce, Deferred Credential and Notification Endpoints are reached
  under, such as the Credential Issuer's own. `issuer/fapiresource`
  checks a DPoP proof against the endpoint URL the handler is given, so
  it must be under one of them. A handler of your own calls
  `resource.VerifyRequestFromHTTP(r)` and sets the request's `URL` to
  the endpoint's absolute URL (the recipe in `issuer/resource_verifier.go`).
- **Authorization Server DPoP nonces.** Under production, the server's
  `Dependencies.Nonces` is required (or `server.NoDPoPNonces{}`), and
  so is the resource verifier's: `serverresource.Options.Nonces`, a
  store of its own, or `resource.NoDPoPNonces{}`. A custom
  `storage.NonceStore` renames `Consume` to `Lookup` and keeps a nonce
  until it expires.
- **Server limits.** `Limits.MaxAccessTokenClaimsBytes` is required;
  `server.RecommendedLimits()`, which `haip` builds on, sets it.
  Production bounds the DPoP, JARM and interaction lifetimes, and
  requires a `Clock` that reads the system time.
- **Pre-authorized code refresh tokens** issued before this release
  record no grant type and are refused with `invalid_grant`: a wallet
  holding one receives a new pre-authorized code, as when it expires.
- **RSA keys.** Every RSA key must use the exponent 65537, and one a
  wallet or Wallet Provider supplies is at most 4096 bits.
- **The issuer's own DPoP nonces are valid for a time window, and
  `DPoPNonceStore.Consume` is now `Lookup`.** RFC 9449 §8 has a server
  keep a window of recent nonces and a client use one until given a new
  one; a single-use nonce challenged every concurrent Token Request from
  a Wallet but the first. `ExchangePreAuthorizedCode` now hands out one
  current nonce per `Issuer`, valid for `Limits.DPoPNonceLifetime` for
  any number of proofs, and issues the next once half that lifetime has
  passed; the previous one keeps working until it expires. A proof's
  `jti` (`Dependencies.DPoPReplay`) still refuses a replay. For your own
  store: rename `Consume` to `Lookup` (`issuer.DPoPNonceConsumption` is
  now `issuer.DPoPNonceLookup`), stop deleting the record on lookup
  (drop it only after its `ExpiresAt`), and return an error wrapping
  `issuer.ErrDPoPNonceUnknown` for a nonce you hold no record of. Any
  other `Lookup` error now fails the request as a server error (500)
  instead of a `use_dpop_nonce` challenge. Run
  `issuertest.TestDPoPNonceStoreContract` against it. Under production
  the store must declare `StoreCapabilities{Durable: true}`;
  `AtomicConsume` is no longer required of it.
- **The issuer's own DPoP nonces are required under production.** Under
  `issuer.AssuranceProduction`, where the issuer verifies the Token
  Request's DPoP proof itself (`Dependencies.PreAuthorizedCodes` set,
  `Config.PreAuthorizedCodeClientAuthentication` not
  `issuer.VerifiedPreAuthorizedCode{}`), `issuer.New` refuses a nil
  `Dependencies.DPoPNonces`. Pass a durable `issuer.DPoPNonceStore` with
  `Limits.DPoPNonceLifetime` (at most 15 minutes under production; five
  minutes suits most deployments), or `issuer.NoDPoPNonces{}` to keep
  accepting proofs without a nonce, as nil did before.

### Wallet (`walletflow`)

- **Clock.** Outside `Development`, `walletflow.New` refuses a
  `Dependencies.Clock` when the wallet receives credentials: leave it
  nil, the system clock. FAPIgo's client requires it under production;
  before, the wallet would have failed at its first issuance instead.

## v0.54.0 → v0.55.0

This release pins FAPIgo v0.62.0.

### Credential Issuer (`issuer`, `haip`)

- **Revocation choices under production.** Under
  `issuer.AssuranceProduction`, every `issuer.X5CAttestationVerifier`
  and `issuer.X5CProofBindingKeyResolver` in Dependencies must set
  `Revocation`: `certrevocation.CRLs` (a `certrevocation.Refresher`'s
  `Checker()`, say), your own `certrevocation.Checker`, or
  `certrevocation.NoCheck{}` to keep accepting certificates without a
  revocation check.
- **Attestation proof type.** Under production, `issuer.New` refuses a
  Credential Configuration that takes the `attestation` proof type
  unless `Config.AllowAttestationProofType` is set: a key attestation
  sent that way can be relayed to another issuer. Take jwt proofs
  carrying it in their `key_attestation` header instead
  (`haip.RecommendedJWTKeyAttestationProofType`).
  `haip.RecommendedIssuerConfig` no longer includes the attestation
  proof type, or a jwt proof type without a key attestation.
- **iss.** An SD-JWT VC whose `Prepare` sets no `Iss` now carries `iss`
  set to `Config.Issuer`.
- **Key attestation status.** An `AttestationStatusChecker` that should
  deny a revoked or suspended key attestation must wrap
  `issuer.ErrKeyAttestationRevoked`. Any other error now leaves a
  pending deferred transaction pending
  (`ErrDeferredAttestationStatusUnknown`) until it's decided or expires,
  and is answered `server_error` (500) at a Credential Request instead
  of `invalid_proof`. The same holds for a key attestation's or an x5c
  proof key's certificate whose revocation can't be decided: no current
  CRL, or a cancelled request.
- **Nonce lifetime.** Under production, `issuer.New` refuses a
  `Limits.NonceLifetime` over an hour.
- **HAIP scopes.** `haip.ValidateIssuerConfig` refuses a scope shared by
  Credential Configurations that require different key attestations.
- **The Authorization Server** (fapigo/server, FAPIgo v0.62.0): an
  `X5CAttesterChain` must set `Revocation` at every assurance level, to
  `server.ClientCertificateCRLs` or
  `server.NoClientCertificateRevocationCheck{}`. Under production with
  attestation-based client authentication,
  `Dependencies.ClientAttestationStatus` is required: a checker of the
  Wallet Attestation's status claim, or
  `server.NoClientAttestationStatusCheck{}`. A custom
  `ClientCertificateRevocation` must wrap `server.ErrCertificateRevoked`
  for a revoked certificate; any other error now answers `server_error`.
  See `haip.RecommendedAuthorizationServerConfig`.

### Verifier (`verifier`, `mdocdcapi`)

- **Transaction stores.** A `TransactionStore` must persist the new
  `Transaction.Owner`: `Begin` and `BeginDCAPI` read the first
  transaction back and fail if it was dropped (`verifiertest`'s contract
  checks it). Under production, transactions saved before the upgrade
  can't be read: let pending ones expire first.
- **Shared stores.** `Transactions` instances sharing a store each read
  only their own transactions. Instances meant to handle each other's
  requests must have the same client_id, response_uri and
  `RequestURIBase`, or set the same `TransactionsConfig.Scope`.
  Instances with all three in common but different policies, such as
  several DC-API-only `Transactions` on one Verifier, set a distinct
  `Scope` each.
- **DC API origins.** Under production, `TransactionsConfig.Origins`
  must list the origins of the pages that call
  `navigator.credentials.get`. `BeginDCAPI` refuses any other, and
  `NewTransactions` refuses a DC-API-only configuration (no
  `RequestURIBase`) without them. `mdocdcapi.VerifyParams.Origins` is
  required under production; `BuildRequest` refuses an origin that isn't
  https or loopback http, and `VerifyResponse` refuses a non-loopback
  http origin, in development too. List origins as
  `scheme://host[:port]`.
- **SD-JWT VC issuer certificates.** With `X5CIssuerKeyResolver.LeafPolicy`
  unset, an issuer certificate is refused when its extended key usage
  lists only other roles' purposes (TLS server or client, code signing,
  email, time stamping, IPsec), lists OCSP signing or the mdoc reader
  authentication purpose at all, or when every path to it goes through
  an intermediate restricted to other roles. Issue SD-JWT VC issuers
  their own certificates, or set `LeafPolicy`: call
  `verifier.DefaultSDJWTIssuerLeafPolicy` from yours to keep these
  refusals, or set `verifier.AnyIssuerLeaf` to accept every
  chain-verified leaf.
- **System roots.** Under production, issuer roots must be the issuers'
  own CAs. `x509.SystemCertPool()` is refused, and on Linux and other
  Unix systems so is a pool built by adding certificates to it.
- **Status checks.** `RequireValidStatus` refuses a credential whose
  status list signer it can't bind to the credential's issuer: one
  verified by a custom key resolver that reports no issuer chain, with
  no iss (SD-JWT VC) or no MSO status Certificate (mdoc). Report the
  chain (`SDJWTVCIssuerChainResolver`, `MdocIssuerChainResolver`), or
  use `RequireValidStatusFrom` with a `StatusIssuerPolicy`
  (`verifier.AnyStatusListSigner` where every signer under the roots may
  decide every credential's status). A non-object SD-JWT VC `status`
  claim is an error.

### Wallet (`walletflow`, the mobile libraries)

- **Redirect URIs.** `walletflow.New`, and the mobile `NewWallet` as
  `invalid_input`, refuse a `RedirectURI` that isn't a private-use
  scheme in `reverse.domain:/path` form (`com.example.wallet:/callback`)
  or loopback http (or, in development, https), or that carries a
  fragment or credentials. Outside development, loopback must be
  `127.0.0.1` or `[::1]`. A wallet with any other redirect URI could never complete an
  authenticated issuance.
- **Identifier lists.** `Wallet.CheckStatus` records
  `walletflow.StatusUnknown` for an mdoc naming an ISO/IEC 18013-5
  identifier list, which the wallet doesn't check yet, and the mobile
  `ProximityReader` reports `unknown` for one; treat it as not checked.
  The Swift and Kotlin `CredentialStatus.Value` gain an `unknown` case:
  add it to exhaustive `switch` and `when` expressions.
- **Missing configuration.** The mobile libraries report a missing
  `issuer_roots`, `redirect_uri`, `verifier_roots` or HAIP provider as
  `invalid_input` with the detail `not_configured`, not as `protocol`.
- **Status lists.** An mdoc's status list without `exp`, or with its
  `x5chain` outside the protected header, is refused (ISO/IEC 18013-5
  §12.3.6.3).
- **Pinned certificates and CRLs.** A certificate pinned in a roots PEM
  (a Verifier's leaf in `verifier_roots`, say) whose role is listed in
  `revocation` is checked against its CA's CRL: give that CA's
  certificate in the new `crl_issuers`, or it's refused.
- **Revocation is an explicit choice.** Outside `Development`,
  `walletflow.New` refuses a trust role in use without a revocation
  Checker: `IssuerRevocation` and `StatusRevocation` when
  `IssuerRoots`, `MdocIssuerRoots` or `MdocIssuerRootsByDocType` is
  set, `IssuerMetadataRevocation` with `IssuerMetadataRoots`,
  `RegistrarRevocation` with `RegistrarRoots`, `MdocReaderRevocation`
  with `MdocReaderRoots`, and `Revocation` on a
  `wallet.X5CVerifierRoots` `VerifierTrust`. Set each to a
  `certrevocation.Refresher`'s `Checker()` (or your own Checker), or to
  `certrevocation.NoCheck{}` to keep the old behaviour of checking
  nothing. `wallet.New` under `wallet.AssuranceProduction` requires the
  same of `IssuerMetadataRevocation` and an `X5CVerifierRoots`. In the
  mobile libraries, outside `development`, each role whose roots are set
  must be named in `revocation` (checked against `crls`) or in the new
  `no_revocation_check` (`noRevocationCheck` in Swift and Kotlin) to
  decline, or `NewWallet` is `invalid_input`; a role can't be in both.
  The roles are `issuer` and `status` (for `issuer_roots` and the mdoc
  roots), `issuer_metadata`, `registrar`, `mdoc_reader` and `verifier`.

### Revocation lists (`statuslist`, `identifierlist`, `certrevocation`, `mdoc`)

- **Status List Tokens.** A token whose `ttl` is 0 or negative, or whose
  `exp` isn't after its `iat`, is refused, and a negative
  `VerifyOptions.MaxAge` is an error instead of turning freshness checks
  off.
- **CWT Status List Tokens.** `statuslist.Checker.Check` and
  `RequireValid` with cwt true refuse a token without `exp` or with an
  unprotected `x5chain`. To check a CWT token outside ISO/IEC 18013-5,
  fetch it with `Fetcher` and call `statuslist.CheckCWTX5Chain` with the
  options it needs. Elsewhere, `statuslist.VerifyOptions.RequireExp` and
  `X5ChainProtectedOnly` apply the same rules.
- **Identifier lists.** `identifierlist.Check` and `Checker.Check`
  refuse a reference with no Certificate when no document signer path is
  given: pass the MSO's verified IssuerAuth x5chain, or set
  `VerifyOptions.UnboundSigner` (`identifierlist.AnyListSigner` where
  every CA under the roots may decide every MSO's revocation).
- **Issuing mdocs.** `mdoc.Issue` refuses an `IdentifierList` reference
  with no ID or URI, or whose Certificate isn't an X.509 certificate.
- **Pinned leaves.** `certrevocation.CRLs` checks a pinned leaf
  certificate against its CA's CRL: add the CA's certificate to
  `CRLs.Issuers`, or to a `Refresher`'s `Issuers`, or the leaf is
  refused with `ErrNoCurrentCRL`.
