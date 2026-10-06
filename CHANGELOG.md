# Changelog

## [0.34.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.33.0...v0.34.0) (2026-10-06)


### Features

* **walletflow:** answer OpenID4VP requests over the Digital Credentials API ([#471](https://github.com/IDFoundry/OID4VCgo/issues/471)) ([b640739](https://github.com/IDFoundry/OID4VCgo/commit/b64073941d54f5c423f83a28bc35a6fd7f93347a))


### Bug Fixes

* **walletflow:** let an abandoned authorization begin again ([#467](https://github.com/IDFoundry/OID4VCgo/issues/467)) ([ae5f09b](https://github.com/IDFoundry/OID4VCgo/commit/ae5f09bc48d655efb3603041c7a469d7c2bf1b28))
* **walletflow:** retire an authorization begun again; refuse unsigned DC API requests on request ([471b7c2](https://github.com/IDFoundry/OID4VCgo/commit/471b7c2de20f3f8313d48eacc74e66b290eb0611))

## [0.33.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.32.0...v0.33.0) (2026-10-06)


### ⚠ BREAKING CHANGES

* **proximity:** `BuildDeviceResponse` takes the `DocRequest` it answers in place of its docType — `BuildDeviceResponse(req, issuerSigned, holder, sessionTranscriptBytes, elements)` — and refuses elements the request doesn't list: pass the `DocRequest` from `ParseDeviceRequest` ([06df34b](https://github.com/IDFoundry/OID4VCgo/commit/06df34b))
* verifier.VerifyResponseRequest needs ExpectedOrigins whenever Origin is set. Pass the ExpectedOrigins field of the BuildDCAPIAuthorizationRequestResult the request came from, and set Origin to this Verifier's own origin, never to a value from the response's HTTP request.

### Features

* check mdoc reader certificates' purpose and optionally require a trusted reader ([eb7fe8b](https://github.com/IDFoundry/OID4VCgo/commit/eb7fe8b9e3f6959dec47d872376ff53b679ba0f3))


### Bug Fixes

* bound the work a Digital Credentials API request can cause ([f2c8bac](https://github.com/IDFoundry/OID4VCgo/commit/f2c8bac0709a87371002f2949b43452219f1442c))
* **mobile:** warn of linkable presentations in the iOS document provider ([6b2b6c8](https://github.com/IDFoundry/OID4VCgo/commit/6b2b6c8e008f7909c2e2794c9a36f823aad2d253))
* **proximity:** disclose only requested elements; reader clock skew and document signer policy ([06df34b](https://github.com/IDFoundry/OID4VCgo/commit/06df34b))
* **proximity:** stop an empty message crashing the reader; check document signers by default ([fef1a60](https://github.com/IDFoundry/OID4VCgo/commit/fef1a60ab17c2226f85d2b366dace8899c5225a5))
* **proximity:** take the issuer algorithm from its certificate, expose the MSO status ([c854dae](https://github.com/IDFoundry/OID4VCgo/commit/c854daedc81c002c72897ee12ad8ba375e49d841))
* verify a DC API response's origin against the request; tighten unsigned-request trust ([a054621](https://github.com/IDFoundry/OID4VCgo/commit/a054621379a067c9f6ccfee54e8a92ad0c366ce2))

## [0.32.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.31.1...v0.32.0) (2026-10-06)


### Features

* **mdocdcapi:** answer an org-iso-mdoc request as a wallet ([1efa2c4](https://github.com/IDFoundry/OID4VCgo/commit/1efa2c48421c173bc784c7ac31bd1767a76bd6ce))
* **mdocdcapi:** verify ISO mdoc presented over the Digital Credentials API ([bbf2925](https://github.com/IDFoundry/OID4VCgo/commit/bbf2925891b9ab6514434cdcb862a20a4dd61978))
* **proximity:** ISO/IEC 18013-5 in-person presentation over BLE, holder and reader sides ([#439](https://github.com/IDFoundry/OID4VCgo/pull/439)) ([75211ad](https://github.com/IDFoundry/OID4VCgo/commit/75211ad))
* **wallet:** accept unsigned and multi-signed DC API requests ([6ac6709](https://github.com/IDFoundry/OID4VCgo/commit/6ac67092872584c59c015c833a581c3ee6e03355))
* **walletflow:** present an mdoc over the Digital Credentials API ([de2fcec](https://github.com/IDFoundry/OID4VCgo/commit/de2fcec8f0564277b05208401f73b7a38e005723))

## [0.31.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.31.0...v0.31.1) (2026-10-05)


### Bug Fixes

* bind the Wallet Provider's trust anchor to its provider ([c955299](https://github.com/IDFoundry/OID4VCgo/commit/c9552999a022a73b6355002ceaeff5ca42889d73))

## [0.31.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.30.1...v0.31.0) (2026-10-05)


### ⚠ BREAKING CHANGES

* **deps:** FAPIgo's own breaking changes since v0.48.1 reach integrators who use its packages beside OID4VCgo, e.g. an issuer's Authorization Server or resource verifier. Among them: server.RegisteredAttesterKeys needs Keys, a keys.AttesterKeySource of the attesters' own keys (keys.StaticAttesterKeys); resource.Config needs Assurance; production assurance refuses loopback http issuers and endpoints and needs a hardened CIBA notifier; prompt=login is enforced at CompleteAuthorization; and a federation Resolve Response is trusted only from the named resolver. See FAPIgo's CHANGELOG.

### Features

* **dcql:** add SDJWTVCQuery, MdocQuery and KeyPath ([b509fea](https://github.com/IDFoundry/OID4VCgo/commit/b509fea0b97ef1a49f61ac1a980799b21a72d935))
* **verifier:** allow issuer clock skew on presented credentials ([bbad51f](https://github.com/IDFoundry/OID4VCgo/commit/bbad51fe5a97c121a70f2d250b864b12266a9a65))


### Bug Fixes

* **deps:** pin FAPIgo v0.50.0 ([a52a260](https://github.com/IDFoundry/OID4VCgo/commit/a52a2600395d83335d32861bd53e49928006293d), [6710083](https://github.com/IDFoundry/OID4VCgo/commit/6710083349e4d46e5036cae803d3f604390067d6))
* **haip:** declare the recommendations with public types ([5da504e](https://github.com/IDFoundry/OID4VCgo/commit/5da504ec7295abea58c5daea6b0317a9c1337325))
* name only public types in exported declarations ([deb3ad3](https://github.com/IDFoundry/OID4VCgo/commit/deb3ad30fd2c56a7bf265af6135678701db93e94))
* **verifier:** don't present a refused answer as the holder's doing ([dd4e608](https://github.com/IDFoundry/OID4VCgo/commit/dd4e60825e548918d59efecff431b01411257605))

## [0.30.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.30.0...v0.30.1) (2026-10-04)


### Bug Fixes

* **wallet:** allow a minute of issuer clock skew on received credentials ([9672adb](https://github.com/IDFoundry/OID4VCgo/commit/9672adb679f05e952abbdcc02301a2bf57355563))

## [0.30.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.29.0...v0.30.0) (2026-10-04)


### ⚠ BREAKING CHANGES

* **walletflow:** a walletflow.Wallet outside Development no longer reaches issuers, Authorization Servers or Verifiers at private, loopback or link-local addresses, or follows redirects, by default; set Dependencies.HTTP to a client that does if a deployment needs it. Presentation.Respond can return ErrLinkable.
* **issuer:** issuer.PreAuthorizedCodeStore.Consume takes a fourth argument, maxAttempts (0 or less: no limit), and must invalidate the code and return issuer.ErrTooManyTxCodeAttempts, without comparing, once the code has maxAttempts wrong guesses, and invalidate it when a wrong guess reaches maxAttempts, atomically with the comparison. Custom store implementations need updating; issuertest's contract covers it.
* **dcql:** Query.Validate (and so the verifier and wallet) refuses a dc+sd-jwt Credential Query without vct_values and an mso_mdoc one without doctype_value; NewSDJWTVCMeta and NewMdocMeta refuse empty input.
* **registration:** Verify requires the registrar's iss to be a URI SAN of its signing certificate: reissue registrar certificates with one.
* Certificate chains with a nil root pool, or a CA certificate as the leaf, no longer verify.
* **verifier:** New under AssuranceProduction requires Dependencies.Random to be crypto/rand.Reader; Transactions.Begin requires a browser binding of at least 16 bytes; VerifiedCredential.StatusListRef returns an error for an mdoc whose status is only an identifier list.

### Features

* **verifier:** add ClientIDForCertificate, and check carried registrations ([d1afd1e](https://github.com/IDFoundry/OID4VCgo/commit/d1afd1edc8663cab6d5663e5887386cad5b4951b))


### Bug Fixes

* bound the demo's public state, and hide the offer code until revealed ([6441298](https://github.com/IDFoundry/OID4VCgo/commit/6441298018753ae95324d7d6f7ded7cca853554d))
* harden trust anchors, DCQL types, registrar trust and status checks ([3d38e88](https://github.com/IDFoundry/OID4VCgo/commit/3d38e88271b37947de7a29cc93e30424afc5b2d9))
* **issuer:** bound tx_code guesses atomically, and tighten the endpoints ([1f90d73](https://github.com/IDFoundry/OID4VCgo/commit/1f90d735d41065a5c7753c090d9947058238e011))
* **walletflow:** recheck linkability at Respond, and harden the default client ([05f0c03](https://github.com/IDFoundry/OID4VCgo/commit/05f0c03fd9032b274bb9cce1ee711fde6ad76fc4))

## [0.29.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.28.0...v0.29.0) (2026-10-04)


### ⚠ BREAKING CHANGES

* **deps:** FAPIgo's Server.RevokeToken returns (TokenRevocationResult, error) instead of error. Code built on this version of OID4VCgo that calls fapigo/server's RevokeToken itself must take the result, or discard it with _, err := srv.RevokeToken(...) (FAPIgo's UPGRADING.md, v0.48.0).

### Features

* carry and check verifier registrations in verifier_info ([93fc83a](https://github.com/IDFoundry/OID4VCgo/commit/93fc83a27413e2b04833665198b4d4ca6644ce53))
* **wallet:** ErrUntrustedVerifier for a request from an untrusted Verifier ([7495d50](https://github.com/IDFoundry/OID4VCgo/commit/7495d50b73431ffa83985acd1dfa02cc753c324f))


### Bug Fixes

* **deps:** pin FAPIgo v0.48.1 ([fe3dec3](https://github.com/IDFoundry/OID4VCgo/commit/fe3dec3dde6822d70d31489667c6cd9f07e31fbd), [7b0002a](https://github.com/IDFoundry/OID4VCgo/commit/7b0002a3a7ae74768c139a211e4360cbb9a93277))

## [0.28.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.27.0...v0.28.0) (2026-10-04)


### Features

* **walletflow:** choose credential copies per presentation or per verifier ([321785a](https://github.com/IDFoundry/OID4VCgo/commit/321785a39ff60d5c4856c90f840856687152a156))
* **walletflow:** report when presentations of a credential can be linked ([3f7a42e](https://github.com/IDFoundry/OID4VCgo/commit/3f7a42ee96536d8c53b398e89af19517cb390ec3))
* **walletflow:** reuse the least-shown copy once every copy has been presented ([0743641](https://github.com/IDFoundry/OID4VCgo/commit/0743641a05fcf6ae48eb8aa084f3a7ad774a8bbb))


## [0.27.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.26.0...v0.27.0) (2026-10-04)


### ⚠ BREAKING CHANGES

* **deps:** an Authorization Server built on fapigo/server now refuses to redeem a refresh token issued to an attested client unless the refresh request's Client Attestation is for the same instance key: invalid_grant, "refresh_token was issued to another client instance". A wallet must keep the instance key it received the refresh token with, and refresh with it, as walletflow does. Refresh tokens issued before this version have no recorded key and stay redeemable.

### Features

* **issuer:** let a pre-authorized code's Token Response carry a refresh token ([4d2c461](https://github.com/IDFoundry/OID4VCgo/commit/4d2c461278da2cfb02b2bd48f500387c13fa5ccf))
* **walletflow:** refresh a credential's copies with a refresh token ([0c6ccc2](https://github.com/IDFoundry/OID4VCgo/commit/0c6ccc27534fb116aa0c21be59b11287b784d402))
* **walletflow:** refresh credentials received with a pre-authorized code ([9e2b110](https://github.com/IDFoundry/OID4VCgo/commit/9e2b110445ce9a770fbd2b289a871eb1346551af))
* **walletflow:** revoke a refresh token when its last credential is deleted ([6f3ce24](https://github.com/IDFoundry/OID4VCgo/commit/6f3ce243fb38b05af60b6abb65ea9508af3e57bf))
* **wallet:** read a pre-authorized code Token Response's refresh token ([6ad3cd4](https://github.com/IDFoundry/OID4VCgo/commit/6ad3cd4e7363fbae1b08f1707283a93c8b2750d6))
* **wallet:** read an Authorization Server's revocation endpoint ([2d69e72](https://github.com/IDFoundry/OID4VCgo/commit/2d69e720da90f06f80069e65416c27aa7d6e3187))


### Bug Fixes

* **dcql:** let credential sets that share a query each take one option ([db9afce](https://github.com/IDFoundry/OID4VCgo/commit/db9afce275578835c091dbc1b7c2824b1c7abe13))
* **deps:** pin FAPIgo v0.47.0, binding refresh tokens to the wallet instance key ([102690b](https://github.com/IDFoundry/OID4VCgo/commit/102690b5301c5b6e055ca36974a231952cc4137b))
* **issuer:** keep the pre-authorized Token Response out of caches ([ff12994](https://github.com/IDFoundry/OID4VCgo/commit/ff12994eb49120624776286353e67795d32e4b3d))
* **walletflow:** serialize credential changes, and check refresh grants ([6813e8d](https://github.com/IDFoundry/OID4VCgo/commit/6813e8d13c24d2766989d835126782522692da8a))

## [0.26.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.25.0...v0.26.0) (2026-10-03)


### ⚠ BREAKING CHANGES

* **mobile:** ABI version 8. Candidates is replaced by Queries, and Preview and Respond take a selection object instead of an array of credential IDs. In Swift, candidates becomes queries, and preview(credentialIDs:) and respond(credentialIDs:) become preview(selection:) and respond(selection:); call defaultSelection() for the former nil.
* **walletflow:** Presentation.Candidates and the Candidates type are replaced by Queries and Query (QueryID becomes ID). Preview and Respond take a Selection instead of []string: pass walletflow.Selection{queryID: {credentialID}} for each query answered. Where nil let the request choose, pass p.DefaultSelection(ctx).

### Features

* **dcql:** check which credential queries a response answers ([a1eea1e](https://github.com/IDFoundry/OID4VCgo/commit/a1eea1ef11e82298a4b297cfb0b0ae472c5f1c48))
* **mobile:** choose a presentation by selection (ABI 8) ([052c66e](https://github.com/IDFoundry/OID4VCgo/commit/052c66e61611a9183c4940b8da5b67268032df1b))
* **walletflow:** present exactly the application's selection ([7eaeba2](https://github.com/IDFoundry/OID4VCgo/commit/7eaeba2d4f762df0624e5385cabf00e7172f1874))
* **wallet:** validate and present a selection exactly ([67ce687](https://github.com/IDFoundry/OID4VCgo/commit/67ce6878e58fbc160a3ea42b4aa466297221fb15))


### Bug Fixes

* **verifier:** refuse a response that answers what the query didn't ask ([bc3aedd](https://github.com/IDFoundry/OID4VCgo/commit/bc3aedd5f189e4acdc1f18ab38b4c0f7cc1b226b))
* **wallet:** refuse a selection that answers two alternatives ([b84b6ae](https://github.com/IDFoundry/OID4VCgo/commit/b84b6aef39dcde1d16c52a18acff34fd04220ccc))

## [0.25.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.24.0...v0.25.0) (2026-10-03)


### Features

* **walletflow:** add session-oriented wallet orchestration ([32a522a](https://github.com/IDFoundry/OID4VCgo/commit/32a522a10593b875361a7a0ce94c92c768ea42b0))
* **walletflow:** add walletflowtest, an in-process HAIP issuer for wallet tests ([39db564](https://github.com/IDFoundry/OID4VCgo/commit/39db5643cd25442213ac7e033f8abeef8467f5a0))
* **wallet:** report an issued credential's expiry and status list ([20aca69](https://github.com/IDFoundry/OID4VCgo/commit/20aca691a0235d9f08880afdcf3f5a1e2c127ad9))


### Bug Fixes

* **deps:** pin FAPIgo v0.46.0 ([b1ed1d8](https://github.com/IDFoundry/OID4VCgo/commit/b1ed1d85c38247c58e307583258f5609e3de1bc3))
* **verifier:** answer a Wallet's error response with 200 ([0bf23c2](https://github.com/IDFoundry/OID4VCgo/commit/0bf23c2e7d18dd985df57725976fec8f9f73f1ed))
* **wallet:** add PlanPreAuthorizedCode, refusing an unlisted Authorization Server ([7b06ab8](https://github.com/IDFoundry/OID4VCgo/commit/7b06ab87b4ac533951a230959c46c50409c7be44))

## [0.24.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.23.0...v0.24.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* **deps:** FAPIgo v0.43.0's breaking changes since v0.41.0 reach deployments using fapigo directly alongside OID4VCgo, including those pairing issuer with a fapigo/server.Server. Server: a malformed max_age is rejected at PAR, and an authentication older than the requested max_age gets login_required; a client sending authorization_details must list every type in storage.RegisteredClientConfig.AuthorizationDetailsTypes (an empty list allows none), or the request is refused with invalid_authorization_details; server.TrustedClientCAs requires Roots and Revocation. Resource: resource.Verifier answers a Bearer request without a client certificate with 401 invalid_token (was 400 invalid_request). Client: a custom storage.SessionStore must persist NewSession.Record and return it as ConsumedSession.Record; a fapigo/client requesting max_age refuses an ID token without auth_time or older than max_age. See FAPIgo's UPGRADING.md for v0.42.0 and v0.43.0.
* **wallet:** ParseAuthorizationRequest and FetchAuthorizationRequest refuse a Request Object whose response_type isn't vp_token or whose response_mode isn't direct_post.jwt, and ParseDCAPIRequest one whose response_type isn't vp_token.

### Features

* redeem the pre-authorized_code grant with the Authorization Server's client and DPoP checks ([762c6ab](https://github.com/IDFoundry/OID4VCgo/commit/762c6ab55fe633ba9afa40a28baac5c9f20ec96a))


### Bug Fixes

* **conformance:** deliver the multiple-clients module's second Credential Offer ([73e56cc](https://github.com/IDFoundry/OID4VCgo/commit/73e56ccd1c3c1f39f494de9870a7d76f8af064c3))
* **deps:** pin FAPIgo v0.43.0 ([1a670f4](https://github.com/IDFoundry/OID4VCgo/commit/1a670f4754266dea11fdafdffa156332d619672d))
* read resource and authorization requests with FAPIgo's HTTP helpers ([6e9f798](https://github.com/IDFoundry/OID4VCgo/commit/6e9f79827cdd03782c260e7c39e752b5ec5e265a))
* **wallet:** require vp_token and the flow's Response Mode, and parse DC API requests with the Wallet's trust ([08dabe5](https://github.com/IDFoundry/OID4VCgo/commit/08dabe56c3f35ebccb065c63fede146e3201437e))

## [0.23.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.22.0...v0.23.0) (2026-10-01)


### ⚠ BREAKING CHANGES

* **wallet:** X5CVerifierRoots refuses a Request Object whose x5c includes the trust anchor its chain verifies to; a Verifier must send its leaf, and any intermediates, only.
* **wallet:** X5CVerifierRoots refuses a Verifier leaf that is a CA certificate or whose key usage doesn't include digitalSignature.
* **statuslist:** Fetcher ignores HTTP.Transport's Proxy (and so HTTPS_PROXY) unless AllowProxy is set, and refuses an HTTP.Transport that isn't an *http.Transport unless UncheckedTransport is set. A status list host that only resolves to a special-purpose address is refused.
* **issuer:** a Credential Request with CredentialRequest.Defer set needs AuthorizedRequest.Subject; set it from the verified access token's subject (issuer/fapiresource does). DeferredTransactionRecord gains Subject, which a persistent DeferredTransactionStore must save. Limits.DeferredIssuancePollInterval below one second is refused.

### Features

* **wallet:** verify a DC API request against the platform's origin ([19d43df](https://github.com/IDFoundry/OID4VCgo/commit/19d43df41173e74d39571f7433ed2e77a796e18a))


### Bug Fixes

* **issuer:** bind a deferred transaction to the token's subject ([4d2da01](https://github.com/IDFoundry/OID4VCgo/commit/4d2da01f0a528548ada4a1786330b5f95604ee2b))
* **issuer:** check a deferred poll before Resolve, and deny an unsent deferral ([c6151c0](https://github.com/IDFoundry/OID4VCgo/commit/c6151c00936e0910b5318e02807d3692807c79c7))
* **statuslist:** close the gaps in Fetcher's address policy ([be802ec](https://github.com/IDFoundry/OID4VCgo/commit/be802ec7fdb9741bcf824f68988a239926cd87e4))
* tie the demo's outcome to the committed answer, and correct misleading docs ([cbbcb74](https://github.com/IDFoundry/OID4VCgo/commit/cbbcb7415e28aec3fd50d643403be395c51ccd5b))
* **wallet:** refuse a Verifier x5c chain that includes its trust anchor ([73cd8f7](https://github.com/IDFoundry/OID4VCgo/commit/73cd8f78a938f450cca3142486e52ca23e211b7d))
* **wallet:** refuse Verifier certificates that can't sign requests ([0d54682](https://github.com/IDFoundry/OID4VCgo/commit/0d546822ca6be0791d6fba836613c7f1383444cd))

## [0.22.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.21.0...v0.22.0) (2026-09-30)


### ⚠ BREAKING CHANGES

* **deps:** Wallets calling the Credential, Deferred Credential or Notification Endpoints now get 401 with no error code for a request without credentials (was 400 invalid_request), and invalid_dpop_proof for an invalid DPoP proof at any endpoint (was invalid_request or invalid_token); FAPIgo v0.41.0's own federation changes are breaking too, for code using fapigo/federation directly — see FAPIgo's UPGRADING.md.
* **issuer:** issuer.DeferredTransactionStore adds Create and Update (atomic per transaction), and under AssuranceProduction must declare AtomicConsume as well as Durable; issuer.Limits.DeferredTransactionLifetime is required when Endpoints.DeferredCredential is set; DeferredCredentialHandler takes a DeferredCredentialHandlerConfig (embed your ProtectedEndpointConfig).
* **statuslist:** statuslist.Fetcher refuses non-public addresses — set AllowLoopback or AllowPrivate for a status list served on loopback or a private network; statuslist.Publisher's methods now have pointer receivers, so serve &statuslist.Publisher{...}, and call Invalidate after a status changes to serve it at once.
* **verifier:** verifier.Transactions.Begin refuses an empty browserBinding for cross-device requests too; pass a secret you keep (a cookie, or a server-side value) and give the same one to Lookup.
* **statuslist:** statuslist.StatusListRef.Idx is a uint64 (was int); convert an int index with uint64(idx), and copy it to or from credential/mdoc.StatusListRef.Idx directly.

### Features

* **haip:** recommend a HAIP Authorization Server config and Wallet client ([9cbb57d](https://github.com/IDFoundry/OID4VCgo/commit/9cbb57d25ac24c250b99c86714212cdc2c609c84))
* **issuer:** defer issuance from a Credential Request ([9e11bbd](https://github.com/IDFoundry/OID4VCgo/commit/9e11bbd8897909956baed99ee64baf6a37d99e86))
* **issuer:** serve the Deferred Credential and Notification Endpoints ([10ea446](https://github.com/IDFoundry/OID4VCgo/commit/10ea446bf44c56be2f2b625631cf25cd567867d2))


### Bug Fixes

* bind client-less tokens explicitly, and skip signing keys for encryption ([7818d33](https://github.com/IDFoundry/OID4VCgo/commit/7818d33866cea40bdef41780dd809964bf728cd1))
* **conformance:** check the Verifier's certificate chain in conformance-wallet-vp ([92766de](https://github.com/IDFoundry/OID4VCgo/commit/92766de7e1f56ba4e8c2a6f691bf68cd66f0467c))
* **deps:** build resource verifiers with fapigo/serverresource ([dfeb4df](https://github.com/IDFoundry/OID4VCgo/commit/dfeb4df909037188a810d3e3857aa2563c9a5976))
* **deps:** pin FAPIgo v0.41.0 ([9efcf84](https://github.com/IDFoundry/OID4VCgo/commit/9efcf84bf02c78efcdf8a30bb5e1f0d73921baf8))
* **statuslist:** fetch only public addresses, and cache served tokens ([#309](https://github.com/IDFoundry/OID4VCgo/issues/309)) ([7657dc9](https://github.com/IDFoundry/OID4VCgo/commit/7657dc9fb637c9dd84f5530b466f93e8558629b2))
* **statuslist:** make StatusListRef.Idx a uint64 ([91bfe83](https://github.com/IDFoundry/OID4VCgo/commit/91bfe8390f8de922d2d56cd547055872027a5dd8))
* **verifier:** require a binding for every presentation request ([69a59e9](https://github.com/IDFoundry/OID4VCgo/commit/69a59e946ec7de2e1b66ecb3a3e037907e027607))

## [0.21.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.20.0...v0.21.0) (2026-09-30)


### ⚠ BREAKING CHANGES

* **deps:** wallet.Config.Fetch.AllowLoopbackHTTP no longer admits a hostname that merely resolves to a loopback address — list it in Fetch.AllowedLoopbackHosts; for https-only local setups use Fetch.AllowLoopbackHosts, which AssuranceProduction refuses.
* import github.com/idfoundry/oid4vcgo/issuer/issuertest for issuer.Test…StoreContract / issuer.Test…CheckerContract, and github.com/idfoundry/oid4vcgo/verifier/verifiertest for verifier.TestX5CTrustContract, TestX5ChainTrustContract, ContractCA, ContractLeaf and ContractSelfSignedLeaf; the names are unchanged.

### Features

* **issuer:** let callers build error responses with NewError ([59d0c3f](https://github.com/IDFoundry/OID4VCgo/commit/59d0c3fa345ea6ba9a95f0f638ca60d5fba2e217))
* **issuer:** serve the Credential Endpoint with CredentialHandler ([a4b5a81](https://github.com/IDFoundry/OID4VCgo/commit/a4b5a810bee5f5309febeb0337d683c3e87de393))
* **statuslist:** fetch and check a credential's status in one call ([e80efa4](https://github.com/IDFoundry/OID4VCgo/commit/e80efa40f0704bb59ec840c99e03be1eda25cf47))
* **statuslist:** serve a Status List Token with Publisher ([c03b101](https://github.com/IDFoundry/OID4VCgo/commit/c03b101a53f2ad1686708f0bef71ee60ba2135f1))
* **verifier:** track presentation requests end to end with Transactions ([82cbf0d](https://github.com/IDFoundry/OID4VCgo/commit/82cbf0dc50c2d46ead86fa77f9f3f631f9c35264))
* **wallet:** choose credential encryption from metadata, and answer a request in one call ([27f9cbb](https://github.com/IDFoundry/OID4VCgo/commit/27f9cbb8dbfdf1e4e997905bddc4ea018418aa43))


### Bug Fixes

* **deps:** pin FAPIgo v0.40.0 ([69bed71](https://github.com/IDFoundry/OID4VCgo/commit/69bed71cd9d60cbbeb207c80a4b23ddec5287418))
* give the JOSE and COSE algorithm types public names ([1328ca0](https://github.com/IDFoundry/OID4VCgo/commit/1328ca09b4824cb34f2daec731110dac4384385b))
* move the reusable contract tests out of issuer and verifier ([dafcdf9](https://github.com/IDFoundry/OID4VCgo/commit/dafcdf9a34432be25d1e73d98b7032fac469bcd9))
* **storage:** copy transactions in and out of VerifierTransactionStore ([bcc40ba](https://github.com/IDFoundry/OID4VCgo/commit/bcc40bac000762465240cffe2df6f2d780b7e1fa))

## [0.20.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.19.0...v0.20.0) (2026-09-28)


### ⚠ BREAKING CHANGES

* **deps:** deployments that use fapigo directly alongside this library move to fapigo v0.39.0; its release notes list the migrations (server.GrantedAuthorization.ApprovedIdentityClaims for OIDC claims-parameter identity claims, renamed ReturnInTokenClaims extensions, backchannelhttp.New Config.Transport, federation VerifyTrustMark accreditation and Limits.MaxAuthorityHints).
* **issuer:** a production issuer (AssuranceProduction) that supports the "attestation" proof type must configure Config.Endpoints.Nonce.
* **issuer:** a production issuer (AssuranceProduction) using the pre-authorized code flow must set Config.PreAuthorizedCodeClientAuthentication: issuer.AnonymousPreAuthorizedCode{}.
* **dcql:** verifier.VerifyResponse refuses a dcql.AKITrustedAuthoritiesChecker without Roots when a credential query declares trusted_authorities. Set Roots to the issuer key resolver's trust anchors, e.g. `dcql.AKITrustedAuthoritiesChecker{Roots: issuerRoots}`.

### Bug Fixes

* **dcql:** match aki trusted_authorities against the verified chain ([4127dce](https://github.com/IDFoundry/OID4VCgo/commit/4127dce95c925df9d086ab7cce6c1095312798b1))
* **deps:** pin fapigo v0.39.0 ([27e1639](https://github.com/IDFoundry/OID4VCgo/commit/27e1639785b9248251b88af8849edefe6e11477d))
* enforce dcql claim values, refuse unrequested zip, document error responses ([dc3bb91](https://github.com/IDFoundry/OID4VCgo/commit/dc3bb91facfa59c588b5ce85329ccb8cec492987))
* **issuer:** add x5c leaf policies and require a nonce for attestation proofs ([5150f6c](https://github.com/IDFoundry/OID4VCgo/commit/5150f6cdc15fe60b8e66a2de0d2ac8a5b8c0e7d4))
* **issuer:** check key attestation status; refuse anonymous pre-auth in haip validation ([d1ba241](https://github.com/IDFoundry/OID4VCgo/commit/d1ba2416658d44981d12cda57dc6ffccc45dadf7))
* **issuer:** require an explicit choice to redeem pre-authorized codes anonymously ([4716dfa](https://github.com/IDFoundry/OID4VCgo/commit/4716dfa0b1cea5aba7fb3a3d1f9f91db12d202a0))

## [0.19.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.18.0...v0.19.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **deps:** OID4VCgo now requires fapigo v0.38.0, which brings three breaking changes. (1) server.X5CAttesterChain needs IssuerBinding set: a deployment pairing issuer with a fapigo/server that uses X5CAttesterChain must choose AttesterIssuerInCertificate (its attester certificates name the attester as a URI SAN) or AttesterIssuerByTrustAnchors (only when each client's anchors belong to its attester alone). (2) A Wallet driving fapigo/client's Authorization Code Flow must keep the SessionHandle BeginAuthorization returns with the user agent it sends to the authorization URL (e.g. an HttpOnly, Secure, SameSite=Lax cookie) and pass it back as AuthorizationCallback.Session; a callback without it is rejected. (3) Under AssuranceProduction, fapigo requires declared key custody and crypto/rand.Reader as Dependencies.Random. For the passport-vdc demo: a wallet-provider.pem created before this must be regenerated, and walletapp.Approver now takes and returns the session handle.
* sdjwtvc.TypeMetadata no longer has Schema, SchemaURI or SchemaURIIntegrity; TypeDisplay.Lang and ClaimDisplay.Lang are renamed Locale and serialize as "locale"; TypeMetadata.Validate requires VCT.
* **issuer:** a CredentialConfiguration without a Scope is issued only through an authorization_details grant naming it. A credential_configuration_id request is refused when the token's authorization detail for it carries credential_identifiers. issuer.New requires Limits.MaxProofAge when Endpoints.Nonce is not set. A DeferredTransactionStore's Invalidate must fail when the transaction_id is unknown or already invalidated (storage.DeferredTransactionStore does).

### Features

* **issuer:** vary each credential of a batch, and refuse a shared status reference ([c59d9e9](https://github.com/IDFoundry/OID4VCgo/commit/c59d9e9d43ad6729484fd0f62c5364150a2ee8a5))
* **statuslist:** issue and check Status List Tokens by their certificate chain ([15156a6](https://github.com/IDFoundry/OID4VCgo/commit/15156a6a3bd6ec578505f1899cef0a17a31d4fdc))
* target the SD-JWT VC and Token Status List versions HAIP 1.0 pins ([3ccd963](https://github.com/IDFoundry/OID4VCgo/commit/3ccd9632a4ba5b933f3f95fa9abbeb22f15d779a))


### Bug Fixes

* **deps:** require fapigo v0.36.0, which binds attester certificates to the client's attester ([d32afcf](https://github.com/IDFoundry/OID4VCgo/commit/d32afcfbc6327b00a324be8dec0cc2125e6a3939))
* **deps:** require fapigo v0.38.0, which binds authorization callbacks to their user agent ([dce26f7](https://github.com/IDFoundry/OID4VCgo/commit/dce26f7146b4d70ae3c7ab413b51b1ca9b2fa57a))
* **issuer:** authorize every credential configuration, and enforce key attestation levels and proof freshness ([21b770d](https://github.com/IDFoundry/OID4VCgo/commit/21b770d2be6f28797aee00285ed4d530db4a6fbd))
* **issuer:** bind credentials to the proof key's public members only, and refuse private JWKs ([f386714](https://github.com/IDFoundry/OID4VCgo/commit/f38671490fe22b79f448aae945ebef337a88adc2))
* **sdjwtvc:** refuse disclosable registered claims and empty key binding expectations, and reject COSE crit ([9810adc](https://github.com/IDFoundry/OID4VCgo/commit/9810adc4e59810746199744e0f4ba9453705c291))
* **verifier:** refuse compressed responses, surface mdoc status, and apply Now to mdoc validity ([978d45c](https://github.com/IDFoundry/OID4VCgo/commit/978d45cdd76d367486167f96b138d8553f6f362b))
* **wallet:** never follow redirects when submitting a direct_post response ([#265](https://github.com/IDFoundry/OID4VCgo/issues/265)) ([23cdd7f](https://github.com/IDFoundry/OID4VCgo/commit/23cdd7f6bfc0aae1e0271d7daf3de3082c11ab5d))
* **wallet:** require an https response_uri and harden verifier-supplied text ([658302d](https://github.com/IDFoundry/OID4VCgo/commit/658302dfff6e24fd421a3cba34d469f094f2bef2))

## [0.18.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.17.0...v0.18.0) (2026-09-27)


### Features

* export JWE encryption parameters and enforce required response encryption ([7ead104](https://github.com/IDFoundry/OID4VCgo/commit/7ead104f98c13a8093dc2b10547fc8edaae26e29))
* parse credential requests, and helpers for attested keys, AKI trusted authorities and type metadata ([5e8f75b](https://github.com/IDFoundry/OID4VCgo/commit/5e8f75b7cbe0988376b17016741daac2143a60bd))
* verify issued credentials, submit direct_post responses and route them by kid ([668e2a3](https://github.com/IDFoundry/OID4VCgo/commit/668e2a33e41db8de0aa2e35de6a4ce0dd8c5efcc))
* **wallet:** plan authorizations, preview presentations and parse request links ([3ff14d1](https://github.com/IDFoundry/OID4VCgo/commit/3ff14d139bf1cdbbe3c918cb7afd73ddef173ab8))

## [0.17.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.16.0...v0.17.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* OID4VCgo now requires fapigo v0.34.0, so a fapigo/server built with Config.AttestationBasedClientAuthentication must set Dependencies.AttesterTrust — server.X5CAttesterChain for HAIP's certificate-based trust, or server.RegisteredAttesterKeys{} for the previous kid lookup.

### Features

* trust Wallet Attestations by their x5c certificate chain ([658ebc6](https://github.com/IDFoundry/OID4VCgo/commit/658ebc6ac1e5d2dc37e8bd7db1f414eac16641b4))

## [0.16.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.15.0...v0.16.0) (2026-09-27)


### ⚠ BREAKING CHANGES

* **wallet:** ParseAuthorizationRequestParams.VerifierTrust is required, and FetchAuthorizationRequest fails unless Config.VerifierTrust is set. Set wallet.X5CVerifierRoots{Roots: ...} with the trust anchors of the Verifiers to accept, or wallet.NoVerifierTrust{} to opt out explicitly (not permitted under AssuranceProduction).

### Bug Fixes

* **issuer:** check a key attestation's alg against the advertised algorithms ([b63942b](https://github.com/IDFoundry/OID4VCgo/commit/b63942bad69e7a9ae36200325b3784f8dbd19679))
* **wallet:** check fetched metadata names the issuer it was fetched for ([c033727](https://github.com/IDFoundry/OID4VCgo/commit/c03372739d2b6640dd58b9441960a77faea84e3b))
* **wallet:** validate the Verifier's certificate trust chain ([4641672](https://github.com/IDFoundry/OID4VCgo/commit/464167289e8112b014dc25f9564d0372246cfcfa))

## [0.15.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.14.0...v0.15.0) (2026-09-26)


### Features

* support authorization_servers in Credential Issuer Metadata ([0497eea](https://github.com/IDFoundry/OID4VCgo/commit/0497eeae35f708a0871d576aad5ee2e51135d580))


### Bug Fixes

* **wallet:** discover a loopback http issuer when AllowLoopbackHTTP is set ([c9115f4](https://github.com/IDFoundry/OID4VCgo/commit/c9115f4dac26ad2b5e1426c07f18d3afe950a52e))

## [0.14.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.13.0...v0.14.0) (2026-09-26)


### Features

* **attestation:** add IssueWalletAttestation for Wallet Providers ([#228](https://github.com/IDFoundry/OID4VCgo/issues/228)) ([4c93453](https://github.com/IDFoundry/OID4VCgo/commit/4c93453051363c3e2b8de265cf7216c6c2e64868))
* **issuer:** carry a pre-authorized_code's subject into the access token ([f56f49a](https://github.com/IDFoundry/OID4VCgo/commit/f56f49a8a9d4237e3cc65c56fb859e5efeb00539))


### Bug Fixes

* **sdjwtvc:** bound a whole SD-JWT presentation at 1 MiB, not 64 KiB ([1a59a75](https://github.com/IDFoundry/OID4VCgo/commit/1a59a7505e1ad527765d5339b8086c56940f6502))

## [0.13.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.12.0...v0.13.0) (2026-09-26)


### ⚠ BREAKING CHANGES

* verifier.Config and wallet.Config gain a required Assurance field; New rejects the zero value. Existing callers must set verifier.AssuranceDevelopment/wallet.AssuranceDevelopment to keep their current behavior, or the Production level to opt into the new checks. A custom SDJWTVCIssuerKeyResolver/MdocIssuerKeyResolver used with a production verifier must implement verifier.KeySourceAssurance.

### Features

* add a required AssuranceLevel to verifier.New and wallet.New ([e4afefc](https://github.com/IDFoundry/OID4VCgo/commit/e4afefc7b11431dc5503b2a1d5fb635154d3e96d))


### Bug Fixes

* **conformance:** don't fill the screenshot placeholder for wallet-VP error-response modules ([9ee66bf](https://github.com/IDFoundry/OID4VCgo/commit/9ee66bf49690ac646d32de82fa7aa806e75d2909))
* **conformance:** serve wallet-VP's authorize result page as text/plain ([66bff90](https://github.com/IDFoundry/OID4VCgo/commit/66bff90f7280dcdf707a69f49572dc6a80f6ecf7))
* **conformance:** stop warning on the 4 negative tests that correctly return 200 ([e4f945a](https://github.com/IDFoundry/OID4VCgo/commit/e4f945a9e3a02a2fa5ee7d0c71a5feb47c49b983))
* **sdjwtvc:** bound IssueOptions.Decoys ([99f626e](https://github.com/IDFoundry/OID4VCgo/commit/99f626eee17b9b6d2b03850bdd43855e7a907af0))

## [0.12.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.11.1...v0.12.0) (2026-09-23)


### Features

* add wallet.BuildDirectPostErrorResponse, use it once a request is verified legitimate ([f8460a5](https://github.com/IDFoundry/OID4VCgo/commit/f8460a535c6dbd2e7aa2290ac7d3e2dac367ea4d))
* send an OID4VP error response for redirect_uri/transaction_data violations too ([f58fc28](https://github.com/IDFoundry/OID4VCgo/commit/f58fc284ce633df4d66629d9874f6988e6a0fa18))


### Bug Fixes

* **wallet-vp:** support every ISO 18013-5 mandatory mDL claim in the mdoc fixture ([3809710](https://github.com/IDFoundry/OID4VCgo/commit/38097103ca07a0f696d7c418665fda611fa70006))
* **wallet:** send access_denied, not invalid_request, for an unsatisfiable DCQL query ([36c297f](https://github.com/IDFoundry/OID4VCgo/commit/36c297f99507878e9cacd271cd8df88715835ff9))

## [0.11.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.11.0...v0.11.1) (2026-09-22)


### Bug Fixes

* close two mdoc gaps found live against the public OIDF suite ([680bbc0](https://github.com/IDFoundry/OID4VCgo/commit/680bbc0d415abeded3f5956e8db8a7683af4d6ab))

## [0.11.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.10.0...v0.11.0) (2026-09-21)


### ⚠ BREAKING CHANGES

* enforce ISO/IEC 18013-5's docType, ValidityInfo, KeyAuthorizations, and X5Chain constraints in credential/mdoc
* replace ClientIDIntentionallyUnset bool with a typed ClientIdentity opt-out ([#182](https://github.com/IDFoundry/OID4VCgo/issues/182))

### Features

* **issuer:** extend AssuranceProduction to cover key-source resolvers ([1f9fee1](https://github.com/IDFoundry/OID4VCgo/commit/1f9fee1e3be0fba055687825b405499db620a87b))


### Bug Fixes

* enforce ISO/IEC 18013-5's docType, ValidityInfo, KeyAuthorizations, and X5Chain constraints in credential/mdoc ([43759bc](https://github.com/IDFoundry/OID4VCgo/commit/43759bc7e7f6a6be3c4fb20bf30dbfffb1184934))
* **issuer:** derive ProofBindingKeyResolver's algorithm from the resolved key, not the untrusted header ([c57c7c2](https://github.com/IDFoundry/OID4VCgo/commit/c57c7c24e6edb06b90ae3f3e465bcd960be4874f))
* **issuer:** reject a CredentialConfiguration whose Format disagrees with VCT/DocType/alg-form ([5dcad51](https://github.com/IDFoundry/OID4VCgo/commit/5dcad5124cfe7737cc7005fab85343554b367eda))
* **issuer:** reject a negative Config.Limits.MaxDPoPClockSkew ([#185](https://github.com/IDFoundry/OID4VCgo/issues/185)) ([7a025c0](https://github.com/IDFoundry/OID4VCgo/commit/7a025c0429d843c41880ed663e427c2cbf5401eb))
* **lint:** remove unused assuredProofBindingKeyResolver test wrapper ([c68a657](https://github.com/IDFoundry/OID4VCgo/commit/c68a657002320b16943fcc793e98dbefdea5f7ac))
* **mdoc:** bound UnmarshalIssuerSigned/UnmarshalDeviceSigned to MaxBytes ([#188](https://github.com/IDFoundry/OID4VCgo/issues/188)) ([3b957d8](https://github.com/IDFoundry/OID4VCgo/commit/3b957d8dc2defc3e93785394d09de6e25ef3c50f))
* replace ClientIDIntentionallyUnset bool with a typed ClientIdentity opt-out ([#182](https://github.com/IDFoundry/OID4VCgo/issues/182)) ([1a0ec0e](https://github.com/IDFoundry/OID4VCgo/commit/1a0ec0e4cb61eca7d2be581d81c249dbd51ff784))
* **sdjwtvc:** avoid a panic when Issue's signer/certificate check meets a non-comparable Signer ([3c9dfcf](https://github.com/IDFoundry/OID4VCgo/commit/3c9dfcf716d69ec4c756ba789895c1ba59f85a03))
* validate every jose.Alg/cose.Alg signing config field against the supported set ([5e3b7a4](https://github.com/IDFoundry/OID4VCgo/commit/5e3b7a43dfc268893adce29a7a152f2607fb3535))
* **verifier:** distinguish Wallet-caused failures from caller mistakes with a typed error ([62c6349](https://github.com/IDFoundry/OID4VCgo/commit/62c6349a2dc29e930f5fc8610bf3d26b4981884b))

## [0.10.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.9.0...v0.10.0) (2026-09-21)


### Features

* **wallet:** add FetchAuthorizationRequest for OID4VP §5.10 request_uri fetch ([1ab9359](https://github.com/IDFoundry/OID4VCgo/commit/1ab9359ebddb2062d3098431574d308f0cbb8ee9))


### Bug Fixes

* **ci:** stop masking Issuer container-startup failures too; fix likely root cause ([f6206de](https://github.com/IDFoundry/OID4VCgo/commit/f6206de1edc4a040955ba210190225f885d2c1db))
* **ci:** stop the conformance workflow from reporting false success ([401788e](https://github.com/IDFoundry/OID4VCgo/commit/401788e59d44cda656726632c94cf54ffafc94ae))
* cmd/conformance-verifier never actually verified anything; fix a real core-library bug found along the way ([#172](https://github.com/IDFoundry/OID4VCgo/issues/172)) ([1c51d0b](https://github.com/IDFoundry/OID4VCgo/commit/1c51d0bf10ae39060c279b1d3b35a8a310bed140))
* **lint:** silence gosec G306 on the three intentional 0o644 writes ([97cd4c3](https://github.com/IDFoundry/OID4VCgo/commit/97cd4c3ea91cf35fdeb4b25b673dc7f0df5e5f73))

## [0.9.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.8.0...v0.9.0) (2026-09-20)


### Features

* close OID4VP Verifier and Wallet iso_mdl certification gaps ([095fd1b](https://github.com/IDFoundry/OID4VCgo/commit/095fd1b4147c40b49b7368b68715fa76c1f12041))


### Bug Fixes

* dedupe remaining wallet_initiated literal flagged by SonarCloud ([3d09af5](https://github.com/IDFoundry/OID4VCgo/commit/3d09af53c64a4ae3d504d06a4a400c8dd82d09e3))
* extract shared driving-loop/summary logic to kill new duplication ([34d7fbf](https://github.com/IDFoundry/OID4VCgo/commit/34d7fbf8cd949e2931bf58319d79a28b1e774704))
* reduce duplicated string literals in run-all.sh's matrix output ([5a074f8](https://github.com/IDFoundry/OID4VCgo/commit/5a074f8d980a48f3fa4a23883ee8c5af7376ba79))

## [0.8.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.7.2...v0.8.0) (2026-09-20)


### Features

* add issuer-initiated Credential Offer support, close Issuer-HAIP module gap ([51b0c23](https://github.com/IDFoundry/OID4VCgo/commit/51b0c2324f4e77acf5139500cb20ef20c76bb976))


### Bug Fixes

* scope issuer-initiated Credential Offer to VCI-specific modules; add certification profile matrix to run-all.sh ([4e9f6cc](https://github.com/IDFoundry/OID4VCgo/commit/4e9f6cc7495c4361cabdc904f93826e5140965cb))

## [0.7.2](https://github.com/IDFoundry/OID4VCgo/compare/v0.7.1...v0.7.2) (2026-09-20)


### Bug Fixes

* fully flatten decryptedCredentialRequest's nested anonymous structs ([9c3e3d3](https://github.com/IDFoundry/OID4VCgo/commit/9c3e3d33a24aba7b2fc7b2d071c3c5ca1498c57a))
* resolve 36 safe SonarCloud findings (S1192/S107/S7682/S7688/S8193/S8205/S8239/S978) ([143e450](https://github.com/IDFoundry/OID4VCgo/commit/143e450ef22e775186bdfe143efbb9a336678cdd))

## [0.7.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.7.0...v0.7.1) (2026-09-19)


### Bug Fixes

* **cose:** bound COSE_Sign1/COSE_Sign1_Tagged/COSE_Mac0 parse size ([7f5bdd8](https://github.com/IDFoundry/OID4VCgo/commit/7f5bdd8ad6410640a9e2ed1e5da9247b7dec8846))
* **issuer:** bound consecutive wrong tx_code guesses per pre-authorized_code ([abef2d4](https://github.com/IDFoundry/OID4VCgo/commit/abef2d4929f4ccf1242580c4b8938d753972f87b))
* **issuer:** cap attestation attested_keys fan-out at batch_size ([0d3f1e6](https://github.com/IDFoundry/OID4VCgo/commit/0d3f1e69069ecc293dac9f69f6ca1a20d7036b85))
* **sdjwtvc:** bound ResolveDisclosures's own recursion depth ([ea9ce43](https://github.com/IDFoundry/OID4VCgo/commit/ea9ce43349e91ff776735d2ac8142f4136061d7b))
* **verifier:** bound Presentation/DeviceResponse parse size regardless of flow ([da50891](https://github.com/IDFoundry/OID4VCgo/commit/da5089112afe6c4e6a9d7e029bc20c93381e04c2))
* **verifier:** enforce a Credential Query's own trusted_authorities restriction ([e87f0cb](https://github.com/IDFoundry/OID4VCgo/commit/e87f0cb43fdad5daecf37176e042e471aa499f0a))
* **wallet:** bound Issuer response body reads in credential/notification calls ([925d355](https://github.com/IDFoundry/OID4VCgo/commit/925d3550486e786e647cfd21e26fa691690ce51f))
* **wallet:** enforce a Credential Query's own trusted_authorities restriction ([f7af874](https://github.com/IDFoundry/OID4VCgo/commit/f7af8748cc7cc7f0feb7af138487e1366893fdfa))

## [0.7.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.6.0...v0.7.0) (2026-09-19)


### Features

* **issuer,verifier:** add exported contract test suites ([da5190b](https://github.com/IDFoundry/OID4VCgo/commit/da5190ba7acb000a04d5e53d50ff014930490ad2))
* **issuer:** add a production-assurance gate for store dependencies ([e658eae](https://github.com/IDFoundry/OID4VCgo/commit/e658eae92da263cb0a2900315e4a7e4c5528e0bd))
* **issuer:** add structured audit logging, required under AssuranceProduction ([571986a](https://github.com/IDFoundry/OID4VCgo/commit/571986abbaef4adf2fe987dffe677307f494e962))
* **issuer:** add X5C reference implementations for the two attestation/proof-binding resolvers ([68d9a9f](https://github.com/IDFoundry/OID4VCgo/commit/68d9a9f75d7c3de4ab54ea44c8ac2884bc279642))
* **sdjwtvc:** require an explicit KeyBindingRequirement, not a bare bool ([3f02a26](https://github.com/IDFoundry/OID4VCgo/commit/3f02a260d3a4ad3b1bf7fbb007bedcb65f04054c))


### Bug Fixes

* **issuer:** require an explicit decision on AuthorizedRequest.ClientID ([ac33b85](https://github.com/IDFoundry/OID4VCgo/commit/ac33b8506b9c8ca8f8310b823d42243ac91e3982))
* **jose,jwe:** bound pre-verification input size and reject unrecognized crit ([388b713](https://github.com/IDFoundry/OID4VCgo/commit/388b71360cd1d199df2ac5ce67157b7037ddc0ea))
* **sdjwtvc,verifier:** require MaxKeyBindingAge whenever key binding is required ([6df09dd](https://github.com/IDFoundry/OID4VCgo/commit/6df09dd137de533a4f28f5015108a8a631c8dda6))
* **verifier:** dedup leaf-cert-chain verification onto a shared helper ([2a60204](https://github.com/IDFoundry/OID4VCgo/commit/2a6020419510f48196191e3f9fcb976261870f26))

## [0.6.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.5.0...v0.6.0) (2026-09-18)


### Features

* **jwk:** add private-key marshaling and JWK Set entry support ([6ed2d07](https://github.com/IDFoundry/OID4VCgo/commit/6ed2d07991bde708776230e462175cb091cb9c88))
* **verifier:** add VPFormatsSupported typed builders ([3ba7e6a](https://github.com/IDFoundry/OID4VCgo/commit/3ba7e6a1cf6d8f587049b6fe98c42a842eed2c83))


### Bug Fixes

* **cmd:** dedup PEM parsing onto internal/conformancecert helpers ([f605b2e](https://github.com/IDFoundry/OID4VCgo/commit/f605b2ee479d569a7c68d0be2ac4653a14411924))
* **conformancecert:** dedup Client Attestation JWT minting ([07cca8e](https://github.com/IDFoundry/OID4VCgo/commit/07cca8e55d476618b62535183c3b4f594ffd1b60))

## [0.5.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.4.1...v0.5.0) (2026-09-18)


### Features

* add Go native fuzz testing, daily CI job (mirrors FAPIgo) ([45a3174](https://github.com/IDFoundry/OID4VCgo/commit/45a3174d60444468e0d89f29637c18753c712ca7))
* extend fuzz coverage to remaining untrusted-input boundaries ([3853363](https://github.com/IDFoundry/OID4VCgo/commit/3853363ca42edbf30c207efee3673257bd06710c))


### Bug Fixes

* dedupe exp/nbf test setup, fixing SonarCloud's duplication gate ([09d9016](https://github.com/IDFoundry/OID4VCgo/commit/09d90168da21ae5ad82bcbe1ba47aa8aceaf0b88))
* dedupe fuzz seed setup, fixing SonarCloud's duplication gate ([38f82bb](https://github.com/IDFoundry/OID4VCgo/commit/38f82bbdc70088119d10b8bd7ce5697da4202786))
* **issuer:** don't burn a pre-authorized_code on a wrong tx_code ([29b77be](https://github.com/IDFoundry/OID4VCgo/commit/29b77be0043f06c09be2bb9b43b2b1b42cb9e09e))
* **issuer:** don't burn a pre-authorized_code on a wrong tx_code ([49581ad](https://github.com/IDFoundry/OID4VCgo/commit/49581ad9ae96846b5a3a907fec9ed7218d3af80c))
* **jwe:** bound inflate against a pre-authentication decompression bomb ([52a3094](https://github.com/IDFoundry/OID4VCgo/commit/52a3094acede85846869e7158524971fbfd7514b))
* **sdjwtvc,oid4vpmdoc:** check exp/nbf, require thumbprint binding ([df87bc1](https://github.com/IDFoundry/OID4VCgo/commit/df87bc17aa5b88ab7a919a1d987e4146dc0e868e))
* **sdjwtvc,oid4vpmdoc:** check exp/nbf, require thumbprint binding ([74b0688](https://github.com/IDFoundry/OID4VCgo/commit/74b0688b6ffd9166486d675adeddf78b6324e0f0))
* **statuslist:** bound decompress against a decompression bomb ([cd727ab](https://github.com/IDFoundry/OID4VCgo/commit/cd727abf77ed7f7ab4de95b1f66a1d2569a5b553))
* **verifier:** stop panicking on non-stdlib signers, document footguns ([f196dc0](https://github.com/IDFoundry/OID4VCgo/commit/f196dc032f6590524af6c043210ea91235bdea2a))
* **verifier:** stop panicking on non-stdlib signers, document footguns ([f404ea5](https://github.com/IDFoundry/OID4VCgo/commit/f404ea5951cfd8b2b3459013e82f98f27078c2e0))
* **wallet:** fail closed instead of over-disclosing on unsupported claim paths ([a4e8237](https://github.com/IDFoundry/OID4VCgo/commit/a4e82372cd53a93bcc27f5dbb121af5b34557eda))
* **wallet:** fail closed instead of over-disclosing on unsupported claim paths ([61c1d6d](https://github.com/IDFoundry/OID4VCgo/commit/61c1d6de1a69351380b6aed756b7fd947cd124b7))

## [0.4.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.4.0...v0.4.1) (2026-09-18)


### Bug Fixes

* **conformance-wallet:** thread issuer_state through the FAPI2SP battery too, not just VCIWalletTest* ([a5ea01a](https://github.com/IDFoundry/OID4VCgo/commit/a5ea01a9bf05a10a842f28554c1888bff3a3b2de))
* **mdoc:** make Document Signer/IACA certificates ISO/IEC 18013-5 Annex B compliant ([1edbfdd](https://github.com/IDFoundry/OID4VCgo/commit/1edbfdd26fec225430aeb197d21adea930f2e36b))
* **wallet:** skip unusable keys in client_metadata.jwks instead of only trying keys[0] ([b885240](https://github.com/IDFoundry/OID4VCgo/commit/b88524059f2e654518816a8ecd5612d5367bc4fa))

## [0.4.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.3.0...v0.4.0) (2026-09-18)


### Features

* **conformance:** automate Wallet-VP's alternate-happy-flow fragment relay ([3b79e00](https://github.com/IDFoundry/OID4VCgo/commit/3b79e00d7448761e60dd03ae3ab018475821a83d))
* **conformance:** close both Issuer base-plan negative-test skips ([aedd45f](https://github.com/IDFoundry/OID4VCgo/commit/aedd45f9b8faacf37ad3d36e6c5fc75af6ed6a43))


### Bug Fixes

* **conformance:** share one revocation store between the AS and resource verifier ([8f03150](https://github.com/IDFoundry/OID4VCgo/commit/8f0315063b3c71059ab894522aea6847c5c090c5))

## [0.3.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.2.0...v0.3.0) (2026-09-18)


### Features

* **conformance:** issue a real mDL, not a PID-shaped doctype, in the Issuer's mdoc battery ([721965a](https://github.com/IDFoundry/OID4VCgo/commit/721965ae47c6849c2089402edf43a2999f1153cc))

## [0.2.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.1.0...v0.2.0) (2026-09-17)


### Features

* **conformance-verifier:** add mso_mdoc DCQL query support, close the iso_mdl certification gap ([8f4f432](https://github.com/IDFoundry/OID4VCgo/commit/8f4f432a6e64e5d77a0d419ab9a87f080924bb27))
* **conformance-verifier:** add run-sdjwt-modules, closing the last "driven by hand" gap ([844c961](https://github.com/IDFoundry/OID4VCgo/commit/844c9614dd5b1779f1ccd1626ad84a2eb5bc955d))
* **conformance-wallet-vp:** add run-modules, closing 13 of 14 driven-by-hand modules ([e33dffd](https://github.com/IDFoundry/OID4VCgo/commit/e33dffdd93dadac3eeb8fa519c52a31374726ddb))
* **conformance:** add run-all.sh, one command for every conformance run ([d64906f](https://github.com/IDFoundry/OID4VCgo/commit/d64906fcb5d7df4e1748de7c6d1a615bc1c8bc34))
* **conformance:** automate Notification Endpoint HAIP coverage, clarify Deferred Credential Endpoint ([5d75d14](https://github.com/IDFoundry/OID4VCgo/commit/5d75d1463062443c13d4312971a3ffa85efce3ce))
* **issuer:** add SignMetadataJWS/MetadataHandler, promoted from conformance-issuer ([3a4f64e](https://github.com/IDFoundry/OID4VCgo/commit/3a4f64efe62be67d185122f9c6a0c607bfece71b))
* **issuer:** add SignMetadataJWS/MetadataHandler, promoted from conformance-issuer ([35ddf4b](https://github.com/IDFoundry/OID4VCgo/commit/35ddf4beb3e386555013e5168e93ea60226e86e8))
* **issuer:** add WriteError, promoted from conformance-issuer ([8de6ada](https://github.com/IDFoundry/OID4VCgo/commit/8de6adab6a5e220aacacc6f3dbb02a13aeed7fcc))
* **issuer:** add WriteError, promoted from conformance-issuer ([27d8a77](https://github.com/IDFoundry/OID4VCgo/commit/27d8a77da336eda34f7c719577caa34d599bf133))
* **oid4vci,wallet:** move Credential Issuer Metadata to oid4vci, add wallet fetch ([5a3ccca](https://github.com/IDFoundry/OID4VCgo/commit/5a3ccca0b44ab0111e0ab4e850920708f4a31215))
* **oid4vci,wallet:** move Credential Issuer Metadata to oid4vci, add wallet fetch ([f926e3d](https://github.com/IDFoundry/OID4VCgo/commit/f926e3d441715ee7a7b3faae84b4c231499e3bc8))
* **wallet:** add OID4VP request/response support, promoted from conformance-wallet-vp ([8ece88f](https://github.com/IDFoundry/OID4VCgo/commit/8ece88fb7e0cd26570ac04edbf7cf75a67e0d80e))
* **wallet:** add OID4VP request/response support, promoted from conformance-wallet-vp ([b39bf37](https://github.com/IDFoundry/OID4VCgo/commit/b39bf37fa9df48d97b71a274516c6692efbb56d4))


### Bug Fixes

* extract Flags/Setup into conformanceverifier, closing remaining duplication ([4e84eb5](https://github.com/IDFoundry/OID4VCgo/commit/4e84eb518c7d640d5930b129cc7d9dfeee9d13b4))
* extract internal/conformanceverifier, eliminating duplication between the two driver scripts ([3eb7084](https://github.com/IDFoundry/OID4VCgo/commit/3eb70847cfdea11d82717ca8ad33070ff11460f5))
* suppress another gosec G101 false positive after the Setup refactor ([9dc4e49](https://github.com/IDFoundry/OID4VCgo/commit/9dc4e49d8a9216929c96cdbda7e025c765bd07f3))

## 0.1.0 (2026-09-17)


### Features

* add dcql and verifier packages (OID4VP Authorization Request, Phase 1) ([92fba43](https://github.com/IDFoundry/OID4VCgo/commit/92fba4360c46b72592913dd52e24c01972c8d3d7))
* add haip profile layer for issuer ([cd9bcff](https://github.com/IDFoundry/OID4VCgo/commit/cd9bcffb249a1f37d5531ecd899bdb84ca4e0866))
* add haip.RecommendedWalletConfig ([aeed512](https://github.com/IDFoundry/OID4VCgo/commit/aeed512320d8b9d6d24cd03fcbb0b21edf2e4630))
* add in-memory reference implementations of issuer's stores ([6280b44](https://github.com/IDFoundry/OID4VCgo/commit/6280b443eee92e46eb5de67877832de616041ae2))
* add internal/dpop (RFC 9449 verification) and JWK.Thumbprint (RFC 7638) ([dafb32e](https://github.com/IDFoundry/OID4VCgo/commit/dafb32ed536c25b36777b7643628d0edfd086e46))
* add internal/jwe, a JWE primitive for OID4VCI 1.0 §10 encryption ([f28ec2c](https://github.com/IDFoundry/OID4VCgo/commit/f28ec2ce6461cf57c5d78d4aaf3bf2fd555c08f0))
* add issuer.ExchangePreAuthorizedCode Token Endpoint ([ac9caba](https://github.com/IDFoundry/OID4VCgo/commit/ac9caba08fbb71e56fadd68350d0ea6c8ab9aa81))
* add mso_mdoc OID4VP presentation support (verifier + wallet) ([1fa8acd](https://github.com/IDFoundry/OID4VCgo/commit/1fa8acd8ac7a08d0ca8487a04952777d62dff18d))
* add mso_mdoc OID4VP presentation support (verifier + wallet) ([0b87ee9](https://github.com/IDFoundry/OID4VCgo/commit/0b87ee9db017c133549f9abc9919f72fc3e86b58))
* add shared issuer_state extension + issuer/fapigo-server integration recipe ([62a4050](https://github.com/IDFoundry/OID4VCgo/commit/62a405036ae82396ff441c2344e2eb684d308018))
* add verifier response parsing and dc+sd-jwt response verification (Phase 2a) ([802b97f](https://github.com/IDFoundry/OID4VCgo/commit/802b97fb9bb3cfe6e64074ae786c6b973a50035c))
* add wallet (OID4VCI client role): offer resolution + Credential Request/Response ([8baf1b9](https://github.com/IDFoundry/OID4VCgo/commit/8baf1b92d70492f8412768f7735dea7e54ecbfc0))
* add wallet-side OID4VP presentation for dc+sd-jwt ([8c88425](https://github.com/IDFoundry/OID4VCgo/commit/8c88425c326e1796a6f479cfa7033977e6fbbc23))
* add wallet's attestation proof type ([86e20ba](https://github.com/IDFoundry/OID4VCgo/commit/86e20ba3a4cfdc48208cae654c9ec94396d06056))
* add wallet's Deferred Credential and Notification Endpoint clients ([5b0f911](https://github.com/IDFoundry/OID4VCgo/commit/5b0f91171a22b52a29a506842e068961892894af))
* add wallet's Pre-Authorized Code Flow Token Request ([9b97576](https://github.com/IDFoundry/OID4VCgo/commit/9b97576cec58966e18cfc9c08e565cc720506f2c))
* **cmd/conformance-issuer,cmd/conformance-wallet:** drive mso_mdoc credential format ([c79f820](https://github.com/IDFoundry/OID4VCgo/commit/c79f82092497f39c8a2cf76ddca62ccc423d946b))
* **cmd/conformance-wallet,conformance/issuer:** drive the base non-HAIP OID4VCI plans ([69651a4](https://github.com/IDFoundry/OID4VCgo/commit/69651a43f5ba7646956b3e5c3ea3695261856159))
* **cmd/conformance-wallet:** add OID4VCI Wallet role conformance binary ([03f8611](https://github.com/IDFoundry/OID4VCgo/commit/03f8611bbf8b00e5b410eb3c9ff86376eed2dd5c))
* **cmd/conformance-wallet:** drive deferred and encrypted issuance-mode crossings ([7d3b9a3](https://github.com/IDFoundry/OID4VCgo/commit/7d3b9a3df110c20586edd0668f64b306128667d7))
* **cmd/conformance-wallet:** drive HAIP Key Attestation (Appendix D) ([1165f84](https://github.com/IDFoundry/OID4VCgo/commit/1165f84a04b3939ebe5939754f483adaa3ee42ea))
* **cmd/conformance-wallet:** drive the HAIP plan's generic FAPI2SP client battery ([8f9370d](https://github.com/IDFoundry/OID4VCgo/commit/8f9370d71d7f437cae205655897f09fd9298bb3b))
* **cmd/conformance-wallet:** drive the issuer_initiated flow variant ([994807a](https://github.com/IDFoundry/OID4VCgo/commit/994807af1a5c02050e68ee44ab2deeb8b473233a))
* **conformance-issuer:** serve RFC 8414 well-known path, add client2 ([f3e7228](https://github.com/IDFoundry/OID4VCgo/commit/f3e7228a7b91e674c5ab29192eaa7b66788e0756))
* **conformance/issuer:** drive the generic FAPI2SP battery (42 modules) ([300dc34](https://github.com/IDFoundry/OID4VCgo/commit/300dc34d83b5416dbb3cd2cced0ff2a689a98e49))
* **conformance:** set exp on issued credentials ([f638626](https://github.com/IDFoundry/OID4VCgo/commit/f638626a743b0e10ac44a5e1128322ed9db7e41d))
* **conformance:** stand up cmd/conformance-issuer (OID4VCI HAIP Issuer role) ([a0e3e17](https://github.com/IDFoundry/OID4VCgo/commit/a0e3e1776a8ff8f6a25c3d13c0dea9db3e9b006a))
* **conformance:** stand up cmd/conformance-issuer (OID4VCI HAIP Issuer role) ([0133bbb](https://github.com/IDFoundry/OID4VCgo/commit/0133bbbb0a53af330274f529dd75fb45dc2e27da))
* **conformance:** stand up cmd/conformance-verifier (OID4VP HAIP Verifier role) ([68bc135](https://github.com/IDFoundry/OID4VCgo/commit/68bc135e00c9d0ac315255a0bc133e838d163109))
* **conformance:** stand up cmd/conformance-wallet-vp (OID4VP HAIP Wallet role) ([24befdb](https://github.com/IDFoundry/OID4VCgo/commit/24befdba5ac08097cd85c1fdfd5b1b737fc5ea15))
* **conformance:** support Credential Request/Response Encryption (OID4VCI §10) ([ffab73a](https://github.com/IDFoundry/OID4VCgo/commit/ffab73a6b8b1f92f4b7254d5ce136bba079ded7d))
* **conformance:** support request_uri_method=post for Verifier and Wallet-VP roles ([8d3f46c](https://github.com/IDFoundry/OID4VCgo/commit/8d3f46c1aa047961923b4b5b246c32f21c33333a))
* **conformance:** support signed Credential Issuer Metadata (OID4VCI §12.2.3) ([40fed4f](https://github.com/IDFoundry/OID4VCgo/commit/40fed4f14857a6f9d982ebcc229ce991f9b9bb94))
* **conformance:** wire up batch credential issuance for the Issuer role ([38e4c07](https://github.com/IDFoundry/OID4VCgo/commit/38e4c07483f71481238095d01540d85b47882d35))
* **credential/mdoc:** wire MSO revocation status_list into the MSO ([b5d0907](https://github.com/IDFoundry/OID4VCgo/commit/b5d0907bf0f0ac15f52dbb7e9ef032192ce4433c))
* **dcql:** implement §6.4.1 claim_sets alternative-claim-combination rule ([202d9d9](https://github.com/IDFoundry/OID4VCgo/commit/202d9d97e878a8ab7655bb56aa39fa7e16c31902))
* **dcql:** implement §6.4.1 claim_sets alternative-claim-combination rule ([0a45111](https://github.com/IDFoundry/OID4VCgo/commit/0a45111d0497407b84006350e7c67fafb165b7fe))
* **haip:** add RecommendedVerifierConfig ([b49421e](https://github.com/IDFoundry/OID4VCgo/commit/b49421e1fc0ae797df46c9e913f0767226009e37))
* **haip:** add RecommendedVerifierConfig ([8a202b1](https://github.com/IDFoundry/OID4VCgo/commit/8a202b1f9ce8dc9cbead3f72ab7ac7896d7650d0))
* handle a Credential Response that defers issuance at first response ([8195cc4](https://github.com/IDFoundry/OID4VCgo/commit/8195cc4b93fbf764265fbcd3110f5743e85fa975))
* implement §6.1 multiple selection rule ([1d57337](https://github.com/IDFoundry/OID4VCgo/commit/1d573373208ecbecc846c5fd9cd8a556115549c3))
* implement §6.1 multiple selection rule ([082332f](https://github.com/IDFoundry/OID4VCgo/commit/082332f1eb1f879229f8a7c41a72f0080ea21020))
* implement §6.4.2 credential_sets selection rules ([7c8e46a](https://github.com/IDFoundry/OID4VCgo/commit/7c8e46a013ecfc55bc0aba1e5f8545f37ac83825))
* implement §6.4.2 credential_sets selection rules ([419313c](https://github.com/IDFoundry/OID4VCgo/commit/419313c9bf9d75dbbed415948feeb2640989ca9f))
* implement credential/mdoc issuer-side (IssuerSigned, MSO, IssuerAuth) ([9978625](https://github.com/IDFoundry/OID4VCgo/commit/99786250ce58879f1a0a26433be8a72dcdbe12d5))
* implement DeviceSigned for mdoc presentation ([6434616](https://github.com/IDFoundry/OID4VCgo/commit/64346167a3ae416669d55a8da8f12b1ac1a64c7d))
* implement internal/cose COSE_Sign1 signer/verifier ([c264aee](https://github.com/IDFoundry/OID4VCgo/commit/c264aeef5f167b72fd4038da5b826644bac0a568))
* implement issuer Nonce Endpoint and a first Metadata shape ([1c0d6cf](https://github.com/IDFoundry/OID4VCgo/commit/1c0d6cf03a751cd1a701b566e09b628c02a1ed98))
* implement Key Attestation and Wallet Attestation extra claims ([8401ae5](https://github.com/IDFoundry/OID4VCgo/commit/8401ae5bba4bb286293d04917123a0e12d5f45fe))
* implement SD-JWT VC (draft-11) credential format ([edd3b00](https://github.com/IDFoundry/OID4VCgo/commit/edd3b00b7485581434959cad3b80296fe91f0834))
* implement statuslist CWT/COSE encoding ([5034c9a](https://github.com/IDFoundry/OID4VCgo/commit/5034c9a165b581461f50aff11c546e587d202e46))
* implement the Credential Offer (OID4VCI 1.0 §4) ([c957220](https://github.com/IDFoundry/OID4VCgo/commit/c95722083b5c38767605b81c1808a25b79c91e3c))
* implement the Deferred Credential Endpoint (OID4VCI 1.0 §9) ([fafa369](https://github.com/IDFoundry/OID4VCgo/commit/fafa369112145064220b3c3192b3bf4d6aaec301))
* implement the Notification Endpoint (OID4VCI 1.0 §11) ([b4e0e11](https://github.com/IDFoundry/OID4VCgo/commit/b4e0e11feba24bfdd14e2d53a68ffcd46f87405e))
* implement Token Status List (draft-12) ([0c764c2](https://github.com/IDFoundry/OID4VCgo/commit/0c764c25676c07621aba7955896340e40dc17fd1))
* implement wallet minimal-disclosure trimming for dc+sd-jwt ([46a56ae](https://github.com/IDFoundry/OID4VCgo/commit/46a56ae37667c5ccf4a70e9e8af89c11de9b23bf))
* **issuer:** add batch_credential_issuance, display, credential_metadata ([e49b45c](https://github.com/IDFoundry/OID4VCgo/commit/e49b45cd51dde9fb8fd18de50ae4727b0ab0b85f))
* **issuer:** add RFC 9449 §8 DPoP nonce-challenge support for ExchangePreAuthorizedCode ([b71015c](https://github.com/IDFoundry/OID4VCgo/commit/b71015c4ac5fcfb0f27dd3ce5c772134952aeeb2))
* **issuer:** enforce batch_credential_issuance's own batch_size ([9facb1c](https://github.com/IDFoundry/OID4VCgo/commit/9facb1c7eb6750665ad7c408307d38b3425710a4))
* **issuer:** mint credential_identifier/authorization_details in ExchangePreAuthorizedCode ([d050958](https://github.com/IDFoundry/OID4VCgo/commit/d050958bcb9ddb8c62286cd38943892ceb5ffe11))
* **issuer:** support credential_identifier-based Credential Requests ([5f82caa](https://github.com/IDFoundry/OID4VCgo/commit/5f82caa379f6d72183cda9523a933f67b1ff6004))
* **mdoc:** support the identifier_list MSO revocation mechanism (§12.3.6.4) ([4378228](https://github.com/IDFoundry/OID4VCgo/commit/4378228c184be37c56b2a616af03d182fe7d09e9))
* **oid4vpmdoc:** add BuildDCAPISessionTranscriptBytes for the DC API flow ([a50247c](https://github.com/IDFoundry/OID4VCgo/commit/a50247cb7d94fe8443d1bf1eea5b4ef97feaf4a1))
* **sdjwtvc:** add x5c header support to Issue ([62c209c](https://github.com/IDFoundry/OID4VCgo/commit/62c209c27e17b04e07ce0f563ec2704455d6b472))
* **storage:** add in-memory DPoPNonceStore and DPoPReplayChecker ([e091824](https://github.com/IDFoundry/OID4VCgo/commit/e091824e29a8b53c5997d29cb15be2faf7465206))
* support kid/x5c-conveyed binding keys for the jwt proof type ([c92c4ec](https://github.com/IDFoundry/OID4VCgo/commit/c92c4ec0dd5cec4e0c2d72e276b6c779b08a1ddb))
* **verifier:** add BuildDCAPIAuthorizationRequest for the DC API flow ([2a12d00](https://github.com/IDFoundry/OID4VCgo/commit/2a12d004d884c7c8ea73249d279dea944e5d6c4e))
* **verifier:** add X5ChainIssuerKeyResolver for mso_mdoc ([1768728](https://github.com/IDFoundry/OID4VCgo/commit/1768728e24deff70430da5560a21abf70becd541))
* **verifier:** add X5CIssuerKeyResolver, a real x5c chain validator ([576fdfc](https://github.com/IDFoundry/OID4VCgo/commit/576fdfc65d8ac44b3f04e0114db3cb1900982364))
* **verifier:** make VerifyResponse accept DC API responses ([5f48256](https://github.com/IDFoundry/OID4VCgo/commit/5f4825689bed7d4c3866ef7a6f0fe144f7a86fdd))
* **wallet,cmd/conformance-wallet:** drive Key Attestation nested in a jwt-type proof (Appendix D.1) ([2545317](https://github.com/IDFoundry/OID4VCgo/commit/25453174dbdc3573bc0ff95bdfae3200376b8888))
* **wallet,credential/mdoc:** add mso_mdoc minimal-disclosure trimming ([a0ad545](https://github.com/IDFoundry/OID4VCgo/commit/a0ad545ae8b6581db5129b7f0a503e85ef2bb167))
* **wallet:** build DC API presentations ([43fde55](https://github.com/IDFoundry/OID4VCgo/commit/43fde5599f87e4287ccdf7823feabec452d40d24))
* **wallet:** prove Wallet Attestation client auth end-to-end ([716c9b0](https://github.com/IDFoundry/OID4VCgo/commit/716c9b0d172e0d5ba6074c0ab235d36733eecbce))
* **wallet:** support credential_identifier in CredentialRequest ([f2d51f2](https://github.com/IDFoundry/OID4VCgo/commit/f2d51f252e2ab824db09fca0628bd161f6b65230))
* wire credential/mdoc and credential/sdjwtvc into issuer's Credential Endpoint ([29f0db7](https://github.com/IDFoundry/OID4VCgo/commit/29f0db70c1cf67a906205367c14863fb9de3267b))
* wire internal/jwe into issuer for §10 Encrypted Requests/Responses ([d545e20](https://github.com/IDFoundry/OID4VCgo/commit/d545e20a79d6061280368fcc63eb10a5821ab0a3))
* wire internal/jwe into wallet for §10 Encrypted Requests/Responses ([d85d1b0](https://github.com/IDFoundry/OID4VCgo/commit/d85d1b016e98423320747f5a3058651c6f4223a5))
* wire issuer Metadata for the mso_mdoc credential format ([1f7c168](https://github.com/IDFoundry/OID4VCgo/commit/1f7c168345a1e696fbd9f5ff5506d3cdd131684f))
* wire the Authorization Code Flow's OID4VCI-specific request shape ([895ac82](https://github.com/IDFoundry/OID4VCgo/commit/895ac82ed21c053461353239e5e3432535040a2e))


### Bug Fixes

* address CI failures in internal/cose ([298e712](https://github.com/IDFoundry/OID4VCgo/commit/298e7129f9e259e4dce42aa25b4cc2c77a54a417))
* **conformance-issuer:** configure FAPI-RW TLS cipher suites ([7d78113](https://github.com/IDFoundry/OID4VCgo/commit/7d78113f0ee60d7766737a957744090c1de10bd2))
* **conformance-wallet-vp:** reject redirect_uri and transaction_data ([08383c5](https://github.com/IDFoundry/OID4VCgo/commit/08383c5f0ae967533539c332246f885c74aef3b3))
* **conformance:** fix three real bugs found by a full PAR-to-credential flow test ([5218cfc](https://github.com/IDFoundry/OID4VCgo/commit/5218cfcccfbe099c9ea54cafee8de8d10fa1fdc3))
* **conformance:** fix three real bugs found by a full PAR-to-credential flow test ([b765734](https://github.com/IDFoundry/OID4VCgo/commit/b765734dcc9344408514634ceaf1f2bf1a279e75))
* **conformance:** round exp to the issuance day to close a linkability gap ([fdd2453](https://github.com/IDFoundry/OID4VCgo/commit/fdd2453646386725e18842bca0da3fadddc4f41d))
* **conformance:** stop clobbering FAPIgo's own conformance-as ports ([a53d069](https://github.com/IDFoundry/OID4VCgo/commit/a53d069eefba25fe9de3bd694158678af74ce1d6))
* consolidate near-duplicate batch-size tests to satisfy SonarCloud ([5ca2e02](https://github.com/IDFoundry/OID4VCgo/commit/5ca2e021f192713b72d401efcef98db3bffdb26f))
* extract shared config-writing test helper, further cut duplication ([ea71ed5](https://github.com/IDFoundry/OID4VCgo/commit/ea71ed5a5c88dfb0e2f3a78aac9e39dcbccfb38e))
* extract shared conformancecert package, reduce test complexity ([e678be6](https://github.com/IDFoundry/OID4VCgo/commit/e678be60d36da63d7792f73c8231d0cb1ff7f0ac))
* extract shared present-and-verify tail to satisfy SonarCloud ([f23362e](https://github.com/IDFoundry/OID4VCgo/commit/f23362eee0a6a40579ebd4517e46652ab80875b9))
* **jwe:** incorporate apu/apv into the Concat KDF on decrypt ([70b1eaa](https://github.com/IDFoundry/OID4VCgo/commit/70b1eaa03cc22b1ae9fac9841c26369c494b936f))
* pin the FAPIgo PAR fix, fix issuer's own x5c gap, re-confirm live ([3a4d165](https://github.com/IDFoundry/OID4VCgo/commit/3a4d165edd61ba87183117b6d8b6b900f7e83048))
* reduce test duplication flagged by SonarCloud ([1a88111](https://github.com/IDFoundry/OID4VCgo/commit/1a88111d1ec810a5d14614e11718b70b147086f7))
* stop flipping the last base64url char in the tamper test ([9bd95bb](https://github.com/IDFoundry/OID4VCgo/commit/9bd95bb924ed2e6f73dac6f225e9d89eece33b8f))
* stop overstating identifier_list/status_list as a spec MUST ([7569ed4](https://github.com/IDFoundry/OID4VCgo/commit/7569ed4cfd045e71fd45d0df578195572ff9c876))
* **verifier:** stop calling implemented functionality "not yet" done ([cf41675](https://github.com/IDFoundry/OID4VCgo/commit/cf41675c68a6dbdc46915b2bc51e3fc39f609fc0))
