# Changelog

## [0.56.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.55.0...v0.56.0) (2026-10-28)


### ⚠ BREAKING CHANGES

* **issuer:** issuer.DPoPNonceStore's Consume method is now Lookup, and issuer.DPoPNonceConsumption is now issuer.DPoPNonceLookup. Lookup must leave the record in place, so every lookup of an issued nonce succeeds until it expires; drop records only after their ExpiresAt. Return an error wrapping issuer.ErrDPoPNonceUnknown for an unknown nonce: any other error now fails the request with a 500 rather than a use_dpop_nonce challenge. Run issuertest.TestDPoPNonceStoreContract against your store. Under issuer.AssuranceProduction, an issuer that sets Dependencies.PreAuthorizedCodes without issuer.VerifiedPreAuthorizedCode must set Dependencies.DPoPNonces to a durable store (declaring StoreCapabilities{Durable: true}) with a Limits.DPoPNonceLifetime of at most 15 minutes, or to issuer.NoDPoPNonces{} to keep accepting proofs without a nonce.
* **deps:** resource.NewVerifier and serverresource.NewVerifier require ResourceURLs, and VerifyRequestFromHTTP takes only the request. Under production, the server and the resource verifier each need a DPoP nonce store (or NoDPoPNonces{}), a Clock reading the system time, and lifetimes within FAPIgo's production bounds; server Limits need MaxAccessTokenClaimsBytes. Pre-authorized code refresh tokens issued before this release are refused with invalid_grant, and the wallet receives a new code. RSA keys must use the exponent 65537, and one a wallet or Wallet Provider supplies is at most 4096 bits. Outside Development, walletflow.New refuses a Dependencies.Clock when the wallet receives credentials. See UPGRADING.md and FAPIgo's UPGRADING.md.

### Features

* **statuslist:** let a Publisher choose its form when Accept names neither ([b7c71ae](https://github.com/IDFoundry/OID4VCgo/commit/b7c71aedc7f53ef3206f463a224db009d0f691d8))


### Bug Fixes

* **deps:** pin FAPIgo v0.65.1 ([63d55f7](https://github.com/IDFoundry/OID4VCgo/commit/63d55f7a14255a1e7a381365b1c9dcf052e130d2))
* **issuer:** keep DPoP nonces valid for a time window ([b80049c](https://github.com/IDFoundry/OID4VCgo/commit/b80049c86e1dbe6c4db34ddce1b578b11bc8a4c0))
* **statuslist:** read every Accept line, and refuse an unknown DefaultForm ([de839a4](https://github.com/IDFoundry/OID4VCgo/commit/de839a43220260993921e80e1ce0340e6c96e302))

## [0.55.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.54.0...v0.55.0) (2026-10-27)


### ⚠ BREAKING CHANGES

* **walletflow:** outside Development, set a revocation Checker for each trust role a walletflow.Config uses: IssuerRevocation and StatusRevocation with IssuerRoots or the mdoc roots, IssuerMetadataRevocation with IssuerMetadataRoots, RegistrarRevocation with RegistrarRoots, MdocReaderRevocation with MdocReaderRoots, and Revocation on a wallet.X5CVerifierRoots VerifierTrust. Use a certrevocation.Refresher's Checker(), your own Checker, or certrevocation.NoCheck{} to keep checking nothing. wallet.New under AssuranceProduction requires the same of IssuerMetadataRevocation and X5CVerifierRoots.Revocation. In the mobile libraries, outside development, name each role whose roots are set in "revocation" or in the new "no_revocation_check" (noRevocationCheck in Swift and Kotlin).
* **walletflow:** walletflow.Wallet.CheckStatus records StatusUnknown ("unknown") for an mdoc naming an identifier list, where it used to return the credential with no status: treat it as not known, like a status never checked. The Swift and Kotlin CredentialStatus.Value gain an unknown case: add it to exhaustive switch and when expressions.
* **walletflow:** walletflow.New, and mobile NewWallet (as invalid_input), refuse a Config.RedirectURI / redirect_uri that isn't a private-use scheme in reverse.domain:/path form (com.example.wallet:/callback), loopback http, or in Development https, or that carries a fragment or credentials, even in Development and for a wallet that doesn't receive credentials. Such a wallet could never complete an authenticated issuance; register and configure a redirect URI of that form instead.
* **statuslist:** statuslist.Checker.Check and RequireValid with cwt true refuse a Status List Token without exp or with an unprotected x5chain. A list issued for mdocs must carry both; to check a CWT Status List Token outside ISO/IEC 18013-5, fetch it with Fetcher and call statuslist.CheckCWTX5Chain with the options it needs.
* **identifierlist:** identifierlist.Check and Checker.Check refuse a reference with no Certificate when documentSignerPath is empty. Pass the MSO's IssuerAuth x5chain as verified (VerifiedCredential's IssuerChain, parsed), or, where every CA under the roots may decide every MSO's revocation, set VerifyOptions.UnboundSigner to identifierlist.AnyListSigner or to a policy of your own.
* **issuer:** under issuer.AssuranceProduction, set Revocation on every issuer.X5CAttestationVerifier and issuer.X5CProofBindingKeyResolver in Dependencies: certrevocation.CRLs, such as the one a certrevocation.Refresher's Checker method returns, your own certrevocation.Checker, or certrevocation.NoCheck{} to keep accepting certificates without a revocation check.
* **verifier:** under AssuranceProduction on Linux and other Unix systems, issuer roots built by adding certificates to x509.SystemCertPool() are refused. Build the pool from the credential issuers' own CAs (x509.NewCertPool plus AddCert), not from the system pool.
* **verifier:** X5CIssuerKeyResolver without a LeafPolicy refuses an issuer certificate carrying the mdoc reader authentication extended key usage, or chaining only through intermediates restricted to other roles' purposes. Issue SD-JWT VC issuers their own certificates, or set LeafPolicy (verifier.AnyIssuerLeaf accepts every chain-verified leaf).
* **verifier:** a TransactionStore must persist Transaction.Owner, or Begin and BeginDCAPI fail. Under AssuranceProduction, transactions saved before Owner was recorded can no longer be read: let pending ones expire (TransactionsConfig.Lifetime) before upgrading.
* **mdocdcapi:** BuildRequest refuses an Origin that isn't https or loopback http once normalized, and VerifyResponse refuses a non-loopback http Pending.Origin even under AssuranceDevelopment, or a VerifyParams.Origins entry that isn't an origin. Serve development pages over https or from localhost, and list origins as
* **verifier:** under AssuranceProduction, a TransactionsConfig used for the Digital Credentials API alone (no RequestURIBase) must set Origins, or NewTransactions fails; set them to the origins of the pages that call navigator.credentials.get.
* **deps:** an Authorization Server built on fapigo/server with X5CAttesterChain must set its Revocation at every assurance level, to server.ClientCertificateCRLs for the Wallet Provider CAs' CRLs or to server.NoClientCertificateRevocationCheck{}. Under AssuranceProduction with attestation-based client authentication, Dependencies.ClientAttestationStatus is required: a checker of the attestation's status claim, or server.NoClientAttestationStatusCheck{}. A custom ClientCertificateRevocation must wrap server.ErrCertificateRevoked for a revoked certificate; any other error now answers server_error (500) instead of invalid_client. See FAPIgo's UPGRADING.md, v0.62.0.
* **verifier:** RequireValidStatus refuses a credential with a status reference whose issuer it can't identify: one verified by a custom issuer key resolver that reports no issuer chain, with no iss (SD-JWT VC) or no MSO status Certificate (mdoc). Report the chain (SDJWTVCIssuerChainResolver, MdocIssuerChainResolver), or use RequireValidStatusFrom with a StatusIssuerPolicy, AnyStatusListSigner where every signer under the checker's roots may decide every credential's status. A non-object SD-JWT VC status claim is now an error.
* **verifier:** an SD-JWT VC whose issuer certificate lists only serverAuth, clientAuth, codeSigning, emailProtection, timeStamping or IPsec extended key usages, or lists OCSPSigning at all, is now refused when X5CIssuerKeyResolver.LeafPolicy is unset. Issue issuer certificates without those, or set LeafPolicy to accept the ones yours carry. Under AssuranceProduction, issuer roots must be the issuers' own CAs, not x509.SystemCertPool.
* **verifier:** under AssuranceProduction, set TransactionsConfig.Origins to use BeginDCAPI, and mdocdcapi.VerifyParams.Origins to verify an org-iso-mdoc response, each to the serialized origins of the pages that make Digital Credentials API requests. mdocdcapi.VerifyResponse refuses an http origin outside AssuranceDevelopment.
* **verifier:** a TransactionStore must persist the new Transaction.Owner field; verifiertest's contract now checks it. Transactions instances that share a store and were meant to handle each other's requests must now have the same client_id, response_uri and RequestURIBase, or set the same TransactionsConfig.Scope. Instances sharing all three but applying different policies set a distinct Scope each.
* **certrevocation:** a deployment that pins a leaf certificate, rather than a CA, as a trust anchor and checks it with certrevocation.CRLs now has it refused with ErrNoCurrentCRL unless the issuing CA's certificate is in CRLs.Issuers and a current CRL from that CA is held. Add the CA certificate to CRLs.Issuers, or to the Refresher's Issuers when using Refresher.Checker.
* **issuer:** an AttestationStatusChecker that should deny a pending deferred transaction for a revoked or suspended key attestation must wrap issuer.ErrKeyAttestationRevoked in its error; any other error now leaves the transaction pending (ErrDeferredAttestationStatusUnknown) instead of denying it. Under AssuranceProduction, issuer.New refuses a Limits.NonceLifetime over an hour. haip.ValidateIssuerConfig refuses a scope shared by configurations requiring different key attestations.
* **walletflow:** outside Development, walletflow.New and the mobile NewWallet refuse a RedirectURI that is https, or http to anything but 127.0.0.1 or [::1]. Register and use a private-use URI scheme redirect, such as com.example.wallet:/callback. The mobile libraries report a missing issuer_roots, redirect_uri, verifier_roots or HAIP provider as invalid_input rather than protocol.
* **issuer:** under AssuranceProduction, issuer.New refuses a Credential Configuration whose ProofTypesSupported includes the attestation proof type unless Config.AllowAttestationProofType is set. Take jwt proofs with a key attestation in their key_attestation header instead (haip.RecommendedJWTKeyAttestationProofType), or set the field to keep the attestation proof type. haip.RecommendedIssuerConfig no longer includes the attestation proof type or a jwt proof type without a key attestation. SD-JWT VCs whose Prepare sets no Iss now carry iss set to Config.Issuer.
* **statuslist:** a Status List Token whose ttl is 0 or negative, or whose exp isn't after its iat, is now refused, and a negative VerifyOptions.MaxAge is an error instead of silently turning off freshness checks. verifier.RequireValidStatus, walletflow.Wallet.CheckStatus and the mobile ProximityReader refuse an mdoc's status list that has no exp or carries its x5chain outside the protected header (ISO/IEC 18013-5 §12.3.6.3); set statuslist.VerifyOptions.RequireExp and X5ChainProtectedOnly to apply the same rules elsewhere. mdoc.Issue refuses an IdentifierList reference with no ID or URI, or whose Certificate isn't an X.509 certificate.

### Features

* **identifierlist:** issue and check ISO/IEC 18013-5 identifier lists ([4e48799](https://github.com/IDFoundry/OID4VCgo/commit/4e48799a2d2783a0969ff18b0d6847e7cc30763b))


### Bug Fixes

* **certrevocation:** bind Refresher URLs to issuers and keep a rollback floor ([84fd8d1](https://github.com/IDFoundry/OID4VCgo/commit/84fd8d1a0aaf5ca1c1d95dc5e61fc2e7fdaad91b))
* **certrevocation:** check a pinned leaf against its CA's CRL ([1a5821c](https://github.com/IDFoundry/OID4VCgo/commit/1a5821c9cb33f269b4d220696aca6cec41f995a8))
* **certrevocation:** hand OnAccept lists in the order they were accepted ([7d9e022](https://github.com/IDFoundry/OID4VCgo/commit/7d9e0227b7607ab0b0a291ebc92f71ea9e860304))
* **certrevocation:** refuse unknown critical CRL extensions, allow clock skew ([af1717b](https://github.com/IDFoundry/OID4VCgo/commit/af1717bb97d1c1f1cdaf2913b4f8dd715c842dc0))
* **dcql:** match values of every Go numeric kind ([8ad8ee3](https://github.com/IDFoundry/OID4VCgo/commit/8ad8ee316d52dd3790859689cf15c4339f77da7e))
* **deps:** pin FAPIgo v0.62.0 ([76ae9c3](https://github.com/IDFoundry/OID4VCgo/commit/76ae9c3596317fbc6147026993592a7aafe6d0b0))
* **haip:** compare key attestation requirements as sets ([4acb090](https://github.com/IDFoundry/OID4VCgo/commit/4acb09047189cfa9037ac0d83c74fb518259d885))
* **identifierlist:** read a large identifier list without decoding it twice ([91f86d0](https://github.com/IDFoundry/OID4VCgo/commit/91f86d0deb5fa9c467ed1e5364ef3c6d04d658ad))
* **identifierlist:** refuse a list signer nothing binds to the mdoc's issuer ([8f1308a](https://github.com/IDFoundry/OID4VCgo/commit/8f1308a299261f36b90bcc346b80809553c5d99b))
* **issuer:** keep a deferral pending when its attestation status is unknown ([cbbc6a3](https://github.com/IDFoundry/OID4VCgo/commit/cbbc6a34149b47619d6e09c8f28636525800b5eb))
* **issuer:** refuse relayable key attestations and name the issuer in iss ([4376fa0](https://github.com/IDFoundry/OID4VCgo/commit/4376fa09e05b1bd6f083c1a8e13e29dfb561e3cb))
* **issuer:** require a revocation choice for x5c trust under AssuranceProduction ([976f69c](https://github.com/IDFoundry/OID4VCgo/commit/976f69c52fba1f693cfc8f4157e2ea7bcc6939e0))
* **issuer:** tell an undecided key attestation check from an invalid one ([654e3c4](https://github.com/IDFoundry/OID4VCgo/commit/654e3c4e705f7faa58ab663b14ef2b91bb865be9))
* **mdocdcapi:** normalize and validate the Verifier's origins ([5464a71](https://github.com/IDFoundry/OID4VCgo/commit/5464a716aacaf818d769608a843141f2a802128f))
* refuse a status or identifier list token whose exp isn't after its iat ([312f5b4](https://github.com/IDFoundry/OID4VCgo/commit/312f5b4d6ec3909b34821a207f72a3ef94cb3167))
* say so when a list signer's ECDSA key isn't on P-256 ([2d8edfb](https://github.com/IDFoundry/OID4VCgo/commit/2d8edfb1fa86e70156eca2cc9835d4cd90a43322))
* **sdjwtvc:** refuse reserved names inside opaque claim values ([2deff38](https://github.com/IDFoundry/OID4VCgo/commit/2deff38ba87a74ab003a9b491abbca3ee09ceb7b))
* **statuslist,identifierlist:** align revocation list verification with the specs ([1a8cf30](https://github.com/IDFoundry/OID4VCgo/commit/1a8cf306b51fe42f95215dde1404ec910ca93d7d))
* **statuslist:** check a Checker's CWT Status List Token as an mdoc's ([9542915](https://github.com/IDFoundry/OID4VCgo/commit/9542915350da125c1fa13677060336ceaba4f722))
* **verifier:** detect issuer roots built from the system root pool ([30a9c11](https://github.com/IDFoundry/OID4VCgo/commit/30a9c11af0e2e27c2c56403e00da73d65e2bfc13))
* **verifier:** hold Digital Credentials API origins to an allow-list ([474587b](https://github.com/IDFoundry/OID4VCgo/commit/474587bba78c5875748d76ef6e8bad5ec654dd88))
* **verifier:** normalize BeginDCAPI's origin and require Origins up front ([91740c2](https://github.com/IDFoundry/OID4VCgo/commit/91740c2c397f702c5ead1e194daadd6774728c6e))
* **verifier:** refuse a status check whose list signer can't be bound ([e79839a](https://github.com/IDFoundry/OID4VCgo/commit/e79839ac1a7e5049daf36885fe4d43b6c68c4f80))
* **verifier:** refuse a transaction store that drops Owner ([8f34374](https://github.com/IDFoundry/OID4VCgo/commit/8f3437400a33e46ff3f450239f90ee2e2c729971))
* **verifier:** refuse mdoc reader certificates as SD-JWT VC issuers ([4ac3376](https://github.com/IDFoundry/OID4VCgo/commit/4ac337694a538b3840ad6454d2c8e0c38b2c7359))
* **verifier:** refuse other roles' certificates as SD-JWT VC issuers by default ([5ee7441](https://github.com/IDFoundry/OID4VCgo/commit/5ee744104a620e5bac9b2068303567c66119e79d))
* **verifier:** scope each transaction to the Transactions that created it ([a98a39b](https://github.com/IDFoundry/OID4VCgo/commit/a98a39bd322a13cbd5be99fa6f59ebfd0333c907))
* **walletflow,mobile:** check an mdoc's status list as ISO/IEC 18013-5 §12.3.6.3 says ([7ef6916](https://github.com/IDFoundry/OID4VCgo/commit/7ef6916ca9d1dbc5a0146faf95981b595fb75881))
* **walletflow:** count a shared mdoc identifier list entry as correlating copies ([7b2e8b9](https://github.com/IDFoundry/OID4VCgo/commit/7b2e8b9703b0a94f930d1d20d749ef7f8fa72d79))
* **walletflow:** refuse a malformed redirect URI at New ([43325e5](https://github.com/IDFoundry/OID4VCgo/commit/43325e56d829e54e4ad1225711cc87eede1cee52))
* **walletflow:** refuse redirect URIs a resumed issuance can't complete ([c866f58](https://github.com/IDFoundry/OID4VCgo/commit/c866f58c21346ad447cd9692d363ed530ab96102))
* **walletflow:** report an mdoc naming an identifier list as status unknown ([e559043](https://github.com/IDFoundry/OID4VCgo/commit/e559043287823c7d80d33f6fd262278ecbce23f2))
* **walletflow:** require an explicit revocation choice for each trust role in use ([8933dab](https://github.com/IDFoundry/OID4VCgo/commit/8933dab0ff5fc9634ad4138f27dc3f69e9d33ccf))

## [0.54.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.53.0...v0.54.0) (2026-10-26)


### ⚠ BREAKING CHANGES

* **deps:** outside Config.Development, walletflow's ResumeIssuance (resumeIssuance in the Swift and Kotlin libraries) fails when Config.RedirectURI is an https Universal Link or App Link: FAPIgo now takes the callback binding a resumed issuance uses only for a native app's redirect URI, a private-use URI scheme or loopback http to 127.0.0.1 or [::1]. A wallet that resumes issuances registers and uses such a redirect URI. On the issuer side, FAPIgo now refuses opaque access tokens issued before this release and refresh-token records written before FAPIgo v0.58.0, so wallets holding them must authorize again; see FAPIgo's UPGRADING.md for v0.61.0's other changes.

### Bug Fixes

* build with Go 1.26.10 for GO-2026-6809 ([6b7ae21](https://github.com/IDFoundry/OID4VCgo/commit/6b7ae2186a96b0c1cefcce9ee0c302af452276b7))
* **deps:** pin FAPIgo v0.61.0 ([8a4351c](https://github.com/IDFoundry/OID4VCgo/commit/8a4351c16b417c3b156e74abafe57c5315a14990))
* **walletflow:** send one jwt proof per key attestation, not one per copy ([f67214b](https://github.com/IDFoundry/OID4VCgo/commit/f67214b25e5583e9ef2733c139655dda99653246))

## [0.53.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.52.0...v0.53.0) (2026-10-25)


### ⚠ BREAKING CHANGES

* **verifier:** set Revocation on every X5CIssuerKeyResolver and X5ChainIssuerKeyResolver. Pass certrevocation.CRLs{Lists: ...} with your issuer CAs' current CRLs, your own certrevocation.Checker (OCSP, for example), or certrevocation.NoCheck{} to keep the previous behaviour of not checking revocation. A resolver left without one is refused by VerifyResponse, NewTransactions and mdocdcapi.VerifyResponse.
* **dcql:** with AKITrustedAuthoritiesChecker.Roots, a trust anchor whose Subject Key Identifier isn't derived from its key (SHA-1, or SHA-256 truncated to 160 bits, of its subjectPublicKey) no longer matches an "aki" value naming that identifier. Set Anchors to the anchor certificates in place of Roots, e.g. dcql.AKITrustedAuthoritiesChecker{Anchors: issuerCAs}, and call Validate at startup to catch anchors claiming the same identifier.
* **wallet:** wallet.VerifyIssuedCredential, and so walletflow, now refuse an issued mdoc that fails mdoc.CheckDocumentSigner, as verifiers already do: among others one whose IACA or document signer certificate has no countryName, or whose issuing_country doesn't match its signer. Issue mdocs from an IACA and document signer that name their country.
* **issuer:** PreAuthorizedCodeStore.Consume gains a final parameter, accept func(PreAuthorizedCodeRecord) error. A custom store must, after its tx_code check succeeds and before it invalidates the code, call accept (when non-nil) with a copy of the record inside the same transaction or lock; if accept returns an error, return that error unchanged (or wrapped so errors.Is finds it), leave the code in place, and count no wrong attempt. Accept is never called for an unknown code or a missing, unexpected or wrong tx_code. Callers of Consume that check nothing pass nil. Run issuertest's TestPreAuthorizedCodeStoreContract against the store to confirm.
* **issuer:** AttestationStatusChecker.CheckAttestationStatus takes an issuer.VerifiedKeyAttestation instead of an attestation.VerifiedClaims. Read the claims from its Claims field, and bind the status list's signer to SignerKey (and Claims.Issuer, when set).
* **issuer:** an AccessTokenVerifier must set Grant.Authorized.Subject to Grant.Subject. A verifier that set only Grant.Subject now gets a 500 for every request; set both to the access token's subject.
* **walletflow:** outside Development, walletflow.New refuses a Config whose IssuerRoots, IssuerMetadataRoots, RegistrarRoots, MdocReaderRoots and VerifierTrust roots share a certificate subject between any two roles, or use a platform system pool beside another role, unless both roles have a leaf policy. Give each such role a leaf policy (an extended key usage) that tells its certificates apart, or build each role's pool from anchors no other role uses.
* **walletflow:** a copy presented over a signed DC API request is no longer recorded as shown to "origin:" + origin, so asking StoredCredential.ShownTo for "origin:" + origin is false for it. Ask the presentation instead: Presentation.ShownTo with the credential's ID reports whether its Verifier has seen it.
* **mdoc:** an mdoc whose document signer certificate has an extended key usage extension without 1.0.18013.5.1.2 (one listing only another purpose, such as clientAuth or a private OID) is now refused by the default policy. Issue document signers with the mDL document signer EKU, or set LeafPolicy, IssuerLeafPolicy or WithDocumentSignerPolicy to a policy accepting the EKU your document signers carry.
* **mdoc:** an mdoc whose status list is signed under a CA other than the one that issued its document signer (directly under the root above that CA, say) now fails its status check. The issuer signs its status lists under the CA that issued its document signer, or names the status list's trust point in the MSO's status Certificate.

### Features

* **certrevocation:** add a background CRL refresher ([bf6b684](https://github.com/IDFoundry/OID4VCgo/commit/bf6b684cc0f4d484c4c5e6fcd457614461237fdb))
* **certrevocation:** add CRL-based certificate revocation checking ([10fcd91](https://github.com/IDFoundry/OID4VCgo/commit/10fcd91d8595a3016d09e03482e48c4014d9afb9))
* **issuer:** bind key attestation signers to the attestation's iss ([9adc860](https://github.com/IDFoundry/OID4VCgo/commit/9adc86036f0f6f8afab31295e6aa3c9fa3d48659))
* **issuer:** check key attestation and proof certificate revocation ([2f0966d](https://github.com/IDFoundry/OID4VCgo/commit/2f0966dc791a1dc84f482d33dbc323d6f23eeea1))
* **issuer:** give AttestationStatusChecker the key attestation's signer ([f48396f](https://github.com/IDFoundry/OID4VCgo/commit/f48396f7d062fa07d19841fad4e97603e604bcb2))
* **mdoc:** add decoy digests to the MSO's valueDigests ([2f533b1](https://github.com/IDFoundry/OID4VCgo/commit/2f533b153856f692462f4e4a22e661244ab0a301))
* **proximity:** check document signer and mdoc reader certificate revocation ([5fdca7d](https://github.com/IDFoundry/OID4VCgo/commit/5fdca7de695e31b4ffee189a9fa850c287ce1f90))
* **registration:** check registrar certificate revocation ([6e192a2](https://github.com/IDFoundry/OID4VCgo/commit/6e192a2e446b1cf8130de3efd7f57f80e5b1da8a))
* **sdjwtvc:** add decoy digests to nested _sd arrays ([a265df5](https://github.com/IDFoundry/OID4VCgo/commit/a265df55e8d223b59b414fe68b98691eba950643))
* **statuslist:** check status list signer certificate revocation ([8bda7d3](https://github.com/IDFoundry/OID4VCgo/commit/8bda7d3515e4c8dde9b62db8f41efa1db468bc95))
* **verifier:** add RequireStatusReference to refuse credentials without a status ([32cca0b](https://github.com/IDFoundry/OID4VCgo/commit/32cca0b6ae7923ca67e51ac5a839d284de968931))
* **verifier:** refuse one credential for two queries under DistinctCredentials ([5e557f1](https://github.com/IDFoundry/OID4VCgo/commit/5e557f1b234eb825bcdf2c5106549bc79d2e7101))
* **verifier:** require a revocation check on X.509 issuer trust ([baff02f](https://github.com/IDFoundry/OID4VCgo/commit/baff02fa9502870416b8fb1e14e9394fef9f5d07))
* **wallet:** check certificate revocation on issuer, verifier and metadata trust ([7cd1047](https://github.com/IDFoundry/OID4VCgo/commit/7cd1047626a1056de30078ce42d03df838a5cdc6))
* **walletflow:** check certificate revocation per trust role ([d344c30](https://github.com/IDFoundry/OID4VCgo/commit/d344c30cbaaa22cc76106445d206e12d1f734fab))
* **walletflow:** fetch request_uri by POST when the link asks for it ([921b81c](https://github.com/IDFoundry/OID4VCgo/commit/921b81c6d5e98c51e6f483a22d43d6ea0695ebb6))
* **walletflow:** give mdocs their own issuer roots and leaf policy ([7ed704f](https://github.com/IDFoundry/OID4VCgo/commit/7ed704f014ceb8f341a7f371e3a6242b392f50dd))


### Bug Fixes

* compare DPoP htm exactly, refuse non-canonical origins, keep results as long as Lookup reports them ([3811bf6](https://github.com/IDFoundry/OID4VCgo/commit/3811bf678121d5a23c612e5c39f1625d78badcd1))
* **dcql:** match trust anchors by key-derived identifiers ([f60ef52](https://github.com/IDFoundry/OID4VCgo/commit/f60ef5227499a901b0c6a47d1645f3503fd402c4))
* **issuer:** call Prepare only once the Credential Request is authorized and its proofs verified ([f618425](https://github.com/IDFoundry/OID4VCgo/commit/f6184259753aae5c6f7dfa7942a9dc318c24d694))
* **issuer:** cap the keys jwt proofs resolve at batch_size in every case ([3cde3ad](https://github.com/IDFoundry/OID4VCgo/commit/3cde3ad68a5ed1cd43c08b51808cad35590727a1))
* **issuer:** check a pre-authorized code's record before consuming it ([1ea1c1a](https://github.com/IDFoundry/OID4VCgo/commit/1ea1c1ae2ff0c366b1b5559ef63d89b5c03c198c))
* **issuer:** refuse a Grant whose two subjects disagree ([df3ed23](https://github.com/IDFoundry/OID4VCgo/commit/df3ed234f2fb031b3c40c5fda6d8eba83b864e7f))
* **issuer:** verify a deferred transaction's key attestations again before issuing ([c89ea8a](https://github.com/IDFoundry/OID4VCgo/commit/c89ea8a3f2277d8fee5958739b880c254b6d3312))
* **mdoc:** bind an mdoc status list's signer to the CA that signed the document signer ([0187d28](https://github.com/IDFoundry/OID4VCgo/commit/0187d285e57a289dcc5c4816e47902c860bcefc5))
* **mdoc:** refuse a document signer whose EKU leaves out the mDL DS purpose ([3f5307a](https://github.com/IDFoundry/OID4VCgo/commit/3f5307a277e1a3ec08d7a48bb4e4251ec03fd95e))
* **verifier:** report only issuer chains the leaf policy approves ([dd83fe7](https://github.com/IDFoundry/OID4VCgo/commit/dd83fe7a90260cf48bb3eee1aa9eda847e4af46f))
* **wallet:** decode issuer, server and verifier responses strictly ([15cc1af](https://github.com/IDFoundry/OID4VCgo/commit/15cc1af4fb1892b2749cf2b86aaf285bfb7f89c8))
* **walletflow:** drop issuer logos on local host names ([2d91744](https://github.com/IDFoundry/OID4VCgo/commit/2d9174401c3c1dbf5d461d894229b87c2c9fcf3b))
* **walletflow:** give a caller's HTTP client a timeout ([cc2da90](https://github.com/IDFoundry/OID4VCgo/commit/cc2da9030f0fc27797b342b61b3afed986433acf))
* **walletflow:** refuse trust pools that may share an anchor ([2600784](https://github.com/IDFoundry/OID4VCgo/commit/2600784da25f13999bbb0ab083129ae9ba6df26a))
* **walletflow:** report copies correlated by shared digests or timestamps ([b154373](https://github.com/IDFoundry/OID4VCgo/commit/b1543739b04af7f85bf5b531886048c40366e5ee))
* **walletflow:** tell apart signed DC API Verifiers sharing an origin ([2d2bc52](https://github.com/IDFoundry/OID4VCgo/commit/2d2bc5291755a0752dfd9760e06ead5700340412))
* **wallet:** preview every claim a presentation reveals inside arrays ([e0fffaf](https://github.com/IDFoundry/OID4VCgo/commit/e0fffaf8a6f040a7d2dde466c37478f789630ea4))
* **wallet:** refuse an issued SD-JWT VC that doesn't end with '~' ([40eb450](https://github.com/IDFoundry/OID4VCgo/commit/40eb450d278bb10938abc96be46f6a393d0265f8))
* **wallet:** run the mdoc document signer checks on receipt ([297d0a1](https://github.com/IDFoundry/OID4VCgo/commit/297d0a1482da4ae762b3a0cb84757e16c663c177))

### Upgrade notes

* **issuer:** since v0.52.0 ([6043a8d](https://github.com/IDFoundry/OID4VCgo/commit/6043a8d930c39e82e59b5b2986bb6a60ffdc2417)), ExchangePreAuthorizedCode hands its DPoPReplayChecker the base64url SHA-256 digest of each DPoP proof's jti, not the jti itself. If you upgrade from v0.51.x or earlier and your replay checker keeps its records across the restart, a proof recorded under its raw jti just before the upgrade no longer matches its record, so it can be used once more while its iat is within Limits.MaxDPoPProofAge. The in-memory storage.DPoPReplayChecker starts empty after every restart, so this changes nothing for it. To close the window, keep the issuer's token endpoint down for Limits.MaxDPoPProofAge plus Limits.MaxDPoPClockSkew across the upgrade.

## [0.52.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.51.0...v0.52.0) (2026-10-23)


### ⚠ BREAKING CHANGES

* **verifier:** X5CIssuerKeyResolver with RequireIssuerName set now refuses an SD-JWT VC without an iss claim.
* **proximity:** RequireReaderAuthenticationEKU (proximity, mdocdcapi), proximity.RequireMDLDocumentSignerEKU and the mobile wallet's *_require_eku settings now refuse a certificate whose every verified path has an intermediate CA whose extended key usage extension lists neither the role's usage nor anyExtendedKeyUsage.
* **verifier:** X5ChainIssuerKeyResolver with no LeafPolicy, and wallet.VerifyIssuedCredential with no IssuerLeafPolicy, now refuse an mdoc whose document signer certificate is an OCSP signer's or has a key usage extension without digitalSignature. Set a LeafPolicy (or IssuerLeafPolicy) to replace the check.
* **issuer:** under AssuranceProduction, issuer.New refuses Limits.MaxTxCodeAttempts above issuer.MaxProductionTxCodeAttempts (10) when Dependencies.PreAuthorizedCodes is set. Lower it to 10 or less.

### Features

* **issuer:** let notification_ids expire, and prune the in-memory stores ([d47e1fe](https://github.com/IDFoundry/OID4VCgo/commit/d47e1fec2852e3c1092fbf22b129c5cd8ae16474))
* **issuer:** optionally add decoy digests to issued SD-JWT VCs ([5e41cd5](https://github.com/IDFoundry/OID4VCgo/commit/5e41cd5ff4e3209a7c9407c3053bdf50aa7c1ba7))
* **mdoc:** add RoundedValidity for an MSO's validityInfo ([b8779b3](https://github.com/IDFoundry/OID4VCgo/commit/b8779b3a1b14780074c23248931b4db0a7aa9ff5))
* **statuslist:** report whether a Fetcher keeps its full address policy ([d318fda](https://github.com/IDFoundry/OID4VCgo/commit/d318fdadd628159b76310483346698be21906750))
* **wallet:** fetch a request_uri by POST through the Wallet's hardened fetcher ([ffbf733](https://github.com/IDFoundry/OID4VCgo/commit/ffbf733667b647bcea2714468d1ed08434df8adc))
* **wallet:** send OpenID4VP responses through the Wallet's own HTTP client ([274ce31](https://github.com/IDFoundry/OID4VCgo/commit/274ce31b09e4024e730fff964af3c623c169da75))


### Bug Fixes

* bound the total data items in a CBOR message ([5571d00](https://github.com/IDFoundry/OID4VCgo/commit/5571d0098b74fec3e6256d995bdf6ad927488eda))
* **certchain:** bound a presented chain's length, and refuse a self-issued anchor without a signature check ([cf38ca5](https://github.com/IDFoundry/OID4VCgo/commit/cf38ca56fe37918ad409c5fd9184c8de3e8e0305))
* **certchain:** refuse a leaf certificate with a small-order Ed25519 key ([7ad2dc6](https://github.com/IDFoundry/OID4VCgo/commit/7ad2dc67c25b51f780c38307bac05972b05707ff))
* **dcql:** bound claim_sets entries, trusted_authorities and vct_values ([40c3349](https://github.com/IDFoundry/OID4VCgo/commit/40c3349be9dce2f53e4ede10e2497008d90f45ff))
* **issuer:** bound the DPoP jti the replay record keeps ([6043a8d](https://github.com/IDFoundry/OID4VCgo/commit/6043a8d930c39e82e59b5b2986bb6a60ffdc2417))
* **issuer:** cap Limits.MaxTxCodeAttempts under AssuranceProduction ([c733b81](https://github.com/IDFoundry/OID4VCgo/commit/c733b81d854373d8883a4c530c77e57d27100b55))
* **mdoc:** share one item budget across an IssuerSigned's items ([221c871](https://github.com/IDFoundry/OID4VCgo/commit/221c8710b781e75fc8f9d242893f2bdbb0d5013b))
* **proximity:** decode within credential/mdoc's CBOR bounds ([7b1d4eb](https://github.com/IDFoundry/OID4VCgo/commit/7b1d4eb8c6686fa4eb6c17c9fbf2b8cdba4c6171))
* **proximity:** drop session secrets when a session closes ([055d946](https://github.com/IDFoundry/OID4VCgo/commit/055d946a0b0d47e3bdefb1a63375b07504c9a231))
* **proximity:** hold a role's extended key usage to the verified path, not just the leaf ([1c751bb](https://github.com/IDFoundry/OID4VCgo/commit/1c751bb7fbf8d62946c423f3e99234120ee23edf))
* **storage:** drop a deferred transaction's Credentials on Invalidate ([113d30d](https://github.com/IDFoundry/OID4VCgo/commit/113d30df304a100ca104736be0153e71cbb03a7f))
* **verifier:** refuse a credential without iss under RequireIssuerName ([2591640](https://github.com/IDFoundry/OID4VCgo/commit/2591640ecd6fee86cee0768c76cdbe5677605c67))
* **verifier:** refuse an IACA's OCSP signer as an mdoc document signer ([99bb345](https://github.com/IDFoundry/OID4VCgo/commit/99bb3451f757429dd99dd09a69b66b18da0156fa))
* **verifier:** stop reporting a completed transaction's result indefinitely ([0c583c9](https://github.com/IDFoundry/OID4VCgo/commit/0c583c95d4ed6a87b3f3eccdaf7cd179002b3fb9))
* **wallet:** decode each held credential once when matching a DCQL query ([fd8aebf](https://github.com/IDFoundry/OID4VCgo/commit/fd8aebf3f076002e25baacc9001b4c24b436bfc7))
* **wallet:** default to one credential for a query that takes several ([1691796](https://github.com/IDFoundry/OID4VCgo/commit/1691796935ecc506afb5e8434bc9e86c9255ffe5))
* **walletflow:** bound the Credential Requests one issuance makes ([17dcff0](https://github.com/IDFoundry/OID4VCgo/commit/17dcff0230997bee2bd49f0eeebfe3fd4d822f7f))
* **walletflow:** check role separation for VerifierTrust given by pointer ([cfa78f9](https://github.com/IDFoundry/OID4VCgo/commit/cfa78f996875a96d6f10741a15498bc0f2cab6ec))
* **walletflow:** don't hand out a deferred credential settled while listing ([cb769d7](https://github.com/IDFoundry/OID4VCgo/commit/cb769d78734c58145f7bea01839f2c0afd95baf3))
* **walletflow:** drop issuer logos on IP addresses and localhost ([bd7d41a](https://github.com/IDFoundry/OID4VCgo/commit/bd7d41adf1f6d72b8d879e66a5a70e11861c6348))
* **walletflow:** keep a copy marked when a later presentation reserved it ([c884b43](https://github.com/IDFoundry/OID4VCgo/commit/c884b43ccbedbd454e20896371124c4f52f91146))
* **walletflow:** report copies an issuer correlated as linkable ([d1971a9](https://github.com/IDFoundry/OID4VCgo/commit/d1971a9a868d3ebb616706af410d146eee22851f))
* **walletflow:** reuse a copy only the returning Verifier has seen ([7311bb6](https://github.com/IDFoundry/OID4VCgo/commit/7311bb6d2b94f99e026ecd7fdfa2db28cdf79dd3))
* **wallet:** refuse an encrypted Credential Response with another enc than requested ([8c382c0](https://github.com/IDFoundry/OID4VCgo/commit/8c382c0c3b2e54a0f11233636edbce9676dc65b4))
* **wallet:** refuse Fetch.AllowedLoopbackHosts under AssuranceProduction ([cee9c88](https://github.com/IDFoundry/OID4VCgo/commit/cee9c88b80dfdccfc26793ebf38f365be4ce0944))
* **wallet:** require crypto/rand.Reader as Random under AssuranceProduction ([773dbc0](https://github.com/IDFoundry/OID4VCgo/commit/773dbc0b00874efad25eb57e02ad9a33a6515ad7))
* **wallet:** time out requests through a given HTTP client without a Timeout ([580096b](https://github.com/IDFoundry/OID4VCgo/commit/580096b21def8f4f6d7ba941e8424402ed3e78f0))

## [0.51.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.50.0...v0.51.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* **walletflow:** outside Development, walletflow.New refuses a Config whose IssuerMetadataRoots is the same certificate pool as IssuerRoots, RegistrarRoots, MdocReaderRoots or the VerifierTrust roots, unless both roles have a leaf policy. Give IssuerMetadataLeafPolicy and the other role's leaf policy an extended key usage each, or use separate pools.
* **walletflow:** walletflow refuses an SD-JWT VC whose iss isn't the offer's credential_issuer. A wallet receiving from an issuer whose credentials carry a different iss sets Config.AllowForeignIss (mobile: allow_foreign_iss), where its IssuerRoots certify that issuer alone.
* **mdocdcapi:** mdocdcapi.VerifyParams.Assurance is required; a zero value is refused. Set verifier.AssuranceDevelopment to keep the previous behaviour, or verifier.AssuranceProduction with IssuerAuthorized or AnyIssuerForAnyType, and Accept (e.g. verifier.RequireValidStatus(checker)) or NoStatusCheck. A status check done on Verified after VerifyResponse returns can move into Accept, where Verified.Credential's IssuerChain lets RequireValidStatus bind the status list to the issuer.
* **issuer:** SignMetadataJWS's JWS now expires DefaultMetadataLifetime (24 hours) after it is signed. A deployment that signs metadata once and serves that copy indefinitely must sign it again before it expires, or serve it with NewMetadataHandler, which re-signs every MetadataSigner.Refresh.

### Bug Fixes

* decode raw JSON members with strictjson ([0c3f570](https://github.com/IDFoundry/OID4VCgo/commit/0c3f57052bb8329b9d7f7bfc6e3e18fc61d0c93e))
* decode signed payloads and issuer metadata with strictjson ([1ab155b](https://github.com/IDFoundry/OID4VCgo/commit/1ab155b9ee5575c7280215d2538790ef4644d344))
* **issuer:** check the grant before running a deferred Resolve ([4d6aee0](https://github.com/IDFoundry/OID4VCgo/commit/4d6aee09d2346ff6bc91f8ef38d7d2aa2e7a44d3))
* **issuer:** give signed Credential Issuer Metadata an exp ([1420001](https://github.com/IDFoundry/OID4VCgo/commit/1420001f9d760abef3a6e3d9509a47e9bcf09a02))
* **issuer:** ignore authorization details located at another issuer ([e31192e](https://github.com/IDFoundry/OID4VCgo/commit/e31192e767f88c8cbe92263ae5693fd42e907cca))
* **jose,jwe,sdjwtvc:** decode base64url strictly ([5501d7e](https://github.com/IDFoundry/OID4VCgo/commit/5501d7e5a12a3adb26ab45b43eab7a1409e2f8e9))
* **jose,jwe:** reject duplicate header parameters and an empty crit ([932dc5b](https://github.com/IDFoundry/OID4VCgo/commit/932dc5b207b38672b1e23237459b3416c3149fcc))
* **jwk:** decode base64url strictly ([50b3dc4](https://github.com/IDFoundry/OID4VCgo/commit/50b3dc4002bb8f90fff96a0be0e27c44072bdd53))
* **mdocdcapi:** require production's issuer and status decisions ([f692881](https://github.com/IDFoundry/OID4VCgo/commit/f6928817fd1d6e4e08c41d6e907f7aeb4d9f090c))
* **mobile:** sanitise mdoc reader names as walletflow does display text ([f338b8a](https://github.com/IDFoundry/OID4VCgo/commit/f338b8af14d66e9ca8dac592051e092e42b4767f))
* parse Digital Credentials API data with strictjson ([485f1e1](https://github.com/IDFoundry/OID4VCgo/commit/485f1e168b7b5e1d81a081e97885f0bf6753f2da))
* refuse duplicate CBOR map keys inside raw fragments ([4c1ca57](https://github.com/IDFoundry/OID4VCgo/commit/4c1ca575dc932493d04a4e3d8d99fac95ae5524f))
* **verifier:** keep sender-chosen text out of a request's LastError ([91c4408](https://github.com/IDFoundry/OID4VCgo/commit/91c44081a9a3d4a20a3201726a6cf54fcdb3e09d))
* **verifier:** refuse one credential presented twice under multiple ([7de2d89](https://github.com/IDFoundry/OID4VCgo/commit/7de2d890462169f7cf33a831e6b1e7393b3cf338))
* **verifier:** stop the response endpoint revealing whether the holder presented ([7012ea7](https://github.com/IDFoundry/OID4VCgo/commit/7012ea703b614d2e1f867cb9e8760b67dbe20f35))
* **walletflow:** drop invisible format characters and line separators from display text ([b22dd13](https://github.com/IDFoundry/OID4VCgo/commit/b22dd1314e79c134ac0899a655db5830b3d3bfd6))
* **walletflow:** keep issuer metadata roots apart from other roles' in production ([a8948a4](https://github.com/IDFoundry/OID4VCgo/commit/a8948a47f6aac9a861f6d26cd01978bac2eb7c8f))
* **walletflow:** refresh the Credential Dataset a credential holds ([7276e5e](https://github.com/IDFoundry/OID4VCgo/commit/7276e5ef8813a650b2029c1a6f9cbd677b9d63ec))
* **walletflow:** refuse an SD-JWT VC naming another issuer than the one asked ([fc9052f](https://github.com/IDFoundry/OID4VCgo/commit/fc9052f7e9cb0f7325afd44d94e1e49db9ccc9d4))
* **walletflow:** send key attestations in audience-bound jwt proofs ([2e3458e](https://github.com/IDFoundry/OID4VCgo/commit/2e3458e7cb068479a6066f0bc07d351b555236a2))

## [0.50.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.49.0...v0.50.0) (2026-10-21)


### Features

* **proximity:** add Android NFC engagement ([36b1e4c](https://github.com/IDFoundry/OID4VCgo/commit/36b1e4c37e9b755442942accfbe21500362bdc58))
* **proximity:** add nfcapdu, NFC's APDU protocols without I/O ([a818b26](https://github.com/IDFoundry/OID4VCgo/commit/a818b267a4ea62753db0dd03193e4c60bbff36aa))
* **proximity:** arbitrate independent QR and NFC offers ([36b1e4c](https://github.com/IDFoundry/OID4VCgo/commit/36b1e4c37e9b755442942accfbe21500362bdc58))
* **verifier:** run Digital Credentials API requests through Transactions ([3c3d1c4](https://github.com/IDFoundry/OID4VCgo/commit/3c3d1c4503d1d78e4869e781856c2a46c6b7617d))


### Bug Fixes

* **proximity:** accept TNEP requests without collision records ([36b1e4c](https://github.com/IDFoundry/OID4VCgo/commit/36b1e4c37e9b755442942accfbe21500362bdc58))
* **proximity:** commit NFC after completed handover ([36b1e4c](https://github.com/IDFoundry/OID4VCgo/commit/36b1e4c37e9b755442942accfbe21500362bdc58))

## [0.49.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.48.0...v0.49.0) (2026-10-20)


### Features

* **issuer:** send a DPoP nonce for the Credential Endpoint in the Nonce Response ([c476e8c](https://github.com/IDFoundry/OID4VCgo/commit/c476e8c9009e6eef1b95a323d2832fbeeea6bcd0))
* **walletflowtest:** send the Credential Endpoint's DPoP nonce in the Nonce Response ([11252a9](https://github.com/IDFoundry/OID4VCgo/commit/11252a9db9ffeaa07b9f5f2ab5b565a4aa3cb430))
* **wallet:** use the Nonce Response's DPoP nonce, and send Accept-Language for issuer metadata ([0eced4b](https://github.com/IDFoundry/OID4VCgo/commit/0eced4b00aae408505f1a8cab14264826bcbfdd2))


### Bug Fixes

* **deps:** pin FAPIgo v0.59.0 ([a92595a](https://github.com/IDFoundry/OID4VCgo/commit/a92595a7936d7882ba329b110a06bb66b4d819e3))
* **deps:** pin FAPIgo v0.60.0 ([a2e9155](https://github.com/IDFoundry/OID4VCgo/commit/a2e9155c0b3a75057254357d135a40702b8ab545))

## [0.48.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.47.0...v0.48.0) (2026-10-20)


### ⚠ BREAKING CHANGES

* **deps:** FAPIgo v0.58.0's breaking changes reach code built on OID4VCgo's wallet and walletflow (which use fapigo/client and fapihttp) and on issuer (which pairs with fapigo/server). A client.Config Scope element must be one scope; under AssuranceProduction, AuthorizationResponseIssPolicy TolerateAbsentAuthorizationResponseIss and CallbackBindingDeviceLocalStore over a store declaring CrossInstanceConsistent are refused; a request object lifetime is at most 60 minutes; sealing keys made entirely of printable text are refused; fapihttp.NewClient offers only ECDHE AES-GCM suites under TLS 1.2; resource.OpaqueAccessTokens needs Audience under production; a federation entity key may not be a protocol key. See FAPIgo's UPGRADING.md, v0.58.0.

### Bug Fixes

* **deps:** pin FAPIgo v0.58.0 ([e856044](https://github.com/IDFoundry/OID4VCgo/commit/e856044fcf40c5e53e92ec09d88b36b8701dbece))

## [0.47.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.46.0...v0.47.0) (2026-10-19)


### ⚠ BREAKING CHANGES

* **walletflow:** in production with IssuerRoots set, walletflow.New refuses Keys without durable custody, a non-crypto Random, non-Durable Grants with RequestRefresh, and non-Durable Authorizations with a RedirectURI. It refuses one certificate pool given to two roles without a leaf policy on each, and an unknown IssuanceProfile or CopyPolicy, or a negative BatchSize.
* **wallet:** a Request Object whose aud is present and isn't https://self-issued.me/v2, whose exp has passed, or whose nbf hasn't come, is refused.
* **issuer:** RequestCredential returns an error for an SD-JWT VC status claim without a valid status_list, and mdoc.Issue refuses a Claims.Status with an empty URI.
* **statuslist:** IssueToken and IssueTokenCWT refuse TokenClaims with no Iat, a TTL that isn't positive, or an Exp not after Iat.
* **attestation:** attestation.Issue and IssueWalletAttestation refuse a Header.X5C that isn't base64 DER, whose leaf isn't the signer's, whose leaf is self-signed, or that includes the trust anchor.
* **issuer:** RequestCredential returns an error, rather than signing, when a claim credential_metadata marks mandatory is missing.
* issuer.New and CredentialMetadata.Validate refuse display arrays with two objects for one language, and claims that describe one path twice.
* **haip:** haip.ValidateIssuerConfig refuses configurations of different Credential Types that share a scope.
* **issuer:** a Credential or Deferred Credential Request whose credential_response_encryption.jwk lacks alg is refused.
* **issuer:** RequestCredential returns invalid_credential_request, not invalid_proof, for two proof types, an empty proof array or an unsupported proof type. It returns a plain error (500), not credential_request_denied, when a credential can't be signed.
* **issuer:** New refuses a credential configuration with an unknown format, no binding methods, "jwk" or a "did:" method for an mdoc, "cose_key" for an SD-JWT VC, signing algorithms that don't list the signer's, or a signer certificate that isn't currently valid.
* **issuer:** RequestCredential refuses claims whose vct isn't the resolved configuration's, even when aka_vcts lists it.
* **issuer:** CreatePreAuthorizedOffer requires Subject, and Scopes or CredentialIdentifiers that grant each offered configuration. Under AssuranceProduction it refuses a TxCode under 6 characters and a Lifetime over a week.
* ParseDirectPostJWTResponse refuses a response whose enc the Verifier didn't offer. A Status List Token without exp, checked without MaxAge, is refused once issued more than 24 hours ago. A nil RootsByDocType entry is refused instead of falling back to Roots. CheckCWTX5Chain applies Issuer and IssuerKey.
* **proximity:** a document type mapped to a nil root pool in WithRootsByDocType is refused instead of falling back to the general roots.
* **verifier:** under AssuranceProduction, VerifyResponse refuses MdocIssuerKeys that isn't an MdocIssuerChainResolver and doesn't Unwrap to one.
* **verifier:** VerifyResponse, NewTransactions and mdocdcapi.VerifyResponse refuse a MaxClockSkew or MaxKeyBindingAge above an hour, or negative.
* **verifier:** under AssuranceProduction, VerifyResponse and NewTransactions need VerifyResponseRequest.IssuerAuthorized or AnyIssuerForAnyType, and a direct VerifyResponse also needs Accept or NoStatusCheck. TransactionsConfig.Verify must not set Accept or NoStatusCheck.

### Features

* **issuer:** add NewMetadataHandler, which checks its signer and signs metadata once per refresh ([77cb57e](https://github.com/IDFoundry/OID4VCgo/commit/77cb57e7632ba4199fe9a50c90d4a848c96f3e67))
* **issuer:** verify a jwt proof's key_attestation, and allow key_attestations_required on the jwt proof type ([8f39fde](https://github.com/IDFoundry/OID4VCgo/commit/8f39fde3fe9caaf24cd55f33d11354d54601b7f4))
* **proximity:** give a reader the issuer chain it verified, and no general roots for a document type named without its own ([8e172bc](https://github.com/IDFoundry/OID4VCgo/commit/8e172bcd049b0cb24da4a8445a23200767a75a2d))
* **wallet:** a leaf policy for the issuer metadata signer ([dca9096](https://github.com/IDFoundry/OID4VCgo/commit/dca90968047425e343b2a00faf86dd946a94dd91))
* **walletflow:** send jwt proofs carrying a key attestation where the issuer takes only those ([6e51df2](https://github.com/IDFoundry/OID4VCgo/commit/6e51df243b9f00a868ae5ed53820ebce6e4f6a4c))
* **wallet:** request a configuration without a scope by authorization_details ([72b8b8d](https://github.com/IDFoundry/OID4VCgo/commit/72b8b8d4dd3bb7667ad24b783f7daeb6b59cfe02))


### Bug Fixes

* **attestation:** check an attestation's x5c chain at issuance ([9d83d81](https://github.com/IDFoundry/OID4VCgo/commit/9d83d819a7edda4fdbac597d3313eac4bd82f37e))
* decrypt only offered encryptions, bound status list freshness, and bind a CWT list's signer ([880342c](https://github.com/IDFoundry/OID4VCgo/commit/880342cd9d4a48d093f81a6a47b5d4e00d12bf9f))
* **haip:** require each scope to map to one Credential Type ([41539a9](https://github.com/IDFoundry/OID4VCgo/commit/41539a96a52d708488f10cd1a6a9a6edf45b67f6))
* **issuer:** a deferred poll must still be authorized for its configuration, and holders must be told apart ([d901992](https://github.com/IDFoundry/OID4VCgo/commit/d901992b846c91f2c24feacef4dc6ed02f3db713))
* **issuer:** accept a fractional iat in a jwt proof ([b20f61b](https://github.com/IDFoundry/OID4VCgo/commit/b20f61b9058404a51f2a2d2cf91d60f124454a86))
* **issuer:** answer a malformed proofs or an unsupported proof type with invalid_credential_request, and a signing failure with a server error ([64fbb7b](https://github.com/IDFoundry/OID4VCgo/commit/64fbb7bc3ebcd5ffd7d896d0b5eea08b243f24ad))
* **issuer:** check a key attestation's freshness before its status, and window it without a Nonce Endpoint ([e5b5c6b](https://github.com/IDFoundry/OID4VCgo/commit/e5b5c6bd3f37d3004bc88206573f385548a0e4b5))
* **issuer:** decode proof and attestation claims with exact member names ([a44ab18](https://github.com/IDFoundry/OID4VCgo/commit/a44ab1845cbca9540ccad6b71f266ea2daa4ad8b))
* **issuer:** echo a pre-authorized Token Request's authorization_details, and set locations ([de2c31c](https://github.com/IDFoundry/OID4VCgo/commit/de2c31ca9dcfd2bb5e62c754afa2e251f9276c6c))
* **issuer:** enforce required request encryption whoever calls RequestCredential ([2298c0d](https://github.com/IDFoundry/OID4VCgo/commit/2298c0d0364f16a30384f8062e04aa417e71a0c8))
* **issuer:** refuse a credential configuration the issuer can't issue as it advertises ([d42905e](https://github.com/IDFoundry/OID4VCgo/commit/d42905ebc528f1f6e4b997053125d16894170c89))
* **issuer:** refuse a pre-authorized offer without a subject or a grant for what it offers, and bound its PIN and lifetime in production ([e440aee](https://github.com/IDFoundry/OID4VCgo/commit/e440aee7f629b53c53d8f324faaa13ccaa0fb6fa))
* **issuer:** refuse a request body whose members match a field only case-insensitively ([42b86df](https://github.com/IDFoundry/OID4VCgo/commit/42b86dfb8093a5cdbe79f809a997b322fe676ac4))
* **issuer:** refuse to sign a credential missing a claim its credential_metadata marks mandatory ([8b2b6a0](https://github.com/IDFoundry/OID4VCgo/commit/8b2b6a0ac97cc0759b192654a26d1690ee4faf87))
* **issuer:** refuse to sign a status claim a Verifier would refuse ([d090a54](https://github.com/IDFoundry/OID4VCgo/commit/d090a543bad2b2588c8825cf625a20f1b6b8941c))
* **issuer:** require alg in the Wallet's response-encryption JWK ([ebd588a](https://github.com/IDFoundry/OID4VCgo/commit/ebd588a06cf76ee1a3a1d6b5eb9359b81a20dc95))
* **issuer:** send Pragma: no-cache with the pre-authorized Token Response ([55f6d29](https://github.com/IDFoundry/OID4VCgo/commit/55f6d29216c33789e4921a647acde5ae296fe421))
* **issuer:** sign an SD-JWT VC only with the configuration's exact vct ([e004c50](https://github.com/IDFoundry/OID4VCgo/commit/e004c5057c18a7f4a7bc4b4eb1b2e3198f2e36e8))
* keep forged names and identifiers off the holder's consent screen ([274ef3a](https://github.com/IDFoundry/OID4VCgo/commit/274ef3ae4dfbc90dcdf907aadfbe7d815dfb94a5))
* **mdoc:** issue validity times in UTC with whole seconds ([90c9e45](https://github.com/IDFoundry/OID4VCgo/commit/90c9e456cf17ee997b25609345f1d8d57369ff73))
* **mdoc:** refuse a DeviceAuth carrying both deviceSignature and deviceMac ([9a2124c](https://github.com/IDFoundry/OID4VCgo/commit/9a2124c8e0fe827c9483d6833b05aff12257a7c2))
* **mdoc:** return the values Verify digested, not the editable struct's ([df31947](https://github.com/IDFoundry/OID4VCgo/commit/df3194786f4dc4906cc5cab9f8ec9ab552ff71df))
* refuse an Ed25519 key of the wrong length instead of panicking ([f8626fb](https://github.com/IDFoundry/OID4VCgo/commit/f8626fb3fb8af055e3cb8cd7f5c63f22bc8e0145))
* refuse duplicate display locales and claim descriptions in issuer metadata ([defa722](https://github.com/IDFoundry/OID4VCgo/commit/defa7221dc653bd9cf4733a442af1ed5971cff14))
* refuse duplicate JSON members, and case-only member matches at every depth ([2fe74a3](https://github.com/IDFoundry/OID4VCgo/commit/2fe74a36708aab895a2cdd40488d8e8b3e634317))
* **sdjwtvc:** add no decoys to an SD-JWT VC without selectively disclosable claims ([0b57c1d](https://github.com/IDFoundry/OID4VCgo/commit/0b57c1d5b829ef4f22d3f58a36a4e661b30db483))
* **sdjwtvc:** refuse a disclosure with a null salt or claim name, or a member twice ([2f42059](https://github.com/IDFoundry/OID4VCgo/commit/2f4205957798c6fd4d0a5f7031ebb0098079d4f4))
* **sdjwtvc:** refuse duplicate members in the issuer JWT and KB-JWT ([a489048](https://github.com/IDFoundry/OID4VCgo/commit/a489048fd219285f86d8953cdb4073a1c5e48eef))
* smaller wallet presentation gaps from the 2026-10-18 review ([7068465](https://github.com/IDFoundry/OID4VCgo/commit/7068465d6bb6ebc0360c879356470b2844072aea))
* **statuslist:** follow https redirects, parse the content type, and cap decompression at 16 MiB ([e30e0ef](https://github.com/IDFoundry/OID4VCgo/commit/e30e0ef2ebcfb7bfb1b4fa69ea7d2b31d5aa8c05))
* **statuslist:** refuse a Status List Token before its nbf, and accept fractional NumericDates ([0137579](https://github.com/IDFoundry/OID4VCgo/commit/0137579603ef21674af352d8d6c398483b38402b))
* **statuslist:** refuse token claims a Relying Party would refuse, and serve gzip ([6797970](https://github.com/IDFoundry/OID4VCgo/commit/67979709630478422665733ed31711a9af57798c))
* **verifier:** answer an unencrypted same-device error response with the redirect_uri ([50f2968](https://github.com/IDFoundry/OID4VCgo/commit/50f2968869f4ebc3231160f1e7fa3ec76649fd61))
* **verifier:** bound the clock skew and Key Binding JWT age a Verifier allows ([f9e3174](https://github.com/IDFoundry/OID4VCgo/commit/f9e3174563d71f2602bc68c48236934bac03241c))
* **verifier:** keep an mdoc's document signer checks through wrapped resolvers, and trust only the path that passed them ([ceeb9e2](https://github.com/IDFoundry/OID4VCgo/commit/ceeb9e27691bfd1fcd05fb5ce518361aa2e04f12))
* **verifier:** production must decide which issuers may issue which types, and whether revocation is checked ([267406e](https://github.com/IDFoundry/OID4VCgo/commit/267406ea0a3f81955171c2485dfc32d124d10651))
* **wallet:** check a request's DCQL query when it's parsed, ignoring exact duplicate claims ([c67b958](https://github.com/IDFoundry/OID4VCgo/commit/c67b958fcded97910a41c7760064275f8ee76e0f))
* **walletflow:** bound the credential_identifiers an issuance requests ([f57232f](https://github.com/IDFoundry/OID4VCgo/commit/f57232f301f721fb1050a4a82c3e163af867b7c9))
* **walletflow:** present one copy per credential per response, prefer valid copies, and keep a batch's copies alike ([67d81f2](https://github.com/IDFoundry/OID4VCgo/commit/67d81f279280f9c82658864bbb24cd61f727e0e6))
* **walletflow:** refuse a production wallet that can't safely receive credentials when it's made, not later ([af4f322](https://github.com/IDFoundry/OID4VCgo/commit/af4f32215428431595c3caeea19aff2c39e94465))
* **wallet:** follow an app's redirect_uri, accept application/jwt request objects, and send DC API errors as A.4 shapes them ([29051ac](https://github.com/IDFoundry/OID4VCgo/commit/29051acbd0c1b9baf5e34f65e35caa9584c6d8e5))
* **wallet:** preview what a presentation actually discloses ([b7a24a2](https://github.com/IDFoundry/OID4VCgo/commit/b7a24a206f29323326f9a5a358565f883fac6b3f))
* **wallet:** read errors from WWW-Authenticate, accept a fractional interval, and check a credential response's shape ([b1c0063](https://github.com/IDFoundry/OID4VCgo/commit/b1c006330b96698382578392d32f30d1a8964c70))
* **wallet:** refuse a Request Object for another audience, expired, or not yet valid ([4f3fc52](https://github.com/IDFoundry/OID4VCgo/commit/4f3fc5288083b6f411885468342452b0b5192f71))
* **wallet:** refuse an offer's credential_issuer with a query, always send Accept for metadata, and keep event_description to its characters ([1e01efb](https://github.com/IDFoundry/OID4VCgo/commit/1e01efb0105c5bbaea80ac33e51993dcb647f00a))

## [0.46.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.45.0...v0.46.0) (2026-10-17)


### ⚠ BREAKING CHANGES

* **issuer:** New refuses a Config.Issuer with a query or fragment.
* **walletflow:** StartPresentation returns a *RequestRefusedError (errors.Is ErrRequestRefused), no longer wrapping the *wallet.RequestRejectedError, for an authentic request the wallet refuses, after sending the Verifier the error response. StartDCAPIPresentation returns it, not ErrMalformedRequest, for such a request. On mobile, these are request_refused, not invalid_input.
* VerifyResponseRequest.MaxKeyBindingAge (and Transactions' Verify.MaxKeyBindingAge) is required for every dc+sd-jwt credential query, not only those requiring holder binding. A presentation of a cnf-bound credential without a valid KB-JWT is refused even where the query doesn't require holder binding.
* **mobile:** outside development, NewWallet refuses issuer_roots sharing a trust anchor with another role's unless issuer_require_eku is set, and mdoc_reader_roots sharing one unless mdoc_reader_require_eku is set.
* **walletflow:** StartIssuance and ResumeIssuance refuse a credential configuration whose format the wallet can't verify, or that names no vct or doctype, with an error wrapping ErrFormatUnsupported. ResumeIssuance applies the issuance profile, so a resumed issuance can now fail with ErrProfileViolation.
* **issuer:** an access token that doesn't authorize the requested Credential Configuration is answered 403 insufficient_scope, not 400 invalid_credential_request. AssuranceProduction requires SDJWTSigner.IssuerCertificate. A batch proving one key twice is refused. No notification_id is issued without Endpoints.Notification. New refuses proof signing algorithms it can't verify.
* **verifier:** VerifyResponse refuses a whole response in which any presentation is bound to another nonce or audience, rather than discarding that presentation. It also refuses more than 32 presentations for one credential query, and an Origin that isn't a serialized origin. BuildDCAPIAuthorizationRequest refuses such an expected_origins entry.
* **issuer:** RequestCredential refuses claims whose vct (or aka_vcts) or docType isn't the resolved Credential Configuration's, where it signed them before. Build claims for CredentialRequest.ResolvedConfigurationID.
* **statuslist:** a status list for an SD-JWT VC without an issuer name must now be signed with the credential's own key, or by a Status Issuer a StatusIssuerPolicy accepts. An mdoc's revocation list must chain to the Certificate its MSO's status names, or else to the CA that signed its document signer; one signed under another trusted CA is refused unless a StatusIssuerPolicy accepts it.
* **verifier:** verifier.IssuerAuthorization.Issuer is empty unless the issuer key resolver checked iss against the certificate (X5CIssuerKeyResolver.RequireIssuerName). A hook allowing issuers by name sees "" and refuses until that's set. Use ClaimedIssuer for the unchecked value, and IssuerChain to decide from the certificate.

### Features

* **mobile:** an issuer EKU, and the shared-anchor check for every role ([97fccd4](https://github.com/IDFoundry/OID4VCgo/commit/97fccd4284ffb973ed0888b30bfa686fee7c5b79))
* **wallet:** bind signed issuer metadata to the issuer, and bound its age ([78d75d8](https://github.com/IDFoundry/OID4VCgo/commit/78d75d8d6573ef54140a2c77433c32ce8dbfc26e))
* **walletflow:** issuer trust options: signed issuer metadata and the iss check ([18cc625](https://github.com/IDFoundry/OID4VCgo/commit/18cc62533bd8425d62a7a3a97468c360846542a5))
* **walletflow:** show the holder which claims the Verifier will keep ([8c6d61d](https://github.com/IDFoundry/OID4VCgo/commit/8c6d61d0c081aff1ab832037c206edbd66257df3))
* **wallet:** honor the Verifier's vp_formats_supported ([a0ee614](https://github.com/IDFoundry/OID4VCgo/commit/a0ee61400d5189e93807651a3345d85b1c1d3272))


### Bug Fixes

* a key-bound SD-JWT VC is always presented with a KB-JWT, and it's always checked ([e7c52b4](https://github.com/IDFoundry/OID4VCgo/commit/e7c52b4ed9ef67a54147060e8dc85b95f41b3091))
* a Status List Token or key attestation is expired at its exp ([492dee9](https://github.com/IDFoundry/OID4VCgo/commit/492dee9ad24c903ae800ce906c1e544683bedab7))
* **certchain:** refuse a signing leaf whose key usage doesn't allow signatures ([85b5717](https://github.com/IDFoundry/OID4VCgo/commit/85b57178a08f608d000bf97ed74ff883355980a7))
* **cose:** accept alg -9 (ESP256) as ES256 when verifying ([f72f49c](https://github.com/IDFoundry/OID4VCgo/commit/f72f49c9bf26fcbfa02c55957f15aa7bf3cc595c))
* **dcql:** check trusted_authorities chains at the verification time ([cd20e80](https://github.com/IDFoundry/OID4VCgo/commit/cd20e80db624556559c9eda1750277349e7fff92))
* **deps:** pin FAPIgo v0.57.1 ([3e9c5dc](https://github.com/IDFoundry/OID4VCgo/commit/3e9c5dc3e16eb41d33ed70617930b88e495e7847))
* **ecdsafixed:** refuse an out-of-range signature instead of panicking ([0fa73ae](https://github.com/IDFoundry/OID4VCgo/commit/0fa73ae1570b168b476642bdd4d57019ee3838c4))
* **issuer:** mark error and Deferred Credential Responses no-store ([d3aaefd](https://github.com/IDFoundry/OID4VCgo/commit/d3aaefdcba10c9d741cc337e1e1c59b898c62dc2))
* **issuer:** OpenID4VCI and HAIP conformance at the credential endpoint ([6c77c01](https://github.com/IDFoundry/OID4VCgo/commit/6c77c0174906b15d3dba7cea2c0c1d5b7265a0fa))
* **issuer:** refuse a Credential Issuer Identifier with a query or fragment ([5469d34](https://github.com/IDFoundry/OID4VCgo/commit/5469d34444cef3129031bac7f796b96824d1c104))
* **issuer:** refuse a trust anchor in a key attestation's x5c, and check it at the issuer's clock ([ee536e5](https://github.com/IDFoundry/OID4VCgo/commit/ee536e5663ce68d10b9a2090941276ad621f9b51))
* **issuer:** sign only credentials of the configuration the token authorized ([822c6be](https://github.com/IDFoundry/OID4VCgo/commit/822c6be8144fd40eca480f5317f913787097c9a5))
* match JSON and CBOR member names exactly, and refuse duplicate CWT claims ([77a09b0](https://github.com/IDFoundry/OID4VCgo/commit/77a09b0bde0f90eae8191b8d42d7fb5b777da5e0))
* **registration:** check the registrar's certificate at the verification time ([e33cec0](https://github.com/IDFoundry/OID4VCgo/commit/e33cec0ae3b92b929e885e79152acc1f0c3da2c6))
* **sdjwtvc:** a disclosure's form by its arity, a non-string _sd_alg, and what Issue can sign ([d5ea252](https://github.com/IDFoundry/OID4VCgo/commit/d5ea252e9a1dbcf94a9506d6142aa7e6275b13ec))
* **sdjwtvc:** seal SD markers inside typed containers, and refuse the ones it can't ([abc68c1](https://github.com/IDFoundry/OID4VCgo/commit/abc68c1f674dd7a53927f21e41682e5ed7a6612c))
* **statuslist:** bind a status list's signer whenever the credential's issuer is known ([8c74352](https://github.com/IDFoundry/OID4VCgo/commit/8c743527d08fd64c8a39be0af9a38d6b8df1f595))
* **statuslist:** refuse to publish with a chain HAIP forbids ([2cbb71c](https://github.com/IDFoundry/OID4VCgo/commit/2cbb71c9bc9ffc8d06c84233377491038f88a9a1))
* **verifier:** answer same-device declines with a redirect_uri, and acknowledge unencrypted error responses ([0327719](https://github.com/IDFoundry/OID4VCgo/commit/0327719885bfdfecbcee573f044cc2c65def2198))
* **verifier:** give IssuerAuthorized a checked issuer name only ([547c4fd](https://github.com/IDFoundry/OID4VCgo/commit/547c4fdad6b13e3834f5ae477204ebe51be4df69))
* **verifier:** refuse a response carrying another request's presentation, and tighten what a response may carry ([6c5f397](https://github.com/IDFoundry/OID4VCgo/commit/6c5f397a543d77d0de52b30e2d2a3153039d8786))
* **wallet:** check an issued credential's certificate at its own time, and read only the status list ([45c9ed4](https://github.com/IDFoundry/OID4VCgo/commit/45c9ed42ba90bacf7818ae368732216c50a38636))
* **walletflow:** keep a presentation's copies presented once the Verifier has replied ([ed12e57](https://github.com/IDFoundry/OID4VCgo/commit/ed12e578dac6df38be8439be929d884281d7600b))
* **walletflow:** refresh and revoke credentials whose configuration has no scope ([e8f8a45](https://github.com/IDFoundry/OID4VCgo/commit/e8f8a45f2fd496d8c5019e184b4a7b2c56f652d2))
* **walletflow:** refuse a credential the wallet can't receive, and recheck a resumed issuance ([f15209d](https://github.com/IDFoundry/OID4VCgo/commit/f15209dc7e677bb53132bb2a615ce568595035d7))
* **walletflow:** request every credential_identifier the token grants ([1208b10](https://github.com/IDFoundry/OID4VCgo/commit/1208b102dc002413d460c9366ab04e485de74128))
* **walletflow:** sanitize the issuer's display text and colors ([5d2a66d](https://github.com/IDFoundry/OID4VCgo/commit/5d2a66df7930dd4aaed234c0a483132a4129606e))
* **walletflow:** tell the Verifier when the wallet refuses its request ([21ff492](https://github.com/IDFoundry/OID4VCgo/commit/21ff49292f7ca8e6319899576a5546b50add35ed))
* **walletflow:** track each copy's own status and expiry ([947a9f5](https://github.com/IDFoundry/OID4VCgo/commit/947a9f5d93493e97798af692efeda3a717137659))

## [0.45.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.44.0...v0.45.0) (2026-10-16)


### Features

* **sdjwtvc:** check issued claims against their published Type Metadata ([673ce00](https://github.com/IDFoundry/OID4VCgo/commit/673ce004cf7a1d8dc31b443701f5011baf23429c))


### Bug Fixes

* **mdoc:** accept an IssuerAuth x5chain in the protected header ([99a91cd](https://github.com/IDFoundry/OID4VCgo/commit/99a91cdf24c87e2647a81bddd2bdb55617b20c71))
* **sdjwtvc:** require HTTPS or data: rendering URIs in TypeMetadata ([49d7834](https://github.com/IDFoundry/OID4VCgo/commit/49d7834c960a3bd2fbefd5e1e32ff15eada319ac))
* **statuslist:** answer a historical status list request with 501 ([81f5c5a](https://github.com/IDFoundry/OID4VCgo/commit/81f5c5aec34fc9efb5c198f550c66bb7f7bf573e))
* **statuslist:** check a token signer's certificates at VerifyOptions.Now ([62f0c11](https://github.com/IDFoundry/OID4VCgo/commit/62f0c113dcd1726e4d3c16ca957e73978a524cd6))
* **walletflow:** don't fetch an expired credential's status list ([485c955](https://github.com/IDFoundry/OID4VCgo/commit/485c955c8ad0bd44d39d04524be7e5d2292c6d59))
* **wallet:** refuse a request with no nonce or dcql_query ([5530caf](https://github.com/IDFoundry/OID4VCgo/commit/5530cafdd129b4160df755354565268e6f268240))

## [0.44.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.43.0...v0.44.0) (2026-10-16)


### ⚠ BREAKING CHANGES

* **sdjwtvc:** sdjwtvc.Verify refuses an Issuer-signed JWT whose typ is vc+sd-jwt, and sdjwtvc.LegacyTypHeader is removed. Issuers still using vc+sd-jwt must move to dc+sd-jwt (sdjwtvc.TypHeader).
* **sdjwtvc:** sdjwtvc.Verify, and with it the verifier and wallet, refuses an SD-JWT VC that makes a sub-claim of cnf, status or another registered claim selectively disclosable, and sdjwtvc.Issue refuses SD markers in Claims.Status and Claims.CNF.
* **verifier:** a SD-JWT VC, Request Object or signed metadata whose x5c includes a self-signed certificate after the leaf is refused; send the chain without the trust anchor. With VerifyResponseRequest.Now (or mdocdcapi's Now) set, issuer certificates are checked at that instant, not the current time.
* **verifier:** RequireValidStatus and walletflow's CheckStatus refuse an SD-JWT VC's Status List Token that another issuer signed: its signer must sign with the key that signed the credential, or have a certificate naming the credential's iss. A deployment whose status lists come from a separate Status Issuer names it with verifier.RequireValidStatusFrom (a StatusIssuerPolicy) or walletflow.Config.StatusIssuers (status_issuers in the mobile libraries).

### Features

* **sdjwtvc:** aka_vcts, and match vct_values by a credential's other types ([56748de](https://github.com/IDFoundry/OID4VCgo/commit/56748de0231f28ff93cd7dc441c67013138dadaf))
* **verifier:** IssuerAuthorized, an explicit per-type issuer authorization check ([841b673](https://github.com/IDFoundry/OID4VCgo/commit/841b673fd290a55938008c96be010b86e1acb019))
* **verifier:** RequireValidStatusFrom accepts a separate Status Issuer ([a860065](https://github.com/IDFoundry/OID4VCgo/commit/a86006503de1df9f55277b03b0be3656b97e1544))
* **walletflow:** Config.StatusIssuers for issuers whose status lists a Status Issuer signs ([321a7a8](https://github.com/IDFoundry/OID4VCgo/commit/321a7a8c32463d7ac707b8ccae488449d4b8f085))
* **wallet:** name the Credential Issuer as the resource of pre-authorized code tokens ([166e39c](https://github.com/IDFoundry/OID4VCgo/commit/166e39c78398c52481df5de3ef71f45a4242a925))


### Bug Fixes

* refuse a COSE structure behind a CBOR tag other than its own ([bb2b8a1](https://github.com/IDFoundry/OID4VCgo/commit/bb2b8a1d007e2885818de55492def23871e43d99))
* **sdjwtvc:** accept only the dc+sd-jwt typ ([e6d055b](https://github.com/IDFoundry/OID4VCgo/commit/e6d055b5550a1ff4bdfcc97356b9e47f57c81bea))
* **sdjwtvc:** check a Key Binding JWT's exp and nbf ([ea51c0e](https://github.com/IDFoundry/OID4VCgo/commit/ea51c0ef984dbf2cd0d191b4a72d52c8001ecc4d))
* **sdjwtvc:** refuse selectively disclosable sub-claims of registered claims ([ec1e0df](https://github.com/IDFoundry/OID4VCgo/commit/ec1e0dfaad9a4f37c77889c3bf68eae6760c46b9))
* **statuslist:** refuse a truncated or corrupt status list ([de244fe](https://github.com/IDFoundry/OID4VCgo/commit/de244fe96cb54f137c24ff4cc7c9b9ab5d4062e1))
* **verifier:** accept a status list signed with the credential's own key, whatever names its certificate carries ([58e24ff](https://github.com/IDFoundry/OID4VCgo/commit/58e24ffa6f2d8fd838ccafd3bd39a69a22d3ebeb))
* **verifier:** refuse a status list another issuer signed ([e51915c](https://github.com/IDFoundry/OID4VCgo/commit/e51915c5ad582db6ddce2a842e931590bfeaa77a))
* **verifier:** refuse a trust anchor sent in x5c, and check certificates at the verification time ([8df41e8](https://github.com/IDFoundry/OID4VCgo/commit/8df41e8d14932b2a3c3ff2b290e8e5061eec068b))
* **verifier:** RequireIssuerName, an opt-in check that an SD-JWT VC's iss names its x5c certificate, in the verifier's X5CIssuerKeyResolver and the wallet's VerifyIssuedCredentialParams ([4ec198d](https://github.com/IDFoundry/OID4VCgo/commit/4ec198d4faa9f99ebb0096c3da39dba787d32fe8))
* **verifier:** report a malformed direct_post.jwt response as a verifier.Error ([59b75c6](https://github.com/IDFoundry/OID4VCgo/commit/59b75c61a4e77d0d3bef2f20d158f03d0e4cffde))

## [0.43.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.42.0...v0.43.0) (2026-10-15)


### ⚠ BREAKING CHANGES

* **deps:** in fapigo/server, a TokenEndpointRequest's Parameters() no longer includes resource: a deployment serving its own token-endpoint grant type (an OpenID4VCI pre-authorized code grant beside issuer, say) that reads Parameters()["resource"] must read Resources() instead, and pass them in IssueAccessTokenRequest.Resources. With opaque access tokens, the server now records each token's audience and serverresource.NewVerifier checks it. See FAPIgo's UPGRADING.md, v0.57.0.

### Features

* **sdjwtvc:** ErrKeyBinding for a Key Binding JWT that fails ([0884c0e](https://github.com/IDFoundry/OID4VCgo/commit/0884c0eb695e5ee55ddced51a564db49e71b1c5c))
* **verifier:** Error.Reason says why verification failed ([9d8a2cb](https://github.com/IDFoundry/OID4VCgo/commit/9d8a2cb159f4a6446689b9fd4d4546069cb30da2))
* **walletflow:** ErrTxCodeRefused for a PIN the issuer refused ([92639d7](https://github.com/IDFoundry/OID4VCgo/commit/92639d7a69fac055b9d204709bb27326c3edc12a))
* **wallet:** say which endpoint an Error came from ([852fa04](https://github.com/IDFoundry/OID4VCgo/commit/852fa044e7f5c0100b28392b8fbeaa0bd5b8f614))
* **wallet:** send resource through fapigo/client, so the token request names it too ([3e809aa](https://github.com/IDFoundry/OID4VCgo/commit/3e809aa0ac6e41c2a3c7411a6dff1ece113c57cc))


### Bug Fixes

* **deps:** pin FAPIgo v0.57.0 ([4b0b0ae](https://github.com/IDFoundry/OID4VCgo/commit/4b0b0ae926788a7c1e40d045a507f7a39395b056))

## [0.42.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.41.1...v0.42.0) (2026-10-15)


### ⚠ BREAKING CHANGES

* **wallet:** under AssuranceProduction, wallet.New (and so walletflow.New) refuses a Dependencies.HTTP other than nil or fapihttp.NewClient's client with its transport intact and no loopback exception.
* **deps:** under production assurance, FAPIgo now refuses a client.Dependencies.HTTP that isn't fapihttp.NewClient's client with its transport intact (no Proxy, custom dialer, clone, wrapper such as an OpenTelemetry RoundTripper, or TLS verification change after construction), a JWKS key source fetched over any other client, and, with OpenID Federation, such a FederationHTTP. A walletflow wallet given Dependencies.HTTP, and an issuer or verifier deployment wiring fapigo/client, fapigo/server or keys.NewJWKSIssuerKeySource, must build that client with fapihttp.NewClient and set mutual TLS, a private CA (TransportConfig.RootCAs) or pinning in its TransportConfig. See FAPIgo's UPGRADING.md, v0.56.0.
* **issuer:** CredentialHandler, DeferredCredentialHandler and NotificationEndpointHandler refuse a URL other than the one Config.Endpoints publishes for them. Leave URL nil, or set it to that.
* **verifier:** Transactions.Begin refuses a query its TransactionsConfig.Verify can't verify an answer to (see above), where it used to create a request every answer to which would fail.
* **verifier:** for an mdoc, IssuerChain is the verified path, which can differ from the presented x5chain, and is nil when MdocIssuerKeys/IssuerKeys isn't an MdocIssuerChainResolver; a trusted_authorities query then fails for that credential.
* **walletflow:** Presentation.Decline's Presented.DCAPIResponse for a DC API request is {"error": "access_denied"} rather than {"response": <JWE>}. A Verifier page reading the decline should check data.error before data.response.
* **issuer:** under AssuranceProduction, CreateCredentialOffer refuses an offer with a pre-authorized code grant. Use CreatePreAuthorizedOffer instead.
* **issuer:** issuer.New refuses a credential configuration whose jwt proof type sets KeyAttestationsRequired; put the requirement on the attestation proof type instead. A Credential Request with more than one key attestation is refused with invalid_proof.
* **issuer:** a PreAuthorizedCodeStore must return ErrTxCodeRequired when the record has a TxCode and wantTxCode is empty (without counting an attempt), and ErrTxCodeUnexpected when the record has none and wantTxCode isn't empty (without consuming the code); issuertest.TestPreAuthorizedCodeStoreContract checks both. Token requests with a DPoP proof that doesn't verify get invalid_dpop_proof rather than invalid_request.
* **dcql:** dcql.Query.Validate, and so verifier.New, BuildAuthorizationRequest and the wallet's request parsing, refuse an empty claims, claim_sets or values array, a values element that isn't a string, integer or boolean, and an mso_mdoc claims path that isn't two strings. Leave an empty array out instead.
* under AssuranceProduction, issuer.New refuses a self-signed SDJWTSigner.IssuerCertificate or MdocSigner.X5Chain leaf, and verifier.New a self-signed ClientCertificate; use certificates issued by a CA the other side trusts. issuer.New also refuses a signer whose certificate's key isn't its own, at any assurance, and SignMetadataJWS refuses a self-signed certificate.
* **mdoc:** verifier.VerifyResponse, mdocdcapi.VerifyResponse and the proximity reader refuse a Photo ID (org.iso.23220.1) or EU PID (eu.europa.ec.eudi.pid.1) whose disclosed issuing_country isn't the document signer certificate's countryName, or whose issuing_jurisdiction isn't its stateOrProvinceName when it has one. Issuers set issuing_country to their own country.
* **verifier:** verifier.New refuses an EncValuesSupported value other than A128GCM, A192GCM or A256GCM, and, under AssuranceProduction, a list without both A128GCM and A256GCM. haip.RecommendedVerifierConfig already lists both.
* **issuer:** issuer.New refuses a Config with ResponseEncryption and no RequestEncryption. Configure RequestEncryption too (it can stay optional, Required false), or drop ResponseEncryption.
* under AssuranceProduction, issuer.New refuses a Dependencies.Random other than crypto/rand.Reader, any http URL in its Config, and an AttestationVerifier without AttestationStatus unless Config.NoAttestationStatusCheck is set; verifier.NewTransactions refuses a config with neither Accept nor NoStatusCheck. Use crypto/rand.Reader and https URLs; set AttestationStatus (an issuer.AttestationStatusChecker) and Accept (e.g. a status list check), or the explicit opt-outs.

### Features

* **issuer:** CreatePreAuthorizedOffer builds a pre-authorized offer in one step ([cf738d4](https://github.com/IDFoundry/OID4VCgo/commit/cf738d4bc4b7feb87b0337b20c622568c96bc5e4))
* **proximity:** WithIssuerRootsByDocType for the reader ([29ff39f](https://github.com/IDFoundry/OID4VCgo/commit/29ff39f7546d1be131e6db18e42fdbc16066af66))
* **registration:** register claims for a given type of credential ([9aef1a9](https://github.com/IDFoundry/OID4VCgo/commit/9aef1a91e41c9389803d9088e3a004efa481ab8f))
* send intermediate certificates in x5c, and refuse self-signed signers in production ([6184dd7](https://github.com/IDFoundry/OID4VCgo/commit/6184dd770873369f9c6e635336d7c28d52737e60))
* **verifier:** hold each mdoc document type to its own issuer roots ([96c037e](https://github.com/IDFoundry/OID4VCgo/commit/96c037e21c6e3fc4126f3cb942d2c9e80690313e))
* **verifier:** RequireValidStatus, an Accept that refuses non-VALID credentials ([90c4df0](https://github.com/IDFoundry/OID4VCgo/commit/90c4df0b531cd341d307d3b9e2f76d7010ee7d27))
* **wallet:** name the Credential Issuer as the authorization request's resource ([7619685](https://github.com/IDFoundry/OID4VCgo/commit/7619685af5b41c39042e0ea501769d85b3166d7e))
* **wallet:** present SD-JWT VC claims addressed into arrays ([b9f23fc](https://github.com/IDFoundry/OID4VCgo/commit/b9f23fc871af69ce945298c2c8f7dd499ae40b8d))
* **wallet:** show the holder which mdoc elements a verifier will keep ([86e31a7](https://github.com/IDFoundry/OID4VCgo/commit/86e31a7a0e59c1884c14e55f8837e67fc5f19436))
* **wallet:** verify signed Credential Issuer Metadata ([8375145](https://github.com/IDFoundry/OID4VCgo/commit/83751450529f6d5fcded81d73492664e6cc0d4f6))


### Bug Fixes

* count a tx_code description's characters, not its bytes ([2fa02e7](https://github.com/IDFoundry/OID4VCgo/commit/2fa02e7f4136389822c9b20df13fdf795574cacc))
* **dcql:** bound a query's size ([97acfa7](https://github.com/IDFoundry/OID4VCgo/commit/97acfa7f223ff448ae4d96525025f3e0ddfeb5dd))
* **dcql:** convert an mdoc's CBOR value to JSON before matching values ([2837c4a](https://github.com/IDFoundry/OID4VCgo/commit/2837c4a8c15d72c73c929e878afe56d2b23b8ec9))
* **dcql:** refuse claims queries OpenID4VP rules out ([b6dacd8](https://github.com/IDFoundry/OID4VCgo/commit/b6dacd8897d8c1e3a420833ae74353b10f53351c))
* **deps:** pin FAPIgo v0.56.0 ([9a8046e](https://github.com/IDFoundry/OID4VCgo/commit/9a8046ecfc83b1c30d29c5c74a58bb400b645d8b))
* **issuer:** build production pre-authorized offers only with CreatePreAuthorizedOffer ([26b61cb](https://github.com/IDFoundry/OID4VCgo/commit/26b61cb76f86fb99ed58b46979548578471a0a69))
* **issuer:** default handler URLs to the published endpoints, and refuse others ([f81fe00](https://github.com/IDFoundry/OID4VCgo/commit/f81fe00a1a795bc3637a0d908fa6551481f6aa39))
* **issuer:** keep error_description to the characters it allows ([92461d0](https://github.com/IDFoundry/OID4VCgo/commit/92461d016a3117d97a5f685194f217a3b856057b))
* **issuer:** refuse proof configurations and requests Appendix F rules out ([6ec13cc](https://github.com/IDFoundry/OID4VCgo/commit/6ec13cc6b1173ad95def95b942bcdf7bac2c0467))
* **issuer:** refuse response encryption without request encryption ([69a87bd](https://github.com/IDFoundry/OID4VCgo/commit/69a87bd5b5cf4e1b410da464580e8b43d46af75f))
* **issuer:** report tx_code and DPoP errors at the token endpoint as OID4VCI says ([3ce3595](https://github.com/IDFoundry/OID4VCgo/commit/3ce35951b4ce9e50d609e8dae74b3626743768ba))
* **mdoc:** bound the CBOR an untrusted mdoc decodes to ([8d7c1cf](https://github.com/IDFoundry/OID4VCgo/commit/8d7c1cfe2c219dc043965225206558f10f8ac404))
* **mdoc:** hold a photo ID's and a PID's issuing_country to the document signer ([e40d4b6](https://github.com/IDFoundry/OID4VCgo/commit/e40d4b63ac575e05134e1b201b2ada4d5d80762e))
* **mdoc:** refuse an empty document signer path instead of panicking ([c131fb0](https://github.com/IDFoundry/OID4VCgo/commit/c131fb0908de902aea8660ac1f3da50abbcf6ab4))
* read a parameterised application/jwt Content-Type as encrypted ([3dc28c8](https://github.com/IDFoundry/OID4VCgo/commit/3dc28c838e5b5c4f242fa62e802a64819e5c1085))
* refuse production configurations that would weaken issuance or verification ([ba1dadb](https://github.com/IDFoundry/OID4VCgo/commit/ba1dadbe11424e267dd683eacec4bddbea0f9289))
* **statuslist:** read one status in constant memory, not the whole list ([7fbe695](https://github.com/IDFoundry/OID4VCgo/commit/7fbe69555b77d4c9c20fb821f99c858afec7e406))
* **statuslist:** return INVALID with every error, and add RequireValid ([df1495e](https://github.com/IDFoundry/OID4VCgo/commit/df1495e5724924ea77269f7335024e7c96871a11))
* **verifier:** advertise only enc values it can decrypt, and HAIP's pair in production ([069c88b](https://github.com/IDFoundry/OID4VCgo/commit/069c88b68deeee31b17ab482e71aba260187f53c))
* **verifier:** discard a presentation that fails, not the whole response ([145d928](https://github.com/IDFoundry/OID4VCgo/commit/145d92888ba794a3832abc411b7afebde0ea5271))
* **verifier:** hand out only the verified mdoc issuer chain ([03fa2f4](https://github.com/IDFoundry/OID4VCgo/commit/03fa2f42c3b3b019c196f24c06759348955caab6))
* **verifier:** refuse requests Transactions can't verify, and answer its own faults with 500 ([6fab9e3](https://github.com/IDFoundry/OID4VCgo/commit/6fab9e3eb6b48fd0b606c3fa00be26d4e93be5b7))
* **wallet:** default to fapihttp's hardened client, and follow no redirect ([f437ddd](https://github.com/IDFoundry/OID4VCgo/commit/f437ddd885bfade5b0523033c75ef7869dff849a))
* **wallet:** encrypt a presentation to an ECDH-ES key with the strongest enc ([b3bdb56](https://github.com/IDFoundry/OID4VCgo/commit/b3bdb561295ccebab912793ccaf4d3bdf6740603))
* **walletflow:** decline a DC API request with Appendix A.4's error object ([cc3424f](https://github.com/IDFoundry/OID4VCgo/commit/cc3424f44782303b5b0e7f20cf16374771cfcbb5))
* **walletflow:** don't present a credential refreshed since the holder was shown it ([f6d7acf](https://github.com/IDFoundry/OID4VCgo/commit/f6d7acf77a938a8ebe6eced3d07c14a142072e79))
* **wallet:** honour require_cryptographic_holder_binding when presenting ([5f79e00](https://github.com/IDFoundry/OID4VCgo/commit/5f79e00984c6f9cc106c78842f89bda9111a228d))
* **wallet:** inflate a compressed Credential Response to at most 16 MiB ([0ef30c6](https://github.com/IDFoundry/OID4VCgo/commit/0ef30c61b4dfd989bb8408619b2a0d9bc3308bdd))
* **wallet:** issue in plaintext when optional encryption can't be used ([f0c42c2](https://github.com/IDFoundry/OID4VCgo/commit/f0c42c2e2968d209bd41960fc2b212234c87991a))
* **wallet:** take only fapihttp's hardened HTTP client in production ([33468fc](https://github.com/IDFoundry/OID4VCgo/commit/33468fc417b4af8853dc3e46468e9834ad37da0a))

## [0.41.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.41.0...v0.41.1) (2026-10-14)


### Bug Fixes

* **wallet:** name always-disclosed claims in a selection's preview too ([0afdb2c](https://github.com/IDFoundry/OID4VCgo/commit/0afdb2c5e86c8078e34d93d6e45440893332d9d6))

## [0.41.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.40.1...v0.41.0) (2026-10-13)


### ⚠ BREAKING CHANGES

* **deps:** an application pairing OID4VCgo with fapigo/server gets FAPIgo v0.55.0's changes. A server.Config that isn't OAuthOnly must set Subjects; server.PublicSubjects keeps every sub as it is. Code reading resource.AuthorizationContext.Subject reads InternalSubject instead; SubjectKind keeps its name. See FAPIgo's UPGRADING.md for v0.55.0.

### Bug Fixes

* **deps:** pin FAPIgo v0.55.0 ([294be98](https://github.com/IDFoundry/OID4VCgo/commit/294be98445b7698d3d77347a8ad795fcafc64e56))

## [0.40.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.40.0...v0.40.1) (2026-10-12)


### Bug Fixes

* **deps:** update fxamacker/cbor to v2.9.6 ([e416737](https://github.com/IDFoundry/OID4VCgo/commit/e4167379cc865d2ce44957d4c4f8559ed09286aa))

## [0.40.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.39.0...v0.40.0) (2026-10-11)


### ⚠ BREAKING CHANGES

* **deps:** an application pairing OID4VCgo with fapigo/server gets FAPIgo v0.54.0's changes. CompleteAuthorization refuses an Authorize whose authentication time is in the future; pass the time the user authenticated to NewAuthenticationContext, which also refuses one before 1970. The fapigo client refuses an ID token whose auth_time is in the future. Under production assurance with CIBA, keep MaxBackchannelAuthenticationRequestLifetime at 60 minutes or less, and keep openid in a CIBA approval's granted scope. See FAPIgo's UPGRADING.md for v0.54.0.
* **statuslist:** a Status List Token without an iat, or issued more than a minute in the future, is refused. Set VerifyOptions.MaxClockSkew for a status list issuer whose clock runs further ahead, and MaxAge to bound how stale a list may be.
* **verifier:** VerifyResponse and mdocdcapi.VerifyResponse, with X5ChainIssuerKeyResolver, refuse an mdoc whose document signer certificate's countryName differs from its IACA's (or neither has one, which Annex B makes mandatory), which was signed outside the DS certificate's validity, or whose mDL issuing_country or issuing_jurisdiction doesn't match the DS certificate. trusted_authorities fails for a credential whose header chain didn't sign it. mdocdcapi.Verified.IssuerChain is nil in that case.
* **dcql:** with AKITrustedAuthoritiesChecker.Roots, an "aki" value naming an intermediate CA whose Subject Key Identifier isn't derived from its key (method 1 SHA-1, or SHA-256 truncated to 160 bits) no longer matches. Name the trust anchor, or the intermediate's key-derived identifier.

### Features

* **issuer:** redeem a pre-authorized code without issuing its token ([20d2be8](https://github.com/IDFoundry/OID4VCgo/commit/20d2be831abba0ed18acb7af28a4e889472d1cd1))
* **mdoc:** compute DeviceMac from an ECDH shared secret ([791b329](https://github.com/IDFoundry/OID4VCgo/commit/791b3294d68386d4a3cd5fa65716293c372cbd30))
* **mdocdcapi:** report the requested elements a document didn't disclose ([3145a5c](https://github.com/IDFoundry/OID4VCgo/commit/3145a5c1cb74840fc6921bc21f6f3af605bd61fb))
* **proximity:** answer with MAC device authentication ([b7c164e](https://github.com/IDFoundry/OID4VCgo/commit/b7c164e35a72f49909e4558b268879a9fe03cca7))
* **walletflow:** prefer MAC device authentication in person ([d5fd7b8](https://github.com/IDFoundry/OID4VCgo/commit/d5fd7b8aecf62ddad2042df6847eff861dc2a340))
* **wallet:** the preview names the claims every presentation discloses, and the copy that's sent ([5c1c6b0](https://github.com/IDFoundry/OID4VCgo/commit/5c1c6b0e432dfd776e91e67c02b5f1d5dc8484cd))


### Bug Fixes

* **android:** keep a holder key in StrongBox rather than move it to the TEE to agree keys ([fdf676c](https://github.com/IDFoundry/OID4VCgo/commit/fdf676c93743c0a3efc61f184c3b6be35573b486))
* compare JWT times instead of negating ages, and refuse dates outside 1970–9999 ([9197622](https://github.com/IDFoundry/OID4VCgo/commit/91976222e2820df294dd33ad7c35400e3002acbd))
* **dcql:** match an intermediate CA only by a key identifier derived from its key ([a7fadf0](https://github.com/IDFoundry/OID4VCgo/commit/a7fadf091d7e6828c91f7e69803ec23be2e32e26))
* **deps:** pin FAPIgo v0.54.0 ([5af8405](https://github.com/IDFoundry/OID4VCgo/commit/5af84058f8d2de58fd7f7c98506e1c3517e29068))
* **issuer:** a pointer client-authentication choice, and deferred notification_ids bound to the holder ([9972b2e](https://github.com/IDFoundry/OID4VCgo/commit/9972b2e63e4f24bdaa477577159c426502e5ebc4))
* **jwk:** refuse small-order Ed25519 keys, and give each key one thumbprint ([f2c457c](https://github.com/IDFoundry/OID4VCgo/commit/f2c457c2e336eef5bfb87c14d10fc0d08ec8530d))
* **proximity:** limit what one DeviceRequest may ask for ([c73a2b5](https://github.com/IDFoundry/OID4VCgo/commit/c73a2b5612a35bb00f124de847d68f10926f6b02))
* **statuslist:** require a Status List Token's iat, and allow a maximum age ([604f5c2](https://github.com/IDFoundry/OID4VCgo/commit/604f5c221cb7f735fa8ef7baf875b566a1710e3e))
* **verifier:** tie an issuer's chain to the key that verified it, and check mdoc document signers ([74bdf8b](https://github.com/IDFoundry/OID4VCgo/commit/74bdf8bcf30b79963607fb14d9d62b859388cfa6))
* **walletflow:** an issuance's keys survive another closing, and a batch's copies must agree ([2960f37](https://github.com/IDFoundry/OID4VCgo/commit/2960f37c5320d79e96de5edba0d017fe587bd711))
* **walletflow:** trust an in-person reader only when every document request is signed by it ([a3945bc](https://github.com/IDFoundry/OID4VCgo/commit/a3945bc6a45654650d67cfd44c1cb6dcd9784954))

## [0.39.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.38.0...v0.39.0) (2026-10-10)


### ⚠ BREAKING CHANGES

* **deps:** FAPIgo v0.53.0's breaking changes reach applications that use its server beside OID4VCgo's issuer. server.NewSubjectID refuses a value over 255 bytes or outside printable ASCII: use a stable ID of your own as the subject, not a DID or an email address. Under production assurance, server.New refuses Limits outside FAPI 2.0's (MaxClockSkew outside 10 to 60 seconds, an authorization code lifetime over 60 seconds, a pushed request lifetime of 600 seconds or more, a request object lifetime over 60 minutes): start from server.RecommendedLimits, as haip does. A CIBA endpoint can't be combined with OAuthOnly, and a CIBA request needs openid. An id_token_hint or claims sub is now enforced. Sealer and cookie keys that are one byte repeated are refused. See FAPIgo's UPGRADING.md for v0.53.0.
* **issuer:** under AssuranceProduction with Dependencies.PreAuthorizedCodes set, and a PreAuthorizedCodeClientAuthentication other than VerifiedPreAuthorizedCode, issuer.New refuses a Limits.MaxDPoPClockSkew under 10 seconds (zero included) or over 60. Set it to 10 seconds.

### Bug Fixes

* **deps:** pin FAPIgo v0.53.0 ([#542](https://github.com/IDFoundry/OID4VCgo/issues/542)) ([464eeae](https://github.com/IDFoundry/OID4VCgo/commit/464eeaecaa91afd00c6a778022cd9bb0c31f1b16))
* **issuer:** hold the DPoP clock skew to FAPI 2.0's bounds under production ([#542](https://github.com/IDFoundry/OID4VCgo/issues/542)) ([464eeae](https://github.com/IDFoundry/OID4VCgo/commit/464eeaecaa91afd00c6a778022cd9bb0c31f1b16))

## [0.38.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.37.1...v0.38.0) (2026-10-10)


### Features

* **walletflow:** ErrMalformedRequest for a Digital Credentials API request that can't be parsed ([76bf989](https://github.com/IDFoundry/OID4VCgo/commit/76bf98931d6cabedf5e3c019349f89405a3358dc))

## [0.37.1](https://github.com/IDFoundry/OID4VCgo/compare/v0.37.0...v0.37.1) (2026-10-09)


### Bug Fixes

* **issuer:** accept only an end user's access token at the Credential Endpoint ([f9f8d4d](https://github.com/IDFoundry/OID4VCgo/commit/f9f8d4d5709958bb1a81e604074b4659bb0a93b1))

## [0.37.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.36.0...v0.37.0) (2026-10-09)


### ⚠ BREAKING CHANGES

* **deps:** FAPIgo v0.52.0's breaking changes reach applications that use its packages beside OID4VCgo's. A deployment of issuer with fapigo/server or fapigo/serverresource at production assurance must set server.Config.Deployment (and resource.Config's), in place of HorizontallyScaled, and give X5CAttesterChain an anchor source declaring keys.KeySourceAssurance LiveFetchHardened (server.StaticAttesterAnchors and StaticAttesterTrustAnchors do). Every extension.Definition registered beside oid4vci.IssuerStateExtension must set Sensitivity. A client.TokenSet built by hand for RefreshTokens must set Issuer. keys.NewKeyManagerFromSigners takes []keys.SignerSpec. Go 1.26.9 or later is now required, as FAPIgo's go.mod requires it. See FAPIgo's UPGRADING.md for v0.52.0.

### Bug Fixes

* **deps:** pin FAPIgo v0.52.1 ([4155b0d](https://github.com/IDFoundry/OID4VCgo/commit/4155b0db4a69f840985fc1b0ee2c28e00200ad67))

## [0.36.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.35.0...v0.36.0) (2026-10-09)


### Features

* **proximity:** the holder offers mdoc central client mode, or both modes ([797466d](https://github.com/IDFoundry/OID4VCgo/commit/797466d9e3643408828b7735922dbabe295076c4))
* **walletflow:** pin hosts' certificates for the wallet's HTTPS requests (`Config.TLSPins`) ([#506](https://github.com/IDFoundry/OID4VCgo/issues/506)) ([055d13b](https://github.com/IDFoundry/OID4VCgo/commit/055d13bd2079cbd41deaea1fe95859d302f9738c))

## [0.35.0](https://github.com/IDFoundry/OID4VCgo/compare/v0.34.0...v0.35.0) (2026-10-08)


### Features

* **proximity:** reader authentication, status 12, case-sensitive keys ([ae8cdb9](https://github.com/IDFoundry/OID4VCgo/commit/ae8cdb95136ef8d059d41a071e05ece02857d1d8))


### Bug Fixes

* **deps:** pin FAPIgo v0.50.1 ([2bc0e73](https://github.com/IDFoundry/OID4VCgo/commit/2bc0e732c1f01f3cb6655f62403616d7a0d75dec))
* **deps:** pin FAPIgo v0.51.0 ([c92b0cd](https://github.com/IDFoundry/OID4VCgo/commit/c92b0cd23e4a518b8447c4a15c0cf536892cb68b))

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
