# Changelog

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
