# Changelog

## [0.12.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.11.1...sqlstore/v0.12.0) (2026-11-11)


### Features

* **sqlstore:** declare whether the issuer stores seal their records ([31456e9](https://github.com/IDFoundry/OID4VCgo/commit/31456e915f640a05a0cee2695b7b3971bfb00d64))
* **sqlstore:** say whether the Wallet Provider stores seal their records ([2025c13](https://github.com/IDFoundry/OID4VCgo/commit/2025c130d3a9e87eb55e0ebba957f76aeb876744))


### Bug Fixes

* **deps:** pin FAPIgo v0.72.4 and fapigo/sqlstore v0.8.1 ([97e0d80](https://github.com/IDFoundry/OID4VCgo/commit/97e0d80b736bc185683ceb65515b994524c927ab))
* **sqlstore:** require OID4VCgo v0.76.0 ([85e19e1](https://github.com/IDFoundry/OID4VCgo/commit/85e19e15a0f45ef9286471012dcb3ca1cf2347f0))

## [0.11.1](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.11.0...sqlstore/v0.11.1) (2026-11-11)


### Bug Fixes

* build with Go 1.26.11 for GO-2026-6859 ([a5f71bd](https://github.com/IDFoundry/OID4VCgo/commit/a5f71bd87a4fa8e570ba446f0a9e5ac9e75066f1))

## [0.11.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.10.0...sqlstore/v0.11.0) (2026-11-08)


### ⚠ BREAKING CHANGES

* **deps:** OID4VCgo requires FAPIgo v0.72.0, and the sqlstore tests and passport-vdc fapigo/sqlstore v0.8.0. Replace asDB.Grants().Batching() with asDB.BatchingGrants(), asDB.Revocation().Batching() with asDB.BatchingRevocation(), and a ResourceServer's Revocation.Batching() with its BatchingRevocation field. A wrapper embedding server.JWTAccessTokens, server.NoBackchannelNotifications or resource.NoRevocationUntilExpiry must follow FAPIgo's UPGRADING.md.

### Features

* **sqlstore:** lock Migrate per schema on Postgres ([73c29ee](https://github.com/IDFoundry/OID4VCgo/commit/73c29ee891b07f0a5a0145c2435c3d6c1cb0ca2b))


### Bug Fixes

* **deps:** pin FAPIgo v0.72.0 and fapigo/sqlstore v0.8.0 ([86deaa9](https://github.com/IDFoundry/OID4VCgo/commit/86deaa9208e0aea4e0b32e2d214cd4b5c4ab2b40))

## [0.10.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.9.1...sqlstore/v0.10.0) (2026-11-07)


### ⚠ BREAKING CHANGES

* **deps:** OID4VCgo now requires FAPIgo v0.71.0. Code calling IsAnyRevoked or RecordIssuedTokens on a memstore store calls IsRevoked per key, or RecordIssuedAccessToken then RecordIssuedRefreshToken, instead. A deployment wiring fapigo/sqlstore's Grants() and Revocation() into server.Dependencies wires Grants().Batching() and Revocation().Batching() to keep the batched queries; without them every answer is the same, from a query per key.

### Features

* **sqlstore:** let Sweep run from every instance ([0e53ccb](https://github.com/IDFoundry/OID4VCgo/commit/0e53ccb0062ab6b8fd37730560103a6c43f0f0aa))


### Bug Fixes

* **deps:** pin FAPIgo v0.71.0 and FAPIgo sqlstore v0.7.0 ([6ccddf9](https://github.com/IDFoundry/OID4VCgo/commit/6ccddf97c3ab9a18ea8b0f9e34ba59039b420034))
* **sqlstore:** register one wallet instance per App Attest key ([351b106](https://github.com/IDFoundry/OID4VCgo/commit/351b10635d90317688da662ef41a9a85ee1df961))

## [0.9.1](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.9.0...sqlstore/v0.9.1) (2026-11-07)


### Bug Fixes

* **deps:** pin FAPIgo v0.70.0 and FAPIgo sqlstore v0.6.0 ([a8796a5](https://github.com/IDFoundry/OID4VCgo/commit/a8796a536a8227cf3e9bff570f74dce86caeb518))

## [0.9.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.8.0...sqlstore/v0.9.0) (2026-11-06)


### Features

* **sqlstore:** delete retired status lists and expired instance keys ([5faa9d4](https://github.com/IDFoundry/OID4VCgo/commit/5faa9d4f9f09251f6637697a72051fe447894700))
* **sqlstore:** list Wallet Provider instance keys with no RetainUntil ([c82fe68](https://github.com/IDFoundry/OID4VCgo/commit/c82fe684472bea4c40512431984a13ac2773da66))
* **sqlstore:** reserve a batch's status indices in one INSERT ([5e71a63](https://github.com/IDFoundry/OID4VCgo/commit/5e71a63e42a91b81ffdb357b8833f4a68784a0c4))
* **sqlstore:** spend stateless c_nonces ([968ba98](https://github.com/IDFoundry/OID4VCgo/commit/968ba98ade7eea7768dadd6ebf2d4b9f194d05e3))
* **sqlstore:** store shared Status List tokens and list versions ([53471b2](https://github.com/IDFoundry/OID4VCgo/commit/53471b26164809dd128999db1f92e704c7bbab3f))


### Bug Fixes

* **sqlstore:** keep each shared status list token's signer ([a946301](https://github.com/IDFoundry/OID4VCgo/commit/a946301b9c6b9ddaa1435ae5a0d499918df6ee46))


### Performance Improvements

* **sqlstore:** don't rewrite a record an update leaves unchanged ([fa40237](https://github.com/IDFoundry/OID4VCgo/commit/fa4023722f2a7f74c52cee880caa6e0b48316a85))
* **sqlstore:** shard each status list's reserved count ([470bc90](https://github.com/IDFoundry/OID4VCgo/commit/470bc90ae71abfd4587c9a67b1ae0adebf7d6b82))
* **sqlstore:** sweep in batches, and use the lookups' partial indexes ([89cfe84](https://github.com/IDFoundry/OID4VCgo/commit/89cfe84414828369f4ecb866f71c4111658152c6))

## [0.8.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.7.1...sqlstore/v0.8.0) (2026-11-05)


### Features

* **sqlstore:** update Wallet Provider instance keys with a compare-and-swap ([73c2db4](https://github.com/IDFoundry/OID4VCgo/commit/73c2db41b4eeb382267e260fab0a2bc7727d84c5))

## [0.7.1](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.7.0...sqlstore/v0.7.1) (2026-11-05)


### Performance Improvements

* **sqlstore:** count reserved status indices and index the set ones ([dd718c4](https://github.com/IDFoundry/OID4VCgo/commit/dd718c42bbae8b4d1e195480e9d167c2885532b4))

## [0.7.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.6.0...sqlstore/v0.7.0) (2026-11-05)


### Features

* **sqlstore:** add a durable Wallet Provider instance key store ([b4d648e](https://github.com/IDFoundry/OID4VCgo/commit/b4d648eaf5c094e91b9a7b4a95f4cfe963d438b3))

## [0.6.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.5.0...sqlstore/v0.6.0) (2026-11-05)


### Features

* **sqlstore:** add durable Wallet Provider instance and challenge stores ([361cc86](https://github.com/IDFoundry/OID4VCgo/commit/361cc867f15f18bfd54a63b79aff6d655cf65976))

## [0.5.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.4.0...sqlstore/v0.5.0) (2026-11-04)


### Features

* **sqlstore:** add a durable statuslist.IndexStore ([a7f9ff7](https://github.com/IDFoundry/OID4VCgo/commit/a7f9ff7c00cf9928e84230347749c3b321317a58))

## [0.4.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.3.0...sqlstore/v0.4.0) (2026-11-03)


### ⚠ BREAKING CHANGES

* **sqlstore:** on a DB with a Sealer, DB.Transactions(TransactionCodec{}) now seals transactions, and no longer reads the unsealed ones it wrote

### Bug Fixes

* **sqlstore:** seal verifier transactions with the DB's Sealer by default ([0dd269f](https://github.com/IDFoundry/OID4VCgo/commit/0dd269f5a7476dc9e34952203d390a00000d22b1))

## [0.3.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.2.1...sqlstore/v0.3.0) (2026-11-02)


### ⚠ BREAKING CHANGES

* **sqlstore:** Migrate and CheckSchema refuse a SQLite database not in WAL mode. Open it with ?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL).
* **deps:** an issuer running fapigo/server beside issuer gets FAPIgo v0.69.0's behavioural changes: Wallet Attestation x5c RSA keys over 4096 bits or with e != 65537 are refused; IssueAccessToken and IssueRefreshToken refuse a TokenBinding or AttestedClient changed after the server returned it; pushed request parameters are bounded; a request_uri allows at most eight BeginAuthorization calls; a query or bare '#' in the issuer, endpoint or redirect URIs is refused; and fapigo/sqlstore refuses a SQLite file not in WAL mode. See UPGRADING.md.

### Bug Fixes

* **deps:** pin FAPIgo v0.69.0 and fapigo/sqlstore v0.4.0 ([ce226cf](https://github.com/IDFoundry/OID4VCgo/commit/ce226cfe67fefe23904e14e822349208de618a1e))
* **sqlstore:** refuse a SQLite database not in WAL mode ([220a6ac](https://github.com/IDFoundry/OID4VCgo/commit/220a6ac09065264bcb7794355170578a4200e550))

## [0.2.1](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.2.0...sqlstore/v0.2.1) (2026-11-01)


### Bug Fixes

* **sqlstore:** answer an ID Postgres can't hold as not found ([9207ea4](https://github.com/IDFoundry/OID4VCgo/commit/9207ea46a29ba1814bf50332d5a9a5cc09172e80))
* **sqlstore:** check a pre-authorized code's tx_code_hash column against its sealed record ([65e68e0](https://github.com/IDFoundry/OID4VCgo/commit/65e68e07ed410ffbdbc3dc7df17ca296eb60c4f6))
* **sqlstore:** document RotatingSealer as the way to change the sealing key ([738bdde](https://github.com/IDFoundry/OID4VCgo/commit/738bddeaa33fa7f2b6a2ba60c92917fa39e20cd1))
* **sqlstore:** leave expired wallet authorizations to walletflow in Sweep ([f4afca7](https://github.com/IDFoundry/OID4VCgo/commit/f4afca70f94cd664eabc5cfeab18055fb3d93cbd))
* **sqlstore:** pin Postgres writes to READ COMMITTED; honour ctx waiting for SQLite writes ([e4184a3](https://github.com/IDFoundry/OID4VCgo/commit/e4184a326ccb4772d4891a1e4dd7c71f3cd354fc))

## [0.2.0](https://github.com/IDFoundry/OID4VCgo/compare/sqlstore/v0.1.0...sqlstore/v0.2.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* **deps:** an issuer whose Authorization Server verifies Wallet Attestations with server.X5CAttesterChain now refuses, with invalid_client, an attestation signed by a certificate listing (or chaining only through a CA restricted to) the ISO/IEC 18013-5 mDL JWS or VICAL signer, ISO/IEC TS 23220-4 mdoc document signer or reader, RFC 9336 document signing, or RFC 6187 SSH extended key usage; issue attesters a dedicated certificate. It also refuses an x5c carrying a re-issued or cross-signed copy of a trust anchor (same subject and public key): send the signing certificate and its intermediates only. A deployment running fapigo/sqlstore v0.2.0 with a Sealer upgrades every instance at once, since v0.2.0 can't open records v0.3.0 seals, then runs SealRecords once.

### Bug Fixes

* **deps:** pin FAPIgo v0.68.0 and fapigo/sqlstore v0.3.0 ([de45f51](https://github.com/IDFoundry/OID4VCgo/commit/de45f51555d997be0d9980772b101588d358cf50))

## 0.1.0 (2026-10-31)


### Features

* **sqlstore:** add a database/sql module with durable issuer stores ([6be2576](https://github.com/IDFoundry/OID4VCgo/commit/6be25761ca7dd6654d6706e1e8ec75aecbbecc26))
* **sqlstore:** add a durable verifier TransactionStore ([776b070](https://github.com/IDFoundry/OID4VCgo/commit/776b0708b2b5f71548805d86e212ea4d5069873d))
* **sqlstore:** add durable walletflow stores ([35d3210](https://github.com/IDFoundry/OID4VCgo/commit/35d3210c25287f81059d9801e1123aed212d02d4))


### Bug Fixes

* **deps:** pin FAPIgo v0.67.0 ([537ab6f](https://github.com/IDFoundry/OID4VCgo/commit/537ab6fef91755a61ba5b06cc405fb3add0c475a))
* **deps:** pin FAPIgo v0.67.2 ([ab6edc0](https://github.com/IDFoundry/OID4VCgo/commit/ab6edc09a9b7278d35d44d3ec679373c24b2e704))
