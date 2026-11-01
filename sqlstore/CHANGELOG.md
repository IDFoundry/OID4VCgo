# Changelog

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
