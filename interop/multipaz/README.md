# Multipaz interop

Interop with [Multipaz](https://github.com/openwallet-foundation/multipaz),
the OpenWallet Foundation's identity library (formerly Google's
identity-credential), from its published JVM library: its mdoc reader,
holder, Annex C verifier and wallet, OpenID4VP wallet and Verifier, and
OpenID4VCI wallet and issuer, against OID4VCgo's.
[`run.sh`](run.sh) runs every case, from
[`.github/workflows/multipaz-interop.yml`](../../.github/workflows/multipaz-interop.yml).

## Cases

| Direction | Case | Expected |
|---|---|---|
| Multipaz reader → OID4VCgo's holder (`walletflow`) | mDL, QR engagement, reader authentication, device signature | Multipaz verifies it; only the requested elements disclosed; the holder recognizes the reader |
| | The same, deviceMac | Multipaz verifies the MAC |
| | The reader's certificate under a CA the holder doesn't trust | the holder shows the reader as untrusted |
| OID4VCgo's reader (`proximity`) → Multipaz holder (`Iso18013Presentment`) | mDL, QR engagement, reader authentication, device signature | OID4VCgo verifies it; Multipaz recognizes the reader |
| | The same, deviceMac | OID4VCgo verifies the MAC |
| | The mDL from an IACA the reader doesn't trust | the reader refuses it |
| | A DeviceResponse signed over another session transcript | the reader refuses it |
| Multipaz verifier → OID4VCgo's wallet (`walletflow`), Annex C | `org-iso-mdoc` request signed by the reader | Multipaz decrypts and verifies the answer; the wallet names the reader |
| | Signed under a CA the wallet doesn't trust | the wallet names no reader |
| OID4VCgo's verifier (`mdocdcapi`) → Multipaz wallet, Annex C | `org-iso-mdoc` request signed by OID4VCgo's reader | OID4VCgo decrypts and verifies the answer |
| | An unsigned request, answered as if from another origin | the verifier refuses it (HPKE open fails: its info is the session transcript) |
| | The mDL from an IACA the verifier doesn't trust | the verifier refuses it |
| Multipaz wallet → `cmd/conformance-verifier`, OpenID4VP 1.0 | SD-JWT VC PID, cross-device (`x509_hash`, `direct_post.jwt`, `request_uri_method` `get`) | verified |
| | mDL, cross-device, `request_uri_method` `post` | verified |
| | PID and mDL over the Digital Credentials API (`openid4vp-v1-signed`, `dc_api.jwt`) | verified |
| | The PID from an issuer the verifier doesn't trust | the verifier refuses it |
| `walletflow` → Multipaz Verifier (`VerificationSession`), OpenID4VP 1.0 | PID and mDL, cross-device (signed `x509_hash` request, `direct_post.jwt`) | Multipaz verifies it: the claims asked for, only, under OID4VCgo's IACA |
| | PID and mDL over the Digital Credentials API | Multipaz verifies it |
| | The Verifier under a CA the wallet doesn't trust | the wallet refuses it |
| | An `x509_hash` client_id naming another certificate than the one signing the request | the wallet refuses it |
| Multipaz wallet ← `cmd/conformance-issuer`, OpenID4VCI 1.0 | SD-JWT VC PID and mdoc PID, authorization code (PAR, PKCE, `scope`), Wallet Attestation and PoP, DPoP, Key Attestation proof | issued, under OID4VCgo's CAs |
| | A pre-authorized code: Multipaz asks for the configuration by `authorization_details`, then requests it by `credential_configuration_id` | the issuer refuses it (§8.2: use `credential_identifier`) |
| | A Wallet Attestation from an attester the issuer doesn't trust | the issuer refuses it (`invalid_client`) |
| | A Wallet Attestation valid for 2000 days, as Multipaz's local backend makes them | the issuer refuses it (at most a day) |
| `walletflow` ← Multipaz issuer, OpenID4VCI 1.0 | mDL and PID (mdoc and SD-JWT VC), pre-authorized code, Wallet Attestation and PoP, DPoP, Key Attestation proof | issued, and pass the wallet's checks |
| | A Wallet Attestation from an attester Multipaz's issuer doesn't trust | Multipaz's issuer refuses it |

Each control is checked for its reason, not just for a failure.

## How it's set up

- **Two programs, whole messages.** [`driver`](driver) is a Kotlin
  program on Multipaz's library; it starts [`scripts/peer`](scripts/peer),
  OID4VCgo's side, and exchanges each message with it as base64url in
  one JSON object per line. Neither side has a radio: the driver hands
  Multipaz's holder the reader's messages through an `MdocTransport` of
  its own, as Multipaz's own tests do.
- **Each side's own certificates.** Multipaz's IACA, document signer
  and reader certificates come from its `MdocUtil` generators; OID4VCgo's
  from the generators its OIDF conformance runs use, to ISO/IEC 18013-5
  Annex B. Each side trusts the other's IACA and reader CA, written to
  the work directory at start.
- **OID4VCgo's holder** is `walletflow`, as the mobile libraries use it,
  with the mDL in its store and a key store whose keys agree keys, as a
  phone's do, for deviceMac. It runs in development: it fetches nothing
  here. **Its readers** run under production assurance; `proximity`'s
  binds the IACA to the mDL document type and, by default, requires the
  mDL document signer extended key usage.
- **Multipaz's holder** is `Iso18013Presentment` with a
  `SimplePresentmentSource` whose consent prompt agrees to what's
  asked; its mDL is Multipaz's sample mDL, with two credentials, one
  signing and one agreeing keys, and its PID Multipaz's sample SD-JWT
  VC PID. Its wallet is `uriSchemePresentment` (cross-device) and
  `digitalCredentialsPresentment` (DC API) over the same source.
- **OpenID4VP.** OID4VCgo's Verifier is `cmd/conformance-verifier`,
  the binary OIDF-certified as a Verifier, an `x509_hash` client under
  OID4VCgo's reader CA, which the peer starts per case. Multipaz's is a
  `VerificationSession` the driver serves over HTTPS on loopback, signing
  as an `x509_hash` client with its reader certificate. Both serve the
  peer's certificate for `localhost`, which `walletflow`'s development
  fetcher reaches by name.
- **OpenID4VCI.** OID4VCgo's issuer is `cmd/conformance-issuer` as
  [`../eudi/scripts/setup-issuer`](../eudi/scripts/setup-issuer)
  configures it, which the peer starts, trusting an attester the peer
  makes: Multipaz names a Wallet Attestation's `iss` after its
  certificate's common name, so the attester's certificate is named for
  its issuer, and Multipaz's local wallet backend signs Key Attestations
  with the same key, so the issuer trusts that key for them too.
  Multipaz's wallet is `OpenID4VCI.createClientFromOffer` with that
  backend, its Wallet Attestations valid for an hour (the backend is the
  Wallet Provider's side; its own are valid for 2000 days, a control).
  Multipaz's issuer runs in the driver from its published libraries
  (`multipaz-openid4vci`'s routes on Netty, over TLS), signing with the
  driver's document signer and trusting the peer's Wallet Provider, which
  attests `walletflow`'s instance and keys.

## What it found

Seen running Multipaz 0.102.0; none reported upstream.

1. **Multipaz's wallet doesn't bind an `x509_hash` client_id to the
   request's certificate.** `uriSchemePresentment` checks the request
   object's signature against its `x5c` leaf, but never that the
   `client_id`'s hash is that leaf's (OpenID4VP 1.0 §5.9.3), nor, for a
   cross-device request, that the chain verifies: a request naming
   another Verifier's `x509_hash`, signed under a CA the holder doesn't
   trust, was answered, the app only told (through its trust callback)
   that the requester is unrecognized. OID4VCgo's wallet refuses such a
   request (the control above).
2. **Multipaz's Verifier doesn't check a Key Binding JWT's `aud` or
   `iat`** (`verifyOpenID4VPResponse` passes checks that accept any,
   the audience one marked TODO), and its
   OpenID4VP verification takes the SD-JWT VC issuer's key from `x5c`
   without a trust anchor: the run checks the chain itself.
3. **Multipaz's wallet always encrypts with `A128GCM`**, whatever
   `encrypted_response_enc_values_supported` lists; OID4VCgo's Verifier
   lists both `A128GCM` and `A256GCM`, as HAIP requires, so it agrees.
4. **Multipaz's wallet can't redeem a pre-authorized code at an issuer
   that follows OpenID4VCI 1.0 §6.2 and §8.2.** Its Token Request always
   names the configuration in `authorization_details`, which the issuer
   must grant with `credential_identifiers`, but it never reads them, and
   requests the credential by `credential_configuration_id`, which §8.2
   forbids once they were granted. Its authorization code flow asks by
   `scope`, and works.
5. **Multipaz's Wallet Attestations are valid for 2000 days**
   (`OpenID4VCIBackendUtil.createWalletAttestation`): an issuer that
   bounds their lifetime refuses them, as OID4VCgo's does past a day. A
   policy difference, not a protocol one, but one a Wallet Provider on
   Multipaz's backend meets.
6. **Multipaz's issuer requires `client_id` in a Token Request** of a
   client that authenticates by Wallet Attestation, whose `sub` already
   names it, though OpenID4VCI 1.0 §6.1 makes it optional; `walletflow`
   sends none, so the run's HTTP client adds it to the issuer's token
   requests (`scripts/peer`'s `withClientID`).

Every in-person and Annex C case agreed with ISO/IEC 18013-5 and TS
18013-7 on both sides. One behaviour worth knowing: Multipaz's wallet
won't answer a signed `org-iso-mdoc` request from another origin than
the one it was built for, since the reader authentication covers the
session transcript; so the origin control uses an unsigned request.

## What isn't covered

- The radio transports (BLE, NFC) and NFC engagement: only QR
  engagement.
- Multipaz's servers as deployed: its Verifier here is the library's
  `VerificationSession`, and its issuer the library's routes, without
  its records server or consent pages (so only its pre-authorized
  codes).
- Requests for several documents, transaction data, zero-knowledge
  proofs, status lists, and OpenID4VCI's refresh tokens, deferred
  issuance, Transaction Codes, batches, and encryption.

## Running it

```sh
interop/multipaz/run.sh
MULTIPAZ_VERSION=latest interop/multipaz/run.sh
```

It needs Go and a JDK (21 or later), and exits 0 only if every case
behaves as expected. `MULTIPAZ_VERSION` builds the driver against
another Multipaz release (`latest`: Maven Central's newest, found with
`curl`) without the locks and checksums, which are the pinned
release's. `WORK` keeps the run's files; `driver.log` has
Multipaz's own logging.

## Moving the pin

Multipaz is pinned in [`driver/gradle/libs.versions.toml`](driver/gradle/libs.versions.toml),
with every dependency locked and its checksum recorded. To move it, read
its CHANGELOG, change the version, and from an empty Gradle cache:

```sh
cd interop/multipaz/driver
GRADLE_USER_HOME=$(mktemp -d) ./gradlew --write-verification-metadata sha256 --write-locks resolveAndLockAll installDist
```

Multipaz's API changes between releases, so expect the driver to need
changes with it. Its JVM library also depends on Google's Android Key
Attestation verifier and androidx's annotations, from Google's Maven
repository, and its server library on JDBC drivers: the driver leaves
them out, and raises Netty and logback past known vulnerabilities
([`build.gradle.kts`](driver/build.gradle.kts)); check those again when
the pin moves.
`interop/eudi/presentation` uses the same Multipaz release.

The weekly run tests Multipaz's newest release (`MULTIPAZ_VERSION=latest`)
with the pinned driver, and opens an `interop-multipaz-latest` issue
when it fails: a new release, or one the driver no longer builds
against.
