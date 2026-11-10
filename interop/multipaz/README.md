# Multipaz interop

Interop with [Multipaz](https://github.com/openwallet-foundation/multipaz),
the OpenWallet Foundation's identity library (formerly Google's
identity-credential), from its published JVM library: its mdoc reader,
holder, Annex C verifier and Annex C wallet against OID4VCgo's.
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
  signing and one agreeing keys.

## What it found

Nothing to report: every case agreed with ISO/IEC 18013-5 and TS 18013-7
on both sides. One behaviour worth knowing: Multipaz's wallet won't
answer a signed `org-iso-mdoc` request from another origin than the one
it was built for, since the reader authentication covers the session
transcript; so the origin control uses an unsigned request.

## What isn't covered

- The radio transports (BLE, NFC) and NFC engagement: only QR
  engagement.
- OpenID4VP and OpenID4VCI with Multipaz, and Multipaz's servers.
- Requests for several documents, zero-knowledge proofs, and status
  lists.

## Running it

```sh
interop/multipaz/run.sh
```

It needs Go and a JDK (21 or later), and exits 0 only if every case
behaves as expected. `WORK` keeps the run's files; `driver.log` has
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
repository: the driver leaves them out ([`build.gradle.kts`](driver/build.gradle.kts)).
`interop/eudi/presentation` uses the same Multipaz release.
