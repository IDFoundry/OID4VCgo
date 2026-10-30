# Going to production

What a wallet needs before real holders use it.

A wallet holding real credentials is only as trustworthy as the
platform it runs on. The library enforces some of this itself: without
`WalletConfiguration.development`, receiving credentials needs a key
store and a credential store that both say they're durable, and
services on loopback addresses are refused. The rest is the app's.

## Keys and storage

- Keep `AndroidKeystoreKeyStore`'s defaults: keys in StrongBox where the
  device has it, else the TEE, usable only while the device is unlocked,
  and holder keys asking for the holder's fingerprint or screen lock
  before each presentation, through `BiometricPromptAuthenticator`.
  That needs Android 11 (API 30) and a secure lock screen.
- Use `FileCredentialStore`: each record encrypted under a Keystore key
  that works only while the device is unlocked, out of backups.
  `InMemoryCredentialStore` is for tests.
- Call `Wallet.sweepOrphanedKeys` at launch, before any issuance, so keys
  an interrupted issuance left don't accumulate.
- Make one `Wallet` per key store and credential store, and share it
  for the app's life. Two over the same stores don't coordinate: both
  could present the same copy of a credential, so Verifiers could link
  the presentations, or redeem the same refresh token, so the
  authorization server revokes the grant.
- A device restored from a backup, or a new one the app moved to, has no
  holder keys: its credentials show `holderKeyPresent` as false and
  can't be presented. Delete them, and receive them again.

## The Wallet Provider

Issuers trust the wallet because its Wallet Provider attests it: a Key
Attestation's `key_storage` and `user_authentication` tell an issuer
the holder keys can't be copied off the device, and it binds
credentials to them on that word. A provider that attests whatever keys
it's sent lets a modified app, or an emulator, get credentials bound to
software keys anyone can copy. Play Integrity attests the app, not where
its keys live: it doesn't stand in for Key Attestation.

So the provider checks Android Key Attestation of each key before
attesting it:

1. **Give a challenge.** Implement `WalletProvider.attestationChallenge`:
   for `KeyPurpose.INSTANCE` and `KeyPurpose.HOLDER`, fetch a fresh,
   random, single-use challenge (16 to 128 bytes) from your backend,
   which remembers it with an expiry; for `KeyPurpose.DPOP`, return
   null. `AndroidKeystoreKeyStore` makes each key over its challenge,
   so Android Keystore certifies the key, the challenge and the app
   that made it.
2. **Receive the evidence.** Implement the `WalletAttestationRequest`
   and `KeyAttestationRequest` versions of `walletAttestation` and
   `keyAttestation`, and send each key's `KeyEvidence` —
   `certificateChain`, DER, the key's certificate first — to your
   backend with its JWK.
3. **Verify the chain, on the backend.** Refuse a key whose chain is
   empty. Otherwise:
   - each certificate is signed by the next, all are within their
     validity, and the last is one of Google's hardware attestation
     roots;
   - no certificate in it is revoked or suspended in Google's
     attestation status list;
   - the first certificate's public key is the JWK being attested;
   - its key description extension (OID 1.3.6.1.4.1.11129.2.1.17)
     has the challenge you issued for this key, unused and unexpired,
     which you then consume;
   - its attestation and KeyMint security levels are
     `TrustedEnvironment` or `StrongBox`, never `Software`;
   - its hardware-enforced list has origin `GENERATED`, an EC P-256 key
     for signing, and a root of trust with `verifiedBootState`
     `Verified` and `deviceLocked` true;
   - its `attestationApplicationId` names your app's package and
     signing certificate digest.
4. **Attest only what you verified.** Claim `key_storage` and
   `user_authentication` levels the attestation supports — StrongBox
   or the TEE; user authentication only for a holder key whose
   hardware-enforced list requires it (`AndroidKeystoreKeyStore`'s
   `holderUserAuthentication`) — and never more.
5. **Keep your own signing key in an HSM.**

A key is attested once, when it's made, over that moment's challenge. A
key attested again later — the instance key, when a refresh needs a new
Wallet Attestation — brings the same chain: recognise a key you verified
before (by its JWK thumbprint) rather than asking for a fresh challenge.

A custom `KeyStore` gives the provider no evidence unless it implements
`createKey(purpose, attestationChallenge)` and `attestationChain(id)`:
keep `AndroidKeystoreKeyStore`. The demo wallet's provider attests
anything, and is for development only.

## Trust

- Configure only your ecosystem's roots: `issuerRoots` for credentials,
  `verifierRoots` for the Verifiers the wallet answers, and
  `registrarRoots` only for registrars, never for Verifiers or issuers,
  which could then register themselves.
- For readers, `mdocReaderRoots` with `mdocReaderRequireEKU`, and
  `requireTrustedMdocReader` where every reader must be a known one.
- Never ship with `development` set, or `developmentRoots`.
- To pin your services' certificates, set `tlsPins`: host → base64
  SHA-256 digests of a certificate's SubjectPublicKeyInfo. Pin a CA's
  key, so a leaf renewal doesn't break the app, and keep a backup pin:
  a wrong set locks the wallet out of that host until an update. Pins
  cover the SDK's own requests, not your app's, such as to your Wallet
  Provider: pin that client yourself (OkHttp's `CertificatePinner`, or
  a network security configuration).
- To refuse certificates your ecosystem's CAs have revoked, list the
  roles to check in `revocation` and give their CAs' CRLs (PEM
  `X509 CRL` blocks) in `crls`. A role listed fails closed for any CA it
  has no current CRL from, so list only roles whose CAs publish CRLs.
  Every role whose roots you set must be in `revocation` or in
  `noRevocationCheck`, which declines checking it, or the wallet isn't
  made (`invalidInput`): decline only where something else stands in
  for revocation, such as certificates too short-lived to be worth
  revoking. `issuerRoots` and the mdoc roots bring two roles, `ISSUER`
  and `STATUS` (the status lists' signers). CRLs expire at their nextUpdate: fetch fresh ones in the background
  and hand them over with `Wallet.setCRLs`, which replaces them all
  (empty text removes them) and throws `invalidInput`, keeping the old
  lists, for anything that isn't a CRL. A certificate pinned in the
  roots, such as a Verifier's leaf in `verifierRoots`, is checked
  against its CA's CRL: give that CA's certificate in `crlIssuers`, or
  it's refused. A `ProximityReader` takes the same, for its document
  signers and status lists.
- As a Credential Manager provider, see the open caveat in
  [Presenting to Chrome](PresentingToChrome.md).

### Settings to decide

Each of these is off or open by default. Decide each for your
ecosystem, and record why:

- `issuanceProfile`: `IssuanceProfile.HAIP` refuses issuers that don't
  follow HAIP 1.0 (`profileViolation`); it needs a `WalletProvider` and
  `clientID`. Set it where every issuer should be a HAIP one.
- Signed issuer metadata: `issuerMetadataRoots` asks for and verifies
  it; `requireSignedIssuerMetadata` refuses an issuer without it before
  the holder signs in or enters a code; `requireIssuerMetadataName`
  refuses metadata whose certificate doesn't name the issuer;
  `maxIssuerMetadataAgeSeconds` bounds its age; and
  `issuerMetadataRequireEKU` its signer's extended key usage. Set them
  together where your issuers sign their metadata.
- `requireIssuerName`: refuses an SD-JWT VC whose `iss` its signing
  certificate doesn't name. Set it where `issuerRoots` certify several
  issuers, so one can't issue in another's name.
- `allowForeignIss`: receives an SD-JWT VC whose `iss` isn't the issuer
  it came from. Leave it off unless an issuer names itself differently,
  and `issuerRoots` certify it alone.
- `statusIssuers`: the Status Issuers that may sign an issuer's status
  lists for it. Without it, only the issuer's own lists are accepted:
  add only delegations your ecosystem publishes.
- `mdocIssuerRoots` and `mdocIssuerRootsByDocType`: the IACAs mdocs, or
  each document type, must chain to, instead of `issuerRoots`, so an
  SD-JWT VC issuer's CA can't sign an mDL. `mdocIssuerRequireEKU`
  requires document signers' extended key usage (the mDL's is
  1.0.18013.5.1.2).
- `proximityDeviceAuth`: `MAC_PREFERRED` answers readers with deviceMac,
  which the reader can't show anyone else; it needs
  `holderKeyAgreement`. `SIGNATURE`, the default, signs.
- For a `ProximityReader`: `issuerRootsByDocType` confines each document
  type to its own IACAs, and `requireMDLSignerEKU` accepts only document
  signers with the mDL document signer extended key usage.

## Privacy

- Request batches of copies (`batchSize`) and refresh them as they're
  used up (`requestRefresh`), so presentations stay unlinkable; warn the
  holder when one wouldn't be (`linkableHere`).
- Log `WalletException.message`, never claims, credentials or QR codes.
- Set `FLAG_SECURE` on windows that show credentials, so the recents
  thumbnail and screenshots show no claims or portraits.
- Fetch an issuer's `Logo` once, when the holder accepts the credential,
  and keep it: loading it on the offer's preview tells whoever serves it
  that the offer was opened.

## The build

- Ship the release AAR, which carries the release build of the Go
  library. Refuse to run on the test build, which carries an in-process
  issuer and Verifier: check `OID4VC.isTestBuild` at launch.
- Check the AAR you ship: the release's `SHA256SUMS`, and its provenance
  with `gh attestation verify`.
- The AAR carries its own R8 rules (`consumer-rules.pro`), which keep the
  Go library's bindings. A minified build hasn't been tested as widely
  as a debug one: test yours.
