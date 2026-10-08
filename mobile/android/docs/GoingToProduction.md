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
- A device restored from a backup, or a new one the app moved to, has no
  holder keys: its credentials show `holderKeyPresent` as false and
  can't be presented. Delete them, and receive them again.

## The Wallet Provider

Issuers trust the wallet because its Wallet Provider attests it. A
production Wallet Provider should attest a wallet and its keys only
after checking evidence that it's talking to your genuine app on a
genuine device — Android Key Attestation of the keys (that they're in
StrongBox or the TEE, for your app's signing certificate), or Play
Integrity — and should keep its own signing key in an HSM. The demo
wallet's provider attests anything, and is for development only.

## Trust

- Configure only your ecosystem's roots: `issuerRoots` for credentials,
  `verifierRoots` for the Verifiers the wallet answers, and
  `registrarRoots` only for registrars, never for Verifiers or issuers,
  which could then register themselves.
- For readers, `mdocReaderRoots` with `mdocReaderRequireEKU`, and
  `requireTrustedMdocReader` where every reader must be a known one.
- Never ship with `development` set, or `developmentRoots`.
- As a Credential Manager provider, see the open caveat in
  [Presenting to Chrome](PresentingToChrome.md).

## Privacy

- Request batches of copies (`batchSize`) and refresh them as they're
  used up (`requestRefresh`), so presentations stay unlinkable; warn the
  holder when one wouldn't be (`linkableHere`).
- Log `WalletException.message`, never claims or credentials.

## The build

- Ship the release AAR, which carries the release build of the Go
  library. Refuse to run on the test build, which carries an in-process
  issuer and Verifier: check `OID4VC.isTestBuild` at launch.
- Check the AAR you ship: the release's `SHA256SUMS`, and its provenance
  with `gh attestation verify`.
- The AAR carries its own R8 rules (`consumer-rules.pro`), which keep the
  Go library's bindings. A minified build hasn't been tested as widely
  as a debug one: test yours.
