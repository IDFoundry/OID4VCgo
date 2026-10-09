# Going to production

What a wallet needs before real holders use it.

## Overview

A wallet holding real credentials is only as trustworthy as the
platform it runs on. The package enforces some of this itself: without
``WalletConfiguration/development``, receiving credentials needs a key
store and a credential store that both say they're durable
(``KeyStore/isDurable``, ``CredentialStore/isDurable``), and services on
loopback addresses are refused. The rest is the app's.

### Keys and storage

- Keep ``KeychainKeyStore``'s defaults: keys in the Secure Enclave,
  persistent, and holder keys asking for Face ID, Touch ID or the
  passcode before each presentation. Add `NSFaceIDUsageDescription` to
  the Info.plist.
- Use ``FileCredentialStore``: complete data protection, out of backups.
  ``InMemoryCredentialStore`` is for tests.
- Call ``Wallet/sweepOrphanedKeys(in:)`` at launch, before any issuance,
  so keys an interrupted issuance left don't accumulate.
- A device restored from a backup has no holder keys: its credentials
  show ``CredentialSummary/holderKeyPresent`` as false and can't be
  presented. Delete them, and receive them again.

### The Wallet Provider

Issuers trust the wallet because its Wallet Provider attests it. A
production Wallet Provider should attest a wallet and its keys only
after checking App Attest evidence that it's talking to your genuine
app on a genuine device, and should keep its own signing key in an
HSM. The demo wallet's provider attests anything, and is for
development only.

### Trust

- Configure only your ecosystem's roots: ``WalletConfiguration/issuerRoots``
  for credentials, ``WalletConfiguration/verifierRoots`` for the
  Verifiers the wallet answers, and ``WalletConfiguration/registrarRoots``
  only for registrars, never for Verifiers or issuers, which could then
  register themselves.
- For readers, ``WalletConfiguration/mdocReaderRoots`` with
  ``WalletConfiguration/mdocReaderRequireEKU``, and
  ``WalletConfiguration/requireTrustedMdocReader`` where every reader
  must be a known one.
- Never ship with ``WalletConfiguration/development`` set.

### Privacy

- Request batches of copies (``WalletConfiguration/batchSize``) and
  refresh them as they're used up (``WalletConfiguration/requestRefresh``),
  so presentations stay unlinkable; warn the holder when one wouldn't
  be (``CredentialSummary/linkableHere``).
- Log ``WalletError/message``, never claims or credentials.

### The build

Ship the release build of `Mobile`, which the package links by default.
Refuse to run on the test build, which carries an in-process issuer and
Verifier: check ``OID4VC/isTestBuild`` at launch.

### A document provider extension

The app and its extension each update a credential's record — marking
a copy presented, replacing copies on refresh — with a lock that spans
only their own process. Refresh credentials when the app becomes
active, not while it's in the background, so the two don't write the
same record at once.
