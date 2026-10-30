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
- Make one ``Wallet`` per key store and credential store, and share it
  for the app's life. Two over the same stores don't coordinate: both
  could present the same copy of a credential, so Verifiers could link
  the presentations, or redeem the same refresh token, so the
  authorization server revokes the grant.
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

App Attest attests your app, not where its keys live: it can't show
that the wallet's keys are in the Secure Enclave, and iOS has no
attestation of Secure Enclave keys a Wallet Provider can verify. Have
the app assert with App Attest over the keys it asks to have attested,
so the provider knows your genuine app sent them; their `key_storage`
then rests on your app keeping them in the Secure Enclave, as
``KeychainKeyStore`` does, not on hardware evidence. Android's library,
by contrast, hands its provider each key's Android Key Attestation
chain.

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
- To pin your services' certificates, set
  ``WalletConfiguration/tlsPins``: host → base64 SHA-256 digests of a
  certificate's SubjectPublicKeyInfo. Pin a CA's key, so a leaf renewal
  doesn't break the app, and keep a backup pin: a wrong set locks the
  wallet out of that host until an update. Pins cover the SDK's own
  requests, which `NSPinnedDomains` doesn't reach, not your app's, such
  as to your Wallet Provider: pin that `URLSession` yourself.
- To refuse certificates your ecosystem's CAs have revoked, list the
  roles to check in ``WalletConfiguration/revocation`` and give their
  CAs' CRLs (PEM `X509 CRL` blocks) in ``WalletConfiguration/crls``. A
  role listed fails closed for any CA it has no current CRL from, so
  list only roles whose CAs publish CRLs. Every role whose roots you set
  must be in ``WalletConfiguration/revocation`` or in
  ``WalletConfiguration/noRevocationCheck``, which declines checking
  it, or the wallet isn't made (`invalidInput`): decline only where
  something else stands in for revocation, such as certificates too
  short-lived to be worth revoking. ``WalletConfiguration/issuerRoots``
  and the mdoc roots bring two roles, `.issuer` and `.status` (the
  status lists' signers). CRLs expire at their
  nextUpdate: fetch fresh ones in the background and hand them over
  with ``Wallet/setCRLs(_:)``, which replaces them all (empty text
  removes them) and throws `invalidInput`, keeping the old lists, for
  anything that isn't a CRL. A certificate pinned in the roots, such as
  a Verifier's leaf in ``WalletConfiguration/verifierRoots``, is checked
  against its CA's CRL: give that CA's certificate in
  ``WalletConfiguration/crlIssuers``, or it's refused. A
  ``ProximityReader`` takes the same, for its document signers and
  status lists.

### Settings to decide

Each of these is off or open by default. Decide each for your
ecosystem, and record why:

- ``WalletConfiguration/issuanceProfile``:
  ``WalletConfiguration/IssuanceProfile/haip`` refuses issuers that
  don't follow HAIP 1.0 (``WalletError/Code/profileViolation``); it
  needs a `WalletProvider` and ``WalletConfiguration/clientID``. Set it
  where every issuer should be a HAIP one.
- Signed issuer metadata: ``WalletConfiguration/issuerMetadataRoots``
  asks for and verifies it;
  ``WalletConfiguration/requireSignedIssuerMetadata`` refuses an issuer
  without it before the holder signs in or enters a code;
  ``WalletConfiguration/requireIssuerMetadataName`` refuses metadata
  whose certificate doesn't name the issuer;
  ``WalletConfiguration/maxIssuerMetadataAgeSeconds`` bounds its age;
  and ``WalletConfiguration/issuerMetadataRequireEKU`` its signer's
  extended key usage. Set them together where your issuers sign their
  metadata.
- ``WalletConfiguration/requireIssuerName``: refuses an SD-JWT VC whose
  `iss` its signing certificate doesn't name. Set it where
  ``WalletConfiguration/issuerRoots`` certify several issuers, so one
  can't issue in another's name.
- ``WalletConfiguration/allowForeignIss``: receives an SD-JWT VC whose
  `iss` isn't the issuer it came from. Leave it off unless an issuer
  names itself differently, and ``WalletConfiguration/issuerRoots``
  certify it alone.
- ``WalletConfiguration/statusIssuers``: the Status Issuers that may
  sign an issuer's status lists for it. Without it, only the issuer's
  own lists are accepted: add only delegations your ecosystem
  publishes.
- ``WalletConfiguration/mdocIssuerRoots`` and
  ``WalletConfiguration/mdocIssuerRootsByDocType``: the IACAs mdocs, or
  each document type, must chain to, instead of
  ``WalletConfiguration/issuerRoots``, so an SD-JWT VC issuer's CA
  can't sign an mDL. ``WalletConfiguration/mdocIssuerRequireEKU``
  requires document signers' extended key usage (the mDL's is
  1.0.18013.5.1.2).
- ``WalletConfiguration/proximityDeviceAuth``:
  ``WalletConfiguration/ProximityDeviceAuth/macPreferred`` answers
  readers with deviceMac, which the reader can't show anyone else; it
  needs a key store that is also a ``KeyAgreement``.
  ``WalletConfiguration/ProximityDeviceAuth/signature``, the default,
  signs.

### Privacy

- Request batches of copies (``WalletConfiguration/batchSize``) and
  refresh them as they're used up (``WalletConfiguration/requestRefresh``),
  so presentations stay unlinkable; warn the holder when one wouldn't
  be (``CredentialSummary/linkableHere``).
- Log ``WalletError/message``, never claims or credentials.
- Cover the window when the scene isn't active, so the app switcher's
  snapshot shows no claims or portraits.
- Fetch an issuer's ``Logo`` once, when the holder accepts the
  credential, and keep it: loading it on the offer's preview tells
  whoever serves it that the offer was opened.

### The build

Ship the release build of `Mobile`, which the package links by default.
Refuse to run on the test build, which carries an in-process issuer and
Verifier: check ``OID4VC/isTestBuild`` at launch.

### A document provider extension

The app and its extension each update a credential's record — marking
a copy presented, replacing copies on refresh. Give both one
``FileCredentialStore/inAppGroup(_:options:)`` store, whose
``FileCredentialStore/compareAndSwap(id:expected:record:)`` takes a
file lock in the shared container, so their updates don't overwrite
each other. A ``CredentialStore`` of your own must make
`compareAndSwap` atomic across both processes too.
